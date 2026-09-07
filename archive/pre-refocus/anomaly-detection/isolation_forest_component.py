"""Offline-only Isolation Forest analyst-assistance study for Sentinel-CPS.

This module deliberately has no live-system, transport, or response integration.
It ranks eligible evidence windows for analyst review; its output is not an attack,
intent, delivery, execution, mitigation, or physical-safety determination.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import subprocess
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from statistics import median
from typing import Any, Iterable, Mapping

import joblib
import numpy as np
import scipy
import sklearn
import threadpoolctl
from sklearn.ensemble import IsolationForest

SCHEMA_VERSION = "isolation_forest_study_v1"
WINDOW_SECONDS = 30.0
SEED = 69201
FEATURE_NAMES = (
    "action_count", "start_stop_action_count", "non_success_action_count",
    "telemetry_row_count", "telemetry_interval_median_sec", "adc_l_range",
    "adc_r_range", "steer_range", "matched_serial_write_count",
    "matched_serial_write_requested_bytes", "matched_serial_read_count",
    "uncorrelated_matched_write_count",
)
MANIFEST_FIELDS = (
    "schema_version", "capture_id", "split", "evidence_class", "scenario_id",
    "capture_start_utc", "capture_end_utc", "actions_csv", "telemetry_csv",
    "ebpf_csv", "ebpf_coverage_complete", "clock_assessment",
    "deterministic_results_csv", "notes",
)
ACTIONS_HEADER = ("timestamp", "event_id", "source", "command", "details", "result", "mode")
TELEMETRY_HEADER = ("timestamp", "vehicle_id", "adc_l", "adc_r", "steer", "state", "source")
EBPF_HEADER = (
    "timestamp", "timestamp_iso", "monotonic_ns", "pid", "comm", "syscall",
    "fd", "count", "retval", "fd_path", "device_match", "notes",
)
WINDOW_RESULT_FIELDS = (
    "schema_version", "run_id", "model_id", "split", "evidence_class", "capture_id",
    "scenario_id", "window_id", "window_start_utc", "window_end_utc", "window_status",
    "exclusion_reason", "anomaly_score", "threshold", "iforest_flag", "rule_ids_in_window",
    "rule_count", *FEATURE_NAMES,
)
SUMMARY_FIELDS = (
    "run_id", "split", "evidence_class", "scenario_id", "eligible_windows",
    "excluded_windows", "flagged_windows", "false_positive_rate", "abnormal_window_detection_rate",
    "scenario_detected", "score_min", "score_median", "score_max", "threshold", "notes",
)
ALLOWED_SPLITS = {"train", "validation", "test"}
ALLOWED_EVIDENCE_CLASSES = {"SYNTHETIC", "FIXTURE", "MOCK", "PHYSICAL"}
NOMINAL_SCENARIO = "NOMINAL"
# This is intentionally a closed vocabulary derived from the current Gateway
# action-log result values.  Do not infer success from free text or from an
# inequality comparison: an unrecognized value invalidates its evidence window.
ACTION_RESULT_SUCCESS = frozenset({"SUCCESS", "ACKNOWLEDGED", "STOP_CONFIRMED"})
ACTION_RESULT_NON_SUCCESS = frozenset({
    "REJECTED", "REJECTED_LOCKED", "SERIAL_UNAVAILABLE", "SERIAL_WRITE_ERROR",
    "ACK_TIMEOUT", "NACK", "INVALID_ACK", "LOCALLY_LOCKED", "STOP_EXECUTION_UNKNOWN",
})
RECOGNIZED_ACTION_RESULTS = ACTION_RESULT_SUCCESS | ACTION_RESULT_NON_SUCCESS
ACCEPTED_CLOCK_ASSESSMENTS = {"CONSISTENT", "ALIGNED", "COMPATIBLE"}
CLAIM_BOUNDARY = (
    "Isolation Forest flags rank statistically unusual evidence windows for analyst review only. "
    "They do not prove an attack, malicious intent, compromise, RF delivery, vehicle actuation, "
    "motor cessation, successful mitigation, or physical safety."
)


class StudyError(ValueError):
    """Raised for invalid study inputs or safety gates."""


@dataclass(frozen=True)
class Capture:
    capture_id: str
    split: str
    evidence_class: str
    scenario_id: str
    start: float
    end: float
    actions_path: Path
    telemetry_path: Path
    ebpf_path: Path
    ebpf_coverage_complete: bool
    clock_assessment: str
    deterministic_path: Path | None
    notes: str


@dataclass(frozen=True)
class Event:
    timestamp: float
    row_number: int
    row: Mapping[str, str]


@dataclass
class ParsedEvents:
    """Validated rows plus row-level issues retained for window exclusion."""

    events: list[Event]
    assigned_problems: list[tuple[float, str]]
    capture_problems: list[str]


@dataclass
class Window:
    capture: Capture
    index: int
    start: float
    end: float
    status: str = "EXCLUDED"
    reason: str = "EMPTY_WINDOW"
    features: dict[str, float] | None = None
    rule_ids: list[str] | None = None
    score: float | None = None
    flag: bool | None = None


def _finite(value: Any) -> float | None:
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _utc_epoch(value: str, field: str) -> float:
    text = (value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise StudyError(f"{field} must be an ISO-8601 UTC timestamp.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise StudyError(f"{field} must include a UTC offset (+00:00 or Z).")
    return parsed.timestamp()


def utc_text(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_csv_sha256(path: Path) -> str:
    """Hash parsed CSV content independent of newline, quoting, and row order.

    This deliberately detects exact semantic replay across splits.  It is not a
    near-duplicate, fuzzy, or adversarial similarity detector.
    """
    try:
        with path.open("r", newline="", encoding="utf-8") as stream:
            rows = list(csv.reader(stream, strict=True))
    except (OSError, csv.Error) as exc:
        raise StudyError(f"Cannot canonicalize CSV source '{path}': {exc}") from exc
    if not rows:
        raise StudyError(f"CSV source is empty: {path}")
    header, body = rows[0], rows[1:]
    canonical = json.dumps(
        {"header": header, "rows": sorted(body)},
        ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _read_exact_csv(path: Path, expected_header: tuple[str, ...], kind: str) -> list[dict[str, str]]:
    if not path.is_file():
        raise StudyError(f"{kind} input file does not exist: {path}")
    try:
        with path.open("r", newline="", encoding="utf-8") as stream:
            reader = csv.reader(stream, strict=True)
            header = tuple(next(reader, []))
            if header != expected_header:
                raise StudyError(f"{kind} has incompatible header; expected {expected_header!r}, got {header!r}")
            rows: list[dict[str, str]] = []
            for number, values in enumerate(reader, start=2):
                if len(values) != len(expected_header):
                    raise StudyError(f"{kind} row {number} has {len(values)} fields; expected {len(expected_header)}")
                rows.append(dict(zip(expected_header, values)))
            return rows
    except csv.Error as exc:
        raise StudyError(f"Malformed {kind} CSV '{path}': {exc}") from exc


def _record_quality(quality: dict[str, Any], key: str, row_number: int) -> None:
    quality[key] = int(quality.get(key, 0)) + 1
    rows_key = f"{key}_row_numbers"
    quality.setdefault(rows_key, []).append(row_number)


def _parse_events(rows: Iterable[dict[str, str]], kind: str, quality: dict[str, Any]) -> ParsedEvents:
    events: list[Event] = []
    assigned_problems: list[tuple[float, str]] = []
    capture_problems: list[str] = []
    previous: float | None = None
    for row_number, row in enumerate(rows, start=2):
        timestamp = _finite(row.get("timestamp"))
        if timestamp is None:
            _record_quality(quality, f"{kind}_unassignable_timestamp_rows", row_number)
            capture_problems.append("UNASSIGNABLE_TIMESTAMP_ROW")
            continue
        problem: str | None = None
        if kind == "telemetry":
            if any(_finite(row.get(name)) is None for name in ("adc_l", "adc_r", "steer")):
                problem = "INVALID_REQUIRED_VALUE"
        elif kind == "ebpf":
            count = _finite(row.get("count"))
            if count is None or count < 0:
                problem = "INVALID_REQUIRED_VALUE"
            elif not (row.get("syscall") or "").strip():
                problem = "INVALID_REQUIRED_VALUE"
            elif (row.get("device_match") or "").strip().lower() not in {"true", "false"}:
                problem = "INVALID_DEVICE_MATCH"
        elif kind == "actions":
            result = (row.get("result") or "").strip().upper()
            if not (row.get("command") or "").strip():
                problem = "INVALID_REQUIRED_VALUE"
            elif result not in RECOGNIZED_ACTION_RESULTS:
                problem = "INVALID_RESULT"
        if problem is not None:
            _record_quality(quality, f"{kind}_{problem.lower()}_rows", row_number)
            assigned_problems.append((timestamp, f"{kind.upper()}_{problem}_ROW_{row_number}"))
            continue
        if previous is not None and timestamp < previous:
            _record_quality(quality, f"{kind}_timestamp_regressions", row_number)
            capture_problems.append("ORIGINAL_ORDER_TIMESTAMP_REGRESSION")
        previous = timestamp
        events.append(Event(timestamp, row_number, row))
    # Python's sort is stable; row_number makes the preserved input order explicit
    # for equal timestamps while retaining every duplicate event.
    return ParsedEvents(
        events=sorted(events, key=lambda item: (item.timestamp, item.row_number)),
        assigned_problems=assigned_problems,
        capture_problems=sorted(set(capture_problems)),
    )


def _parse_bool(value: str, field: str) -> bool:
    normalized = (value or "").strip().lower()
    if normalized in {"true", "yes", "1"}:
        return True
    if normalized in {"false", "no", "0"}:
        return False
    raise StudyError(f"{field} must be true or false.")


def load_study_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise StudyError(f"Cannot read study config: {config_path}") from exc
    except json.JSONDecodeError as exc:
        raise StudyError(f"Malformed study config JSON: {exc.msg}") from exc
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "window_seconds"}:
        raise StudyError("Study config must contain exactly schema_version and window_seconds.")
    if raw["schema_version"] != SCHEMA_VERSION or raw["window_seconds"] != 30:
        raise StudyError(f"Study config must specify {SCHEMA_VERSION!r} and window_seconds 30.")
    return dict(raw)


def load_manifest(path: str | Path) -> list[Capture]:
    manifest_path = Path(path).resolve()
    if not manifest_path.is_file():
        raise StudyError(f"Manifest does not exist: {manifest_path}")
    try:
        with manifest_path.open("r", newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream, strict=True)
            if tuple(reader.fieldnames or ()) != MANIFEST_FIELDS:
                raise StudyError(f"Manifest header must be exactly {MANIFEST_FIELDS!r}.")
            rows = list(reader)
    except csv.Error as exc:
        raise StudyError(f"Malformed manifest CSV: {exc}") from exc
    if not rows:
        raise StudyError("Manifest contains no captures.")
    base = manifest_path.parent
    captures: list[Capture] = []
    seen: set[str] = set()
    for number, row in enumerate(rows, start=2):
        capture_id = (row.get("capture_id") or "").strip()
        split = (row.get("split") or "").strip()
        evidence_class = (row.get("evidence_class") or "").strip()
        scenario_id = (row.get("scenario_id") or "").strip()
        required_text = (
            "schema_version", "capture_id", "split", "evidence_class", "scenario_id",
            "capture_start_utc", "capture_end_utc", "actions_csv", "telemetry_csv",
            "ebpf_csv", "ebpf_coverage_complete", "clock_assessment", "notes",
        )
        missing = [field for field in required_text if not (row.get(field) or "").strip()]
        if missing:
            raise StudyError(f"Manifest row {number} requires nonblank fields: {', '.join(missing)}.")
        if row.get("schema_version") != SCHEMA_VERSION:
            raise StudyError(f"Manifest row {number} has unsupported schema_version.")
        if capture_id in seen:
            raise StudyError(f"capture_id {capture_id!r} is duplicated or reused across splits.")
        seen.add(capture_id)
        if split not in ALLOWED_SPLITS:
            raise StudyError(f"Manifest row {number} has invalid split {split!r}.")
        if evidence_class not in ALLOWED_EVIDENCE_CLASSES:
            raise StudyError(f"Manifest row {number} has invalid evidence_class {evidence_class!r}.")
        start = _utc_epoch(row.get("capture_start_utc", ""), f"Manifest row {number} capture_start_utc")
        end = _utc_epoch(row.get("capture_end_utc", ""), f"Manifest row {number} capture_end_utc")
        if end <= start:
            raise StudyError(f"Manifest row {number} capture_end_utc must be after capture_start_utc.")
        if split in {"train", "validation"} and scenario_id.upper() != NOMINAL_SCENARIO:
            raise StudyError(f"{split} capture {capture_id!r} must use scenario_id NOMINAL.")
        def resolve(field: str, optional: bool = False) -> Path | None:
            text = (row.get(field) or "").strip()
            if optional and not text:
                return None
            if not text:
                raise StudyError(f"Manifest row {number} requires {field}.")
            candidate = Path(text)
            return candidate if candidate.is_absolute() else (base / candidate).resolve()
        captures.append(Capture(
            capture_id, split, evidence_class, scenario_id, start, end,
            resolve("actions_csv"), resolve("telemetry_csv"), resolve("ebpf_csv"),
            _parse_bool(row.get("ebpf_coverage_complete", ""), f"Manifest row {number} ebpf_coverage_complete"),
            (row.get("clock_assessment") or "").strip(), resolve("deterministic_results_csv", True),
            row.get("notes") or "",
        ))
    _validate_split_boundaries(captures)
    return captures


def _validate_split_boundaries(captures: list[Capture]) -> None:
    hashes: dict[str, set[str]] = {}
    canonical_hashes: dict[str, set[str]] = {}
    for capture in captures:
        for path in (capture.actions_path, capture.telemetry_path, capture.ebpf_path, capture.deterministic_path):
            if path is None:
                continue
            if not path.is_file():
                raise StudyError(f"Manifest input does not exist: {path}")
            digest = sha256_file(path)
            hashes.setdefault(digest, set()).add(capture.split)
            canonical = canonical_csv_sha256(path)
            canonical_hashes.setdefault(canonical, set()).add(capture.split)
    if any(len(splits) > 1 for splits in hashes.values()):
        raise StudyError("Byte-identical source input is reused across splits.")
    if any(len(splits) > 1 for splits in canonical_hashes.values()):
        raise StudyError("Canonical parsed-content source input is reused across splits.")
    for index, left in enumerate(captures):
        for right in captures[index + 1:]:
            if left.split != right.split and max(left.start, right.start) < min(left.end, right.end):
                raise StudyError("Capture-session windows overlap across splits.")


def _in_window(events: Iterable[Event], start: float, end: float) -> list[Event]:
    return [event for event in events if start <= event.timestamp < end]


def _is_match(event: Event, syscall: str) -> bool:
    return event.row.get("syscall", "").strip().lower() == syscall and event.row.get("device_match", "").strip().lower() == "true"


def _deterministic_rule_windows(path: Path | None, windows: list[Window], quality: dict[str, Any]) -> None:
    if path is None:
        return
    try:
        with path.open("r", newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream, strict=True)
            if not reader.fieldnames or not {"timestamp", "rule_id"}.issubset(reader.fieldnames):
                raise StudyError("Deterministic-results CSV must contain timestamp and rule_id columns.")
            for row in reader:
                timestamp = _finite(row.get("timestamp"))
                rule_id = (row.get("rule_id") or "").strip()
                if timestamp is None or not rule_id:
                    quality["deterministic_invalid_rows"] = quality.get("deterministic_invalid_rows", 0) + 1
                    continue
                for window in windows:
                    if window.start <= timestamp < window.end:
                        assert window.rule_ids is not None
                        window.rule_ids.append(rule_id)
                        break
    except csv.Error as exc:
        raise StudyError(f"Malformed deterministic-results CSV '{path}': {exc}") from exc
    for window in windows:
        window.rule_ids = sorted(set(window.rule_ids or []))


def _problem_for_window(problems: Iterable[tuple[float, str]], start: float, end: float) -> str | None:
    matches = [reason for timestamp, reason in problems if start <= timestamp < end]
    return sorted(matches)[0] if matches else None


def build_capture_windows(capture: Capture) -> tuple[list[Window], dict[str, Any], dict[str, str]]:
    quality: dict[str, Any] = {}
    for label, path in (("actions", capture.actions_path), ("telemetry", capture.telemetry_path), ("ebpf", capture.ebpf_path)):
        if not path.is_file():
            raise StudyError(f"{label} input file does not exist: {path}")
    if capture.deterministic_path is not None and not capture.deterministic_path.is_file():
        raise StudyError(f"deterministic-results input file does not exist: {capture.deterministic_path}")
    source_hashes = {
        "actions_csv": sha256_file(capture.actions_path),
        "telemetry_csv": sha256_file(capture.telemetry_path),
        "ebpf_csv": sha256_file(capture.ebpf_path),
    }
    if capture.deterministic_path is not None:
        source_hashes["deterministic_results_csv"] = sha256_file(capture.deterministic_path)
    actions = _parse_events(_read_exact_csv(capture.actions_path, ACTIONS_HEADER, "actions"), "actions", quality)
    telemetry = _parse_events(_read_exact_csv(capture.telemetry_path, TELEMETRY_HEADER, "telemetry"), "telemetry", quality)
    ebpf = _parse_events(_read_exact_csv(capture.ebpf_path, EBPF_HEADER, "ebpf"), "ebpf", quality)
    capture_problems = sorted(set(actions.capture_problems + telemetry.capture_problems + ebpf.capture_problems))
    assigned_problems = actions.assigned_problems + telemetry.assigned_problems + ebpf.assigned_problems
    windows: list[Window] = []
    start = capture.start
    index = 0
    while start + WINDOW_SECONDS <= capture.end:
        window = Window(capture, index, start, start + WINDOW_SECONDS, rule_ids=[])
        index += 1
        start += WINDOW_SECONDS
        if "UNASSIGNABLE_TIMESTAMP_ROW" in capture_problems:
            window.reason = "UNASSIGNABLE_TIMESTAMP_ROW"
        elif "ORIGINAL_ORDER_TIMESTAMP_REGRESSION" in capture_problems:
            window.reason = "ORIGINAL_ORDER_TIMESTAMP_REGRESSION"
        elif capture.clock_assessment.upper() not in ACCEPTED_CLOCK_ASSESSMENTS:
            window.reason = "CLOCK_INCONSISTENT"
        elif not capture.ebpf_coverage_complete:
            window.reason = "EBPF_COVERAGE_MISSING"
        else:
            assigned_problem = _problem_for_window(assigned_problems, window.start, window.end)
            if assigned_problem is not None:
                window.reason = assigned_problem
            else:
                action_rows = _in_window(actions.events, window.start, window.end)
                telemetry_rows = _in_window(telemetry.events, window.start, window.end)
                ebpf_rows = _in_window(ebpf.events, window.start, window.end)
                if not action_rows and not telemetry_rows and not ebpf_rows:
                    window.reason = "EMPTY_WINDOW"
                elif len(telemetry_rows) < 2:
                    window.reason = "INSUFFICIENT_TELEMETRY"
                else:
                    intervals = [telemetry_rows[i].timestamp - telemetry_rows[i - 1].timestamp for i in range(1, len(telemetry_rows))]
                    writes = [event for event in ebpf_rows if _is_match(event, "write")]
                    reads = [event for event in ebpf_rows if _is_match(event, "read")]
                    uncorrelated = sum(
                        1 for write in writes
                        if not any(abs(write.timestamp - action.timestamp) <= 2.0 for action in actions.events)
                    )
                    values = {
                        "action_count": float(len(action_rows)),
                        "start_stop_action_count": float(sum(event.row.get("command", "").strip().upper() in {"START", "STOP"} for event in action_rows)),
                        "non_success_action_count": float(sum(event.row.get("result", "").strip().upper() in ACTION_RESULT_NON_SUCCESS for event in action_rows)),
                        "telemetry_row_count": float(len(telemetry_rows)),
                        "telemetry_interval_median_sec": float(median(intervals)),
                        "adc_l_range": max(float(event.row["adc_l"]) for event in telemetry_rows) - min(float(event.row["adc_l"]) for event in telemetry_rows),
                        "adc_r_range": max(float(event.row["adc_r"]) for event in telemetry_rows) - min(float(event.row["adc_r"]) for event in telemetry_rows),
                        "steer_range": max(float(event.row["steer"]) for event in telemetry_rows) - min(float(event.row["steer"]) for event in telemetry_rows),
                        "matched_serial_write_count": float(len(writes)),
                        "matched_serial_write_requested_bytes": float(sum(float(event.row["count"]) for event in writes)),
                        "matched_serial_read_count": float(len(reads)),
                        "uncorrelated_matched_write_count": float(uncorrelated),
                    }
                    window.status, window.reason, window.features = "ELIGIBLE", "", values
        windows.append(window)
    if not windows:
        raise StudyError(f"Capture {capture.capture_id!r} has no complete 30-second windows.")
    _deterministic_rule_windows(capture.deterministic_path, windows, quality)
    return windows, quality, source_hashes


def feature_matrix(windows: Iterable[Window]) -> np.ndarray:
    selected = list(windows)
    return np.asarray([[window.features[name] for name in FEATURE_NAMES] for window in selected], dtype=float)


def _git_state(package_dir: Path) -> dict[str, str]:
    def command(*args: str) -> str:
        try:
            return subprocess.check_output(args, cwd=package_dir, text=True, stderr=subprocess.DEVNULL).strip()
        except (OSError, subprocess.CalledProcessError):
            return "UNKNOWN"
    return {
        "git_commit": command("git", "rev-parse", "HEAD"),
        "git_branch": command("git", "branch", "--show-current"),
        "git_dirty": "UNKNOWN" if command("git", "status", "--porcelain") == "UNKNOWN" else str(bool(command("git", "status", "--porcelain"))),
    }


def _safe_output_dir(path: str | Path, overwrite: bool) -> Path:
    output = Path(path).resolve()
    if output.exists():
        if not output.is_dir():
            raise StudyError(f"Output path is not a directory: {output}")
        if any(output.iterdir()) and not overwrite:
            raise StudyError("Output directory must be new or empty; use --safe-overwrite only for a prior study output directory.")
        if overwrite:
            allowed = {"isolation_forest_model.joblib", "isolation_forest_model_metadata.json", "iforest_window_results.csv", "iforest_evaluation_summary.csv"}
            unexpected = [item.name for item in output.iterdir() if item.name not in allowed or not item.is_file()]
            if unexpected:
                raise StudyError("Safe overwrite refuses directories or unknown files.")
    else:
        output.mkdir(parents=True)
    return output


def _fmt(value: float | None) -> str:
    return "" if value is None else format(value, ".12g")


def _result_row(window: Window, run_id: str, model_id: str, threshold: float | None) -> dict[str, str]:
    capture = window.capture
    row: dict[str, str] = {
        "schema_version": SCHEMA_VERSION, "run_id": run_id, "model_id": model_id,
        "split": capture.split, "evidence_class": capture.evidence_class, "capture_id": capture.capture_id,
        "scenario_id": capture.scenario_id, "window_id": f"{capture.capture_id}:{window.index:06d}",
        "window_start_utc": utc_text(window.start), "window_end_utc": utc_text(window.end),
        "window_status": window.status, "exclusion_reason": window.reason,
        "anomaly_score": _fmt(window.score), "threshold": _fmt(threshold) if window.status == "ELIGIBLE" else "",
        "iforest_flag": "" if window.flag is None else str(window.flag).lower(),
        "rule_ids_in_window": ";".join(window.rule_ids or []), "rule_count": str(len(window.rule_ids or [])),
    }
    for name in FEATURE_NAMES:
        row[name] = _fmt(window.features[name]) if window.features is not None else ""
    return row


def _summary_rows(windows: list[Window], run_id: str, threshold: float | None) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    keys = sorted({(w.capture.split, w.capture.evidence_class, w.capture.scenario_id) for w in windows})
    for split, evidence_class, scenario_id in keys:
        group = [w for w in windows if (w.capture.split, w.capture.evidence_class, w.capture.scenario_id) == (split, evidence_class, scenario_id)]
        eligible = [w for w in group if w.status == "ELIGIBLE"]
        scores = [w.score for w in eligible if w.score is not None]
        flags = [w for w in eligible if w.flag]
        fpr = ""
        detection_rate = ""
        scenario_detected = ""
        if split == "validation" and scenario_id.upper() == NOMINAL_SCENARIO and threshold is not None and eligible:
            fpr = _fmt(len(flags) / len(eligible))
        # Only explicitly named controlled test scenarios may carry a detection metric;
        # PHYSICAL remains a separate evidence class and never creates a physical claim.
        if split == "test" and scenario_id.upper().startswith("CONTROLLED_") and evidence_class != "PHYSICAL" and threshold is not None and eligible:
            detection_rate = _fmt(len(flags) / len(eligible))
            scenario_detected = str(bool(flags)).lower()
        notes = "RANKING_ONLY" if threshold is None else "Analyst-review statistic only; not threat or physical attribution."
        rows.append({
            "run_id": run_id, "split": split, "evidence_class": evidence_class, "scenario_id": scenario_id,
            "eligible_windows": str(len(eligible)), "excluded_windows": str(len(group) - len(eligible)),
            "flagged_windows": str(len(flags)), "false_positive_rate": fpr,
            "abnormal_window_detection_rate": detection_rate, "scenario_detected": scenario_detected,
            "score_min": _fmt(min(scores)) if scores else "", "score_median": _fmt(float(median(scores))) if scores else "",
            "score_max": _fmt(max(scores)) if scores else "", "threshold": _fmt(threshold), "notes": notes,
        })
    return rows


def _deterministic_comparison(windows: list[Window], threshold_available: bool) -> dict[str, Any]:
    """Describe window-level overlap without feeding deterministic output to the model."""
    with_rules = [window for window in windows if window.rule_ids]
    result: dict[str, Any] = {
        "deterministic_results_supplied": bool(with_rules),
        "windows_with_rule_ids": len(with_rules),
        "rule_ids_observed": sorted({rule_id for window in with_rules for rule_id in window.rule_ids or []}),
        "comparison_is_descriptive_only": True,
    }
    if threshold_available:
        eligible = [window for window in windows if window.status == "ELIGIBLE"]
        result["iforest_and_rule_window_count"] = sum(bool(window.flag) and bool(window.rule_ids) for window in eligible)
        result["iforest_only_window_count"] = sum(bool(window.flag) and not bool(window.rule_ids) for window in eligible)
        result["rule_only_window_count"] = sum(not bool(window.flag) and bool(window.rule_ids) for window in eligible)
        result["neither_window_count"] = sum(not bool(window.flag) and not bool(window.rule_ids) for window in eligible)
    else:
        result["status"] = "RANKING_ONLY_NO_FLAG_COMPARISON"
    return result


def run_study(manifest_path: str | Path, config_path: str | Path, output_dir: str | Path, safe_overwrite: bool = False) -> dict[str, Any]:
    """Run one controlled offline study and write exactly four operator-requested artifacts."""
    load_study_config(config_path)
    captures = load_manifest(manifest_path)
    all_windows: list[Window] = []
    quality_totals: dict[str, int] = {}
    quality_by_capture: dict[str, dict[str, Any]] = {}
    source_hashes: dict[str, dict[str, str]] = {}
    for capture in captures:
        windows, quality, hashes = build_capture_windows(capture)
        all_windows.extend(windows)
        source_hashes[capture.capture_id] = hashes
        quality_by_capture[capture.capture_id] = quality
        for name, count in quality.items():
            if isinstance(count, int):
                quality_totals[name] = quality_totals.get(name, 0) + count
    train = [w for w in all_windows if w.capture.split == "train" and w.status == "ELIGIBLE"]
    validation = [w for w in all_windows if w.capture.split == "validation" and w.status == "ELIGIBLE"]
    train_ids = {w.capture.capture_id for w in train}
    validation_ids = {w.capture.capture_id for w in validation}
    if len(train) < 100 or len(train_ids) < 2:
        raise StudyError("Training gate failed: require at least 100 eligible windows from at least two nominal training captures.")
    output = _safe_output_dir(output_dir, safe_overwrite)
    model = IsolationForest(
        random_state=SEED, n_estimators=200, max_samples=min(256, len(train)),
        max_features=1.0, bootstrap=False, contamination="auto", n_jobs=1,
    )
    model.fit(feature_matrix(train))
    for window in (w for w in all_windows if w.status == "ELIGIBLE"):
        window.score = float(-model.score_samples(feature_matrix([window]))[0])
    threshold: float | None = None
    ranking_only = len(validation) < 100 or len(validation_ids) < 2
    if not ranking_only:
        validation_scores = sorted(float(w.score) for w in validation if w.score is not None)
        threshold = validation_scores[math.ceil(0.99 * len(validation_scores)) - 1]
        for window in (w for w in all_windows if w.status == "ELIGIBLE"):
            window.flag = bool(window.score is not None and window.score > threshold)
    model_id = "iforest-" + hashlib.sha256((SCHEMA_VERSION + ":" + ",".join(FEATURE_NAMES)).encode()).hexdigest()[:16]
    run_id = str(uuid.uuid4())
    model_path = output / "isolation_forest_model.joblib"
    joblib.dump(model, model_path)
    model_hash = sha256_file(model_path)
    with (output / "iforest_window_results.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=WINDOW_RESULT_FIELDS, extrasaction="raise")
        writer.writeheader()
        writer.writerows(_result_row(window, run_id, model_id, threshold) for window in all_windows)
    summaries = _summary_rows(all_windows, run_id, threshold)
    with (output / "iforest_evaluation_summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=SUMMARY_FIELDS, extrasaction="raise")
        writer.writeheader()
        writer.writerows(summaries)
    feature_hash = hashlib.sha256(",".join(FEATURE_NAMES).encode("utf-8")).hexdigest()
    empirical_fpr = None if threshold is None else sum(bool(w.flag) for w in validation) / len(validation)
    metadata = {
        "schema_version": SCHEMA_VERSION, "model_id": model_id, "run_id": run_id, "model_sha256": model_hash,
        "feature_names": list(FEATURE_NAMES), "feature_schema_sha256": feature_hash,
        "source_file_sha256": source_hashes, **_git_state(Path(__file__).resolve().parent),
        "versions": {"python": sys.version.split()[0], "scikit_learn": sklearn.__version__, "numpy": np.__version__, "scipy": scipy.__version__, "joblib": joblib.__version__, "threadpoolctl": threadpoolctl.__version__},
        "seed": SEED, "resolved_isolation_forest_parameters": {"random_state": SEED, "n_estimators": 200, "max_samples": min(256, len(train)), "max_features": 1.0, "bootstrap": False, "contamination": "auto", "n_jobs": 1},
        "training_eligible_window_count": len(train), "validation_eligible_window_count": len(validation),
        "capture_ids_by_split": {split: [c.capture_id for c in captures if c.split == split] for split in sorted(ALLOWED_SPLITS)},
        "evidence_classes": sorted({c.evidence_class for c in captures}), "scenario_ids": sorted({c.scenario_id for c in captures}),
        "threshold": {"method": "nearest_rank_99th_percentile_nominal_validation", "target_fpr": 0.01, "actual_threshold": threshold, "empirical_validation_fpr": empirical_fpr, "status": "RANKING_ONLY" if ranking_only else "THRESHOLD_AVAILABLE"},
        "deterministic_rule_comparison": _deterministic_comparison(all_windows, threshold is not None),
        "exclusion_and_data_quality_counts": {
            **quality_totals,
            "excluded_windows": sum(w.status != "ELIGIBLE" for w in all_windows),
            "eligible_windows": sum(w.status == "ELIGIBLE" for w in all_windows),
        },
        "quality_diagnostics_by_capture": quality_by_capture,
        "generated_at_utc": utc_text(datetime.now(UTC).timestamp()), "claim_boundary": CLAIM_BOUNDARY,
    }
    (output / "isolation_forest_model_metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"run_id": run_id, "model_id": model_id, "output_dir": str(output), "training_windows": len(train), "validation_windows": len(validation), "ranking_only": ranking_only, "threshold": threshold, "eligible_windows": sum(w.status == "ELIGIBLE" for w in all_windows), "excluded_windows": sum(w.status != "ELIGIBLE" for w in all_windows)}
