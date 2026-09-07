"""Reusable deterministic anomaly engine for Sentinel-CPS.

The engine has no live-system integrations.  It accepts already-loaded rows,
evaluates the v0.1.1 R001--R007 baseline, and returns ordinary dictionaries.
Callers may copy and extend those dictionaries with live-only provenance fields;
the offline scorer intentionally writes only :data:`OUTPUT_FIELDNAMES`.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


OUTPUT_FIELDNAMES = [
    "timestamp",
    "timestamp_iso",
    "event_type",
    "source_file",
    "related_command",
    "severity",
    "score",
    "rule_id",
    "description",
    "recommended_response",
    "evidence_reference",
]


DEFAULT_CONFIG: dict[str, int | float] = {
    "command_burst_window_sec": 5.0,
    "max_commands_per_window": 4,
    "telemetry_flood_window_sec": 2.0,
    "max_telemetry_rows_per_window": 8,
    "toggle_window_sec": 10.0,
    "max_start_stop_toggles_per_window": 3,
    "locked_state_write_window_sec": 10.0,
    "locked_write_grace_sec": 0.5,
    "max_allowed_writes_after_locked": 0,
    "serial_orphan_window_sec": 2.0,
    "max_orphan_serial_writes": 2,
    "replay_like_interval_tolerance_sec": 0.005,
    "replay_like_sequence_length": 5,
    "malformed_telemetry_penalty": 80,
    "orphan_serial_activity_penalty": 60,
    "anomaly_score_threshold_low": 40,
    "anomaly_score_threshold_medium": 70,
    "anomaly_score_threshold_high": 90,
}

_POSITIVE_DURATIONS = (
    "command_burst_window_sec",
    "telemetry_flood_window_sec",
    "toggle_window_sec",
    "locked_state_write_window_sec",
    "locked_write_grace_sec",
    "serial_orphan_window_sec",
)
_NONNEGATIVE_COUNTS = (
    "max_commands_per_window",
    "max_telemetry_rows_per_window",
    "max_start_stop_toggles_per_window",
    "max_allowed_writes_after_locked",
    "max_orphan_serial_writes",
)
_NONNEGATIVE_NUMBERS = (
    "replay_like_interval_tolerance_sec",
    "malformed_telemetry_penalty",
    "orphan_serial_activity_penalty",
    "anomaly_score_threshold_low",
    "anomaly_score_threshold_medium",
    "anomaly_score_threshold_high",
)


class ConfigurationError(ValueError):
    """Raised when anomaly-rule configuration is malformed."""


@dataclass(frozen=True)
class NormalizedAction:
    timestamp: float
    row: Mapping[str, Any]


@dataclass(frozen=True)
class NormalizedTelemetry:
    timestamp: float
    row: Mapping[str, Any]
    row_number: int


@dataclass(frozen=True)
class NormalizedEbpf:
    timestamp: float
    row: Mapping[str, Any]
    row_number: int


@dataclass(frozen=True)
class SourceFiles:
    actions: str = "actions.csv"
    telemetry: str = "telemetry.csv"
    ebpf: str = "serial_trace.csv"


def _finite_number(name: str, value: Any) -> float:
    if isinstance(value, bool):
        raise ConfigurationError(f"Configuration field '{name}' must be a finite number, not a boolean.")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError(f"Configuration field '{name}' must be a finite number.") from exc
    if not math.isfinite(number):
        raise ConfigurationError(f"Configuration field '{name}' must be finite.")
    return number


def _nonnegative_integer(name: str, value: Any) -> int:
    number = _finite_number(name, value)
    if number < 0 or not number.is_integer():
        raise ConfigurationError(f"Configuration field '{name}' must be a nonnegative integer.")
    return int(number)


def validate_configuration(config: Mapping[str, Any]) -> dict[str, int | float]:
    """Apply v0.1.1 defaults and validate every current configuration field."""
    if not isinstance(config, Mapping):
        raise ConfigurationError("Anomaly configuration must be a JSON object.")

    validated: dict[str, int | float] = dict(DEFAULT_CONFIG)
    for name in DEFAULT_CONFIG:
        if name in config:
            validated[name] = config[name]

    for name in _POSITIVE_DURATIONS:
        number = _finite_number(name, validated[name])
        if number <= 0:
            raise ConfigurationError(f"Configuration field '{name}' must be positive.")
        validated[name] = number

    for name in _NONNEGATIVE_COUNTS:
        validated[name] = _nonnegative_integer(name, validated[name])

    replay_length = _nonnegative_integer(
        "replay_like_sequence_length", validated["replay_like_sequence_length"]
    )
    if replay_length == 0:
        raise ConfigurationError("Configuration field 'replay_like_sequence_length' must be positive.")
    validated["replay_like_sequence_length"] = replay_length

    for name in _NONNEGATIVE_NUMBERS:
        number = _finite_number(name, validated[name])
        if number < 0:
            raise ConfigurationError(f"Configuration field '{name}' must be nonnegative.")
        validated[name] = number

    low = float(validated["anomaly_score_threshold_low"])
    medium = float(validated["anomaly_score_threshold_medium"])
    high = float(validated["anomaly_score_threshold_high"])
    if not low <= medium <= high:
        raise ConfigurationError(
            "Severity thresholds must be ordered: anomaly_score_threshold_low <= "
            "anomaly_score_threshold_medium <= anomaly_score_threshold_high."
        )

    return validated


def load_configuration(path: str | Path) -> dict[str, int | float]:
    """Load a JSON configuration file and return validated baseline settings."""
    try:
        with Path(path).open("r", encoding="utf-8") as config_file:
            config = json.load(config_file)
    except json.JSONDecodeError as exc:
        raise ConfigurationError(f"Malformed JSON configuration '{path}': {exc.msg}.") from exc
    return validate_configuration(config)


def safe_float(value: Any) -> float | None:
    try:
        number = float(str(value).strip())
        if math.isnan(number) or math.isinf(number):
            return None
        return number
    except Exception:
        return None


def safe_int(value: Any) -> int | None:
    try:
        text = str(value).strip()
        if text.lower() in {"nan", "inf", "-inf"}:
            return None
        return int(float(text))
    except Exception:
        return None


def timestamp_iso(timestamp: float | None) -> str:
    if timestamp is None:
        return ""
    # The v0.1.1 baseline intentionally uses the host's local time.
    return datetime.fromtimestamp(timestamp).isoformat(timespec="milliseconds")


def severity_for_score(score: int, config: Mapping[str, Any]) -> str:
    if score >= int(config.get("anomaly_score_threshold_high", 90)):
        return "HIGH"
    if score >= int(config.get("anomaly_score_threshold_medium", 70)):
        return "MEDIUM"
    if score >= int(config.get("anomaly_score_threshold_low", 40)):
        return "LOW"
    return "INFO"


def build_output_row(
    timestamp: float,
    event_type: str,
    source_file: str,
    related_command: Any,
    score: int,
    rule_id: str,
    description: str,
    recommended_response: str,
    evidence_reference: Any,
    config: Mapping[str, Any],
) -> dict[str, Any]:
    """Build one baseline row; callers may externally add future-only fields."""
    return {
        "timestamp": f"{timestamp:.6f}",
        "timestamp_iso": timestamp_iso(timestamp),
        "event_type": event_type,
        "source_file": source_file,
        "related_command": related_command,
        "severity": severity_for_score(score, config),
        "score": score,
        "rule_id": rule_id,
        "description": description,
        "recommended_response": recommended_response,
        "evidence_reference": evidence_reference,
    }


def normalize_actions(rows: Iterable[Mapping[str, Any]]) -> list[NormalizedAction]:
    normalized = []
    for row in rows:
        timestamp = safe_float(row.get("timestamp"))
        if timestamp is not None:
            normalized.append(NormalizedAction(timestamp, row))
    normalized.sort(key=lambda item: item.timestamp)
    return normalized


def normalize_telemetry(rows: Iterable[Mapping[str, Any]]) -> list[NormalizedTelemetry]:
    normalized = []
    for row_number, row in enumerate(rows, start=1):
        timestamp = safe_float(row.get("timestamp"))
        if timestamp is not None:
            normalized.append(NormalizedTelemetry(timestamp, row, row_number))
    normalized.sort(key=lambda item: item.timestamp)
    return normalized


def normalize_ebpf(rows: Iterable[Mapping[str, Any]]) -> list[NormalizedEbpf]:
    normalized = []
    for row_number, row in enumerate(rows, start=1):
        timestamp = safe_float(row.get("timestamp"))
        if timestamp is not None:
            normalized.append(NormalizedEbpf(timestamp, row, row_number))
    normalized.sort(key=lambda item: item.timestamp)
    return normalized


def deduplicate(anomalies: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Preserve v0.1.1 integer-second sliding-window deduplication."""
    seen: set[tuple[str, str, int]] = set()
    output: list[dict[str, Any]] = []
    for item in sorted(anomalies, key=lambda row: (row["rule_id"], float(row["timestamp"]))):
        bucket = int(float(item["timestamp"]))
        key = (item["rule_id"], item["event_type"], bucket)
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return sorted(output, key=lambda row: float(row["timestamp"]))


def evaluate_anomalies(
    actions: Iterable[Mapping[str, Any]],
    telemetry: Iterable[Mapping[str, Any]],
    ebpf: Iterable[Mapping[str, Any]],
    config: Mapping[str, Any],
    source_files: SourceFiles | None = None,
) -> list[dict[str, Any]]:
    """Evaluate deterministic R001--R007 rules and return ordered baseline rows."""
    cfg = validate_configuration(config)
    sources = source_files or SourceFiles()
    action_rows = normalize_actions(actions)
    telemetry_rows = normalize_telemetry(telemetry)
    ebpf_rows = normalize_ebpf(ebpf)
    anomalies: list[dict[str, Any]] = []

    # R001 deliberately counts every timestamped action, including rejected and
    # non-operator rows.  The quadratic forward-window scan is baseline behavior.
    burst_window = float(cfg["command_burst_window_sec"])
    max_commands = int(cfg["max_commands_per_window"])
    for action in action_rows:
        window = [
            candidate
            for candidate in action_rows
            if action.timestamp <= candidate.timestamp <= action.timestamp + burst_window
        ]
        if len(window) > max_commands:
            anomalies.append(build_output_row(
                action.timestamp, "COMMAND_BURST", sources.actions,
                action.row.get("command", ""), 85, "R001",
                f"{len(window)} commands observed within {burst_window:.1f}s.",
                "Review command source; consider rate limiting or manual STOP if live behavior is unsafe.",
                action.row.get("event_id", f"action_{action.timestamp}"), cfg,
            ))

    # R002 and R005.
    telemetry_window = float(cfg["telemetry_flood_window_sec"])
    max_telemetry = int(cfg["max_telemetry_rows_per_window"])
    for telemetry_item in telemetry_rows:
        row = telemetry_item.row
        if safe_int(row.get("adc_l")) is None or safe_int(row.get("adc_r")) is None or safe_float(row.get("steer")) is None:
            anomalies.append(build_output_row(
                telemetry_item.timestamp, "MALFORMED_TELEMETRY", sources.telemetry,
                "N/A", int(cfg["malformed_telemetry_penalty"]), "R005",
                "Telemetry row contains non-numeric adc_l, adc_r, or steer value.",
                "Drop malformed row; inspect Hub/vehicle telemetry parsing.",
                f"telemetry_row_{telemetry_item.row_number}", cfg,
            ))

        window = [
            candidate
            for candidate in telemetry_rows
            if telemetry_item.timestamp <= candidate.timestamp <= telemetry_item.timestamp + telemetry_window
        ]
        if len(window) > max_telemetry:
            anomalies.append(build_output_row(
                telemetry_item.timestamp, "TELEMETRY_FLOOD", sources.telemetry,
                "N/A", 95, "R002",
                f"{len(window)} telemetry rows observed within {telemetry_window:.1f}s.",
                "Review telemetry source; consider STOP if live system behavior is unsafe.",
                f"telemetry_row_{telemetry_item.row_number}", cfg,
            ))

    # R003 deliberately counts START/STOP commands, not successful transitions.
    toggle_window = float(cfg["toggle_window_sec"])
    max_toggles = int(cfg["max_start_stop_toggles_per_window"])
    toggle_actions = [
        action for action in action_rows
        if action.row.get("command", "").upper() in {"START", "STOP"}
    ]
    for action in toggle_actions:
        window = [
            candidate
            for candidate in toggle_actions
            if action.timestamp <= candidate.timestamp <= action.timestamp + toggle_window
        ]
        if len(window) > max_toggles:
            anomalies.append(build_output_row(
                action.timestamp, "REPEATED_START_STOP_TOGGLE", sources.actions,
                action.row.get("command", ""), 80, "R003",
                f"{len(window)} START/STOP commands observed within {toggle_window:.1f}s.",
                "Review operator behavior; keep system in STOP/LOCKED if physical behavior is unsafe.",
                action.row.get("event_id", f"action_{action.timestamp}"), cfg,
            ))

    # R004 deliberately treats all STOP commands and LOCKED telemetry as markers.
    stop_times = [
        action.timestamp for action in action_rows
        if action.row.get("command", "").upper() == "STOP"
    ]
    locked_telemetry_times = [
        item.timestamp for item in telemetry_rows
        if item.row.get("state", "").upper() == "LOCKED"
    ]
    locked_markers = sorted(set(stop_times + locked_telemetry_times))
    locked_window = float(cfg["locked_state_write_window_sec"])
    grace = float(cfg["locked_write_grace_sec"])
    max_writes = int(cfg["max_allowed_writes_after_locked"])
    for locked_timestamp in locked_markers:
        writes = [
            item for item in ebpf_rows
            if item.row.get("syscall", "").lower() == "write"
            and str(item.row.get("device_match", "")).lower() == "true"
            and locked_timestamp + grace <= item.timestamp <= locked_timestamp + locked_window
        ]
        if len(writes) > max_writes:
            anomalies.append(build_output_row(
                locked_timestamp, "SERIAL_WRITE_AFTER_LOCKED", sources.ebpf,
                "STOP/LOCKED", 100, "R004",
                f"{len(writes)} serial write event(s) observed after STOP/LOCKED marker and {grace:.1f}s grace window.",
                "Keep system locked; inspect Gateway process and any rogue serial writers.",
                f"locked_marker_{locked_timestamp:.3f}", cfg,
            ))

    # R006 deliberately aggregates orphan writes across the entire input file.
    orphan_window = float(cfg["serial_orphan_window_sec"])
    max_orphans = int(cfg["max_orphan_serial_writes"])
    orphan_writes = []
    for ebpf_item in ebpf_rows:
        if ebpf_item.row.get("syscall", "").lower() != "write":
            continue
        if str(ebpf_item.row.get("device_match", "")).lower() != "true":
            continue
        near_action = any(
            abs(ebpf_item.timestamp - action.timestamp) <= orphan_window
            for action in action_rows
        )
        if not near_action:
            orphan_writes.append(ebpf_item)
    if len(orphan_writes) > max_orphans:
        first_timestamp = orphan_writes[0].timestamp
        anomalies.append(build_output_row(
            first_timestamp, "SERIAL_ACTIVITY_WITHOUT_GATEWAY_ACTION", sources.ebpf,
            "N/A", int(cfg["orphan_serial_activity_penalty"]), "R006",
            f"{len(orphan_writes)} serial write event(s) did not have a Gateway action within ±{orphan_window:.1f}s.",
            "Review process ownership and investigate whether non-Gateway code is writing to the serial device.",
            f"ebpf_orphan_writes_{len(orphan_writes)}", cfg,
        ))

    # R007 deliberately retains the weak-signal ability to flag exact 1 Hz data.
    replay_length = int(cfg["replay_like_sequence_length"])
    tolerance = float(cfg["replay_like_interval_tolerance_sec"])
    if len(telemetry_rows) >= replay_length + 1:
        times = [item.timestamp for item in telemetry_rows]
        for index in range(0, len(times) - replay_length):
            intervals = [
                round(times[position + 1] - times[position], 6)
                for position in range(index, index + replay_length)
            ]
            if len(intervals) < replay_length:
                continue
            average = sum(intervals) / len(intervals)
            if average <= 0:
                continue
            if all(abs(interval - average) <= tolerance for interval in intervals):
                anomalies.append(build_output_row(
                    times[index], "REPLAY_LIKE_TIMING_PATTERN", sources.telemetry,
                    "N/A", 45, "R007",
                    f"{len(intervals)} telemetry intervals are nearly identical within ±{tolerance:.3f}s tolerance.",
                    "Treat as weak signal only; compare with physical test notes and eBPF trace context.",
                    f"telemetry_interval_start_{index + 1}", cfg,
                ))
                break

    return deduplicate(anomalies)
