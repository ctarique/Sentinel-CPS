"""Bounded live anomaly monitoring for Sentinel-CPS Phase 5B2B.

This module wraps the unchanged deterministic :mod:`anomaly_engine` with
bounded CSV ingestion, durable rising-edge incident latches, append-only
evidence, and an optional guarded Gateway STOP client.  Importing it performs
no I/O, reads no environment variables, and starts no threads.
"""

from __future__ import annotations

import csv
import fcntl
import hashlib
import io
import json
import math
import os
import secrets
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, MutableMapping, Protocol

from anomaly_engine import (
    ConfigurationError,
    SourceFiles,
    evaluate_anomalies,
    safe_float,
    validate_configuration,
)


MONITOR_VERSION = "0.1.1-phase5b2b"
SCHEMA_VERSION = "sentinel-live-v1"
RULE_IDS = frozenset(f"R00{number}" for number in range(1, 8))
SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH")
EVIDENCE_CLASSES = frozenset(
    {"SYNTHETIC", "HARDWARE_PROTOCOL", "MIXED_UNSUITABLE", "UNKNOWN_UNACTIONABLE"}
)
INCIDENT_STATES = frozenset(
    {
        "DETECTED", "OBSERVE_ONLY", "REQUEST_PLANNED", "REQUEST_SENT",
        "RESPONSE_RECEIVED", "ACKNOWLEDGED_DOWNSTREAM", "EXECUTION_UNKNOWN",
        "SYNTHETIC_ACKNOWLEDGED", "REQUEST_REJECTED", "SUPPRESSED_POLICY",
        "SUPPRESSED_PROVENANCE", "SUPPRESSED_ALREADY_LOCKED",
        "DUPLICATE_SUPPRESSED", "COALESCED_WITH_EXISTING_STOP",
        "RECOVERY_REQUIRES_REVIEW", "CLEARED_NOT_REARMED", "REARMED",
    }
)

ACTIONS_HEADER = ("timestamp", "event_id", "source", "command", "details", "result", "mode")
TELEMETRY_HEADER = ("timestamp", "vehicle_id", "adc_l", "adc_r", "steer", "state", "source")
EBPF_HEADER = (
    "timestamp", "timestamp_iso", "monotonic_ns", "pid", "comm", "syscall",
    "fd", "count", "retval", "fd_path", "device_match", "notes",
)
EXPECTED_HEADERS = {
    "actions": ACTIONS_HEADER,
    "telemetry": TELEMETRY_HEADER,
    "ebpf": EBPF_HEADER,
}

DETECTION_FIELDS = (
    "schema_version", "detector_run_id", "detector_instance_id", "incident_id",
    "detection_id", "operation_epoch", "rule_id", "event_type",
    "rule_config_sha256", "score", "severity", "condition_transition",
    "source_event_time_utc", "detection_time_utc", "source_files",
    "evidence_references", "input_modes", "evidence_class", "actionable",
    "mitigation_decision", "decision_reason",
)
MITIGATION_FIELDS = (
    "schema_version", "record_time_utc", "incident_id", "detection_id",
    "mitigation_request_id", "idempotency_key", "phase",
    "mitigation_request_time_utc", "detector_http_response_time_utc",
    "gateway_request_received_time_utc", "gateway_local_lock_time_utc",
    "stop_dispatch_time_utc", "stop_ack_time_utc", "gateway_response_time_utc",
    "transaction_id", "gateway_mode", "serial_transport", "transaction_result",
    "reason", "ack_state", "ack_origin", "ack_latency_ms",
    "gateway_processing_ms", "command_total_ms", "gateway_locked",
    "vehicle_stop_confirmed", "execution_status", "execution_unknown_reason",
    "duplicate_suppressed", "coalesced", "synthetic", "evidence_class",
)


class LiveConfigurationError(ValueError):
    """Raised when live integration configuration is unsafe or malformed."""


class SchemaError(ValueError):
    """Raised for a live source whose header is not the current contract."""


class GatewayTransportError(RuntimeError):
    """Sanitized network failure; never contains headers or bearer material."""

    def __init__(self, category: str, *, ambiguous: bool = True) -> None:
        super().__init__(category)
        self.category = category
        self.ambiguous = ambiguous


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def epoch_to_utc(value: Any) -> str:
    timestamp = safe_float(value)
    if timestamp is None:
        return ""
    try:
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return ""


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def _resolve_path(value: Any, base: Path, field: str) -> Path:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise LiveConfigurationError(f"{field} must be a non-empty, unambiguous path string")
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = base / candidate
    try:
        return candidate.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise LiveConfigurationError(f"{field} cannot be resolved safely") from exc


def _positive_number(raw: Mapping[str, Any], name: str, default: float) -> float:
    value = raw.get(name, default)
    if isinstance(value, bool):
        raise LiveConfigurationError(f"{name} must be a positive number")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise LiveConfigurationError(f"{name} must be a positive number") from exc
    if not math.isfinite(number) or number <= 0:
        raise LiveConfigurationError(f"{name} must be a positive number")
    return number


def _positive_integer(raw: Mapping[str, Any], name: str, default: int) -> int:
    number = _positive_number(raw, name, default)
    if not number.is_integer():
        raise LiveConfigurationError(f"{name} must be a positive integer")
    return int(number)


@dataclass(frozen=True)
class LiveConfiguration:
    config_path: Path
    rule_config_path: Path
    actions_path: Path
    telemetry_path: Path
    ebpf_path: Path
    state_directory: Path
    evidence_directory: Path
    response_mode: str
    minimum_severity: str
    response_rule_allowlist: tuple[str, ...]
    gateway_url: str
    polling_interval_ms: int
    allow_mock_mitigation: bool
    require_hardware_provenance: bool
    quiet_period_sec: float
    http_timeout_sec: float
    max_read_bytes_per_poll: int
    max_rows_per_source: int
    secret_free_sha256: str


def load_live_configuration(
    path: str | Path,
    *,
    token_available: bool,
    state_root: str | Path | None = None,
    evidence_root: str | Path | None = None,
) -> LiveConfiguration:
    config_path = Path(path).resolve()
    try:
        with config_path.open(encoding="utf-8") as source:
            raw = json.load(source)
    except json.JSONDecodeError as exc:
        raise LiveConfigurationError(f"Malformed live configuration JSON: {exc.msg}") from exc
    if not isinstance(raw, Mapping):
        raise LiveConfigurationError("Live integration configuration must be a JSON object")
    forbidden_names = {"token", "authorization", "credential", "password", "secret", "private_key"}
    def contains_forbidden_key(value: Any) -> bool:
        if isinstance(value, Mapping):
            return any(
                any(name in str(key).lower() for name in forbidden_names)
                or contains_forbidden_key(nested)
                for key, nested in value.items()
            )
        if isinstance(value, list):
            return any(contains_forbidden_key(item) for item in value)
        return False
    if contains_forbidden_key(raw):
        raise LiveConfigurationError("Authentication and credential fields are forbidden in live configuration")
    allowed_fields = {
        "schema_version", "rule_configuration", "inputs", "response_mode",
        "minimum_severity", "response_rule_allowlist", "gateway_url",
        "polling_interval_ms", "allow_mock_mitigation", "require_hardware_provenance",
        "quiet_period_sec", "http_timeout_sec", "max_read_bytes_per_poll",
        "max_rows_per_source", "state_directory", "evidence_directory",
    }
    unexpected_fields = sorted(set(raw) - allowed_fields)
    if unexpected_fields:
        raise LiveConfigurationError(
            f"unsupported live configuration fields: {', '.join(unexpected_fields)}"
        )
    if raw.get("schema_version", SCHEMA_VERSION) != SCHEMA_VERSION:
        raise LiveConfigurationError("live configuration schema_version is incompatible")

    response_mode = raw.get("response_mode", "observe_only")
    if response_mode not in {"observe_only", "mitigate"}:
        raise LiveConfigurationError("response_mode must be observe_only or mitigate")
    minimum = raw.get("minimum_severity", "HIGH")
    if minimum not in SEVERITIES:
        raise LiveConfigurationError("minimum_severity must be INFO, LOW, MEDIUM, or HIGH")
    allowlist = raw.get("response_rule_allowlist", ["R002", "R004"])
    if (
        not isinstance(allowlist, list) or not allowlist
        or any(not isinstance(item, str) or not item or item not in RULE_IDS for item in allowlist)
    ):
        raise LiveConfigurationError("response_rule_allowlist must contain known non-empty R001-R007 IDs")
    if len(set(allowlist)) != len(allowlist):
        raise LiveConfigurationError("response_rule_allowlist cannot contain duplicates")

    gateway_url = raw.get("gateway_url", "http://127.0.0.1:8080")
    try:
        parsed = urllib.parse.urlsplit(gateway_url)
    except (TypeError, ValueError) as exc:
        raise LiveConfigurationError("gateway_url must be a loopback HTTP URL") from exc
    if (
        parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}
        or parsed.username is not None or parsed.password is not None or parsed.query
        or parsed.fragment or parsed.path not in {"", "/"}
    ):
        raise LiveConfigurationError("gateway_url must be a plain loopback HTTP origin")

    allow_mock = raw.get("allow_mock_mitigation", False)
    require_hardware = raw.get("require_hardware_provenance", True)
    if not isinstance(allow_mock, bool) or not isinstance(require_hardware, bool):
        raise LiveConfigurationError("allow_mock_mitigation and require_hardware_provenance must be booleans")
    if allow_mock and require_hardware:
        raise LiveConfigurationError("allow_mock_mitigation=true conflicts with require_hardware_provenance=true")
    if response_mode == "mitigate" and not token_available:
        raise LiveConfigurationError("mitigation mode requires SENTINEL_MITIGATION_TOKEN in the environment")

    base = config_path.parent
    inputs = raw.get("inputs")
    if not isinstance(inputs, Mapping):
        raise LiveConfigurationError("inputs must define actions_csv, telemetry_csv, and ebpf_serial_trace_csv")
    expected_input_fields = {"actions_csv", "telemetry_csv", "ebpf_serial_trace_csv"}
    if set(inputs) != expected_input_fields:
        raise LiveConfigurationError("inputs must contain exactly actions_csv, telemetry_csv, and ebpf_serial_trace_csv")
    actions = _resolve_path(inputs.get("actions_csv"), base, "inputs.actions_csv")
    telemetry = _resolve_path(inputs.get("telemetry_csv"), base, "inputs.telemetry_csv")
    ebpf = _resolve_path(inputs.get("ebpf_serial_trace_csv"), base, "inputs.ebpf_serial_trace_csv")
    if len({actions, telemetry, ebpf}) != 3:
        raise LiveConfigurationError("live source paths must resolve to three distinct files")
    state_value = state_root if state_root is not None else raw.get("state_directory", "../runtime/live_state")
    evidence_value = evidence_root if evidence_root is not None else raw.get("evidence_directory", "../runtime/live_evidence")
    state = _resolve_path(str(state_value), Path.cwd() if state_root is not None else base, "state_directory")
    evidence = _resolve_path(str(evidence_value), Path.cwd() if evidence_root is not None else base, "evidence_directory")
    if state == evidence:
        raise LiveConfigurationError("state_directory and evidence_directory must be distinct")
    for output_root in (state, evidence):
        for source in (actions, telemetry, ebpf):
            if output_root == source or output_root in source.parents or source in output_root.parents:
                raise LiveConfigurationError("state/evidence paths must not overlap or overwrite source CSVs")

    rule_config = _resolve_path(
        raw.get("rule_configuration", "anomaly_rules.example.json"), base, "rule_configuration"
    )
    polling = _positive_integer(raw, "polling_interval_ms", 500)
    max_rows = _positive_integer(raw, "max_rows_per_source", 2048)
    if max_rows < 16:
        raise LiveConfigurationError("max_rows_per_source must be at least 16")
    secret_free = dict(raw)
    secret_free["state_directory"] = str(state)
    secret_free["evidence_directory"] = str(evidence)
    secret_free["inputs"] = {
        "actions_csv": str(actions), "telemetry_csv": str(telemetry),
        "ebpf_serial_trace_csv": str(ebpf),
    }
    return LiveConfiguration(
        config_path=config_path,
        rule_config_path=rule_config,
        actions_path=actions,
        telemetry_path=telemetry,
        ebpf_path=ebpf,
        state_directory=state,
        evidence_directory=evidence,
        response_mode=response_mode,
        minimum_severity=minimum,
        response_rule_allowlist=tuple(allowlist),
        gateway_url=gateway_url.rstrip("/"),
        polling_interval_ms=polling,
        allow_mock_mitigation=allow_mock,
        require_hardware_provenance=require_hardware,
        quiet_period_sec=_positive_number(raw, "quiet_period_sec", 30.0),
        http_timeout_sec=_positive_number(raw, "http_timeout_sec", 2.0),
        max_read_bytes_per_poll=_positive_integer(raw, "max_read_bytes_per_poll", 1048576),
        max_rows_per_source=max_rows,
        secret_free_sha256=canonical_sha256(secret_free),
    )


@dataclass
class TailPoll:
    rows: list[dict[str, str]]
    reset_epoch: bool = False


class CsvTailer:
    """Byte-offset CSV tailer that commits complete newline-terminated rows only."""

    def __init__(
        self,
        name: str,
        path: Path,
        state: MutableMapping[str, Any],
        max_bytes: int,
        diagnose: Callable[[str], None],
    ) -> None:
        self.name = name
        self.path = path
        self.state = state
        self.max_bytes = max_bytes
        self.diagnose = diagnose
        self.expected = EXPECTED_HEADERS[name]

    @staticmethod
    def _identity(stat_result: os.stat_result) -> str:
        return f"{stat_result.st_dev}:{stat_result.st_ino}"

    def poll(self) -> TailPoll:
        try:
            stat_result = self.path.stat()
        except FileNotFoundError:
            self.diagnose(f"{self.name}: source file is not present")
            return TailPoll([])
        if not self.path.is_file():
            self.diagnose(f"{self.name}: source path is not a regular file")
            return TailPoll([])

        identity = self._identity(stat_result)
        old_identity = self.state.get("identity")
        offset = int(self.state.get("offset", 0))
        reset = False
        if old_identity is not None and old_identity != identity:
            offset = 0
            reset = True
            self.diagnose(f"{self.name}: file replacement/rotation detected; starting new file epoch")
        elif stat_result.st_size < offset:
            offset = 0
            reset = True
            self.diagnose(f"{self.name}: truncation detected; starting new file epoch")

        with self.path.open("rb") as source:
            source.seek(offset)
            data = source.read(self.max_bytes)
        newline = data.rfind(b"\n")
        if newline < 0:
            self.state.update({
                "identity": identity,
                "offset": offset,
                "file_epoch": int(self.state.get("file_epoch", 0)) + (1 if reset else 0),
            })
            return TailPoll([], reset)
        complete = data[: newline + 1]
        next_offset = offset + len(complete)
        try:
            text = complete.decode("utf-8")
        except UnicodeDecodeError:
            self.diagnose(f"{self.name}: invalid UTF-8 in complete input; bytes skipped")
            self.state.update({
                "identity": identity,
                "offset": next_offset,
                "file_epoch": int(self.state.get("file_epoch", 0)) + (1 if reset else 0),
            })
            return TailPoll([], reset)

        physical_lines = text.splitlines(keepends=True)
        logical_records: list[tuple[list[str] | None, int, int]] = []
        accumulator = ""
        accumulated_bytes = 0
        committed_bytes = 0
        record_start_line = 1
        for line_number, line in enumerate(physical_lines, start=1):
            accumulator += line
            accumulated_bytes += len(line.encode("utf-8"))
            try:
                parsed_records = list(csv.reader(io.StringIO(accumulator), strict=True))
            except csv.Error as exc:
                if "unexpected end of data" in str(exc).lower():
                    continue
                committed_bytes += accumulated_bytes
                logical_records.append((None, committed_bytes, record_start_line))
                accumulator = ""
                accumulated_bytes = 0
                record_start_line = line_number + 1
                continue
            if len(parsed_records) == 1:
                committed_bytes += accumulated_bytes
                logical_records.append((parsed_records[0], committed_bytes, record_start_line))
                accumulator = ""
                accumulated_bytes = 0
                record_start_line = line_number + 1
        # A quoted logical record can contain newline characters. If its closing
        # quote has not arrived, accumulated_bytes is deliberately not committed.
        if not logical_records:
            self.state.update({
                "identity": identity,
                "offset": offset,
                "file_epoch": int(self.state.get("file_epoch", 0)) + (1 if reset else 0),
            })
            return TailPoll([], reset)
        next_offset = offset + logical_records[-1][1]
        rows: list[dict[str, str]] = []
        record_index = 0
        if offset == 0:
            header = logical_records[0][0]
            if header is None or tuple(header) != self.expected:
                actual = tuple(header or ())
                raise SchemaError(
                    f"{self.name}: incompatible header; expected {self.expected!r}, got {actual!r}"
                )
            self.state["header_sha256"] = hashlib.sha256(
                ",".join(self.expected).encode("utf-8")
            ).hexdigest()
            record_index = 1
        elif self.state.get("header_sha256") != hashlib.sha256(
            ",".join(self.expected).encode("utf-8")
        ).hexdigest():
            raise SchemaError(f"{self.name}: persisted header contract is incompatible")

        for parsed, record_end, start_line in logical_records[record_index:]:
            if parsed is None:
                self.diagnose(f"{self.name}: malformed CSV syntax at physical line {start_line}")
                continue
            if len(parsed) != len(self.expected):
                self.diagnose(
                    f"{self.name}: malformed row at committed byte range ending {offset + record_end}; "
                    f"expected {len(self.expected)} fields, got {len(parsed)}"
                )
                continue
            rows.append(dict(zip(self.expected, parsed)))
        self.state.update(
            {
                "identity": identity,
                "offset": next_offset,
                "file_epoch": int(self.state.get("file_epoch", 0)) + (1 if reset else 0),
            }
        )
        return TailPoll(rows, reset)

class AppendOnlyCsvLedger:
    def __init__(self, path: Path, fields: tuple[str, ...]) -> None:
        self.path = path
        self.fields = fields
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            with path.open(newline="", encoding="utf-8") as source:
                actual = tuple(next(csv.reader(source), []))
            if actual != fields:
                raise SchemaError(f"ledger schema mismatch for {path.name}")
        else:
            with path.open("x", newline="", encoding="utf-8") as output:
                csv.writer(output).writerow(fields)
                output.flush()
                os.fsync(output.fileno())
        self._stream = path.open("a", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._stream, fieldnames=fields, extrasaction="ignore")
        self._lock = threading.Lock()

    def append(self, row: Mapping[str, Any]) -> None:
        safe = {field: _csv_value(row.get(field, "")) for field in self.fields}
        with self._lock:
            self._writer.writerow(safe)
            self._stream.flush()
            os.fsync(self._stream.fileno())

    def close(self) -> None:
        with self._lock:
            if not self._stream.closed:
                self._stream.flush()
                os.fsync(self._stream.fileno())
                self._stream.close()


def _csv_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (dict, list, tuple, set)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value)


class GatewayClientProtocol(Protocol):
    def health(self, timeout: float) -> tuple[int, Mapping[str, Any]]: ...
    def stop(self, payload: Mapping[str, Any], token: str, timeout: float) -> tuple[int, Mapping[str, Any]]: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        del req, fp, code, msg, headers, newurl
        return None


class GatewayClient:
    """Small standard-library JSON client with deliberately sanitized errors."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        # Never honor environment proxy settings or redirects for the
        # loopback-only authenticated boundary.
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirectHandler()
        )

    def _request(
        self, method: str, path: str, timeout: float, payload: Mapping[str, Any] | None = None,
        token: str | None = None,
    ) -> tuple[int, Mapping[str, Any]]:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(self.base_url + path, data=body, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=timeout) as response:
                status = response.status
                raw = response.read(1024 * 1024)
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                raw = exc.read(1024 * 1024)
            finally:
                exc.close()
        except TimeoutError as exc:
            raise GatewayTransportError("HTTP_TIMEOUT", ambiguous=True) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise GatewayTransportError("CONNECTION_FAILURE", ambiguous=True) from exc
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GatewayTransportError("MALFORMED_JSON_RESPONSE", ambiguous=True) from exc
        if not isinstance(parsed, Mapping):
            raise GatewayTransportError("MALFORMED_JSON_RESPONSE", ambiguous=True)
        return status, parsed

    def health(self, timeout: float) -> tuple[int, Mapping[str, Any]]:
        return self._request("GET", "/api/health", timeout)

    def stop(self, payload: Mapping[str, Any], token: str, timeout: float) -> tuple[int, Mapping[str, Any]]:
        return self._request("POST", "/api/mitigation/stop", timeout, payload, token)


def _new_identifier(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(16)}"


class LiveAnomalyMonitor:
    """Single-process bounded monitor with durable no-retry incident latches."""

    def __init__(
        self,
        config: LiveConfiguration,
        *,
        token: str | None = None,
        gateway_client: GatewayClientProtocol | None = None,
        clock: Callable[[], float] = time.time,
        fixture_mode: bool = False,
        injected_test_transport: bool = False,
    ) -> None:
        self.config = config
        self.token = token
        self.gateway = gateway_client or GatewayClient(config.gateway_url)
        self.clock = clock
        self.fixture_mode = fixture_mode
        self.injected_test_transport = injected_test_transport
        self.lock = threading.RLock()
        self.stop_requested = False
        self._closed = False
        self.diagnostics: list[str] = []
        self.detector_run_id = _new_identifier("run")
        self.start_time_utc = utc_now()

        try:
            with config.rule_config_path.open(encoding="utf-8") as source:
                rule_raw = json.load(source)
        except json.JSONDecodeError as exc:
            raise LiveConfigurationError(f"Malformed anomaly rule JSON: {exc.msg}") from exc
        try:
            self.rule_config = validate_configuration(rule_raw)
        except ConfigurationError as exc:
            raise LiveConfigurationError(f"anomaly rule configuration rejected: {exc}") from exc
        if config.max_rows_per_source <= max(
            int(self.rule_config["max_commands_per_window"]),
            int(self.rule_config["max_telemetry_rows_per_window"]),
            int(self.rule_config["max_start_stop_toggles_per_window"]),
            int(self.rule_config["replay_like_sequence_length"]) + 1,
        ):
            raise LiveConfigurationError("max_rows_per_source must exceed every configured live rule threshold")
        self.rule_sha256 = canonical_sha256(self.rule_config)

        config.state_directory.mkdir(parents=True, exist_ok=True)
        config.evidence_directory.mkdir(parents=True, exist_ok=True)
        self._process_lock_stream = (config.state_directory / "monitor.lock").open("a+", encoding="utf-8")
        try:
            fcntl.flock(self._process_lock_stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self._process_lock_stream.close()
            raise LiveConfigurationError(
                "another monitor owns this state directory; concurrent processes are forbidden"
            ) from exc
        self.state_path = config.state_directory / "monitor_state.json"
        self.state = self._load_state()
        self.detector_instance_id = self.state.setdefault(
            "detector_instance_id", _new_identifier("detector")
        )
        self.state.setdefault("tailers", {})
        self.state.setdefault("rows", {"actions": [], "telemetry": [], "ebpf": []})
        self.state.setdefault("r006", {"pending": [], "orphans": [], "file_epoch": 0})
        self.state.setdefault("incidents", {})
        self.state.setdefault("incident_history", [])
        self.state.setdefault("operation_epoch", 0)
        self.state.setdefault("last_gateway_mode", "")
        self.state.setdefault("authoritative_reset_event_ids", [])

        self.detection_ledger = AppendOnlyCsvLedger(
            config.evidence_directory / "live_anomaly_events.csv", DETECTION_FIELDS
        )
        self.mitigation_ledger = AppendOnlyCsvLedger(
            config.evidence_directory / "mitigation_events.csv", MITIGATION_FIELDS
        )
        self._recover_ambiguous_incidents()
        self.tailers = {
            "actions": CsvTailer("actions", config.actions_path, self.state["tailers"].setdefault("actions", {}), config.max_read_bytes_per_poll, self._diagnose),
            "telemetry": CsvTailer("telemetry", config.telemetry_path, self.state["tailers"].setdefault("telemetry", {}), config.max_read_bytes_per_poll, self._diagnose),
            "ebpf": CsvTailer("ebpf", config.ebpf_path, self.state["tailers"].setdefault("ebpf", {}), config.max_read_bytes_per_poll, self._diagnose),
        }
        self.manifest_path = config.evidence_directory / f"run_manifest_{self.detector_run_id}.json"
        self._write_manifest(end_time="", status="RUNNING")
        self._persist()

    def _load_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {"schema_version": SCHEMA_VERSION}
        try:
            with self.state_path.open(encoding="utf-8") as source:
                state = json.load(source)
        except (json.JSONDecodeError, OSError) as exc:
            raise LiveConfigurationError("durable monitor state is unreadable; manual review required") from exc
        if not isinstance(state, dict) or state.get("schema_version") != SCHEMA_VERSION:
            raise LiveConfigurationError("durable monitor state schema is incompatible")
        return state

    def _recover_ambiguous_incidents(self) -> None:
        changed = False
        for incident in self.state["incidents"].values():
            if not incident.get("detection_evidence_recorded", False):
                self._append_detection(
                    incident, None, "INACTIVE_TO_ACTIVE", "DETECTED",
                    "recovered durable detection latch",
                )
                incident["detection_evidence_recorded"] = True
                changed = True
            if incident.get("state") in {"REQUEST_PLANNED", "REQUEST_SENT"}:
                old = incident["state"]
                incident["state"] = "RECOVERY_REQUIRES_REVIEW"
                incident["execution_unknown_reason"] = f"RESTART_AFTER_{old}"
                self._append_mitigation(incident, "RECOVERY_REQUIRES_REVIEW")
                changed = True
        if changed:
            self._persist()

    def _diagnose(self, message: str) -> None:
        # Deliberately record only generated source labels/reasons, never row contents.
        self.diagnostics.append(message)
        self.diagnostics = self.diagnostics[-256:]

    def _persist(self) -> None:
        self.state["schema_version"] = SCHEMA_VERSION
        self.state["updated_time_utc"] = utc_now()
        _atomic_write_json(self.state_path, self.state)

    def _write_manifest(self, *, end_time: str, status: str) -> None:
        package_root = Path(__file__).resolve().parent
        commit = "UNKNOWN"
        dirty = "UNKNOWN"
        try:
            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=package_root, check=True,
                capture_output=True, text=True, timeout=2,
            ).stdout.strip()
            dirty = "dirty" if subprocess.run(
                ["git", "status", "--porcelain", "--", str(package_root)], cwd=package_root,
                check=True, capture_output=True, text=True, timeout=2,
            ).stdout else "clean"
        except (OSError, subprocess.SubprocessError):
            pass
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "detector_version": MONITOR_VERSION,
            "detector_run_id": self.detector_run_id,
            "detector_instance_id": self.detector_instance_id,
            "git_commit": commit,
            "git_dirty_status": dirty,
            "rule_configuration_sha256": self.rule_sha256,
            "live_integration_configuration_sha256": self.config.secret_free_sha256,
            "start_timestamp_utc": self.start_time_utc,
            "end_timestamp_utc": end_time,
            "run_status": status,
            "input_paths": {
                "actions": str(self.config.actions_path),
                "telemetry": str(self.config.telemetry_path),
                "ebpf": str(self.config.ebpf_path),
            },
            "response_mode": self.config.response_mode,
            "fixture_boundary": "NON_PHYSICAL_FIXTURE" if self.fixture_mode else "LIVE_INPUT",
            "evidence_classification_boundary": (
                "Protocol evidence only; no record proves observed physical motor cessation. "
                "SYNTHETIC records remain separate and nonphysical."
            ),
        }
        _atomic_write_json(self.manifest_path, manifest)

    def process_once(self) -> list[dict[str, Any]]:
        """Process currently available complete rows once and durably commit state."""
        with self.lock:
            ingested: dict[str, list[dict[str, str]]] = {}
            for name, tailer in self.tailers.items():
                result = tailer.poll()
                ingested[name] = result.rows
                if name == "ebpf" and result.reset_epoch:
                    self.state["r006"] = {
                        "pending": [], "orphans": [],
                        "file_epoch": int(self.state["r006"].get("file_epoch", 0)) + 1,
                    }
            anomalies = self.ingest_rows(ingested, persist=False)
            self._persist()  # offsets and rule/incident state commit together
            return anomalies

    def ingest_rows(
        self, rows: Mapping[str, list[Mapping[str, Any]]], *, persist: bool = True
    ) -> list[dict[str, Any]]:
        """Testable ingestion boundary; callers provide already parsed source rows."""
        with self.lock:
            now = self.clock()
            for row in rows.get("actions", []):
                minimized = {key: str(row.get(key, "")) for key in ("timestamp", "event_id", "command", "result", "mode")}
                self.state["rows"]["actions"].append(minimized)
                valid_timestamp = safe_float(minimized["timestamp"]) is not None
                if valid_timestamp and minimized["mode"] in {"hardware", "mock"}:
                    self.state["last_gateway_mode"] = minimized["mode"]
                if (
                    valid_timestamp
                    and minimized["command"].upper() == "RESET"
                    and minimized["result"].upper() == "ACKNOWLEDGED"
                    and minimized["mode"].lower() == "hardware"
                    and minimized["event_id"]
                    and minimized["event_id"] not in self.state["authoritative_reset_event_ids"]
                ):
                    self.state["operation_epoch"] += 1
                    self.state["last_authoritative_reset_time"] = safe_float(minimized["timestamp"])
                    self.state["last_authoritative_reset_observed_clock"] = now
                    self.state["authoritative_reset_event_ids"].append(minimized["event_id"])
                    self.state["authoritative_reset_event_ids"] = self.state["authoritative_reset_event_ids"][-256:]
            for row in rows.get("telemetry", []):
                raw_source = str(row.get("source", ""))
                minimized = {key: str(row.get(key, "")) for key in ("timestamp", "adc_l", "adc_r", "steer", "state")}
                minimized["source"] = (
                    "mock_generator" if raw_source == "mock_generator"
                    else "non_mock_protocol" if raw_source else ""
                )
                self.state["rows"]["telemetry"].append(minimized)
            for row in rows.get("ebpf", []):
                minimized = {key: str(row.get(key, "")) for key in ("timestamp", "syscall", "device_match")}
                self.state["rows"]["ebpf"].append(minimized)
                if (
                    safe_float(minimized["timestamp"]) is not None
                    and minimized["syscall"].lower() == "write"
                    and minimized["device_match"].lower() == "true"
                ):
                    self.state["r006"]["pending"].append(minimized)

            self._bound_rows(now)
            anomalies = self._evaluate(now)
            self._update_incidents(anomalies, now)
            if persist:
                self._persist()
            return anomalies

    def _bound_rows(self, now: float) -> None:
        cfg = self.rule_config
        # Mature R006 candidates before pruning the actions that can correlate
        # with them. This preserves the inclusive +/- engine check even after a
        # long polling pause.
        orphan_window = float(cfg["serial_orphan_window_sec"])
        pending = []
        orphans = self.state["r006"]["orphans"]
        max_orphans = int(cfg["max_orphan_serial_writes"]) + 1
        actions = self.state["rows"]["actions"]
        for write in self.state["r006"]["pending"]:
            timestamp = safe_float(write.get("timestamp"))
            if timestamp is None:
                self._diagnose("ebpf: ignored non-finite timestamp in pending live state")
                continue
            if timestamp > now - orphan_window:
                pending.append(write)
                continue
            probe = evaluate_anomalies(
                actions, [], [write], {**cfg, "max_orphan_serial_writes": 0},
                SourceFiles("actions.csv", "telemetry.csv", "serial_trace.csv"),
            )
            if any(item["rule_id"] == "R006" for item in probe) and len(orphans) < max_orphans:
                orphans.append(write)
        self.state["r006"]["pending"] = pending[-self.config.max_rows_per_source :]
        self.state["r006"]["orphans"] = orphans[-max_orphans:]

        horizons = {
            "actions": max(float(cfg["command_burst_window_sec"]), float(cfg["toggle_window_sec"]), float(cfg["serial_orphan_window_sec"])),
            "telemetry": max(float(cfg["telemetry_flood_window_sec"]), float(cfg["locked_state_write_window_sec"])),
            "ebpf": float(cfg["locked_state_write_window_sec"]),
        }
        replay_keep = int(cfg["replay_like_sequence_length"]) + 1
        for name, horizon in horizons.items():
            valid = [row for row in self.state["rows"][name] if safe_float(row.get("timestamp")) is not None]
            valid.sort(key=lambda item: float(item["timestamp"]))
            recent = [row for row in valid if float(row["timestamp"]) >= now - horizon]
            if name == "telemetry":
                identities = {id(item) for item in recent}
                for item in valid[-replay_keep:]:
                    if id(item) not in identities:
                        recent.append(item)
            recent.sort(key=lambda item: float(item["timestamp"]))
            self.state["rows"][name] = recent[-self.config.max_rows_per_source :]

    def _evaluate(self, now: float) -> list[dict[str, Any]]:
        sources = SourceFiles(
            self.config.actions_path.name, self.config.telemetry_path.name, self.config.ebpf_path.name
        )
        evaluated = [
            row for row in evaluate_anomalies(
                self.state["rows"]["actions"], self.state["rows"]["telemetry"],
                self.state["rows"]["ebpf"], self.rule_config, sources,
            ) if row["rule_id"] != "R006"
        ]
        # Replay history is retained by count even when it is older than the
        # time windows needed by other rules.  Do not let those retained rows
        # keep an unrelated condition active indefinitely.
        horizons = {
            "R001": float(self.rule_config["command_burst_window_sec"]),
            "R002": float(self.rule_config["telemetry_flood_window_sec"]),
            "R003": float(self.rule_config["toggle_window_sec"]),
            "R004": float(self.rule_config["locked_state_write_window_sec"]),
            "R005": float(self.rule_config["telemetry_flood_window_sec"]),
        }
        output = [
            row for row in evaluated
            if row["rule_id"] not in horizons
            or float(row["timestamp"]) >= now - horizons[row["rule_id"]]
        ]
        latest_telemetry = max(
            (float(row["timestamp"]) for row in self.state["rows"]["telemetry"]),
            default=float("-inf"),
        )
        if latest_telemetry < now - float(self.rule_config["telemetry_flood_window_sec"]):
            output = [row for row in output if row["rule_id"] != "R007"]
        r006 = evaluate_anomalies(
            [], [], self.state["r006"]["orphans"], self.rule_config, sources
        )
        for row in r006:
            if row["rule_id"] == "R006":
                row = dict(row)
                row["description"] += " Live interpretation: cumulative confirmed orphan writes in the current monitor/eBPF file epoch, capped after threshold crossing."
                row["live_interpretation"] = "CURRENT_MONITOR_FILE_EPOCH_CUMULATIVE"
                output.append(row)
        output.sort(key=lambda item: float(item["timestamp"]))
        return output

    def _provenance(self, anomaly: Mapping[str, Any]) -> tuple[str, bool, str]:
        if self.fixture_mode:
            return "SYNTHETIC", False, "NON_PHYSICAL_FIXTURE"
        mode = self.state.get("last_gateway_mode", "")
        telemetry_sources = {
            row.get("source", "") for row in self.state["rows"]["telemetry"] if row.get("source")
        }
        has_mock_telemetry = "mock_generator" in telemetry_sources
        has_nonmock_telemetry = any(source != "mock_generator" for source in telemetry_sources)
        has_device_trace = any(
            row.get("syscall", "").lower() in {"read", "write"}
            and row.get("device_match", "").lower() == "true"
            for row in self.state["rows"]["ebpf"]
        )
        if (mode == "hardware" and has_mock_telemetry) or (mode == "mock" and has_nonmock_telemetry):
            return "MIXED_UNSUITABLE", False, "conflicting hardware and mock provenance"
        if mode == "mock" or has_mock_telemetry:
            return "SYNTHETIC", bool(self.config.allow_mock_mitigation), "explicit mock provenance"
        if mode == "hardware" and (has_nonmock_telemetry or has_device_trace):
            return "HARDWARE_PROTOCOL", True, "Gateway hardware mode corroborated by non-mock source evidence"
        return "UNKNOWN_UNACTIONABLE", False, "Gateway mode and source evidence do not prove hardware operation"

    def _update_incidents(self, anomalies: list[dict[str, Any]], now: float) -> None:
        by_rule: dict[str, dict[str, Any]] = {}
        for anomaly in anomalies:
            by_rule.setdefault(anomaly["rule_id"], anomaly)
        active = self.state["incidents"]
        for rule_id in RULE_IDS:
            incident = active.get(rule_id)
            anomaly = by_rule.get(rule_id)
            if anomaly is not None and incident is None:
                incident = self._new_incident(anomaly, now)
                active[rule_id] = incident
                self._persist()  # durable DETECTED latch before any policy/network work
                self._append_detection(incident, anomaly, "INACTIVE_TO_ACTIVE", "DETECTED", incident["provenance_reason"])
                incident["detection_evidence_recorded"] = True
                self._persist()
                self._decide_response(incident, anomaly)
            elif anomaly is None and incident is not None and incident.get("condition_active", True):
                incident["condition_active"] = False
                incident["inactive_since"] = now
                incident["state"] = "CLEARED_NOT_REARMED"
                self._append_detection(incident, None, "ACTIVE_TO_INACTIVE", "CLEARED_NOT_REARMED", "quiet period and authoritative hardware RESET are both required")
            elif anomaly is None and incident is not None and not incident.get("condition_active", True):
                inactive_since = float(incident.get("inactive_since", now))
                reset_epoch = int(self.state.get("operation_epoch", 0))
                reset_event_time = safe_float(self.state.get("last_authoritative_reset_time"))
                reset_observed = safe_float(self.state.get("last_authoritative_reset_observed_clock"))
                source_event_time = safe_float(incident.get("source_event_timestamp"))
                reset_is_later = bool(
                    reset_epoch > int(incident["operation_epoch_number"])
                    and reset_event_time is not None and source_event_time is not None
                    and reset_event_time > source_event_time
                    and reset_observed is not None
                    and reset_observed >= float(incident.get("detection_clock_epoch", now))
                )
                if now - inactive_since >= self.config.quiet_period_sec and reset_is_later:
                    incident["state"] = "REARMED"
                    self._append_detection(incident, None, "INACTIVE_TO_REARMED", "REARMED", "quiet period plus later authoritative hardware RESET observed")
                    self.state["incident_history"].append(incident)
                    self.state["incident_history"] = self.state["incident_history"][-1024:]
                    del active[rule_id]
                elif now - inactive_since >= self.config.quiet_period_sec:
                    incident["manual_review_required"] = True

    def _new_incident(self, anomaly: Mapping[str, Any], now: float) -> dict[str, Any]:
        incident_id = _new_identifier("incident")
        detection_id = _new_identifier("detection")
        evidence_class, actionable, provenance_reason = self._provenance(anomaly)
        incident = {
            "detector_run_id": self.detector_run_id,
            "detection_id": detection_id,
            "incident_id": incident_id,
            "idempotency_key": hashlib.sha256(
                f"{incident_id}|{detection_id}|{anomaly['rule_id']}|STOP|v1".encode()
            ).hexdigest(),
            "operation_epoch": f"epoch-{int(self.state['operation_epoch']):06d}",
            "operation_epoch_number": int(self.state["operation_epoch"]),
            "rule_id": anomaly["rule_id"],
            "score": anomaly["score"],
            "severity": anomaly["severity"],
            "event_type": anomaly["event_type"],
            "source_event_time_utc": epoch_to_utc(anomaly["timestamp"]),
            "source_event_timestamp": anomaly["timestamp"],
            "detection_time_utc": utc_now(),
            "detection_clock_epoch": now,
            "evidence_reference": anomaly.get("evidence_reference", ""),
            "evidence_class": evidence_class,
            "actionable": actionable,
            "provenance_reason": provenance_reason,
            "condition_active": True,
            "state": "DETECTED",
            "request_attempted": False,
            "detection_evidence_recorded": False,
        }
        return incident

    def _severity_eligible(self, severity: str) -> bool:
        return SEVERITIES.index(severity) >= SEVERITIES.index(self.config.minimum_severity)

    def _decide_response(self, incident: dict[str, Any], anomaly: Mapping[str, Any]) -> None:
        if self.fixture_mode and not self.injected_test_transport:
            self._set_decision(incident, "OBSERVE_ONLY", "NON_PHYSICAL_FIXTURE; Gateway calls disabled")
            return
        if self.config.response_mode != "mitigate":
            self._set_decision(incident, "OBSERVE_ONLY", "observe-only configuration")
            return
        if anomaly["rule_id"] not in self.config.response_rule_allowlist or not self._severity_eligible(anomaly["severity"]):
            self._set_decision(incident, "SUPPRESSED_POLICY", "rule or severity is outside explicit response policy")
            return
        if not incident["actionable"]:
            self._set_decision(incident, "SUPPRESSED_PROVENANCE", incident["provenance_reason"])
            return
        if incident["evidence_class"] == "SYNTHETIC" and not self.config.allow_mock_mitigation:
            self._set_decision(incident, "SUPPRESSED_PROVENANCE", "mock mitigation is disabled")
            return
        if not self.token:
            self._set_decision(incident, "SUPPRESSED_POLICY", "mitigation credential unavailable at runtime")
            return
        try:
            status, health = self.gateway.health(self.config.http_timeout_sec)
        except GatewayTransportError as exc:
            self._set_decision(incident, "SUPPRESSED_POLICY", f"Gateway preflight unavailable: {exc.category}")
            return
        preflight = self._preflight(status, health, incident["evidence_class"])
        if preflight is not None:
            state, reason = preflight
            self._set_decision(incident, state, reason)
            return
        self._send_once(incident, anomaly)

    def _preflight(self, status: int, health: Mapping[str, Any], evidence_class: str) -> tuple[str, str] | None:
        required = {
            "mode", "serial_transport", "mitigation_api_enabled", "mitigation_api_ready",
            "mitigation_loopback_only", "gateway_locked", "mitigation_active_requests",
            "safety_status", "vehicle_stop_confirmed", "connected", "status",
            "last_mitigation_status",
        }
        if status != 200 or not required.issubset(health):
            return "SUPPRESSED_POLICY", "Gateway health is incompatible with the mitigation contract"
        boolean_fields = (
            "mitigation_api_enabled", "mitigation_api_ready", "mitigation_loopback_only",
            "gateway_locked", "vehicle_stop_confirmed", "connected",
        )
        if any(not isinstance(health.get(field), bool) for field in boolean_fields):
            return "SUPPRESSED_POLICY", "Gateway health contains invalid boolean safety fields"
        if not isinstance(health.get("safety_status"), str) or not isinstance(health.get("status"), str):
            return "SUPPRESSED_POLICY", "Gateway health contains invalid status fields"
        if health.get("gateway_locked") is True:
            return "SUPPRESSED_ALREADY_LOCKED", "Gateway is already locally locked"
        active_requests = health.get("mitigation_active_requests")
        if isinstance(active_requests, bool) or not isinstance(active_requests, int) or active_requests < 0:
            return "SUPPRESSED_POLICY", "Gateway health has an invalid active-request count"
        if (
            active_requests > 0
            or health.get("safety_status") == "LOCALLY_LOCKED_STOP_PENDING"
            or health.get("last_mitigation_status") == "IN_PROGRESS"
        ):
            return "COALESCED_WITH_EXISTING_STOP", "Gateway is already handling a safety STOP"
        if health.get("mitigation_api_enabled") is not True or health.get("mitigation_api_ready") is not True or health.get("mitigation_loopback_only") is not True:
            return "SUPPRESSED_POLICY", "Gateway mitigation endpoint is not enabled, ready, and loopback-only"
        if evidence_class == "HARDWARE_PROTOCOL":
            if (
                health.get("mode") != "hardware" or health.get("serial_transport") != "available"
                or health.get("connected") is not True or health.get("status") != "ok"
            ):
                return "SUPPRESSED_PROVENANCE", "hardware mode and available serial transport are required"
        elif evidence_class == "SYNTHETIC":
            if not self.config.allow_mock_mitigation or health.get("mode") != "mock" or health.get("serial_transport") != "mock":
                return "SUPPRESSED_PROVENANCE", "explicit compatible mock preflight is required"
        else:
            return "SUPPRESSED_PROVENANCE", "unactionable provenance class"
        return None

    def _set_decision(self, incident: dict[str, Any], state: str, reason: str) -> None:
        if state not in INCIDENT_STATES:
            raise AssertionError(f"unknown incident state {state}")
        incident["state"] = state
        incident["decision_reason"] = reason
        self._append_detection(incident, None, "CONTINUING", state, reason)
        self._persist()

    def _send_once(self, incident: dict[str, Any], anomaly: Mapping[str, Any]) -> None:
        if incident.get("request_attempted"):
            self._set_decision(incident, "DUPLICATE_SUPPRESSED", "durable incident latch forbids a second request")
            return
        incident["mitigation_request_id"] = _new_identifier("request")
        incident["mitigation_request_time_utc"] = utc_now()
        incident["state"] = "REQUEST_PLANNED"
        incident["request_attempted"] = True
        self._append_mitigation(incident, "REQUEST_PLANNED")  # flushed before state/network
        self._persist()  # durable latch exists before transmission
        incident["state"] = "REQUEST_SENT"
        self._append_mitigation(incident, "REQUEST_SENT")
        self._persist()  # conservative: a crash from here is ambiguous and never retried
        payload = {
            "incident_id": incident["incident_id"],
            "detection_id": incident["detection_id"],
            "idempotency_key": incident["idempotency_key"],
            "rule_id": incident["rule_id"],
            "severity": incident["severity"],
            "score": incident["score"],
            "detection_timestamp_utc": incident["detection_time_utc"],
            "evidence_class": incident["evidence_class"],
            "detector_run_id": incident["detector_run_id"],
        }
        try:
            http_status, response = self.gateway.stop(payload, self.token or "", self.config.http_timeout_sec)
        except GatewayTransportError as exc:
            incident["state"] = "EXECUTION_UNKNOWN"
            incident["execution_unknown_reason"] = exc.category
            self._append_mitigation(incident, "EXECUTION_UNKNOWN")
            self._persist()
            return
        incident["detector_http_response_time_utc"] = utc_now()
        incident["gateway_response"] = {
            key: response.get(key) for key in (
                "gateway_request_received_time_utc", "gateway_local_lock_time_utc",
                "stop_dispatch_time_utc", "stop_ack_time_utc", "gateway_response_time_utc",
                "transaction_id", "mode", "serial_transport", "result", "reason",
                "ack_state", "ack_origin", "ack_latency_ms", "gateway_processing_ms",
                "command_total_ms", "gateway_locked", "vehicle_stop_confirmed",
                "duplicate_suppressed", "coalesced", "synthetic", "mitigation_status",
            )
        }
        incident["state"] = "RESPONSE_RECEIVED"
        self._append_mitigation(incident, "RESPONSE_RECEIVED")
        self._persist()
        final = self._classify_response(http_status, response, incident)
        incident["state"] = final
        if final == "EXECUTION_UNKNOWN":
            incident["execution_unknown_reason"] = str(response.get("reason") or response.get("mitigation_status") or f"HTTP_{http_status}")
        self._append_mitigation(incident, final)
        self._persist()

    def _classify_response(self, status: int, response: Mapping[str, Any], incident: Mapping[str, Any]) -> str:
        mitigation_status = response.get("mitigation_status")
        if response.get("duplicate_suppressed") is True or mitigation_status == "DUPLICATE_SUPPRESSED":
            return "DUPLICATE_SUPPRESSED"
        if response.get("coalesced") is True or mitigation_status == "COALESCED_WITH_EXISTING_STOP":
            return "COALESCED_WITH_EXISTING_STOP"
        if (
            mitigation_status == "ACKNOWLEDGED_DOWNSTREAM" and status == 200
            and response.get("mode") == "hardware" and response.get("serial_transport") == "available"
            and response.get("vehicle_stop_confirmed") is True and response.get("synthetic") is not True
            and response.get("result") == "ACKNOWLEDGED" and response.get("ack_state") == "LOCKED"
            and response.get("ack_origin") == "VEHICLE" and bool(response.get("transaction_id"))
            and incident.get("evidence_class") == "HARDWARE_PROTOCOL"
        ):
            return "ACKNOWLEDGED_DOWNSTREAM"
        if (
            mitigation_status == "SYNTHETIC_ACKNOWLEDGED" and status == 200
            and response.get("mode") == "mock" and response.get("serial_transport") == "mock"
            and response.get("synthetic") is True and response.get("vehicle_stop_confirmed") is not True
            and self.config.allow_mock_mitigation
        ):
            return "SYNTHETIC_ACKNOWLEDGED"
        if status in {400, 401, 403, 404, 422} and mitigation_status in {
            "REQUEST_REJECTED", "AUTHENTICATION_FAILED", "ENDPOINT_DISABLED"
        }:
            return "REQUEST_REJECTED"
        return "EXECUTION_UNKNOWN"

    def _append_detection(
        self, incident: Mapping[str, Any], anomaly: Mapping[str, Any] | None,
        transition: str, decision: str, reason: str,
    ) -> None:
        self.detection_ledger.append(
            {
                "schema_version": SCHEMA_VERSION,
                "detector_run_id": self.detector_run_id,
                "detector_instance_id": self.detector_instance_id,
                "incident_id": incident.get("incident_id"),
                "detection_id": incident.get("detection_id"),
                "operation_epoch": incident.get("operation_epoch"),
                "rule_id": incident.get("rule_id"),
                "event_type": (anomaly or incident).get("event_type", "INCIDENT_STATE_CHANGE"),
                "rule_config_sha256": self.rule_sha256,
                "score": incident.get("score"),
                "severity": incident.get("severity"),
                "condition_transition": transition,
                "source_event_time_utc": incident.get("source_event_time_utc"),
                "detection_time_utc": utc_now(),
                "source_files": ";".join((self.config.actions_path.name, self.config.telemetry_path.name, self.config.ebpf_path.name)),
                "evidence_references": incident.get("evidence_reference", ""),
                "input_modes": self.state.get("last_gateway_mode", "UNKNOWN") or "UNKNOWN",
                "evidence_class": incident.get("evidence_class", "UNKNOWN_UNACTIONABLE"),
                "actionable": incident.get("actionable", False),
                "mitigation_decision": decision,
                "decision_reason": reason,
            }
        )

    def _append_mitigation(self, incident: Mapping[str, Any], phase: str) -> None:
        response = incident.get("gateway_response") or {}
        self.mitigation_ledger.append(
            {
                "schema_version": SCHEMA_VERSION,
                "record_time_utc": utc_now(),
                "incident_id": incident.get("incident_id"),
                "detection_id": incident.get("detection_id"),
                "mitigation_request_id": incident.get("mitigation_request_id"),
                "idempotency_key": incident.get("idempotency_key"),
                "phase": phase,
                "mitigation_request_time_utc": incident.get("mitigation_request_time_utc"),
                "detector_http_response_time_utc": incident.get("detector_http_response_time_utc"),
                "gateway_request_received_time_utc": response.get("gateway_request_received_time_utc"),
                "gateway_local_lock_time_utc": response.get("gateway_local_lock_time_utc"),
                "stop_dispatch_time_utc": response.get("stop_dispatch_time_utc"),
                "stop_ack_time_utc": response.get("stop_ack_time_utc"),
                "gateway_response_time_utc": response.get("gateway_response_time_utc"),
                "transaction_id": response.get("transaction_id"),
                "gateway_mode": response.get("mode"),
                "serial_transport": response.get("serial_transport"),
                "transaction_result": response.get("result"),
                "reason": response.get("reason") or incident.get("decision_reason"),
                "ack_state": response.get("ack_state"),
                "ack_origin": response.get("ack_origin"),
                "ack_latency_ms": response.get("ack_latency_ms"),
                "gateway_processing_ms": response.get("gateway_processing_ms"),
                "command_total_ms": response.get("command_total_ms"),
                "gateway_locked": response.get("gateway_locked"),
                "vehicle_stop_confirmed": response.get("vehicle_stop_confirmed", False),
                "execution_status": phase,
                "execution_unknown_reason": incident.get("execution_unknown_reason"),
                "duplicate_suppressed": response.get("duplicate_suppressed", False),
                "coalesced": response.get("coalesced", False),
                "synthetic": response.get("synthetic", incident.get("evidence_class") == "SYNTHETIC"),
                "evidence_class": incident.get("evidence_class", "UNKNOWN_UNACTIONABLE"),
            }
        )

    def request_stop(self) -> None:
        self.stop_requested = True

    def run(self) -> None:
        while not self.stop_requested:
            self.process_once()
            if self.stop_requested:
                break
            time.sleep(self.config.polling_interval_ms / 1000.0)

    def close(self, status: str = "COMPLETED") -> None:
        with self.lock:
            if self._closed:
                return
            self._persist()
            self._write_manifest(end_time=utc_now(), status=status)
            self.detection_ledger.close()
            self.mitigation_ledger.close()
            fcntl.flock(self._process_lock_stream.fileno(), fcntl.LOCK_UN)
            self._process_lock_stream.close()
            self._closed = True


__all__ = [
    "ACTIONS_HEADER", "DETECTION_FIELDS", "EBPF_HEADER", "EVIDENCE_CLASSES",
    "GatewayClient", "GatewayTransportError", "INCIDENT_STATES", "LiveAnomalyMonitor",
    "LiveConfiguration", "LiveConfigurationError", "MITIGATION_FIELDS", "RULE_IDS",
    "SCHEMA_VERSION", "SchemaError", "TELEMETRY_HEADER", "load_live_configuration",
]
