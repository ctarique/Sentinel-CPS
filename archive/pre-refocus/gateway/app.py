from __future__ import annotations

import atexit
import csv
import hmac
import ipaddress
import json
import math
import os
import queue
import random
import signal
import statistics
import sys
import threading
import time
import unicodedata
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

try:
    import serial
except ImportError:  # Allows mock mode to run even before pyserial is installed.
    serial = None

from flask import Flask, jsonify, render_template, request

from operator_token import (
    OPERATOR_TOKEN_ENV,
    OPERATOR_TOKEN_HEADER,
    OPERATOR_TOKEN_REQUIREMENT,
    is_valid_operator_token,
)

# -----------------------------------------------------------------------------
# Absolute project paths and configuration
# -----------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("SENTINEL_GATEWAY_DATA_DIR", BASE_DIR / "data"))
ACTIONS_CSV = DATA_DIR / "actions.csv"
TELEMETRY_CSV = DATA_DIR / "telemetry.csv"
PERFORMANCE_CSV = DATA_DIR / "performance.csv"
MITIGATION_CSV = DATA_DIR / "mitigation.csv"

CONFIG_PATH = Path(
    os.environ.get("SENTINEL_GATEWAY_CONFIG", BASE_DIR / "config.json")
)
EXAMPLE_CONFIG_PATH = BASE_DIR / "config.example.json"

if CONFIG_PATH.exists():
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        config = json.load(f)
elif EXAMPLE_CONFIG_PATH.exists():
    with EXAMPLE_CONFIG_PATH.open("r", encoding="utf-8") as f:
        config = json.load(f)
else:
    sys.exit("[FATAL] Configuration missing. Provide config.json or config.example.json.")

MAX_CENTERLINE_POINTS = int(config.get("max_centerline_points", 500))
SERIAL_ACK_TIMEOUT_MS = int(config.get("serial_ack_timeout_ms", 1000))
MOCK_ACK_DELAY_MS = int(config.get("mock_ack_delay_ms", 10))
KEEPALIVE_ENABLED = config.get("keepalive_enabled", True)
KEEPALIVE_INTERVAL_MS = config.get("keepalive_interval_ms", 3000)
MITIGATION_API_ENABLED = config.get("mitigation_api_enabled", False)
MITIGATION_LOOPBACK_ONLY = config.get("mitigation_loopback_only", True)
MITIGATION_IDEMPOTENCY_CACHE_SIZE = config.get(
    "mitigation_idempotency_cache_size", 128
)
MITIGATION_TOKEN_ENV = "SENTINEL_MITIGATION_TOKEN"
MITIGATION_TOKEN_MIN_LENGTH = 32
def _contains_control_characters(value: str) -> bool:
    return any(unicodedata.category(character) == "Cc" for character in value)


def _valid_operator_token(token: str | None) -> bool:
    return is_valid_operator_token(token)


OPERATOR_TOKEN = os.environ.get(OPERATOR_TOKEN_ENV)
if not _valid_operator_token(OPERATOR_TOKEN):
    raise SystemExit(
        "[FATAL] SENTINEL_OPERATOR_TOKEN is required and must contain "
        + OPERATOR_TOKEN_REQUIREMENT
    )
OPERATOR_TOKEN_BYTES = OPERATOR_TOKEN.encode("utf-8")
DATA_DIR.mkdir(parents=True, exist_ok=True)

if SERIAL_ACK_TIMEOUT_MS <= 0:
    raise SystemExit("[FATAL] serial_ack_timeout_ms must be positive")
if MOCK_ACK_DELAY_MS < 0:
    raise SystemExit("[FATAL] mock_ack_delay_ms must be zero or positive")
if config.get("safe_boot_locked", True) is not True:
    raise SystemExit("[FATAL] safe_boot_locked must remain true")
if not isinstance(KEEPALIVE_ENABLED, bool):
    raise SystemExit("[FATAL] keepalive_enabled must be a boolean")
if isinstance(KEEPALIVE_INTERVAL_MS, bool) or not isinstance(
    KEEPALIVE_INTERVAL_MS, int
):
    raise SystemExit("[FATAL] keepalive_interval_ms must be an integer")
if KEEPALIVE_INTERVAL_MS <= 0:
    raise SystemExit("[FATAL] keepalive_interval_ms must be positive")
if KEEPALIVE_INTERVAL_MS >= 7000:
    raise SystemExit("[FATAL] keepalive_interval_ms must be less than 7000")
if not isinstance(MITIGATION_API_ENABLED, bool):
    raise SystemExit("[FATAL] mitigation_api_enabled must be a boolean")
if MITIGATION_LOOPBACK_ONLY is not True:
    raise SystemExit(
        "[FATAL] mitigation_loopback_only must remain true for the thesis baseline"
    )
if isinstance(MITIGATION_IDEMPOTENCY_CACHE_SIZE, bool) or not isinstance(
    MITIGATION_IDEMPOTENCY_CACHE_SIZE, int
):
    raise SystemExit("[FATAL] mitigation_idempotency_cache_size must be an integer")
if not 1 <= MITIGATION_IDEMPOTENCY_CACHE_SIZE <= 1024:
    raise SystemExit(
        "[FATAL] mitigation_idempotency_cache_size must be between 1 and 1024"
    )

# -----------------------------------------------------------------------------
# Thread-safe CSV logging
# -----------------------------------------------------------------------------
csv_lock = threading.Lock()
telemetry_lock = threading.Lock()

ACTION_HEADERS = ["timestamp", "event_id", "source", "command", "details", "result", "mode"]
TELEMETRY_HEADERS = ["timestamp", "vehicle_id", "adc_l", "adc_r", "steer", "state", "source"]
PERFORMANCE_HEADERS = [
    "timestamp",
    "timestamp_utc",
    "event_id",
    "command",
    "mode",
    "result",
    "gateway_processing_ms",
    "state_before",
    "state_after",
]
MITIGATION_HEADERS = [
    "ledger_time_utc",
    "phase",
    "incident_id",
    "detection_id",
    "idempotency_key",
    "detection_timestamp_utc",
    "gateway_request_received_time_utc",
    "gateway_local_lock_time_utc",
    "stop_dispatch_time_utc",
    "stop_ack_time_utc",
    "gateway_response_time_utc",
    "mode",
    "serial_transport",
    "transaction_result",
    "reason",
    "transaction_id",
    "ack_state",
    "ack_origin",
    "mitigation_status",
    "synthetic",
    "duplicate_suppressed",
    "coalesced",
]


def utc_now() -> str:
    """Return an exact, timezone-explicit UTC wall-clock timestamp."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def init_csv(filepath: Path, headers: list[str]) -> None:
    with csv_lock:
        if not filepath.exists():
            with filepath.open("w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
            return

        with filepath.open("r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            existing_headers = next(reader, [])
        if existing_headers != headers:
            raise SystemExit(
                f"[FATAL] CSV schema mismatch for {filepath}. "
                "Archive or delete the old file before running this Gateway version."
            )


def append_csv(filepath: Path, row: list) -> None:
    with csv_lock:
        with filepath.open("a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(row)
            f.flush()


def log_action(source: str, command: str, details: str, result: str, mode: str = "unknown") -> str:
    event_id = f"evt_{uuid.uuid4().hex[:8]}"
    timestamp = time.time()
    append_csv(ACTIONS_CSV, [timestamp, event_id, source, command, details, result, mode])
    return event_id


def log_performance(
    event_id: str,
    command: str,
    mode: str,
    result: str,
    gateway_processing_ms: float,
    state_before: str,
    state_after: str,
) -> None:
    timestamp = time.time()
    timestamp_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))
    append_csv(
        PERFORMANCE_CSV,
        [
            timestamp,
            timestamp_utc,
            event_id,
            command,
            mode,
            result,
            round(gateway_processing_ms, 6),
            state_before,
            state_after,
        ],
    )


def read_performance_rows() -> list[dict[str, str]]:
    with csv_lock:
        if not PERFORMANCE_CSV.exists():
            return []
        with PERFORMANCE_CSV.open("r", newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))


def metric_block(values: list[float]) -> dict:
    if not values:
        return {
            "count": 0,
            "minimum_ms": None,
            "mean_ms": None,
            "median_ms": None,
            "p95_ms": None,
            "maximum_ms": None,
        }

    ordered = sorted(values)
    p95_index = max(0, math.ceil(0.95 * len(ordered)) - 1)

    return {
        "count": len(ordered),
        "minimum_ms": round(ordered[0], 6),
        "mean_ms": round(statistics.fmean(ordered), 6),
        "median_ms": round(statistics.median(ordered), 6),
        "p95_ms": round(ordered[p95_index], 6),
        "maximum_ms": round(ordered[-1], 6),
    }


def summarize_performance() -> dict:
    rows = read_performance_rows()
    user_values: list[float] = []
    user_command_values: dict[str, list[float]] = {}
    user_result_counts: dict[str, int] = {}
    keepalive_values: list[float] = []
    keepalive_result_counts: dict[str, int] = {}

    for row in rows:
        try:
            latency = float(row["gateway_processing_ms"])
        except (KeyError, TypeError, ValueError):
            continue

        command = row.get("command", "UNKNOWN")
        result = row.get("result", "UNKNOWN")

        if command == "AUTO_KEEPALIVE:PING":
            keepalive_values.append(latency)
            keepalive_result_counts[result] = (
                keepalive_result_counts.get(result, 0) + 1
            )
            continue

        user_values.append(latency)
        user_command_values.setdefault(command, []).append(latency)
        user_result_counts[result] = user_result_counts.get(result, 0) + 1

    return {
        "measurement": (
            "Gateway-local processing latency measured with "
            "time.perf_counter_ns(); blocking ACK/NACK wait time is excluded. "
            "Per-command API responses separately expose ack_latency_ms and "
            "command_total_ms."
        ),
        "sample_count": len(user_values),
        "overall": metric_block(user_values),
        "by_command": {
            command: metric_block(values)
            for command, values in sorted(user_command_values.items())
        },
        "result_counts": user_result_counts,
        "automatic_keepalive": {
            "label": "AUTO_KEEPALIVE",
            "sample_count": len(keepalive_values),
            "gateway_processing": metric_block(keepalive_values),
            "result_counts": keepalive_result_counts,
            "note": (
                "Automatic PING samples are intentionally excluded from the "
                "user-command summary above. ACK and total latency remain in "
                "the corresponding AUTO_KEEPALIVE action details."
            ),
        },
        "mode": bridge.current_mode_label(),
    }


init_csv(ACTIONS_CSV, ACTION_HEADERS)
init_csv(TELEMETRY_CSV, TELEMETRY_HEADERS)
init_csv(PERFORMANCE_CSV, PERFORMANCE_HEADERS)
init_csv(MITIGATION_CSV, MITIGATION_HEADERS)

# -----------------------------------------------------------------------------
# Serial bridge abstraction
# -----------------------------------------------------------------------------
@dataclass
class TransactionResult:
    txid: str
    verb: str
    outcome: str
    reason: str | None = None
    state: str | None = None
    origin: str | None = None
    ack_latency_ms: float | None = None
    gateway_processing_ms: float = 0.0
    local_lock_time_utc: str | None = None
    dispatch_time_utc: str | None = None
    response_time_utc: str | None = None
    coalesced: bool = False

    def __iter__(self):
        """Retain two-value unpacking for callers of the earlier bridge API."""
        yield self.outcome == "ACKNOWLEDGED"
        yield self.outcome


@dataclass
class PendingTransaction:
    txid: str
    verb: str
    dispatched_ns: int = 0
    response_kind: str | None = None
    reason: str | None = None
    state: str | None = None
    origin: str | None = None
    received_ns: int = 0
    received_time_utc: str | None = None
    response_processing_ns: int = 0
    transport_error: str | None = None
    transport_reason: str | None = None
    completed: threading.Event = field(default_factory=threading.Event)


@dataclass
class StopFlight:
    txid: str
    source: str


class SerialUnavailableError(OSError):
    """Raised when explicitly selected hardware serial is not usable."""


class SerialBridge:
    """Gateway-to-Hub serial abstraction.

    Explicit mock mode simulates protocol responses. Explicit hardware mode never
    falls back to simulation: unavailable or degraded transport fails closed.
    """

    def __init__(
        self,
        mock_mode: bool,
        port: str,
        baud: int,
        safe_boot_locked: bool = True,
        serial_ack_timeout_ms: int = 1000,
        mock_ack_delay_ms: int = 10,
        keepalive_enabled: bool = True,
        keepalive_interval_ms: int = 3000,
    ):
        self.mock_mode = bool(mock_mode)
        self.port = port
        self.baud = int(baud)
        self.conn = None
        self.last_logged_state = None
        self.safe_boot_locked = bool(safe_boot_locked)
        if not self.safe_boot_locked:
            raise ValueError("safe_boot_locked must remain true")
        self.state_lock = threading.Lock()
        self.locked = self.safe_boot_locked
        self.acknowledged_state = "LOCKED"
        self.state_generation = 0
        self.local_lock_reason: str | None = "SAFE_BOOT"
        self.last_write_result = "NOT_DISPATCHED"
        self.serial_ack_timeout_ms = int(serial_ack_timeout_ms)
        self.mock_ack_delay_ms = int(mock_ack_delay_ms)
        if self.serial_ack_timeout_ms <= 0:
            raise ValueError("serial_ack_timeout_ms must be positive")
        if self.mock_ack_delay_ms < 0:
            raise ValueError("mock_ack_delay_ms must be zero or positive")
        if not isinstance(keepalive_enabled, bool):
            raise ValueError("keepalive_enabled must be a boolean")
        if isinstance(keepalive_interval_ms, bool) or not isinstance(
            keepalive_interval_ms, int
        ):
            raise ValueError("keepalive_interval_ms must be an integer")
        if keepalive_interval_ms <= 0:
            raise ValueError("keepalive_interval_ms must be positive")
        if keepalive_interval_ms >= 7000:
            raise ValueError("keepalive_interval_ms must be less than 7000")
        self.keepalive_enabled = keepalive_enabled
        self.keepalive_interval_ms = keepalive_interval_ms
        self.keepalive_wakeup = threading.Event()
        self.last_keepalive_timestamp: float | None = None
        self.last_keepalive_result: str | None = None
        self.last_keepalive_ack_latency_ms: float | None = None
        self.keepalive_failure_count = 0
        self.last_keepalive_failure: dict | None = None
        self.keepalive_failure_evidence_status: str | None = None
        self.keepalive_failure_evidence_error: str | None = None
        self.last_safety_stop_result: str | None = None
        self.vehicle_stop_confirmed = False
        self.safety_status = "NORMAL"
        self.command_lock = threading.Lock()
        self.stop_coordination_lock = threading.Lock()
        self.stop_inflight: StopFlight | None = None
        self.pending_lock = threading.Lock()
        self.transport_lock = threading.Lock()
        self.pending_transaction: PendingTransaction | None = None
        self.transport_ever_available = False
        self.transport_degraded = False
        self.transport_error: str | None = None
        self.mock_rx_queue: queue.Queue[str] = queue.Queue()
        self.stop_reader = threading.Event()
        self.mock_threads_lock = threading.Lock()
        self.mock_response_threads: set[threading.Thread] = set()
        self.mock_ack_behavior = "ACK"
        self.mock_nack_reason = "MOCK_REJECTED"
        self.mock_response_state: str | None = None
        self.mock_response_origin = "VEHICLE"
        self.mock_interleaved_telemetry = (
            "TEL,esp32_mock_1,3000,2950,0.000,RUNNING"
        )
        self.latest_telemetry = {
            "timestamp": 0.0,
            "vehicle_id": "none",
            "adc_l": 0,
            "adc_r": 0,
            "steer": 0.0,
            "state": "DISCONNECTED",
            "source": "none",
        }
        self.connect()

        if self.locked:
            self._set_telemetry_state(
                "LOCKED",
                vehicle_id="gateway_safe_boot",
                source="gateway_safe_boot_policy",
            )
            self._log_telemetry_snapshot(force=True)
            print("[SAFE BOOT] Gateway initialized LOCKED; RESET is required before START")

        self.thread = threading.Thread(
            target=self.read_loop,
            daemon=True,
            name=f"serial-reader-{id(self)}",
        )
        self.thread.start()
        self.keepalive_thread = threading.Thread(
            target=self._keepalive_loop,
            daemon=True,
            name=f"keepalive-worker-{id(self)}",
        )
        self.keepalive_thread.start()

    def connect(self) -> None:
        if not self.mock_mode:
            if serial is None:
                msg = "pyserial unavailable; hardware transport unavailable"
                print(f"[WARN] {msg}")
                self._mark_transport_degraded(msg, ever_available=False)
                log_action(
                    "system",
                    "SERIAL_CONNECT_FAILED",
                    msg,
                    "SERIAL_UNAVAILABLE",
                    mode="hardware",
                )
            else:
                try:
                    self.conn = serial.Serial(self.port, self.baud, timeout=1)
                    with self.transport_lock:
                        self.transport_ever_available = True
                        self.transport_degraded = False
                        self.transport_error = None
                    print(f"[HW] Connected to {self.port} at {self.baud} baud.")
                    log_action("system", "SERIAL_CONNECTED", f"port={self.port}, baud={self.baud}", "SUCCESS", mode="hardware")
                except Exception as exc:
                    msg = f"Hardware serial failed: {exc}; transport unavailable"
                    print(f"[WARN] {msg}")
                    self._mark_transport_degraded(msg, ever_available=False)
                    log_action(
                        "system",
                        "SERIAL_CONNECT_FAILED",
                        msg,
                        "SERIAL_UNAVAILABLE",
                        mode="hardware",
                    )

        if self.mock_mode:
            with telemetry_lock:
                self.latest_telemetry.update(
                    {
                        "timestamp": time.time(),
                        "vehicle_id": "none",
                        "adc_l": 0,
                        "adc_r": 0,
                        "steer": 0.0,
                        "state": "IDLE (MOCK)",
                        "source": "mock_generator",
                    }
                )
            print("[SIM] Running in MOCK_SERIAL mode.")

    def _mark_transport_degraded(
        self, message: str, *, ever_available: bool | None = None
    ) -> None:
        if self.mock_mode:
            return
        with self.transport_lock:
            if ever_available is not None:
                self.transport_ever_available = ever_available
            self.transport_degraded = True
            self.transport_error = message

    def _fail_pending_transport(self, outcome: str, reason: str) -> None:
        self._mark_transport_degraded(reason)
        with self.pending_lock:
            pending = self.pending_transaction
            if pending is not None and not pending.completed.is_set():
                pending.transport_error = outcome
                pending.transport_reason = reason
                pending.completed.set()

    def _transport_snapshot(self) -> tuple[bool, str]:
        if self.mock_mode:
            return False, "mock"
        connected = bool(self.conn and getattr(self.conn, "is_open", False))
        with self.transport_lock:
            ever_available = self.transport_ever_available
            degraded = self.transport_degraded
        if connected and not degraded:
            return True, "available"
        return False, "degraded" if ever_available else "unavailable"

    def _get_locked(self) -> bool:
        with self.state_lock:
            return self.locked

    def _set_locked(self, value: bool) -> None:
        changed = False
        with self.state_lock:
            normalized = bool(value)
            if self.locked != normalized:
                self.locked = normalized
                self.state_generation += 1
                changed = True
        if changed:
            self.keepalive_wakeup.set()

    def _set_control_state(
        self,
        *,
        locked: bool | None = None,
        acknowledged_state: str | None = None,
        local_lock_reason: str | None = None,
        force_generation: bool = False,
    ) -> int:
        changed = force_generation
        with self.state_lock:
            if locked is not None and self.locked != bool(locked):
                self.locked = bool(locked)
                changed = True
            if (
                acknowledged_state is not None
                and self.acknowledged_state != acknowledged_state
            ):
                self.acknowledged_state = acknowledged_state
                changed = True
            if local_lock_reason != self.local_lock_reason:
                self.local_lock_reason = local_lock_reason
                changed = True
            if changed:
                self.state_generation += 1
            generation = self.state_generation
        if changed:
            self.keepalive_wakeup.set()
        return generation

    def _keepalive_active_locked(self) -> bool:
        return (
            self.keepalive_enabled
            and not self.stop_reader.is_set()
            and not self.locked
            and self.acknowledged_state == "RUNNING"
        )

    def current_mode_label(self) -> str:
        return "mock" if self.mock_mode else "hardware"

    def get_status(self) -> dict:
        with telemetry_lock:
            state = self.latest_telemetry["state"]
        connected, transport = self._transport_snapshot()
        with self.transport_lock:
            transport_error = self.transport_error
        if transport in {"unavailable", "degraded"} and not transport_error:
            transport_error = "serial connection is closed"
        with self.state_lock:
            state_status = {
                "gateway_locked": self.locked,
                "acknowledged_state": self.acknowledged_state,
                "local_lock_reason": self.local_lock_reason,
                "keepalive_enabled": self.keepalive_enabled,
                "keepalive_interval_ms": self.keepalive_interval_ms,
                "keepalive_active": self._keepalive_active_locked(),
                "last_keepalive_timestamp": self.last_keepalive_timestamp,
                "last_keepalive_result": self.last_keepalive_result,
                "last_keepalive_ack_latency_ms": (
                    round(self.last_keepalive_ack_latency_ms, 6)
                    if self.last_keepalive_ack_latency_ms is not None
                    else None
                ),
                "keepalive_failure_count": self.keepalive_failure_count,
                "last_keepalive_failure": (
                    dict(self.last_keepalive_failure)
                    if self.last_keepalive_failure is not None
                    else None
                ),
                "keepalive_failure_evidence_status": (
                    self.keepalive_failure_evidence_status
                ),
                "keepalive_failure_evidence_error": (
                    self.keepalive_failure_evidence_error
                ),
                "last_safety_stop_result": self.last_safety_stop_result,
                "vehicle_stop_confirmed": self.vehicle_stop_confirmed,
                "safety_status": self.safety_status,
            }
        return {
            "status": "ok" if transport in {"mock", "available"} else "degraded",
            "mode": "mock" if self.mock_mode else "hardware",
            "port": self.port,
            "baud": self.baud,
            "connected": connected,
            "serial_transport": transport,
            "transport_error": transport_error,
            "safe_boot_locked": self.safe_boot_locked,
            "vehicle_state": state,
            "serial_ack_timeout_ms": self.serial_ack_timeout_ms,
            **state_status,
        }

    def get_latest_telemetry(self) -> dict:
        with telemetry_lock:
            return self.latest_telemetry.copy()

    def _set_telemetry_state(self, state: str, *, vehicle_id: str | None = None, source: str | None = None) -> None:
        with telemetry_lock:
            self.latest_telemetry["timestamp"] = time.time()
            self.latest_telemetry["state"] = state
            if vehicle_id is not None:
                self.latest_telemetry["vehicle_id"] = vehicle_id
            elif self.latest_telemetry["vehicle_id"] == "none" and state == "LOCKED":
                self.latest_telemetry["vehicle_id"] = "gateway_stop"
            if source is not None:
                self.latest_telemetry["source"] = source

    def _log_telemetry_snapshot(self, *, force: bool = False) -> None:
        snap = self.get_latest_telemetry()
        if not force and snap["vehicle_id"] == "none":
            return
        append_csv(
            TELEMETRY_CSV,
            [
                snap["timestamp"],
                snap["vehicle_id"],
                snap["adc_l"],
                snap["adc_r"],
                snap["steer"],
                snap["state"],
                snap["source"],
            ],
        )
        self.last_logged_state = snap["state"]

    def set_mock_ack_behavior(
        self,
        behavior: str,
        *,
        reason: str = "MOCK_REJECTED",
        state: str | None = None,
        telemetry: str | None = None,
        origin: str = "VEHICLE",
    ) -> None:
        """Select deterministic mock input behavior for tests and development."""
        allowed = {
            "ACK",
            "NACK",
            "TIMEOUT",
            "WRONG_TXID",
            "WRONG_VERB",
            "INTERLEAVED_TELEMETRY",
            "TELEMETRY_ONLY",
            "WRITE_ERROR",
        }
        normalized = behavior.upper().strip()
        if normalized not in allowed:
            raise ValueError(f"Unsupported mock ACK behavior: {behavior}")
        self.mock_ack_behavior = normalized
        self.mock_nack_reason = reason.upper().strip()
        self.mock_response_state = state.upper().strip() if state else None
        self.mock_response_origin = origin.upper().strip()
        if telemetry is not None:
            self.mock_interleaved_telemetry = telemetry

    def inject_mock_line(self, line: str) -> None:
        """Inject one mock RX line; only the reader thread parses it."""
        if not self.mock_mode:
            raise RuntimeError("Mock line injection requires mock mode")
        if self.stop_reader.is_set():
            return
        self.mock_rx_queue.put(line.strip())

    def close(self) -> None:
        self.stop_reader.set()
        self._set_control_state(
            locked=True,
            local_lock_reason="SHUTDOWN",
            force_generation=True,
        )
        self.keepalive_wakeup.set()
        with self.pending_lock:
            pending = self.pending_transaction
            if pending is not None and not pending.completed.is_set():
                pending.transport_error = "SERIAL_UNAVAILABLE"
                pending.transport_reason = "Gateway serial transaction shut down"
                pending.completed.set()
        if self.keepalive_thread.is_alive():
            self.keepalive_thread.join(timeout=1.2)
        if self.thread.is_alive():
            self.thread.join(timeout=1.2)
        with self.mock_threads_lock:
            response_threads = list(self.mock_response_threads)
        for response_thread in response_threads:
            response_thread.join(timeout=1.2)

    def _mock_state_for(self, verb: str) -> str:
        if self.mock_response_state:
            return self.mock_response_state
        if verb == "START":
            return "RUNNING"
        if verb == "STOP":
            return "LOCKED"
        if verb == "RESET":
            return "IDLE"
        return str(self.get_latest_telemetry().get("state", "UNKNOWN")).replace(
            " (MOCK)", ""
        )

    def _schedule_mock_response(self, transaction: PendingTransaction) -> None:
        behavior = self.mock_ack_behavior
        if behavior == "TIMEOUT":
            return

        def emit() -> None:
            try:
                delay_seconds = self.mock_ack_delay_ms / 1000.0
                if behavior == "INTERLEAVED_TELEMETRY":
                    if self.stop_reader.wait(delay_seconds / 2):
                        return
                    self.inject_mock_line(self.mock_interleaved_telemetry)
                    if self.stop_reader.wait(delay_seconds / 2):
                        return
                elif behavior == "TELEMETRY_ONLY":
                    if self.stop_reader.wait(delay_seconds):
                        return
                    self.inject_mock_line(self.mock_interleaved_telemetry)
                    return
                elif self.stop_reader.wait(delay_seconds):
                    return

                txid = transaction.txid
                verb = transaction.verb
                if behavior == "WRONG_TXID":
                    txid = f"wrong_{transaction.txid}"
                if behavior == "WRONG_VERB":
                    verb = "STATUS" if transaction.verb != "STATUS" else "PING"

                state = self._mock_state_for(transaction.verb)
                if behavior == "NACK":
                    line = (
                        f"NACK,{txid},{verb},{self.mock_nack_reason},"
                        f"{state},VEHICLE"
                    )
                else:
                    line = f"ACK,{txid},{verb},{state},{self.mock_response_origin}"
                self.inject_mock_line(line)
            finally:
                with self.mock_threads_lock:
                    self.mock_response_threads.discard(threading.current_thread())

        response_thread = threading.Thread(target=emit, daemon=True)
        with self.mock_threads_lock:
            self.mock_response_threads.add(response_thread)
        response_thread.start()

    def _send_transaction(self, transaction: PendingTransaction) -> None:
        frame = f"CMD,{transaction.txid},{transaction.verb}\n"
        if self.mock_mode:
            if self.mock_ack_behavior == "WRITE_ERROR":
                raise OSError("simulated serial write failure")
            print(f"[SIM TX] -> {frame.strip()}")
            return

        connected, transport = self._transport_snapshot()
        if not connected or transport != "available":
            raise SerialUnavailableError("serial connection is unavailable")
        try:
            self.conn.write(frame.encode("utf-8"))
            self.conn.flush()
        except Exception as exc:
            self._mark_transport_degraded(f"serial write failed: {exc}")
            raise
        print(f"[HW TX] -> {frame.strip()}")

    @staticmethod
    def _keepalive_validation(
        transaction: TransactionResult,
    ) -> tuple[bool, str | None, str]:
        if transaction.outcome != "ACKNOWLEDGED":
            return (
                False,
                transaction.reason or transaction.outcome,
                transaction.outcome,
            )
        if transaction.origin != "VEHICLE":
            return False, "UNEXPECTED_ACK_ORIGIN", "INVALID_ACK"
        if transaction.state != "RUNNING":
            return False, "UNEXPECTED_ACK_STATE", "INVALID_ACK"
        return True, None, "ACKNOWLEDGED"

    def _record_automatic_transaction(
        self,
        transaction: TransactionResult,
        command_total_ms: float,
        automatic_result: str,
    ) -> None:
        details = json.dumps(
            {
                "transaction_id": transaction.txid,
                "result": automatic_result,
                "transaction_result": transaction.outcome,
                "reason": transaction.reason,
                "ack_state": transaction.state,
                "ack_origin": transaction.origin,
                "gateway_processing_ms": round(
                    transaction.gateway_processing_ms, 6
                ),
                "ack_latency_ms": (
                    round(transaction.ack_latency_ms, 6)
                    if transaction.ack_latency_ms is not None
                    else None
                ),
                "command_total_ms": round(command_total_ms, 6),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        event_id = log_action(
            "AUTO_KEEPALIVE",
            "PING",
            details,
            automatic_result,
            mode=self.current_mode_label(),
        )
        log_performance(
            event_id=event_id,
            command="AUTO_KEEPALIVE:PING",
            mode=self.current_mode_label(),
            result=automatic_result,
            gateway_processing_ms=transaction.gateway_processing_ms,
            state_before="RUNNING",
            state_after=(
                "RUNNING"
                if automatic_result == "ACKNOWLEDGED"
                else "LOCKED"
            ),
        )

    def _handle_keepalive_result(
        self,
        transaction: TransactionResult,
        state_generation: int,
        command_total_ms: float,
    ) -> None:
        succeeded, failure_reason, keepalive_result = self._keepalive_validation(
            transaction
        )
        timestamp = time.time()

        with self.state_lock:
            if (
                self.stop_reader.is_set()
                or self.state_generation != state_generation
                or not self._keepalive_active_locked()
            ):
                return

            if succeeded:
                self.last_keepalive_timestamp = timestamp
                self.last_keepalive_result = keepalive_result
                self.last_keepalive_ack_latency_ms = transaction.ack_latency_ms
            else:
                # Accept the failure internally before any potentially blocking
                # logging. This immediately makes keepalive inactive and protects
                # the latch from stale transaction completion, while completed
                # failure health remains unpublished until evidence is resolved.
                self.locked = True
                self.local_lock_reason = "KEEPALIVE_FAILURE"
                self.state_generation += 1
                failure_generation = self.state_generation
                self.keepalive_failure_evidence_status = "APPEND_PENDING"
                self.keepalive_failure_evidence_error = None
                self.last_safety_stop_result = None
                self.vehicle_stop_confirmed = False
                self.safety_status = "LOCALLY_LOCKED_EVIDENCE_PENDING"

        if succeeded:
            try:
                self._record_automatic_transaction(
                    transaction,
                    command_total_ms,
                    keepalive_result,
                )
            except Exception as exc:
                print(f"[WARN] Automatic keepalive logging failed: {exc}")
            return

        failure = {
            "transaction_id": transaction.txid or None,
            "result": keepalive_result,
            "reason": failure_reason,
            "ack_state": transaction.state,
            "ack_origin": transaction.origin,
            "ack_latency_ms": (
                round(transaction.ack_latency_ms, 6)
                if transaction.ack_latency_ms is not None
                else None
            ),
            "timestamp": timestamp,
            "timestamp_utc": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp)
            ),
        }
        failure_details = json.dumps(
            failure, sort_keys=True, separators=(",", ":")
        )

        self.keepalive_wakeup.set()
        self._set_telemetry_state(
            "LOCKED",
            vehicle_id="gateway_keepalive",
            source="gateway_keepalive_failure",
        )

        evidence_status = "APPENDED_AND_FLUSHED"
        evidence_error = None
        try:
            log_action(
                "AUTO_KEEPALIVE",
                "KEEPALIVE_FAILURE",
                failure_details,
                "LOCALLY_LOCKED",
                mode=self.current_mode_label(),
            )
        except Exception as exc:
            evidence_status = "APPEND_FAILED"
            evidence_error = f"{type(exc).__name__}: {exc}"
            print(f"[WARN] Keepalive failure evidence append failed: {exc}")

        completed_failure = {
            **failure,
            "evidence_status": evidence_status,
            "evidence_error": evidence_error,
        }
        with self.state_lock:
            self.last_keepalive_timestamp = timestamp
            self.last_keepalive_result = keepalive_result
            self.last_keepalive_ack_latency_ms = transaction.ack_latency_ms
            self.keepalive_failure_count += 1
            self.last_keepalive_failure = completed_failure
            self.keepalive_failure_evidence_status = evidence_status
            self.keepalive_failure_evidence_error = evidence_error
            self.safety_status = "LOCALLY_LOCKED_STOP_PENDING"

        # write() has returned, so its command-lock scope is over. The guarded
        # STOP below uses the same transaction implementation and cannot recurse
        # into a lock still held by the failed PING.
        self._attempt_keepalive_safety_stop(failure_generation)

        try:
            self._log_telemetry_snapshot(force=True)
        except Exception as exc:
            print(f"[WARN] Keepalive failure telemetry logging failed: {exc}")
        try:
            self._record_automatic_transaction(
                transaction,
                command_total_ms,
                keepalive_result,
            )
        except Exception as exc:
            print(f"[WARN] Automatic keepalive logging failed: {exc}")

    def _attempt_keepalive_safety_stop(self, failure_generation: int) -> None:
        transaction = self.write(
            "STOP",
            source="AUTO_KEEPALIVE_SAFETY",
            expected_state_generation=failure_generation,
        )
        confirmed = (
            transaction.outcome == "ACKNOWLEDGED"
            and transaction.verb == "STOP"
            and transaction.state == "LOCKED"
            and transaction.origin == "VEHICLE"
        )
        with self.state_lock:
            self.last_safety_stop_result = transaction.outcome
            self.vehicle_stop_confirmed = confirmed
            self.safety_status = (
                "STOP_ACKNOWLEDGED" if confirmed else "STOP_EXECUTION_UNKNOWN"
            )

        try:
            log_action(
                "AUTO_KEEPALIVE",
                "SAFETY_STOP",
                json.dumps(
                    {
                        "transaction_id": transaction.txid,
                        "result": transaction.outcome,
                        "reason": transaction.reason,
                        "ack_state": transaction.state,
                        "ack_origin": transaction.origin,
                        "ack_latency_ms": transaction.ack_latency_ms,
                        "vehicle_stop_confirmed": confirmed,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                "STOP_CONFIRMED" if confirmed else "STOP_EXECUTION_UNKNOWN",
                mode=self.current_mode_label(),
            )
        except Exception as exc:
            print(f"[WARN] Keepalive safety STOP logging failed: {exc}")

    def _keepalive_loop(self) -> None:
        next_deadline: float | None = None
        while not self.stop_reader.is_set():
            with self.state_lock:
                active = self._keepalive_active_locked()
                generation = self.state_generation

            if not active:
                next_deadline = None
                self.keepalive_wakeup.wait()
                self.keepalive_wakeup.clear()
                continue

            if next_deadline is None:
                next_deadline = (
                    time.monotonic() + self.keepalive_interval_ms / 1000.0
                )

            remaining = max(0.0, next_deadline - time.monotonic())
            if self.keepalive_wakeup.wait(remaining):
                self.keepalive_wakeup.clear()
                next_deadline = None
                continue
            if self.stop_reader.is_set():
                return

            started_ns = time.perf_counter_ns()
            transaction = self.write(
                "PING",
                source="AUTO_KEEPALIVE",
                expected_state_generation=generation,
                apply_acknowledged_state=False,
            )
            command_total_ms = (
                time.perf_counter_ns() - started_ns
            ) / 1_000_000
            if transaction.outcome != "STALE_SKIPPED":
                self._handle_keepalive_result(
                    transaction,
                    generation,
                    command_total_ms,
                )
            next_deadline = None

    def write(
        self,
        command: str,
        *,
        source: str = "USER_COMMAND",
        expected_state_generation: int | None = None,
        apply_acknowledged_state: bool = True,
    ) -> TransactionResult:
        local_segment_started_ns = time.perf_counter_ns()
        local_processing_ns = 0
        cmd = command.upper().strip()
        txid = uuid.uuid4().hex[:12]
        local_lock_time_utc: str | None = None
        dispatch_time_utc: str | None = None
        stop_flight: StopFlight | None = None

        # STOP is a local safety action before it is a transport transaction.
        # Register the flight before waiting for command_lock so all STOP sources
        # (manual, keepalive, and mitigation) share one coalescing boundary.
        if cmd == "STOP":
            if expected_state_generation is not None:
                with self.state_lock:
                    if (
                        self.state_generation != expected_state_generation
                        or self.stop_reader.is_set()
                    ):
                        return TransactionResult(
                            txid=txid,
                            verb=cmd,
                            outcome="STALE_SKIPPED",
                            reason="AUTHORITATIVE_STATE_CHANGED",
                        )

            local_lock_time_utc = utc_now()
            self._set_control_state(
                locked=True,
                local_lock_reason=(
                    "KEEPALIVE_FAILURE"
                    if source == "AUTO_KEEPALIVE_SAFETY"
                    else "MITIGATION_STOP"
                    if source == "MITIGATION_API"
                    else "STOP_COMMAND"
                ),
                force_generation=True,
            )
            stop_source = (
                "mock_generator" if self.mock_mode else "gateway_local_stop"
            )
            self._set_telemetry_state(
                "LOCKED", vehicle_id="gateway_stop", source=stop_source
            )
            try:
                self._log_telemetry_snapshot(force=True)
            except Exception as exc:
                print(f"[WARN] STOP telemetry logging failed: {exc}")

            with self.stop_coordination_lock:
                existing_stop = self.stop_inflight
                if existing_stop is not None:
                    return TransactionResult(
                        txid="",
                        verb="STOP",
                        outcome="STOP_COALESCED",
                        reason="EXISTING_STOP_IN_FLIGHT",
                        state="LOCKED",
                        local_lock_time_utc=local_lock_time_utc,
                        coalesced=True,
                    )
                stop_flight = StopFlight(txid=txid, source=source)
                self.stop_inflight = stop_flight

        def finish(
            outcome: str,
            *,
            reason: str | None = None,
            state: str | None = None,
            origin: str | None = None,
            ack_latency_ms: float | None = None,
            response_time_utc: str | None = None,
        ) -> TransactionResult:
            nonlocal local_processing_ns, local_segment_started_ns, stop_flight
            local_processing_ns += (
                time.perf_counter_ns() - local_segment_started_ns
            )
            self.last_write_result = outcome
            result = TransactionResult(
                txid=txid,
                verb=cmd,
                outcome=outcome,
                reason=reason,
                state=state,
                origin=origin,
                ack_latency_ms=ack_latency_ms,
                gateway_processing_ms=local_processing_ns / 1_000_000,
                local_lock_time_utc=local_lock_time_utc,
                dispatch_time_utc=dispatch_time_utc,
                response_time_utc=response_time_utc,
            )
            if stop_flight is not None:
                with self.stop_coordination_lock:
                    if self.stop_inflight is stop_flight:
                        self.stop_inflight = None
                stop_flight = None
            return result

        command_lock_wait_started_ns = time.perf_counter_ns()
        with self.command_lock:
            local_processing_ns -= (
                time.perf_counter_ns() - command_lock_wait_started_ns
            )
            if expected_state_generation is not None and cmd != "STOP":
                with self.state_lock:
                    state_is_stale = (
                        self.state_generation != expected_state_generation
                        or self.stop_reader.is_set()
                    )
                if state_is_stale:
                    return finish(
                        "STALE_SKIPPED",
                        reason="AUTHORITATIVE_STATE_CHANGED",
                    )
            if self.stop_reader.is_set():
                return finish(
                    "SERIAL_UNAVAILABLE",
                    reason="Gateway serial transaction shut down",
                    state="LOCKED",
                )

            # Recheck under the single-transaction lock so a queued START cannot
            # pass a concurrent STOP or an unacknowledged RESET.
            if cmd == "START" and self._get_locked():
                print("[WARN] START rejected: Gateway is LOCKED until RESET")
                self._set_telemetry_state(
                    "LOCKED", vehicle_id="gateway_stop", source="gateway_policy"
                )
                self._log_telemetry_snapshot(force=True)
                return finish("REJECTED_LOCKED", state="LOCKED")

            if cmd == "RESET":
                self._set_control_state(
                    locked=True,
                    local_lock_reason="RESET_PENDING",
                    force_generation=True,
                )

            with self.state_lock:
                transaction_state_generation = self.state_generation

            transaction = PendingTransaction(txid=txid, verb=cmd)
            with self.pending_lock:
                self.pending_transaction = transaction

            try:
                dispatch_time_utc = utc_now()
                self._send_transaction(transaction)
                transaction.dispatched_ns = time.perf_counter_ns()
                if self.mock_mode:
                    self._schedule_mock_response(transaction)
            except SerialUnavailableError as exc:
                dispatch_time_utc = None
                print(f"[ERR] Serial unavailable: {exc}")
                with self.pending_lock:
                    if self.pending_transaction is transaction:
                        self.pending_transaction = None
                return finish(
                    "SERIAL_UNAVAILABLE",
                    reason=str(exc),
                    state="LOCKED" if self._get_locked() else None,
                )
            except Exception as exc:
                dispatch_time_utc = None
                print(f"[ERR] Serial write failed: {exc}")
                with self.pending_lock:
                    if self.pending_transaction is transaction:
                        self.pending_transaction = None
                return finish(
                    "SERIAL_WRITE_ERROR",
                    reason=str(exc),
                    state="LOCKED" if self._get_locked() else None,
                )

            wait_started_ns = time.perf_counter_ns()
            local_processing_ns += wait_started_ns - local_segment_started_ns
            completed = transaction.completed.wait(
                self.serial_ack_timeout_ms / 1000.0
            )
            local_segment_started_ns = time.perf_counter_ns()
            with self.pending_lock:
                if self.pending_transaction is transaction:
                    self.pending_transaction = None

            if transaction.transport_error is not None:
                return finish(
                    transaction.transport_error,
                    reason=transaction.transport_reason,
                    state="LOCKED" if self._get_locked() else None,
                )

            if not completed:
                return finish(
                    "ACK_TIMEOUT",
                    state="LOCKED" if self._get_locked() else None,
                )

            ack_latency_ms = max(
                0.0,
                (transaction.received_ns - transaction.dispatched_ns) / 1_000_000,
            )
            local_processing_ns += transaction.response_processing_ns
            outcome = str(transaction.response_kind)
            reason = transaction.reason

            if cmd != "STOP" and apply_acknowledged_state:
                with self.state_lock:
                    state_changed_during_transaction = (
                        self.state_generation != transaction_state_generation
                    )
                if outcome == "ACK" and state_changed_during_transaction:
                    outcome = "NACK"
                    reason = "AUTHORITATIVE_STATE_CHANGED"

            if (
                outcome == "ACK"
                and apply_acknowledged_state
                and transaction.origin != "VEHICLE"
            ):
                outcome = "NACK"
                reason = "UNEXPECTED_ACK_ORIGIN"

            required_ack_state = {
                "START": "RUNNING",
                "STOP": "LOCKED",
                "RESET": "IDLE",
            }.get(cmd)
            if (
                outcome == "ACK"
                and required_ack_state is not None
                and transaction.state != required_ack_state
            ):
                outcome = "NACK"
                reason = "UNEXPECTED_ACK_STATE"

            if outcome == "ACK":
                result_code = "ACKNOWLEDGED"
                if apply_acknowledged_state and transaction.state:
                    acknowledged_locked = None
                    with self.state_lock:
                        local_lock_reason = self.local_lock_reason
                    if cmd == "RESET":
                        acknowledged_locked = False
                        local_lock_reason = None
                    elif cmd == "STOP":
                        acknowledged_locked = True
                    self._set_control_state(
                        locked=acknowledged_locked,
                        acknowledged_state=transaction.state,
                        local_lock_reason=local_lock_reason,
                    )
                if transaction.state:
                    vehicle_id = "gateway_reset" if cmd == "RESET" else None
                    source = "mock_generator" if self.mock_mode else self.port
                    self._set_telemetry_state(
                        transaction.state,
                        vehicle_id=vehicle_id,
                        source=source,
                    )
            else:
                result_code = "NACK"

            if cmd in ("STOP", "RESET"):
                self._log_telemetry_snapshot(force=True)

            return finish(
                result_code,
                reason=reason,
                state=transaction.state,
                origin=transaction.origin,
                ack_latency_ms=ack_latency_ms,
                response_time_utc=transaction.received_time_utc,
            )

    def _handle_telemetry_line(self, line: str, now_ts: float) -> None:
        parts = line.split(",")
        if len(parts) != 6:
            print(f"[HW RX MALFORMED TEL] {line}")
            return
        try:
            _, vehicle_id, adc_l, adc_r, steer, state = parts
            if not vehicle_id.strip() or not state.strip():
                raise ValueError("telemetry identity and state are required")
            parsed = {
                "timestamp": now_ts,
                "vehicle_id": vehicle_id,
                "adc_l": int(adc_l),
                "adc_r": int(adc_r),
                "steer": float(steer),
                "state": state,
                "source": "mock_generator" if self.mock_mode else self.port,
            }
        except (TypeError, ValueError):
            print(f"[HW RX MALFORMED TEL] {line}")
            return
        with telemetry_lock:
            self.latest_telemetry.update(parsed)
        self._log_telemetry_snapshot(force=True)

    def _handle_transaction_response(self, line: str) -> None:
        response_processing_started_ns = time.perf_counter_ns()
        parts = line.split(",")
        kind = parts[0]
        expected_fields = 5 if kind == "ACK" else 6
        if len(parts) != expected_fields:
            print(f"[HW RX MALFORMED {kind}] {line}")
            return

        if kind == "ACK":
            _, txid, verb, state, origin = parts
            reason = None
        else:
            _, txid, verb, reason, state, origin = parts

        required_values = [txid, verb, state, origin]
        if kind == "NACK":
            required_values.append(reason)
        if any(not value.strip() for value in required_values):
            print(f"[HW RX MALFORMED {kind}] {line}")
            return

        with self.pending_lock:
            pending = self.pending_transaction
            if (
                pending is None
                or pending.completed.is_set()
                or pending.txid != txid
                or pending.verb != verb
            ):
                print(f"[HW RX UNMATCHED {kind}] {line}")
                return
            pending.response_kind = kind
            pending.reason = reason
            pending.state = state
            pending.origin = origin
            pending.received_ns = time.perf_counter_ns()
            pending.received_time_utc = utc_now()
            pending.response_processing_ns = (
                pending.received_ns - response_processing_started_ns
            )
            pending.completed.set()

    def _process_incoming_line(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        if line.startswith("TEL,"):
            self._handle_telemetry_line(line, time.time())
        elif line.startswith("ACK,") or line.startswith("NACK,"):
            self._handle_transaction_response(line)
        else:
            print(f"[HW RX NON-PROTOCOL] {line}")

    def read_loop(self) -> None:
        last_mock_telemetry = time.monotonic()
        while not self.stop_reader.is_set():
            if self.mock_mode:
                try:
                    line = self.mock_rx_queue.get(timeout=0.05)
                    self._process_incoming_line(line)
                except queue.Empty:
                    pass

                current = self.get_latest_telemetry()
                if (
                    current["state"] == "RUNNING"
                    and time.monotonic() - last_mock_telemetry >= 1.0
                ):
                    last_mock_telemetry = time.monotonic()
                    self._process_incoming_line(
                        "TEL,esp32_mock_1,"
                        f"{random.randint(2000, 4000)},"
                        f"{random.randint(2000, 4000)},"
                        f"{round(random.uniform(-0.5, 0.5), 3)},RUNNING"
                    )
                continue

            if self.conn and getattr(self.conn, "is_open", False):
                try:
                    line = self.conn.readline().decode("utf-8", errors="ignore").strip()
                    if line:
                        self._process_incoming_line(line)
                except Exception as exc:
                    print(f"[ERR] Serial read failed: {exc}")
                    self._fail_pending_transport(
                        "SERIAL_UNAVAILABLE", f"serial read failed: {exc}"
                    )
                    self.stop_reader.wait(1)
            else:
                self._fail_pending_transport(
                    "SERIAL_UNAVAILABLE", "serial connection is closed"
                )
                self.stop_reader.wait(1)


# -----------------------------------------------------------------------------
# Authenticated, idempotent mitigation STOP service
# -----------------------------------------------------------------------------
MITIGATION_REQUIRED_FIELDS = {
    "incident_id",
    "detection_id",
    "idempotency_key",
    "rule_id",
    "severity",
    "score",
    "detection_timestamp_utc",
}
MITIGATION_OPTIONAL_FIELDS = {"evidence_class", "detector_run_id"}
MITIGATION_STRING_LIMITS = {
    "incident_id": 128,
    "detection_id": 128,
    "idempotency_key": 128,
    "rule_id": 128,
    "severity": 16,
    "detection_timestamp_utc": 64,
    "evidence_class": 128,
    "detector_run_id": 128,
}


def validate_mitigation_payload(payload: object) -> tuple[dict | None, str | None]:
    if not isinstance(payload, dict):
        return None, "JSON body must be an object"

    fields = set(payload)
    missing = sorted(MITIGATION_REQUIRED_FIELDS - fields)
    if missing:
        return None, f"missing required fields: {', '.join(missing)}"
    unexpected = sorted(fields - MITIGATION_REQUIRED_FIELDS - MITIGATION_OPTIONAL_FIELDS)
    if unexpected:
        return None, f"unexpected fields: {', '.join(unexpected)}"

    normalized = dict(payload)
    for field_name, limit in MITIGATION_STRING_LIMITS.items():
        if field_name not in normalized:
            continue
        value = normalized[field_name]
        if not isinstance(value, str):
            return None, f"{field_name} must be a string"
        if not value or not value.strip():
            return None, f"{field_name} cannot be empty"
        if value != value.strip():
            return None, f"{field_name} cannot have leading or trailing whitespace"
        if len(value) > limit:
            return None, f"{field_name} exceeds maximum length {limit}"
        if _contains_control_characters(value):
            return None, f"{field_name} cannot contain control characters"

    if normalized["severity"] not in {"HIGH", "MEDIUM", "LOW", "INFO"}:
        return None, "severity must be one of HIGH, MEDIUM, LOW, INFO"

    score = normalized["score"]
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return None, "score must be numeric"
    if not math.isfinite(float(score)):
        return None, "score must be finite"

    timestamp_text = normalized["detection_timestamp_utc"]
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
    except ValueError:
        return None, "detection_timestamp_utc must be a valid ISO 8601 timestamp"
    if (
        parsed_timestamp.tzinfo is None
        or parsed_timestamp.utcoffset() != timezone.utc.utcoffset(None)
    ):
        return None, "detection_timestamp_utc must be timezone-aware UTC"

    return normalized, None


class MitigationManager:
    """Bounded in-memory idempotency and evidence manager for mitigation STOP."""

    def __init__(
        self,
        serial_bridge: SerialBridge,
        *,
        enabled: bool,
        loopback_only: bool,
        cache_size: int,
        token: str | None,
    ) -> None:
        self.bridge = serial_bridge
        self.enabled = enabled
        self.loopback_only = loopback_only
        self.cache_size = cache_size
        self._token = token if self._valid_token(token) else None
        self.ready = bool(enabled and self._token is not None)
        self.lock = threading.RLock()
        self.records: OrderedDict[str, dict] = OrderedDict()
        self.last_mitigation_status: str | None = None
        self.last_mitigation_timestamp: str | None = None
        self.last_mitigation_incident_id: str | None = None

    @staticmethod
    def _valid_token(token: str | None) -> bool:
        return bool(
            isinstance(token, str)
            and MITIGATION_TOKEN_MIN_LENGTH <= len(token) <= 4096
            and token == token.strip()
            and not any(character.isspace() for character in token)
            and not _contains_control_characters(token)
        )

    def authenticated(self, authorization: str | None) -> bool:
        if self._token is None or not isinstance(authorization, str):
            return False
        scheme, separator, supplied = authorization.partition(" ")
        if separator != " " or scheme != "Bearer" or not supplied:
            return False
        return hmac.compare_digest(supplied, self._token)

    @staticmethod
    def is_loopback(remote_address: str | None) -> bool:
        if not remote_address:
            return False
        try:
            address = ipaddress.ip_address(remote_address)
        except ValueError:
            return False
        if address.is_loopback:
            return True
        mapped = getattr(address, "ipv4_mapped", None)
        return bool(mapped is not None and mapped.is_loopback)

    def health_fields(self) -> dict:
        with self.lock:
            active = sum(
                1
                for record in self.records.values()
                if record["dispatch_started"] and record["response"] is None
            )
            return {
                "mitigation_api_enabled": self.enabled,
                "mitigation_api_ready": self.ready,
                "mitigation_loopback_only": self.loopback_only,
                "mitigation_active_requests": active,
                "mitigation_cached_results": sum(
                    1 for record in self.records.values() if record["response"] is not None
                ),
                "last_mitigation_status": self.last_mitigation_status,
                "last_mitigation_timestamp": self.last_mitigation_timestamp,
                "last_mitigation_incident_id": self.last_mitigation_incident_id,
            }

    def _ledger(
        self,
        phase: str,
        metadata: dict,
        response: dict | None = None,
    ) -> None:
        values = response or {}
        status = self.bridge.get_status()
        append_csv(
            MITIGATION_CSV,
            [
                utc_now(),
                phase,
                metadata.get("incident_id"),
                metadata.get("detection_id"),
                metadata.get("idempotency_key"),
                metadata.get("detection_timestamp_utc"),
                values.get("gateway_request_received_time_utc"),
                values.get("gateway_local_lock_time_utc"),
                values.get("stop_dispatch_time_utc"),
                values.get("stop_ack_time_utc"),
                values.get("gateway_response_time_utc"),
                status["mode"],
                status["serial_transport"],
                values.get("result"),
                values.get("reason"),
                values.get("transaction_id"),
                values.get("ack_state"),
                values.get("ack_origin"),
                values.get("mitigation_status"),
                str(bool(values.get("synthetic"))).lower(),
                str(bool(values.get("duplicate_suppressed"))).lower(),
                str(bool(values.get("coalesced"))).lower(),
            ],
        )

    def _register(self, metadata: dict, received_time_utc: str) -> tuple[str, dict | None]:
        key = metadata["idempotency_key"]
        with self.lock:
            existing = self.records.get(key)
            if existing is not None:
                self.records.move_to_end(key)
                return "DUPLICATE", existing

            while len(self.records) >= self.cache_size:
                evict_key = next(
                    (
                        candidate_key
                        for candidate_key, record in self.records.items()
                        if record["response"] is not None
                    ),
                    None,
                )
                if evict_key is None:
                    return "CAPACITY", None
                del self.records[evict_key]

            record = {
                "request_metadata": dict(metadata),
                "dispatch_started": False,
                "response": None,
                "gateway_request_received_time_utc": received_time_utc,
            }
            self.records[key] = record
            return "NEW", record

    @staticmethod
    def _classification(transaction: TransactionResult, mode: str) -> str:
        if transaction.coalesced or transaction.outcome == "STOP_COALESCED":
            return "COALESCED_WITH_EXISTING_STOP"
        matching_ack = (
            transaction.outcome == "ACKNOWLEDGED"
            and transaction.verb == "STOP"
            and transaction.state == "LOCKED"
            and transaction.origin == "VEHICLE"
            and bool(transaction.txid)
        )
        if matching_ack and mode == "hardware":
            return "ACKNOWLEDGED_DOWNSTREAM"
        if matching_ack and mode == "mock":
            return "SYNTHETIC_ACKNOWLEDGED"
        return "EXECUTION_UNKNOWN"

    def duplicate_response(self, record: dict) -> tuple[dict, int]:
        with self.lock:
            stored = record["response"]
            if stored is None:
                metadata = record["request_metadata"]
                response = {
                    "incident_id": metadata["incident_id"],
                    "detection_id": metadata["detection_id"],
                    "idempotency_key": metadata["idempotency_key"],
                    "duplicate_suppressed": True,
                    "coalesced": True,
                    "mitigation_status": "IN_PROGRESS",
                    "mode": self.bridge.current_mode_label(),
                    "serial_transport": self.bridge.get_status()["serial_transport"],
                    "transaction_id": None,
                    "result": "IN_PROGRESS",
                    "reason": "FIRST_REQUEST_IN_PROGRESS",
                    "ack_state": None,
                    "ack_origin": None,
                    "gateway_request_received_time_utc": record[
                        "gateway_request_received_time_utc"
                    ],
                    "gateway_local_lock_time_utc": None,
                    "stop_dispatch_time_utc": None,
                    "stop_ack_time_utc": None,
                    "gateway_response_time_utc": utc_now(),
                    "gateway_processing_ms": None,
                    "ack_latency_ms": None,
                    "command_total_ms": None,
                    "gateway_locked": self.bridge.get_status()["gateway_locked"],
                    "vehicle_stop_confirmed": False,
                    "synthetic": False,
                }
                self.last_mitigation_status = "IN_PROGRESS"
                self.last_mitigation_timestamp = response[
                    "gateway_response_time_utc"
                ]
                self.last_mitigation_incident_id = metadata["incident_id"]
                self._ledger("DUPLICATE_SUPPRESSED", metadata, response)
                return response, 202

            response = dict(stored)
            response["original_mitigation_status"] = stored["mitigation_status"]
            response["mitigation_status"] = "DUPLICATE_SUPPRESSED"
            response["duplicate_suppressed"] = True
            response["vehicle_stop_confirmed"] = False
            response["gateway_response_time_utc"] = utc_now()
            self.last_mitigation_status = "DUPLICATE_SUPPRESSED"
            self.last_mitigation_timestamp = response[
                "gateway_response_time_utc"
            ]
            self.last_mitigation_incident_id = record["request_metadata"][
                "incident_id"
            ]
            self._ledger("DUPLICATE_SUPPRESSED", record["request_metadata"], response)
            return response, 200

    def execute(self, metadata: dict, received_time_utc: str, record: dict) -> tuple[dict, int]:
        request_started_ns = time.perf_counter_ns()
        with self.lock:
            record["dispatch_started"] = True
        self._ledger(
            "REQUEST_RECEIVED",
            metadata,
            {"gateway_request_received_time_utc": received_time_utc},
        )

        transaction_started_ns = time.perf_counter_ns()
        try:
            transaction = self.bridge.write("STOP", source="MITIGATION_API")
        except Exception:
            fallback_lock_time_utc = utc_now()
            with self.bridge.stop_coordination_lock:
                stop_flight = self.bridge.stop_inflight
                if (
                    stop_flight is not None
                    and stop_flight.source == "MITIGATION_API"
                ):
                    self.bridge.stop_inflight = None
            self.bridge._set_control_state(
                locked=True,
                local_lock_reason="MITIGATION_INTERNAL_FAILURE",
                force_generation=True,
            )
            self.bridge._set_telemetry_state(
                "LOCKED",
                vehicle_id="gateway_stop",
                source="gateway_mitigation_failure",
            )
            transaction = TransactionResult(
                txid="",
                verb="STOP",
                outcome="INTERNAL_FAILURE",
                reason="MITIGATION_DISPATCH_INTERNAL_FAILURE",
                local_lock_time_utc=fallback_lock_time_utc,
            )
            internal_failure = True
        else:
            internal_failure = False
        transaction_completed_ns = time.perf_counter_ns()

        mode = self.bridge.current_mode_label()
        mitigation_status = self._classification(transaction, mode)
        matching_ack = mitigation_status in {
            "ACKNOWLEDGED_DOWNSTREAM",
            "SYNTHETIC_ACKNOWLEDGED",
        }
        bridge_status = self.bridge.get_status()
        response_time_utc = utc_now()
        gateway_processing_ms = (
            (transaction_started_ns - request_started_ns)
            + int(transaction.gateway_processing_ms * 1_000_000)
        ) / 1_000_000
        response = {
            "incident_id": metadata["incident_id"],
            "detection_id": metadata["detection_id"],
            "idempotency_key": metadata["idempotency_key"],
            "duplicate_suppressed": False,
            "coalesced": transaction.coalesced,
            "mitigation_status": mitigation_status,
            "mode": mode,
            "serial_transport": bridge_status["serial_transport"],
            "transaction_id": transaction.txid or None,
            "result": transaction.outcome,
            "reason": transaction.reason,
            "ack_state": transaction.state,
            "ack_origin": transaction.origin,
            "gateway_request_received_time_utc": received_time_utc,
            "gateway_local_lock_time_utc": transaction.local_lock_time_utc,
            "stop_dispatch_time_utc": transaction.dispatch_time_utc,
            "stop_ack_time_utc": transaction.response_time_utc if matching_ack else None,
            "gateway_response_time_utc": response_time_utc,
            "gateway_processing_ms": round(gateway_processing_ms, 6),
            "ack_latency_ms": (
                round(transaction.ack_latency_ms, 6)
                if transaction.ack_latency_ms is not None
                else None
            ),
            "command_total_ms": round(
                (transaction_completed_ns - request_started_ns) / 1_000_000, 6
            ),
            "gateway_locked": bridge_status["gateway_locked"],
            "vehicle_stop_confirmed": mitigation_status == "ACKNOWLEDGED_DOWNSTREAM",
            "synthetic": mitigation_status == "SYNTHETIC_ACKNOWLEDGED",
        }

        if response["gateway_local_lock_time_utc"] is not None:
            self._ledger("LOCALLY_LOCKED", metadata, response)
        if response["stop_dispatch_time_utc"] is not None:
            self._ledger("STOP_DISPATCHED", metadata, response)
        if transaction.response_time_utc is not None:
            self._ledger("RESPONSE_RECEIVED", metadata, response)
        if transaction.coalesced:
            self._ledger("COALESCED", metadata, response)
        self._ledger("FINALIZED", metadata, response)

        with self.lock:
            record["response"] = dict(response)
            self.last_mitigation_status = mitigation_status
            self.last_mitigation_timestamp = response_time_utc
            self.last_mitigation_incident_id = metadata["incident_id"]

        if internal_failure:
            return response, 500
        if transaction.coalesced:
            return response, 202
        return response, 200


# -----------------------------------------------------------------------------
# Flask application
# -----------------------------------------------------------------------------
app = Flask(__name__)
DEFAULT_CENTERLINE_POINTS = [
    {"x": 0.08, "y": 0.52},
    {"x": 0.18, "y": 0.38},
    {"x": 0.34, "y": 0.32},
    {"x": 0.50, "y": 0.50},
    {"x": 0.64, "y": 0.68},
    {"x": 0.80, "y": 0.62},
    {"x": 0.92, "y": 0.46},
]
track_lock = threading.Lock()
current_centerline_points = [dict(point) for point in DEFAULT_CENTERLINE_POINTS]
bridge = SerialBridge(
    config.get("mock_serial", True),
    config.get("serial_port", "/dev/ttyUSB0"),
    config.get("serial_baud", 115200),
    config.get("safe_boot_locked", True),
    SERIAL_ACK_TIMEOUT_MS,
    MOCK_ACK_DELAY_MS,
    KEEPALIVE_ENABLED,
    KEEPALIVE_INTERVAL_MS,
)
atexit.register(bridge.close)
mitigation_manager = MitigationManager(
    bridge,
    enabled=MITIGATION_API_ENABLED,
    loopback_only=MITIGATION_LOOPBACK_ONLY,
    cache_size=MITIGATION_IDEMPOTENCY_CACHE_SIZE,
    token=os.environ.get(MITIGATION_TOKEN_ENV),
)


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/display")
def display():
    return render_template("display.html")


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({**bridge.get_status(), **mitigation_manager.health_fields()})


@app.route("/api/display/status", methods=["GET"])
def display_status():
    status = bridge.get_status()
    snapshot = bridge.get_latest_telemetry()
    return jsonify(
        {
            "gateway_locked": status["gateway_locked"],
            "acknowledged_state": status["acknowledged_state"],
            "vehicle_state": snapshot["state"],
            "steer": snapshot["steer"],
        }
    )


@app.route("/api/telemetry", methods=["GET"])
def telemetry():
    snapshot = bridge.get_latest_telemetry()
    return jsonify(snapshot)


@app.route("/api/metrics", methods=["GET"])
def metrics():
    return jsonify(summarize_performance())


def _operator_authorization_rejection(reason: str, http_status: int):
    try:
        log_action(
            "web_api",
            "OPERATOR_AUTHORIZATION",
            reason,
            "REJECTED",
            mode=bridge.current_mode_label(),
        )
    except Exception:
        print("[WARN] Operator authorization outcome logging failed")
    return jsonify({"error": "Operator authorization required."}), http_status


def require_operator_authorization(view_function):
    """Protect ordinary state-changing APIs with the operator credential."""

    @wraps(view_function)
    def protected_view(*args, **kwargs):
        supplied = request.headers.get(OPERATOR_TOKEN_HEADER)
        if supplied is None:
            return _operator_authorization_rejection(
                "operator_authorization_missing", 401
            )
        if not hmac.compare_digest(supplied.encode("utf-8"), OPERATOR_TOKEN_BYTES):
            return _operator_authorization_rejection(
                "operator_authorization_invalid", 403
            )
        return view_function(*args, **kwargs)

    return protected_view


def _mitigation_rejection(status: str, reason: str, http_status: int):
    return jsonify(
        {
            "mitigation_status": status,
            "reason": reason,
            "vehicle_stop_confirmed": False,
        }
    ), http_status


@app.route("/api/mitigation/stop", methods=["POST"])
def mitigation_stop():
    received_time_utc = utc_now()
    manager = mitigation_manager

    if not manager.enabled:
        return _mitigation_rejection(
            "ENDPOINT_DISABLED", "MITIGATION_API_DISABLED", 404
        )
    if not manager.ready:
        return _mitigation_rejection(
            "ENDPOINT_DISABLED", "MITIGATION_API_NOT_READY", 503
        )
    if manager.loopback_only and not manager.is_loopback(request.remote_addr):
        return _mitigation_rejection(
            "REQUEST_REJECTED", "LOOPBACK_CLIENT_REQUIRED", 403
        )
    if not manager.authenticated(request.headers.get("Authorization")):
        response, status_code = _mitigation_rejection(
            "AUTHENTICATION_FAILED", "BEARER_AUTHENTICATION_REQUIRED", 401
        )
        response.headers["WWW-Authenticate"] = "Bearer"
        return response, status_code

    payload = request.get_json(silent=True)
    if payload is None:
        return _mitigation_rejection(
            "REQUEST_REJECTED", "MALFORMED_JSON", 400
        )
    metadata, validation_error = validate_mitigation_payload(payload)
    if validation_error is not None or metadata is None:
        return _mitigation_rejection(
            "REQUEST_REJECTED", validation_error or "SCHEMA_ERROR", 422
        )

    registration, record = manager._register(metadata, received_time_utc)
    if registration == "DUPLICATE" and record is not None:
        response, status_code = manager.duplicate_response(record)
        return jsonify(response), status_code
    if registration == "CAPACITY" or record is None:
        return _mitigation_rejection(
            "REQUEST_REJECTED", "IDEMPOTENCY_CAPACITY_EXHAUSTED", 503
        )

    response, status_code = manager.execute(metadata, received_time_utc, record)
    return jsonify(response), status_code


def _validate_centerline_points(points) -> tuple[bool, str]:
    if not isinstance(points, list) or len(points) == 0:
        return False, "centerline_points must be a non-empty list"
    if len(points) > MAX_CENTERLINE_POINTS:
        return False, f"centerline_points exceeds max allowed points ({MAX_CENTERLINE_POINTS})"
    for i, pt in enumerate(points):
        if not isinstance(pt, dict):
            return False, f"point at index {i} is not an object"
        if "x" not in pt or "y" not in pt:
            return False, f"point at index {i} missing x or y field"
        if not isinstance(pt["x"], (int, float)) or not isinstance(pt["y"], (int, float)):
            return False, f"point at index {i} has non-numeric x or y"
    return True, ""

@app.route("/api/track", methods=["GET"])
def get_track():
    with track_lock:
        points = [dict(point) for point in current_centerline_points]
    return jsonify({"centerline_points": points})


@app.route("/api/track", methods=["POST"])
@require_operator_authorization
def save_track():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or "centerline_points" not in data:
        event_id = log_action(
            "web_ui",
            "CENTERLINE_UPDATE",
            "Invalid payload: expected centerline_points array",
            "REJECTED",
            mode=bridge.current_mode_label(),
        )
        return jsonify(
            {
                "error": "Invalid JSON: expected object with centerline_points array.",
                "event_id": event_id,
            }
        ), 400

    points = data["centerline_points"]
    ok, reason = _validate_centerline_points(points)
    if not ok:
        event_id = log_action(
            "web_ui",
            "CENTERLINE_UPDATE",
            f"Rejected centerline payload: {reason}",
            "REJECTED",
            mode=bridge.current_mode_label(),
        )
        status = 413 if "exceeds max" in reason else 400
        return jsonify({"error": reason, "event_id": event_id}), status

    event_id = log_action(
        "web_ui",
        "CENTERLINE_UPDATE",
        f"Received {len(points)} centerline points",
        "SUCCESS",
        mode=bridge.current_mode_label(),
    )
    with track_lock:
        current_centerline_points[:] = [dict(point) for point in points]
    return jsonify({"event_id": event_id, "status": "logged", "centerline_points": len(points)})


@app.route("/api/command", methods=["POST"])
@require_operator_authorization
def handle_command():
    handler_started_ns = time.perf_counter_ns()
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or "command" not in data:
        event_id = log_action(
            "web_ui",
            "INVALID_COMMAND_PAYLOAD",
            "Missing command field",
            "REJECTED",
            mode=bridge.current_mode_label(),
        )
        return jsonify(
            {"error": "Invalid JSON: expected object with command field.", "event_id": event_id}
        ), 400

    cmd = str(data["command"]).upper().strip()
    if cmd not in ["START", "STOP", "RESET", "STATUS", "PING"]:
        event_id = log_action("web_ui", cmd, "Invalid command payload", "REJECTED", mode=bridge.current_mode_label())
        return jsonify({"error": "Invalid command", "event_id": event_id}), 400

    mode = bridge.current_mode_label()
    state_before = str(bridge.get_latest_telemetry().get("state", "UNKNOWN"))

    bridge_started_ns = time.perf_counter_ns()
    transaction = bridge.write(cmd)
    bridge_completed_ns = time.perf_counter_ns()
    state_after = str(bridge.get_latest_telemetry().get("state", "UNKNOWN"))
    timing_completed_ns = time.perf_counter_ns()

    gateway_processing_ms = (
        (bridge_started_ns - handler_started_ns)
        + int(transaction.gateway_processing_ms * 1_000_000)
        + (timing_completed_ns - bridge_completed_ns)
    ) / 1_000_000
    event_id = log_action(
        "web_ui",
        cmd,
        (
            f"txid={transaction.txid}; "
            f"gateway_processing_ms={gateway_processing_ms:.6f}; "
            f"ack_latency_ms={transaction.ack_latency_ms}; "
            f"reason={transaction.reason}"
        ),
        transaction.outcome,
        mode=mode,
    )

    log_performance(
        event_id=event_id,
        command=cmd,
        mode=mode,
        result=transaction.outcome,
        gateway_processing_ms=gateway_processing_ms,
        state_before=state_before,
        state_after=state_after,
    )

    command_total_ms = (
        time.perf_counter_ns() - handler_started_ns
    ) / 1_000_000

    return jsonify(
        {
            "event_id": event_id,
            "command": cmd,
            "transaction_id": transaction.txid,
            "result": transaction.outcome,
            "reason": transaction.reason,
            "ack_state": transaction.state,
            "ack_origin": transaction.origin,
            "ack_latency_ms": (
                round(transaction.ack_latency_ms, 6)
                if transaction.ack_latency_ms is not None
                else None
            ),
            "mode": bridge.get_status()["mode"],
            "gateway_processing_ms": round(gateway_processing_ms, 6),
            "command_total_ms": round(command_total_ms, 6),
            "telemetry": bridge.get_latest_telemetry(),
        }
    )


if __name__ == "__main__":
    def _shutdown_signal_handler(_signum, _frame) -> None:
        bridge.close()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _shutdown_signal_handler)
    signal.signal(signal.SIGINT, _shutdown_signal_handler)
    log_action("system", "BOOT", "Gateway MVP Started", "SUCCESS", mode=bridge.current_mode_label())
    try:
        app.run(
            host=config.get("host", "0.0.0.0"),
            port=int(config.get("port", 8080)),
            debug=False,
            threaded=True,
        )
    finally:
        bridge.close()
