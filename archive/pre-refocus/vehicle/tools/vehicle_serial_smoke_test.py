#!/usr/bin/env python3
"""Assertion-based Sentinel-CPS Phase 3B direct-vehicle USB smoke test."""

from __future__ import annotations

import argparse
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, TextIO

try:
    import serial  # type: ignore[import-not-found]
except ImportError:  # Host-side unit tests do not require pyserial.
    serial = None


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = PROJECT_ROOT / "logs"
EXPECTED_ORIGIN = "VEHICLE"


class SmokeTestFailure(AssertionError):
    """Base failure for a direct-vehicle protocol assertion."""


class TransactionTimeout(SmokeTestFailure):
    """Raised when no matching transaction response arrives in time."""


class ResponseValidationError(SmokeTestFailure):
    """Raised when a response violates the transaction contract."""


@dataclass(frozen=True)
class TransactionResponse:
    kind: str
    txid: str
    verb: str
    reason: str | None
    state: str
    origin: str


@dataclass(frozen=True)
class ExpectedResponse:
    kind: str
    verb: str
    state: str
    reason: str | None = None


TEST_SEQUENCE = (
    ExpectedResponse("ACK", "STATUS", "LOCKED"),
    ExpectedResponse("NACK", "START", "LOCKED", "LOCKED_REQUIRE_RESET"),
    ExpectedResponse("ACK", "RESET", "IDLE"),
    ExpectedResponse("ACK", "STATUS", "IDLE"),
    ExpectedResponse("ACK", "START", "RUNNING"),
    ExpectedResponse("ACK", "STATUS", "RUNNING"),
    ExpectedResponse("ACK", "PING", "RUNNING"),
    ExpectedResponse("ACK", "STOP", "LOCKED"),
    ExpectedResponse("ACK", "STATUS", "LOCKED"),
    ExpectedResponse("NACK", "START", "LOCKED", "LOCKED_REQUIRE_RESET"),
)


def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f")


def generate_unique_txid(seen: set[str]) -> str:
    """Return a unique opaque transaction ID for this smoke-test run."""
    while True:
        txid = uuid.uuid4().hex
        if txid not in seen:
            seen.add(txid)
            return txid


def write_log(log_handle: TextIO, message: str) -> None:
    print(message)
    log_handle.write(message + "\n")
    log_handle.flush()


def decode_serial_line(raw: bytes | str) -> str:
    if isinstance(raw, bytes):
        line = raw.decode("utf-8", errors="replace")
    else:
        line = raw
    return line.rstrip("\r\n")


def parse_transaction_response(line: str) -> TransactionResponse | None:
    """Parse ACK/NACK lines and ignore asynchronous telemetry/diagnostics."""
    if line.startswith("ACK_") or line.startswith("ERR_"):
        raise ResponseValidationError(f"legacy response received: {line}")

    if line == "ACK" or line.startswith("ACK,"):
        parts = line.split(",")
        if len(parts) != 5 or any(field == "" for field in parts[1:]):
            raise ResponseValidationError(f"malformed ACK response: {line}")
        _, txid, verb, state, origin = parts
        return TransactionResponse("ACK", txid, verb, None, state, origin)

    if line == "NACK" or line.startswith("NACK,"):
        parts = line.split(",")
        if len(parts) != 6 or any(field == "" for field in parts[1:]):
            raise ResponseValidationError(f"malformed NACK response: {line}")
        _, txid, verb, reason, state, origin = parts
        return TransactionResponse("NACK", txid, verb, reason, state, origin)

    return None


def validate_response(
    response: TransactionResponse,
    expected_txid: str,
    expected: ExpectedResponse,
) -> None:
    wanted = TransactionResponse(
        kind=expected.kind,
        txid=expected_txid,
        verb=expected.verb,
        reason=expected.reason,
        state=expected.state,
        origin=EXPECTED_ORIGIN,
    )
    if response != wanted:
        raise ResponseValidationError(
            f"mismatched response: expected {wanted}, received {response}"
        )


def await_transaction_response(
    ser: Any,
    log_handle: TextIO,
    txid: str,
    expected: ExpectedResponse,
    timeout: float,
    *,
    clock: Callable[[], float] = time.monotonic,
    idle_wait: Callable[[float], None] = time.sleep,
) -> TransactionResponse:
    """Log interleaved lines and require the exact response for one transaction."""
    deadline = clock() + timeout
    while clock() < deadline:
        raw = ser.readline()
        if not raw:
            idle_wait(0.01)
            continue

        line = decode_serial_line(raw)
        display = line if line else "<EMPTY>"
        write_log(log_handle, f"[RX] <- {display}")
        response = parse_transaction_response(line)
        if response is None:
            category = "telemetry" if line.startswith("TEL,") else "diagnostic"
            write_log(log_handle, f"[ASYNC] {category}; transaction still pending")
            continue

        validate_response(response, txid, expected)
        return response

    raise TransactionTimeout(
        "timeout waiting for "
        f"{expected.kind} matching txid={txid} verb={expected.verb}"
    )


def drain_startup(ser: Any, log_handle: TextIO, duration: float) -> None:
    """Log startup/asynchronous output and reject stale transaction responses."""
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        raw = ser.readline()
        if not raw:
            time.sleep(0.01)
            continue

        line = decode_serial_line(raw)
        display = line if line else "<EMPTY>"
        write_log(log_handle, f"[RX] <- {display}")
        response = parse_transaction_response(line)
        if response is not None:
            raise ResponseValidationError(
                f"unexpected transaction response before test sequence: {response}"
            )


def run_transaction(
    ser: Any,
    log_handle: TextIO,
    txid: str,
    expected: ExpectedResponse,
    timeout: float,
) -> None:
    frame = f"CMD,{txid},{expected.verb}"
    write_log(log_handle, f"[TX] -> {frame}")
    ser.write((frame + "\n").encode("utf-8"))
    ser.flush()
    await_transaction_response(ser, log_handle, txid, expected, timeout)
    write_log(
        log_handle,
        f"[ASSERT] PASS txid={txid} verb={expected.verb} "
        f"kind={expected.kind} state={expected.state}",
    )


def run_smoke_test(port: str, baud: int, response_timeout: float) -> int:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / f"vehicle_serial_phase3b_{timestamp()}.txt"

    with log_file.open("w", encoding="utf-8") as log_handle:
        write_log(log_handle, "--- Sentinel-CPS Phase 3B Direct Vehicle USB Test ---")
        write_log(log_handle, f"Port: {port}")
        write_log(log_handle, f"Baud: {baud}")
        write_log(log_handle, f"Started: {time.ctime()}")
        write_log(
            log_handle,
            "Scope: direct USB-to-vehicle parser/state behavior only; no Hub-to-"
            "vehicle or ESP-NOW transport proof.",
        )
        write_log(log_handle, f"Evidence log: {log_file}")

        if serial is None:
            write_log(
                log_handle,
                "[FAIL] pyserial is not installed; use an existing environment "
                "that already provides it.",
            )
            return 1

        try:
            ser = serial.Serial(
                port=port,
                baudrate=baud,
                timeout=min(0.2, max(0.01, response_timeout / 5)),
            )
        except Exception as exc:
            write_log(log_handle, f"[FAIL] Could not open {port}: {exc}")
            return 1

        seen_txids: set[str] = set()
        try:
            with ser:
                write_log(log_handle, "[*] Waiting for vehicle boot/reset output...")
                time.sleep(2)
                drain_startup(ser, log_handle, duration=1.0)

                for expected in TEST_SEQUENCE:
                    txid = generate_unique_txid(seen_txids)
                    run_transaction(
                        ser,
                        log_handle,
                        txid,
                        expected,
                        response_timeout,
                    )
        except (SmokeTestFailure, OSError, ValueError) as exc:
            write_log(log_handle, f"[FAIL] {exc}")
            write_log(log_handle, f"Completed: {time.ctime()}")
            return 1

        write_log(log_handle, "[PASS] All Phase 3B direct USB transactions matched.")
        write_log(
            log_handle,
            "Passing proves direct vehicle serial behavior only; it does not prove "
            "Hub-to-vehicle delivery or ESP-NOW communication.",
        )
        write_log(log_handle, f"Completed: {time.ctime()}")

    print(f"Evidence log preserved at {log_file}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Assert Sentinel-CPS Phase 3B direct-vehicle USB transactions; a "
            "pass does not prove Hub-to-vehicle transport."
        )
    )
    parser.add_argument(
        "--port",
        default="/dev/ttyUSB0",
        help="Serial port, e.g. /dev/ttyUSB0 or /dev/cu.usbserial-0001",
    )
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate")
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Seconds to wait for each exact transaction response",
    )
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    return run_smoke_test(args.port, args.baud, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
