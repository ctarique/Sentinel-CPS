#!/usr/bin/env python3
"""Phase 3B Hub serial fallback test with radio intentionally unavailable."""

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
except ImportError:  # Tests do not require pyserial.
    serial = None


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = PROJECT_ROOT / "logs"
TEST_VERBS = ("STATUS", "RESET", "START", "STOP", "PING")
EXPECTED_REASON = "NO_DOWNSTREAM_TRANSPORT"
EXPECTED_STATE = "LOCKED"
EXPECTED_ORIGIN = "HUB"


class SmokeTestFailure(AssertionError):
    """Base failure for a protocol assertion."""


class TransactionTimeout(SmokeTestFailure):
    """Raised when no matching transaction response arrives in time."""


class ResponseValidationError(SmokeTestFailure):
    """Raised when a received transaction response violates the contract."""


@dataclass(frozen=True)
class TransactionResponse:
    kind: str
    txid: str
    verb: str
    reason: str | None
    state: str
    origin: str


def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f")


def generate_unique_txid(seen: set[str]) -> str:
    """Generate a unique opaque transaction ID for this test run."""
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


def log_received_line(log_handle: TextIO, line: str) -> None:
    display = line if line else "<EMPTY>"
    write_log(log_handle, f"[RX] <- {display}")


def parse_transaction_response(line: str) -> TransactionResponse | None:
    """Parse ACK/NACK transaction lines; return None for diagnostics/TEL."""
    if line.startswith("ACK_"):
        raise ResponseValidationError(f"legacy ACK_* response received: {line}")

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


def validate_phase2_response(
    response: TransactionResponse,
    expected_txid: str,
    expected_verb: str,
) -> None:
    """Require the exact fail-safe NACK emitted when Phase 3B radio is absent."""
    expected = TransactionResponse(
        kind="NACK",
        txid=expected_txid,
        verb=expected_verb,
        reason=EXPECTED_REASON,
        state=EXPECTED_STATE,
        origin=EXPECTED_ORIGIN,
    )
    if response != expected:
        raise ResponseValidationError(
            f"mismatched response: expected {expected}, received {response}"
        )


def await_phase2_nack(
    ser: Any,
    log_handle: TextIO,
    txid: str,
    verb: str,
    timeout: float,
    *,
    clock: Callable[[], float] = time.monotonic,
    idle_wait: Callable[[float], None] = time.sleep,
) -> TransactionResponse:
    """Log every line and wait for the exact NACK for one transaction."""
    deadline = clock() + timeout
    while clock() < deadline:
        raw = ser.readline()
        if not raw:
            idle_wait(0.01)
            continue

        line = decode_serial_line(raw)
        log_received_line(log_handle, line)
        response = parse_transaction_response(line)
        if response is None:
            continue

        validate_phase2_response(response, txid, verb)
        return response

    raise TransactionTimeout(
        f"timeout waiting for NACK matching txid={txid} verb={verb}"
    )


def drain_serial(
    ser: Any,
    log_handle: TextIO,
    duration: float,
) -> None:
    """Log startup/asynchronous lines without treating them as responses."""
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        raw = ser.readline()
        if raw:
            log_received_line(log_handle, decode_serial_line(raw))
        else:
            time.sleep(0.01)


def run_transaction(
    ser: Any,
    log_handle: TextIO,
    txid: str,
    verb: str,
    timeout: float,
) -> None:
    frame = f"CMD,{txid},{verb}"
    write_log(log_handle, f"[TX] -> {frame}")
    ser.write((frame + "\n").encode("utf-8"))
    ser.flush()
    await_phase2_nack(ser, log_handle, txid, verb, timeout)
    write_log(log_handle, f"[ASSERT] PASS txid={txid} verb={verb}")


def run_smoke_test(port: str, baud: int, response_timeout: float) -> int:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / f"serial_smoke_test_{timestamp()}.txt"

    with log_file.open("w", encoding="utf-8") as log_handle:
        write_log(
            log_handle,
            "--- Sentinel-CPS Phase 3B Radio-Unavailable Serial Test ---",
        )
        write_log(log_handle, f"Port: {port}")
        write_log(log_handle, f"Baud: {baud}")
        write_log(log_handle, f"Started: {time.ctime()}")
        write_log(
            log_handle,
            "Scope: Hub fail-safe fallback only; radio must be unavailable.",
        )
        write_log(log_handle, f"Evidence log: {log_file}")

        if serial is None:
            write_log(
                log_handle,
                "[FAIL] pyserial is not installed; use an existing environment with pyserial.",
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
                write_log(log_handle, "[*] Waiting for Hub boot/reset output...")
                time.sleep(2)
                drain_serial(ser, log_handle, duration=1.0)

                for verb in TEST_VERBS:
                    txid = generate_unique_txid(seen_txids)
                    run_transaction(
                        ser,
                        log_handle,
                        txid,
                        verb,
                        response_timeout,
                    )
        except (SmokeTestFailure, OSError, ValueError) as exc:
            write_log(log_handle, f"[FAIL] {exc}")
            write_log(log_handle, f"Completed: {time.ctime()}")
            return 1

        write_log(
            log_handle,
            "[PASS] All radio-unavailable fallback transactions matched exactly.",
        )
        write_log(
            log_handle,
            "Result proves only the Hub's NO_DOWNSTREAM_TRANSPORT fallback; "
            "ESP-NOW and vehicle execution were not tested.",
        )
        write_log(log_handle, f"Completed: {time.ctime()}")

    print(f"Evidence log preserved at {log_file}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Assert the Phase 3B Hub's fail-safe serial response while local "
            "radio transport is unavailable."
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
