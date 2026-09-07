from __future__ import annotations

import io
import sys
import unittest
from collections import deque
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT))

from tools import vehicle_serial_smoke_test as smoke  # noqa: E402


class FakeSerial:
    def __init__(self, *lines: str) -> None:
        self.lines = deque((line + "\n").encode("utf-8") for line in lines)

    def readline(self) -> bytes:
        return self.lines.popleft() if self.lines else b""


class AdvancingClock:
    def __init__(self, increment: float = 0.01) -> None:
        self.value = 0.0
        self.increment = increment

    def __call__(self) -> float:
        self.value += self.increment
        return self.value


def ack(txid: str, verb: str, state: str, origin: str = "VEHICLE") -> str:
    return f"ACK,{txid},{verb},{state},{origin}"


def nack(
    txid: str,
    verb: str,
    reason: str,
    state: str,
    origin: str = "VEHICLE",
) -> str:
    return f"NACK,{txid},{verb},{reason},{state},{origin}"


class VehicleResponseTests(unittest.TestCase):
    def test_matching_ack_is_accepted(self) -> None:
        expected = smoke.ExpectedResponse("ACK", "STATUS", "LOCKED")
        response = smoke.parse_transaction_response(ack("tx-1", "STATUS", "LOCKED"))

        self.assertIsNotNone(response)
        smoke.validate_response(response, "tx-1", expected)

    def test_matching_nack_is_accepted(self) -> None:
        expected = smoke.ExpectedResponse(
            "NACK", "START", "LOCKED", "LOCKED_REQUIRE_RESET"
        )
        response = smoke.parse_transaction_response(
            nack("tx-2", "START", "LOCKED_REQUIRE_RESET", "LOCKED")
        )

        self.assertIsNotNone(response)
        smoke.validate_response(response, "tx-2", expected)

    def test_wrong_transaction_id_is_rejected(self) -> None:
        expected = smoke.ExpectedResponse("ACK", "RESET", "IDLE")
        response = smoke.parse_transaction_response(ack("wrong", "RESET", "IDLE"))

        with self.assertRaisesRegex(smoke.ResponseValidationError, "mismatched"):
            smoke.validate_response(response, "expected", expected)

    def test_wrong_verb_is_rejected(self) -> None:
        expected = smoke.ExpectedResponse("ACK", "START", "RUNNING")
        response = smoke.parse_transaction_response(ack("tx-3", "PING", "RUNNING"))

        with self.assertRaisesRegex(smoke.ResponseValidationError, "mismatched"):
            smoke.validate_response(response, "tx-3", expected)

    def test_wrong_state_is_rejected(self) -> None:
        expected = smoke.ExpectedResponse("ACK", "STATUS", "RUNNING")
        response = smoke.parse_transaction_response(ack("tx-4", "STATUS", "IDLE"))

        with self.assertRaisesRegex(smoke.ResponseValidationError, "mismatched"):
            smoke.validate_response(response, "tx-4", expected)

    def test_legacy_ack_is_rejected(self) -> None:
        with self.assertRaisesRegex(smoke.ResponseValidationError, "legacy"):
            smoke.parse_transaction_response("ACK_START")

    def test_legacy_error_is_rejected(self) -> None:
        with self.assertRaisesRegex(smoke.ResponseValidationError, "legacy"):
            smoke.parse_transaction_response("ERR_LOCKED_REQUIRE_RESET")

    def test_diagnostics_before_ack_are_logged_and_ignored(self) -> None:
        serial_port = FakeSerial(
            "BOOT,VEHICLE,LOCKED,ESP_NOW_UNAVAILABLE",
            "DIAG,VEHICLE,MOTORS_DISABLED",
            "EVENT,VEHICLE,COMMUNICATION_TIMEOUT,LOCKED",
            ack("tx-5", "STATUS", "LOCKED"),
        )
        log = io.StringIO()
        expected = smoke.ExpectedResponse("ACK", "STATUS", "LOCKED")

        response = smoke.await_transaction_response(
            serial_port, log, "tx-5", expected, timeout=0.2
        )

        self.assertEqual(response.txid, "tx-5")
        self.assertIn("[ASYNC] diagnostic", log.getvalue())

    def test_telemetry_before_ack_does_not_complete_transaction(self) -> None:
        telemetry = "TEL,vehicle_01,3100,2910,0.125,RUNNING"
        serial_port = FakeSerial(telemetry, ack("tx-6", "PING", "RUNNING"))
        log = io.StringIO()
        expected = smoke.ExpectedResponse("ACK", "PING", "RUNNING")

        response = smoke.await_transaction_response(
            serial_port, log, "tx-6", expected, timeout=0.2
        )

        self.assertEqual(response.verb, "PING")
        self.assertIn(f"[RX] <- {telemetry}", log.getvalue())
        self.assertIn("[ASYNC] telemetry", log.getvalue())

    def test_only_telemetry_then_timeout_fails(self) -> None:
        expected = smoke.ExpectedResponse("ACK", "STATUS", "LOCKED")

        with self.assertRaises(smoke.TransactionTimeout):
            smoke.await_transaction_response(
                FakeSerial("TEL,vehicle_01,1,2,0.000,LOCKED"),
                io.StringIO(),
                "tx-7",
                expected,
                timeout=0.05,
                clock=AdvancingClock(),
                idle_wait=lambda _: None,
            )

    def test_timeout_without_response_fails(self) -> None:
        expected = smoke.ExpectedResponse("ACK", "RESET", "IDLE")

        with self.assertRaisesRegex(smoke.TransactionTimeout, "timeout"):
            smoke.await_transaction_response(
                FakeSerial(),
                io.StringIO(),
                "tx-8",
                expected,
                timeout=0.03,
                clock=AdvancingClock(),
                idle_wait=lambda _: None,
            )

    def test_late_response_does_not_satisfy_next_transaction(self) -> None:
        expected = smoke.ExpectedResponse("ACK", "PING", "RUNNING")
        serial_port = FakeSerial(
            ack("tx-old", "STATUS", "RUNNING"),
            ack("tx-new", "PING", "RUNNING"),
        )

        with self.assertRaisesRegex(smoke.ResponseValidationError, "mismatched"):
            smoke.await_transaction_response(
                serial_port,
                io.StringIO(),
                "tx-new",
                expected,
                timeout=0.2,
            )

    def test_malformed_transaction_response_is_rejected(self) -> None:
        with self.assertRaisesRegex(smoke.ResponseValidationError, "malformed"):
            smoke.parse_transaction_response("ACK,tx-9,STATUS,LOCKED")

    def test_generated_transaction_ids_are_unique(self) -> None:
        seen: set[str] = set()
        first = smoke.generate_unique_txid(seen)
        second = smoke.generate_unique_txid(seen)

        self.assertNotEqual(first, second)
        self.assertEqual(len(seen), 2)


if __name__ == "__main__":
    unittest.main()
