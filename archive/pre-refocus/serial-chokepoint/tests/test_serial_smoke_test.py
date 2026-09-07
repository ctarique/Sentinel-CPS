from __future__ import annotations

import io
import sys
import unittest
from collections import deque
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT))

from tools import serial_smoke_test as smoke  # noqa: E402


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


def nack(
    txid: str,
    verb: str,
    reason: str = smoke.EXPECTED_REASON,
    state: str = smoke.EXPECTED_STATE,
    origin: str = smoke.EXPECTED_ORIGIN,
) -> str:
    return f"NACK,{txid},{verb},{reason},{state},{origin}"


class TransactionResponseTests(unittest.TestCase):
    def test_valid_matching_nack_is_accepted(self) -> None:
        response = smoke.parse_transaction_response(nack("tx-1", "STATUS"))

        self.assertIsNotNone(response)
        smoke.validate_phase2_response(response, "tx-1", "STATUS")

    def test_wrong_transaction_id_fails(self) -> None:
        response = smoke.parse_transaction_response(nack("wrong", "RESET"))

        with self.assertRaisesRegex(smoke.ResponseValidationError, "mismatched"):
            smoke.validate_phase2_response(response, "expected", "RESET")

    def test_wrong_verb_fails(self) -> None:
        response = smoke.parse_transaction_response(nack("tx-2", "PING"))

        with self.assertRaisesRegex(smoke.ResponseValidationError, "mismatched"):
            smoke.validate_phase2_response(response, "tx-2", "START")

    def test_wrong_reason_fails(self) -> None:
        response = smoke.parse_transaction_response(
            nack("tx-3", "STOP", reason="UNSUPPORTED_VERB")
        )

        with self.assertRaisesRegex(smoke.ResponseValidationError, "mismatched"):
            smoke.validate_phase2_response(response, "tx-3", "STOP")

    def test_legacy_ack_start_fails(self) -> None:
        with self.assertRaisesRegex(smoke.ResponseValidationError, "legacy"):
            smoke.parse_transaction_response("ACK_START")

    def test_malformed_response_fails(self) -> None:
        malformed = "NACK,tx-4,START,NO_DOWNSTREAM_TRANSPORT,LOCKED"

        with self.assertRaisesRegex(smoke.ResponseValidationError, "malformed"):
            smoke.parse_transaction_response(malformed)

    def test_diagnostic_is_logged_but_does_not_complete_transaction(self) -> None:
        serial_port = FakeSerial("ERR,MALFORMED_FRAME")
        log = io.StringIO()

        with self.assertRaises(smoke.TransactionTimeout):
            smoke.await_phase2_nack(
                serial_port,
                log,
                "tx-5",
                "STATUS",
                timeout=0.05,
                clock=AdvancingClock(),
                idle_wait=lambda _: None,
            )

        self.assertIn("[RX] <- ERR,MALFORMED_FRAME", log.getvalue())

    def test_interleaved_diagnostics_before_matching_nack_are_handled(self) -> None:
        serial_port = FakeSerial(
            "BOOT,HUB,LOCKED,ESP_NOW_UNAVAILABLE",
            "ERR,MALFORMED_FRAME",
            nack("tx-6", "PING"),
        )
        log = io.StringIO()

        response = smoke.await_phase2_nack(
            serial_port, log, "tx-6", "PING", timeout=0.2
        )

        self.assertEqual(response.txid, "tx-6")
        self.assertIn("[RX] <- BOOT,HUB,LOCKED,ESP_NOW_UNAVAILABLE", log.getvalue())
        self.assertIn("[RX] <- ERR,MALFORMED_FRAME", log.getvalue())
        self.assertIn(f"[RX] <- {nack('tx-6', 'PING')}", log.getvalue())

    def test_timeout_fails(self) -> None:
        with self.assertRaisesRegex(smoke.TransactionTimeout, "timeout"):
            smoke.await_phase2_nack(
                FakeSerial(),
                io.StringIO(),
                "tx-7",
                "RESET",
                timeout=0.03,
                clock=AdvancingClock(),
                idle_wait=lambda _: None,
            )

    def test_duplicate_or_late_response_cannot_satisfy_next_transaction(self) -> None:
        stale_txid = "tx-old"
        current_txid = "tx-new"
        serial_port = FakeSerial(
            nack(stale_txid, "STATUS"),
            nack(current_txid, "PING"),
        )

        with self.assertRaisesRegex(smoke.ResponseValidationError, "mismatched"):
            smoke.await_phase2_nack(
                serial_port,
                io.StringIO(),
                current_txid,
                "PING",
                timeout=0.2,
            )


if __name__ == "__main__":
    unittest.main()
