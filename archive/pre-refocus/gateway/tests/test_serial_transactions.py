"""Unit tests for ACK-aware Gateway serial transactions.

The data-directory override must be installed before importing ``app`` so the
module-level Gateway instance cannot append to repository CSV evidence.
"""

from __future__ import annotations

import csv
import os
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from queue import Empty, Queue
from unittest import mock


os.environ.setdefault("SENTINEL_OPERATOR_TOKEN", "a" * 64)

TEST_DATA_DIR = None
if "SENTINEL_GATEWAY_DATA_DIR" not in os.environ:
    TEST_DATA_DIR = tempfile.TemporaryDirectory(
        prefix="sentinel_gateway_tests_"
    )
    os.environ["SENTINEL_GATEWAY_DATA_DIR"] = TEST_DATA_DIR.name

import app  # noqa: E402  (environment isolation must precede this import)


class FakeSerialConnection:
    def __init__(self) -> None:
        self.is_open = True
        self.raise_on_write = False
        self.writes: list[bytes] = []
        self.rx: Queue[bytes] = Queue()

    def write(self, payload: bytes) -> int:
        if self.raise_on_write:
            raise OSError("simulated disconnect during write")
        self.writes.append(payload)
        return len(payload)

    def flush(self) -> None:
        return None

    def readline(self) -> bytes:
        try:
            return self.rx.get(timeout=0.01)
        except Empty:
            return b""


class SerialTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bridge = app.SerialBridge(
            mock_mode=True,
            port="/dev/test-serial",
            baud=115200,
            safe_boot_locked=True,
            serial_ack_timeout_ms=40,
            mock_ack_delay_ms=5,
        )

    def tearDown(self) -> None:
        self.bridge.close()

    def unlock_for_test(self) -> None:
        self.bridge.locked = False
        self.bridge._set_telemetry_state(
            "IDLE", vehicle_id="test_vehicle", source="test"
        )

    def test_matching_ack_produces_acknowledged(self) -> None:
        self.unlock_for_test()

        result = self.bridge.write("START")

        self.assertEqual(result.outcome, "ACKNOWLEDGED")
        self.assertEqual(result.verb, "START")
        self.assertEqual(result.state, "RUNNING")
        self.assertEqual(result.origin, "VEHICLE")
        self.assertIsNotNone(result.ack_latency_ms)
        self.assertGreaterEqual(result.gateway_processing_ms, 0)

    def test_write_without_ack_produces_timeout(self) -> None:
        self.unlock_for_test()
        self.bridge.set_mock_ack_behavior("TIMEOUT")

        result = self.bridge.write("PING")

        self.assertEqual(result.outcome, "ACK_TIMEOUT")
        self.assertIsNone(result.ack_latency_ms)

    def test_matching_nack_returns_reason(self) -> None:
        self.unlock_for_test()
        self.bridge.set_mock_ack_behavior(
            "NACK", reason="LOCKED_REQUIRE_RESET", state="LOCKED"
        )

        result = self.bridge.write("START")

        self.assertEqual(result.outcome, "NACK")
        self.assertEqual(result.reason, "LOCKED_REQUIRE_RESET")
        self.assertEqual(result.state, "LOCKED")

    def test_wrong_transaction_id_does_not_complete_command(self) -> None:
        self.unlock_for_test()
        self.bridge.set_mock_ack_behavior("WRONG_TXID")

        result = self.bridge.write("PING")

        self.assertEqual(result.outcome, "ACK_TIMEOUT")

    def test_wrong_verb_does_not_complete_command(self) -> None:
        self.unlock_for_test()
        self.bridge.set_mock_ack_behavior("WRONG_VERB")

        result = self.bridge.write("PING")

        self.assertEqual(result.outcome, "ACK_TIMEOUT")

    def test_telemetry_before_ack_is_logged_but_does_not_complete(self) -> None:
        self.unlock_for_test()
        self.bridge.mock_ack_delay_ms = 24
        self.bridge.set_mock_ack_behavior(
            "INTERLEAVED_TELEMETRY",
            telemetry="TEL,vehicle_interleaved,123,456,0.125,RUNNING",
        )
        before = time.perf_counter()

        result = self.bridge.write("START")
        elapsed_ms = (time.perf_counter() - before) * 1000

        self.assertEqual(result.outcome, "ACKNOWLEDGED")
        self.assertGreaterEqual(elapsed_ms, 15)
        self.assertEqual(
            self.bridge.get_latest_telemetry()["vehicle_id"],
            "vehicle_interleaved",
        )
        with app.TELEMETRY_CSV.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertTrue(
            any(row["vehicle_id"] == "vehicle_interleaved" for row in rows)
        )

    def test_reset_matching_ack_unlocks(self) -> None:
        result = self.bridge.write("RESET")

        self.assertEqual(result.outcome, "ACKNOWLEDGED")
        self.assertEqual(result.state, "IDLE")
        self.assertFalse(self.bridge.locked)

    def test_reset_timeout_remains_locked(self) -> None:
        self.bridge.set_mock_ack_behavior("TIMEOUT")

        result = self.bridge.write("RESET")

        self.assertEqual(result.outcome, "ACK_TIMEOUT")
        self.assertTrue(self.bridge.locked)

    def test_reset_nack_remains_locked(self) -> None:
        self.bridge.set_mock_ack_behavior(
            "NACK", reason="RESET_REJECTED", state="LOCKED"
        )

        result = self.bridge.write("RESET")

        self.assertEqual(result.outcome, "NACK")
        self.assertTrue(self.bridge.locked)

    def test_reset_mismatch_and_write_failure_remain_locked(self) -> None:
        for behavior in ("WRONG_TXID", "WRONG_VERB", "WRITE_ERROR"):
            with self.subTest(behavior=behavior):
                self.bridge.locked = True
                self.bridge.set_mock_ack_behavior(behavior)

                result = self.bridge.write("RESET")

                self.assertIn(
                    result.outcome,
                    {"ACK_TIMEOUT", "SERIAL_WRITE_ERROR"},
                )
                self.assertTrue(self.bridge.locked)

    def test_reset_ack_requires_idle_state_to_unlock(self) -> None:
        self.bridge.set_mock_ack_behavior("ACK", state="RUNNING")

        result = self.bridge.write("RESET")

        self.assertEqual(result.outcome, "NACK")
        self.assertEqual(result.reason, "UNEXPECTED_ACK_STATE")
        self.assertTrue(self.bridge.locked)

    def test_stop_timeout_remains_locked(self) -> None:
        self.unlock_for_test()
        self.bridge.set_mock_ack_behavior("TIMEOUT")

        result = self.bridge.write("STOP")

        self.assertEqual(result.outcome, "ACK_TIMEOUT")
        self.assertTrue(self.bridge.locked)

    def test_stop_nack_remains_locked(self) -> None:
        self.unlock_for_test()
        self.bridge.set_mock_ack_behavior(
            "NACK", reason="STOP_REJECTED", state="RUNNING"
        )

        result = self.bridge.write("STOP")

        self.assertEqual(result.outcome, "NACK")
        self.assertEqual(result.reason, "STOP_REJECTED")
        self.assertTrue(self.bridge.locked)

    def test_stop_write_failure_remains_locked(self) -> None:
        self.unlock_for_test()
        self.bridge.set_mock_ack_behavior("WRITE_ERROR")

        result = self.bridge.write("STOP")

        self.assertEqual(result.outcome, "SERIAL_WRITE_ERROR")
        self.assertTrue(self.bridge.locked)

    def test_status_is_accepted_by_api(self) -> None:
        app.bridge.set_mock_ack_behavior("ACK")
        with app.app.test_client() as client:
            response = client.post(
                "/api/command",
                json={"command": "STATUS"},
                headers={app.OPERATOR_TOKEN_HEADER: app.OPERATOR_TOKEN},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["result"], "ACKNOWLEDGED")

    def test_api_exposes_three_distinct_timing_metrics(self) -> None:
        timing_bridge = app.SerialBridge(
            mock_mode=True,
            port="/dev/timing-test",
            baud=115200,
            safe_boot_locked=True,
            serial_ack_timeout_ms=400,
            mock_ack_delay_ms=100,
        )
        original_bridge = app.bridge
        app.bridge = timing_bridge
        try:
            with app.app.test_client() as client:
                response = client.post(
                    "/api/command",
                    json={"command": "STATUS"},
                    headers={app.OPERATOR_TOKEN_HEADER: app.OPERATOR_TOKEN},
                )
        finally:
            app.bridge = original_bridge
            timing_bridge.close()

        body = response.get_json()
        self.assertEqual(body["result"], "ACKNOWLEDGED")
        self.assertGreaterEqual(body["ack_latency_ms"], 80)
        self.assertGreaterEqual(body["command_total_ms"], 80)
        self.assertLess(body["gateway_processing_ms"], 50)
        self.assertGreater(body["command_total_ms"], body["gateway_processing_ms"])

    def test_late_ack_does_not_affect_next_transaction(self) -> None:
        self.unlock_for_test()
        self.bridge.set_mock_ack_behavior("TIMEOUT")
        first = self.bridge.write("PING")
        self.assertEqual(first.outcome, "ACK_TIMEOUT")

        self.bridge.inject_mock_line(
            f"ACK,{first.txid},PING,IDLE,VEHICLE"
        )
        time.sleep(0.01)
        self.bridge.set_mock_ack_behavior("TIMEOUT")

        second = self.bridge.write("STATUS")

        self.assertNotEqual(first.txid, second.txid)
        self.assertEqual(second.outcome, "ACK_TIMEOUT")

    def test_malformed_and_duplicate_responses_do_not_complete_next(self) -> None:
        self.unlock_for_test()
        self.bridge.set_mock_ack_behavior("ACK")
        first = self.bridge.write("PING")
        self.assertEqual(first.outcome, "ACKNOWLEDGED")

        self.bridge.inject_mock_line("ACK,too,few,fields")
        self.bridge.inject_mock_line(
            f"ACK,{first.txid},PING,IDLE,VEHICLE"
        )
        time.sleep(0.01)
        self.bridge.set_mock_ack_behavior("TIMEOUT")

        second = self.bridge.write("STATUS")

        self.assertEqual(second.outcome, "ACK_TIMEOUT")
        self.assertIsNone(self.bridge.pending_transaction)

    def test_only_one_transaction_is_in_flight(self) -> None:
        self.unlock_for_test()
        self.bridge.mock_ack_delay_ms = 25
        self.bridge.set_mock_ack_behavior("ACK")
        results = []

        def dispatch(verb: str) -> None:
            results.append(self.bridge.write(verb))

        first = threading.Thread(target=dispatch, args=("PING",))
        second = threading.Thread(target=dispatch, args=("STATUS",))
        first.start()
        time.sleep(0.005)
        second.start()

        max_pending = 0
        while first.is_alive() or second.is_alive():
            with self.bridge.pending_lock:
                max_pending = max(
                    max_pending,
                    int(self.bridge.pending_transaction is not None),
                )
            time.sleep(0.002)
        first.join()
        second.join()

        self.assertEqual(max_pending, 1)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.outcome == "ACKNOWLEDGED" for r in results))
        self.assertEqual(len({r.txid for r in results}), 2)

    def test_hardware_telemetry_uses_configured_port_as_source(self) -> None:
        self.bridge.mock_mode = False

        self.bridge._process_incoming_line(
            "TEL,vehicle_port_test,10,20,0.250,IDLE"
        )

        self.assertEqual(
            self.bridge.get_latest_telemetry()["source"],
            "/dev/test-serial",
        )

    def test_explicit_mock_health_is_distinct(self) -> None:
        health = self.bridge.get_status()

        self.assertEqual(health["mode"], "mock")
        self.assertEqual(health["serial_transport"], "mock")
        self.assertFalse(health["connected"])

    def test_hardware_open_failure_does_not_fall_back_to_mock(self) -> None:
        fake_serial = types.SimpleNamespace(
            Serial=mock.Mock(side_effect=OSError("port unavailable"))
        )
        with mock.patch.object(app, "serial", fake_serial):
            bridge = app.SerialBridge(
                mock_mode=False,
                port="/dev/missing-test-port",
                baud=115200,
                safe_boot_locked=True,
                serial_ack_timeout_ms=40,
                mock_ack_delay_ms=0,
            )
        try:
            health = bridge.get_status()
            self.assertEqual(health["mode"], "hardware")
            self.assertEqual(health["status"], "degraded")
            self.assertEqual(health["serial_transport"], "unavailable")
            self.assertFalse(health["connected"])

            reset = bridge.write("RESET")
            self.assertEqual(reset.outcome, "SERIAL_UNAVAILABLE")
            self.assertTrue(bridge.locked)

            bridge.locked = False
            start = bridge.write("START")
            self.assertEqual(start.outcome, "SERIAL_UNAVAILABLE")
        finally:
            bridge.close()

    def test_available_hardware_health_and_disconnect_after_startup(self) -> None:
        connection = FakeSerialConnection()
        fake_serial = types.SimpleNamespace(Serial=mock.Mock(return_value=connection))
        with mock.patch.object(app, "serial", fake_serial):
            bridge = app.SerialBridge(
                mock_mode=False,
                port="/dev/available-test-port",
                baud=115200,
                safe_boot_locked=True,
                serial_ack_timeout_ms=40,
                mock_ack_delay_ms=0,
            )
        try:
            available = bridge.get_status()
            self.assertEqual(available["mode"], "hardware")
            self.assertEqual(available["status"], "ok")
            self.assertEqual(available["serial_transport"], "available")
            self.assertTrue(available["connected"])

            connection.is_open = False
            degraded = bridge.get_status()
            self.assertEqual(degraded["status"], "degraded")
            self.assertEqual(degraded["serial_transport"], "degraded")
            self.assertFalse(degraded["connected"])

            reset = bridge.write("RESET")
            self.assertEqual(reset.outcome, "SERIAL_UNAVAILABLE")
            self.assertTrue(bridge.locked)
        finally:
            bridge.close()

    def test_hardware_disconnect_during_ack_wait_wakes_transaction(self) -> None:
        connection = FakeSerialConnection()
        fake_serial = types.SimpleNamespace(Serial=mock.Mock(return_value=connection))
        with mock.patch.object(app, "serial", fake_serial):
            bridge = app.SerialBridge(
                mock_mode=False,
                port="/dev/mid-transaction-disconnect",
                baud=115200,
                safe_boot_locked=True,
                serial_ack_timeout_ms=1000,
                mock_ack_delay_ms=0,
            )
        results = []
        command_thread = threading.Thread(
            target=lambda: results.append(bridge.write("STATUS"))
        )
        try:
            command_thread.start()
            deadline = time.monotonic() + 0.5
            while not connection.writes and time.monotonic() < deadline:
                time.sleep(0.005)
            connection.is_open = False
            command_thread.join(timeout=0.5)

            self.assertFalse(command_thread.is_alive())
            self.assertEqual(results[0].outcome, "SERIAL_UNAVAILABLE")
            self.assertEqual(
                bridge.get_status()["serial_transport"], "degraded"
            )
        finally:
            bridge.close()
            command_thread.join(timeout=0.5)

    def test_stop_hardware_transport_failure_remains_locked(self) -> None:
        connection = FakeSerialConnection()
        fake_serial = types.SimpleNamespace(Serial=mock.Mock(return_value=connection))
        with mock.patch.object(app, "serial", fake_serial):
            bridge = app.SerialBridge(
                mock_mode=False,
                port="/dev/disconnect-test-port",
                baud=115200,
                safe_boot_locked=True,
                serial_ack_timeout_ms=40,
                mock_ack_delay_ms=0,
            )
        try:
            bridge.locked = False
            connection.is_open = False

            result = bridge.write("STOP")

            self.assertEqual(result.outcome, "SERIAL_UNAVAILABLE")
            self.assertTrue(bridge.locked)
        finally:
            bridge.close()

    def test_hardware_write_error_is_not_mock_acknowledged(self) -> None:
        connection = FakeSerialConnection()
        connection.raise_on_write = True
        fake_serial = types.SimpleNamespace(Serial=mock.Mock(return_value=connection))
        with mock.patch.object(app, "serial", fake_serial):
            bridge = app.SerialBridge(
                mock_mode=False,
                port="/dev/write-error-test-port",
                baud=115200,
                safe_boot_locked=True,
                serial_ack_timeout_ms=40,
                mock_ack_delay_ms=0,
            )
        try:
            result = bridge.write("RESET")

            self.assertEqual(result.outcome, "SERIAL_WRITE_ERROR")
            self.assertTrue(bridge.locked)
            self.assertEqual(bridge.get_status()["serial_transport"], "degraded")
        finally:
            bridge.close()

    def test_shutdown_wakes_waiter_and_cleans_mock_response_threads(self) -> None:
        bridge = app.SerialBridge(
            mock_mode=True,
            port="/dev/shutdown-test",
            baud=115200,
            safe_boot_locked=True,
            serial_ack_timeout_ms=2000,
            mock_ack_delay_ms=1000,
        )
        bridge.set_mock_ack_behavior("ACK")
        results = []
        command_thread = threading.Thread(
            target=lambda: results.append(bridge.write("STATUS"))
        )
        command_thread.start()
        deadline = time.monotonic() + 1
        while bridge.pending_transaction is None and time.monotonic() < deadline:
            time.sleep(0.005)

        bridge.close()
        command_thread.join(timeout=0.5)

        self.assertFalse(command_thread.is_alive())
        self.assertEqual(results[0].outcome, "SERIAL_UNAVAILABLE")
        self.assertIsNone(bridge.pending_transaction)
        self.assertFalse(any(t.is_alive() for t in bridge.mock_response_threads))


if __name__ == "__main__":
    unittest.main(verbosity=2)
