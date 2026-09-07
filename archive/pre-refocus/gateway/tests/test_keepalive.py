"""Phase 4 automatic keepalive and communication-loss safety tests.

All Gateway CSV output is redirected before importing ``app`` so these tests
cannot append to repository data or preserved evidence.
"""

from __future__ import annotations

import csv
import json
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
    TEST_DATA_DIR = tempfile.TemporaryDirectory(prefix="sentinel_keepalive_tests_")
    os.environ["SENTINEL_GATEWAY_DATA_DIR"] = TEST_DATA_DIR.name

import app  # noqa: E402


class FakeSerialConnection:
    def __init__(self, *, raise_on_write: bool = False) -> None:
        self.is_open = True
        self.raise_on_write = raise_on_write
        self.writes: list[bytes] = []
        self.rx: Queue[bytes] = Queue()

    def write(self, payload: bytes) -> int:
        if self.raise_on_write:
            raise OSError("simulated keepalive write failure")
        self.writes.append(payload)
        return len(payload)

    def flush(self) -> None:
        return None

    def readline(self) -> bytes:
        try:
            return self.rx.get(timeout=0.005)
        except Empty:
            return b""


class KeepaliveTests(unittest.TestCase):
    def make_bridge(
        self,
        *,
        enabled: bool = True,
        interval_ms: int = 20,
        timeout_ms: int = 35,
        delay_ms: int = 2,
    ) -> app.SerialBridge:
        bridge = app.SerialBridge(
            mock_mode=True,
            port="/dev/keepalive-test",
            baud=115200,
            safe_boot_locked=True,
            serial_ack_timeout_ms=timeout_ms,
            mock_ack_delay_ms=delay_ms,
            keepalive_enabled=enabled,
            keepalive_interval_ms=interval_ms,
        )
        self.addCleanup(bridge.close)
        return bridge

    def wait_for(self, predicate, timeout: float = 0.75) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.002)
        self.fail("condition was not reached before the test deadline")

    def start_running(self, bridge: app.SerialBridge) -> app.TransactionResult:
        reset = bridge.write("RESET")
        self.assertEqual(reset.outcome, "ACKNOWLEDGED")
        started = bridge.write("START")
        self.assertEqual(started.outcome, "ACKNOWLEDGED")
        self.assertEqual(started.state, "RUNNING")
        return started

    def activate_running_state(self, bridge: app.SerialBridge) -> None:
        """Model an already-acknowledged RUNNING state for transport failures."""
        with bridge.state_lock:
            bridge.locked = False
            bridge.acknowledged_state = "RUNNING"
            bridge.state_generation += 1
        bridge.keepalive_wakeup.set()

    def failure_rows(self, transaction_id: str | None = None) -> list[dict[str, str]]:
        with app.ACTIONS_CSV.open(newline="", encoding="utf-8") as handle:
            rows = [
                row
                for row in csv.DictReader(handle)
                if row["source"] == "AUTO_KEEPALIVE"
                and row["command"] == "KEEPALIVE_FAILURE"
            ]
        if transaction_id is None:
            return rows
        return [
            row
            for row in rows
            if json.loads(row["details"])["transaction_id"] == transaction_id
        ]

    def test_keepalive_inactive_while_locked(self) -> None:
        bridge = self.make_bridge()
        time.sleep(0.06)

        status = bridge.get_status()
        self.assertFalse(status["keepalive_active"])
        self.assertIsNone(status["last_keepalive_timestamp"])

    def test_keepalive_inactive_while_idle(self) -> None:
        bridge = self.make_bridge()
        self.assertEqual(bridge.write("RESET").state, "IDLE")
        time.sleep(0.06)

        self.assertFalse(bridge.get_status()["keepalive_active"])
        self.assertIsNone(bridge.get_status()["last_keepalive_result"])

    def test_disabled_keepalive_remains_inactive_while_running(self) -> None:
        bridge = self.make_bridge(enabled=False)
        self.start_running(bridge)
        time.sleep(0.06)

        self.assertFalse(bridge.get_status()["keepalive_active"])
        self.assertIsNone(bridge.get_status()["last_keepalive_timestamp"])

    def test_start_running_activates_matching_vehicle_ping_ack(self) -> None:
        bridge = self.make_bridge()
        self.start_running(bridge)
        self.wait_for(lambda: bridge.get_status()["last_keepalive_result"] == "ACKNOWLEDGED")

        status = bridge.get_status()
        self.assertTrue(status["keepalive_active"])
        self.assertIsNotNone(status["last_keepalive_timestamp"])
        self.assertIsNotNone(status["last_keepalive_ack_latency_ms"])
        self.assertEqual(status["keepalive_failure_count"], 0)

    def test_automatic_ping_uses_unique_transaction_ids(self) -> None:
        bridge = self.make_bridge(interval_ms=12)
        observed: list[str] = []
        original_send = bridge._send_transaction

        def capture(transaction: app.PendingTransaction) -> None:
            if transaction.verb == "PING":
                observed.append(transaction.txid)
            original_send(transaction)

        with mock.patch.object(bridge, "_send_transaction", side_effect=capture):
            self.start_running(bridge)
            self.wait_for(lambda: len(observed) >= 2)

        self.assertEqual(len(observed), len(set(observed)))

    def test_automatic_metrics_are_separate_from_user_commands(self) -> None:
        bridge = self.make_bridge()
        self.start_running(bridge)
        self.wait_for(lambda: bridge.get_status()["last_keepalive_result"] == "ACKNOWLEDGED")
        self.wait_for(
            lambda: app.summarize_performance()["automatic_keepalive"]["sample_count"]
            >= 1
        )

        summary = app.summarize_performance()
        self.assertGreaterEqual(summary["automatic_keepalive"]["sample_count"], 1)
        self.assertNotIn("AUTO_KEEPALIVE:PING", summary["by_command"])

    def test_telemetry_cannot_satisfy_keepalive(self) -> None:
        bridge = self.make_bridge(timeout_ms=30)
        self.start_running(bridge)
        bridge.set_mock_ack_behavior(
            "TELEMETRY_ONLY",
            telemetry="TEL,telemetry_only,1,2,0.0,RUNNING",
        )

        self.wait_for(lambda: bridge.get_status()["keepalive_failure_count"] == 1)

        status = bridge.get_status()
        self.assertTrue(status["gateway_locked"])
        self.assertEqual(status["last_keepalive_failure"]["result"], "ACK_TIMEOUT")

    def test_wrong_origin_fails(self) -> None:
        bridge = self.make_bridge()
        self.start_running(bridge)
        bridge.set_mock_ack_behavior("ACK", origin="HUB")
        self.wait_for(lambda: bridge.get_status()["keepalive_failure_count"] == 1)

        failure = bridge.get_status()["last_keepalive_failure"]
        self.assertEqual(failure["ack_origin"], "HUB")
        self.assertEqual(failure["reason"], "UNEXPECTED_ACK_ORIGIN")

    def test_wrong_state_fails(self) -> None:
        bridge = self.make_bridge()
        self.start_running(bridge)
        bridge.set_mock_ack_behavior("ACK", state="IDLE")
        self.wait_for(lambda: bridge.get_status()["keepalive_failure_count"] == 1)

        failure = bridge.get_status()["last_keepalive_failure"]
        self.assertEqual(failure["ack_state"], "IDLE")
        self.assertEqual(failure["reason"], "UNEXPECTED_ACK_STATE")

    def test_wrong_verb_and_txid_fail_by_timeout(self) -> None:
        for behavior in ("WRONG_VERB", "WRONG_TXID"):
            with self.subTest(behavior=behavior):
                bridge = self.make_bridge(timeout_ms=25)
                self.start_running(bridge)
                bridge.set_mock_ack_behavior(behavior)
                self.wait_for(lambda: bridge.get_status()["keepalive_failure_count"] == 1)
                self.assertEqual(
                    bridge.get_status()["last_keepalive_failure"]["result"],
                    "ACK_TIMEOUT",
                )
                bridge.close()

    def test_nack_and_timeout_lock_gateway(self) -> None:
        for behavior, expected in (("NACK", "NACK"), ("TIMEOUT", "ACK_TIMEOUT")):
            with self.subTest(behavior=behavior):
                bridge = self.make_bridge(timeout_ms=25)
                self.start_running(bridge)
                bridge.set_mock_ack_behavior(behavior, reason="KEEPALIVE_REJECTED")
                self.wait_for(lambda: bridge.get_status()["keepalive_failure_count"] == 1)
                status = bridge.get_status()
                self.assertTrue(status["gateway_locked"])
                self.assertEqual(status["last_keepalive_failure"]["result"], expected)
                bridge.close()

    def test_failure_event_is_structured(self) -> None:
        bridge = self.make_bridge()
        self.start_running(bridge)
        bridge.set_mock_ack_behavior(
            "NACK",
            reason="KEEPALIVE_REJECTED",
            state="RUNNING",
        )
        self.wait_for(lambda: bridge.get_status()["keepalive_failure_count"] == 1)

        with app.ACTIONS_CSV.open(newline="", encoding="utf-8") as handle:
            rows = [
                row
                for row in csv.DictReader(handle)
                if row["source"] == "AUTO_KEEPALIVE"
                and row["command"] == "KEEPALIVE_FAILURE"
            ]
        self.assertTrue(rows)
        details = json.loads(rows[-1]["details"])
        for field in (
            "transaction_id",
            "result",
            "reason",
            "ack_state",
            "ack_origin",
            "ack_latency_ms",
            "timestamp",
        ):
            self.assertIn(field, details)

    def test_published_failure_always_has_flushed_structured_row(self) -> None:
        for iteration in range(12):
            with self.subTest(iteration=iteration):
                bridge = self.make_bridge(interval_ms=10, timeout_ms=40)
                append_entered = threading.Event()
                release_append = threading.Event()
                stop_completed = threading.Event()
                observations: dict[str, object] = {}
                ping_count = 0
                stop_count = 0
                original_log_action = app.log_action
                original_attempt_stop = bridge._attempt_keepalive_safety_stop

                def respond(transaction: app.PendingTransaction) -> None:
                    nonlocal ping_count, stop_count
                    if transaction.verb == "PING":
                        ping_count += 1
                        bridge.inject_mock_line(
                            f"NACK,{transaction.txid},PING,"
                            "KEEPALIVE_REJECTED,RUNNING,VEHICLE"
                        )
                    elif transaction.verb == "STOP":
                        stop_count += 1
                        bridge.inject_mock_line(
                            f"ACK,{transaction.txid},STOP,LOCKED,VEHICLE"
                        )
                    else:
                        bridge.inject_mock_line(
                            f"ACK,{transaction.txid},{transaction.verb},"
                            f"{bridge._mock_state_for(transaction.verb)},VEHICLE"
                        )

                def gated_log_action(
                    source: str,
                    command: str,
                    details: str,
                    result: str,
                    mode: str = "unknown",
                ) -> str:
                    if command != "KEEPALIVE_FAILURE":
                        return original_log_action(
                            source, command, details, result, mode=mode
                        )

                    failure_details = json.loads(details)
                    observations["details"] = failure_details
                    observations["state_lock_was_free"] = (
                        bridge.state_lock.acquire(blocking=False)
                    )
                    if observations["state_lock_was_free"]:
                        bridge.state_lock.release()
                    observations["command_lock_was_free"] = (
                        bridge.command_lock.acquire(blocking=False)
                    )
                    if observations["command_lock_was_free"]:
                        bridge.command_lock.release()
                    append_entered.set()
                    if not release_append.wait(0.75):
                        raise TimeoutError("test did not release evidence append")
                    event_id = original_log_action(
                        source, command, details, result, mode=mode
                    )
                    observations["row_before_return"] = self.failure_rows(
                        failure_details["transaction_id"]
                    )[-1]
                    observations["status_before_return"] = bridge.get_status()
                    return event_id

                def capture_stop(failure_generation: int) -> None:
                    try:
                        original_attempt_stop(failure_generation)
                    finally:
                        stop_completed.set()

                with mock.patch.object(
                    bridge, "_schedule_mock_response", side_effect=respond
                ), mock.patch.object(
                    app, "log_action", side_effect=gated_log_action
                ), mock.patch.object(
                    bridge,
                    "_attempt_keepalive_safety_stop",
                    side_effect=capture_stop,
                ):
                    self.start_running(bridge)
                    self.assertTrue(append_entered.wait(0.75))

                    pending = bridge.get_status()
                    self.assertTrue(pending["gateway_locked"])
                    self.assertFalse(pending["keepalive_active"])
                    self.assertEqual(pending["keepalive_failure_count"], 0)
                    self.assertIsNone(pending["last_keepalive_failure"])
                    self.assertEqual(
                        pending["keepalive_failure_evidence_status"],
                        "APPEND_PENDING",
                    )
                    transaction_id = observations["details"]["transaction_id"]
                    self.assertFalse(self.failure_rows(transaction_id))

                    release_append.set()
                    self.assertTrue(stop_completed.wait(0.75))

                published = bridge.get_status()
                self.assertEqual(published["keepalive_failure_count"], 1)
                self.assertEqual(
                    published["keepalive_failure_evidence_status"],
                    "APPENDED_AND_FLUSHED",
                )
                self.assertIsNone(published["keepalive_failure_evidence_error"])
                self.assertTrue(observations["state_lock_was_free"])
                self.assertTrue(observations["command_lock_was_free"])
                before_return = observations["status_before_return"]
                self.assertEqual(before_return["keepalive_failure_count"], 0)
                self.assertEqual(ping_count, 1)
                self.assertEqual(stop_count, 1)

                row = observations["row_before_return"]
                details = observations["details"]
                self.assertEqual(row["source"], "AUTO_KEEPALIVE")
                self.assertEqual(row["command"], "KEEPALIVE_FAILURE")
                self.assertEqual(row["result"], "LOCALLY_LOCKED")
                self.assertEqual(details["transaction_id"], transaction_id)
                self.assertEqual(details["result"], "NACK")
                self.assertEqual(details["reason"], "KEEPALIVE_REJECTED")
                self.assertEqual(details["ack_state"], "RUNNING")
                self.assertEqual(details["ack_origin"], "VEHICLE")
                self.assertIsNotNone(details["ack_latency_ms"])
                self.assertIn("timestamp", details)
                self.assertIn("timestamp_utc", details)
                bridge.close()

    def test_failure_evidence_append_error_is_fail_safe_and_visible(self) -> None:
        bridge = self.make_bridge(interval_ms=10, timeout_ms=40)
        handler_completed = threading.Event()
        stop_txids: list[str] = []
        worker_errors: list[threading.ExceptHookArgs] = []
        original_log_action = app.log_action
        original_handler = bridge._handle_keepalive_result

        def respond(transaction: app.PendingTransaction) -> None:
            if transaction.verb == "PING":
                bridge.inject_mock_line(
                    f"NACK,{transaction.txid},PING,"
                    "KEEPALIVE_REJECTED,RUNNING,VEHICLE"
                )
            elif transaction.verb == "STOP":
                stop_txids.append(transaction.txid)
                bridge.inject_mock_line(
                    f"ACK,{transaction.txid},STOP,LOCKED,VEHICLE"
                )
            else:
                bridge.inject_mock_line(
                    f"ACK,{transaction.txid},{transaction.verb},"
                    f"{bridge._mock_state_for(transaction.verb)},VEHICLE"
                )

        def fail_structured_append(
            source: str,
            command: str,
            details: str,
            result: str,
            mode: str = "unknown",
        ) -> str:
            if command == "KEEPALIVE_FAILURE":
                raise OSError("simulated durable evidence failure")
            return original_log_action(source, command, details, result, mode=mode)

        def capture_handler(*args, **kwargs) -> None:
            try:
                original_handler(*args, **kwargs)
            finally:
                handler_completed.set()

        with mock.patch.object(
            bridge, "_schedule_mock_response", side_effect=respond
        ), mock.patch.object(
            app, "log_action", side_effect=fail_structured_append
        ), mock.patch.object(
            bridge, "_handle_keepalive_result", side_effect=capture_handler
        ), mock.patch.object(
            threading, "excepthook", side_effect=worker_errors.append
        ):
            self.start_running(bridge)
            self.assertTrue(handler_completed.wait(0.75))

        status = bridge.get_status()
        self.assertTrue(status["gateway_locked"])
        self.assertFalse(status["keepalive_active"])
        self.assertEqual(status["keepalive_failure_count"], 1)
        self.assertEqual(len(stop_txids), 1)
        self.assertEqual(status["last_safety_stop_result"], "ACKNOWLEDGED")
        self.assertEqual(status["safety_status"], "STOP_ACKNOWLEDGED")
        self.assertEqual(
            status["keepalive_failure_evidence_status"], "APPEND_FAILED"
        )
        self.assertIn(
            "simulated durable evidence failure",
            status["keepalive_failure_evidence_error"],
        )
        self.assertEqual(
            status["last_keepalive_failure"]["evidence_status"],
            "APPEND_FAILED",
        )
        transaction_id = status["last_keepalive_failure"]["transaction_id"]
        self.assertFalse(self.failure_rows(transaction_id))
        self.assertFalse(worker_errors)

    def test_failure_schedules_exactly_one_stop_and_ack_confirms_stop(self) -> None:
        bridge = self.make_bridge(timeout_ms=30)
        stop_txids: list[str] = []

        def respond(transaction: app.PendingTransaction) -> None:
            if transaction.verb == "PING":
                bridge.inject_mock_line(
                    f"NACK,{transaction.txid},PING,KEEPALIVE_REJECTED,RUNNING,VEHICLE"
                )
            elif transaction.verb == "STOP":
                stop_txids.append(transaction.txid)
                bridge.inject_mock_line(
                    f"ACK,{transaction.txid},STOP,LOCKED,VEHICLE"
                )
            else:
                bridge.inject_mock_line(
                    f"ACK,{transaction.txid},{transaction.verb},"
                    f"{bridge._mock_state_for(transaction.verb)},VEHICLE"
                )

        with mock.patch.object(bridge, "_schedule_mock_response", side_effect=respond):
            self.start_running(bridge)
            self.wait_for(lambda: bridge.get_status()["last_safety_stop_result"] is not None)
            time.sleep(0.07)

        status = bridge.get_status()
        self.assertEqual(len(stop_txids), 1)
        self.assertEqual(status["last_safety_stop_result"], "ACKNOWLEDGED")
        self.assertTrue(status["vehicle_stop_confirmed"])
        self.assertEqual(status["safety_status"], "STOP_ACKNOWLEDGED")

    def test_stop_timeout_leaves_execution_unknown_and_locked(self) -> None:
        bridge = self.make_bridge(timeout_ms=25)
        stop_count = 0

        def respond(transaction: app.PendingTransaction) -> None:
            nonlocal stop_count
            if transaction.verb == "PING":
                bridge.inject_mock_line(
                    f"NACK,{transaction.txid},PING,REJECTED,RUNNING,VEHICLE"
                )
            elif transaction.verb == "STOP":
                stop_count += 1
            else:
                bridge.inject_mock_line(
                    f"ACK,{transaction.txid},{transaction.verb},"
                    f"{bridge._mock_state_for(transaction.verb)},VEHICLE"
                )

        with mock.patch.object(bridge, "_schedule_mock_response", side_effect=respond):
            self.start_running(bridge)
            self.wait_for(lambda: bridge.get_status()["last_safety_stop_result"] == "ACK_TIMEOUT")

        status = bridge.get_status()
        self.assertEqual(stop_count, 1)
        self.assertTrue(status["gateway_locked"])
        self.assertFalse(status["vehicle_stop_confirmed"])
        self.assertEqual(status["safety_status"], "STOP_EXECUTION_UNKNOWN")

    def test_manual_stop_and_reset_disable_keepalive(self) -> None:
        for command, expected_state in (("STOP", "LOCKED"), ("RESET", "IDLE")):
            with self.subTest(command=command):
                bridge = self.make_bridge(interval_ms=80)
                self.start_running(bridge)
                result = bridge.write(command)
                self.assertEqual(result.outcome, "ACKNOWLEDGED")
                self.assertEqual(result.state, expected_state)
                time.sleep(0.1)
                self.assertFalse(bridge.get_status()["keepalive_active"])
                self.assertIsNone(bridge.get_status()["last_keepalive_result"])
                bridge.close()

    def test_shutdown_wakes_and_joins_keepalive_worker(self) -> None:
        bridge = self.make_bridge(interval_ms=10, timeout_ms=1500)
        self.start_running(bridge)
        bridge.set_mock_ack_behavior("TIMEOUT")
        self.wait_for(
            lambda: bridge.pending_transaction is not None
            and bridge.pending_transaction.verb == "PING"
        )

        bridge.close()

        self.assertFalse(bridge.keepalive_thread.is_alive())
        self.assertFalse(bridge.thread.is_alive())

    def test_user_command_and_keepalive_are_serialized_without_deadlock(self) -> None:
        bridge = self.make_bridge(interval_ms=10, timeout_ms=200, delay_ms=35)
        self.start_running(bridge)
        self.wait_for(
            lambda: bridge.pending_transaction is not None
            and bridge.pending_transaction.verb == "PING"
        )
        results: list[app.TransactionResult] = []
        user_thread = threading.Thread(target=lambda: results.append(bridge.write("STATUS")))
        user_thread.start()
        user_thread.join(timeout=0.7)

        self.assertFalse(user_thread.is_alive())
        self.assertEqual(results[0].outcome, "ACKNOWLEDGED")

    def test_stale_keepalive_completion_cannot_override_later_stop(self) -> None:
        bridge = self.make_bridge(interval_ms=10, timeout_ms=200)
        entered = threading.Event()
        release = threading.Event()
        original_handler = bridge._handle_keepalive_result

        def pause(result, state_generation, command_total_ms):
            entered.set()
            release.wait(0.5)
            original_handler(result, state_generation, command_total_ms)

        with mock.patch.object(bridge, "_handle_keepalive_result", side_effect=pause):
            self.start_running(bridge)
            self.assertTrue(entered.wait(0.5))
            stopped = bridge.write("STOP")
            self.assertEqual(stopped.outcome, "ACKNOWLEDGED")
            release.set()
            time.sleep(0.03)

        status = bridge.get_status()
        self.assertTrue(status["gateway_locked"])
        self.assertEqual(status["acknowledged_state"], "LOCKED")
        self.assertEqual(status["keepalive_failure_count"], 0)

    def test_stale_keepalive_completion_cannot_override_later_reset(self) -> None:
        bridge = self.make_bridge(interval_ms=10, timeout_ms=200)
        entered = threading.Event()
        release = threading.Event()
        original_handler = bridge._handle_keepalive_result

        def pause(result, state_generation, command_total_ms):
            entered.set()
            release.wait(0.5)
            original_handler(result, state_generation, command_total_ms)

        with mock.patch.object(bridge, "_handle_keepalive_result", side_effect=pause):
            self.start_running(bridge)
            self.assertTrue(entered.wait(0.5))
            reset = bridge.write("RESET")
            self.assertEqual(reset.outcome, "ACKNOWLEDGED")
            release.set()
            time.sleep(0.03)

        status = bridge.get_status()
        self.assertFalse(status["gateway_locked"])
        self.assertEqual(status["acknowledged_state"], "IDLE")
        self.assertEqual(status["keepalive_failure_count"], 0)

    def test_explicit_mock_mode_can_ack_keepalive(self) -> None:
        bridge = self.make_bridge()
        self.start_running(bridge)
        self.wait_for(lambda: bridge.get_status()["last_keepalive_result"] == "ACKNOWLEDGED")
        self.assertEqual(bridge.get_status()["mode"], "mock")

    def test_unavailable_hardware_never_falls_back_and_locks(self) -> None:
        fake_serial = types.SimpleNamespace(
            Serial=mock.Mock(side_effect=OSError("hardware port unavailable"))
        )
        with mock.patch.object(app, "serial", fake_serial):
            bridge = app.SerialBridge(
                mock_mode=False,
                port="/dev/missing-keepalive-port",
                baud=115200,
                safe_boot_locked=True,
                serial_ack_timeout_ms=25,
                mock_ack_delay_ms=0,
                keepalive_enabled=True,
                keepalive_interval_ms=10,
            )
        self.addCleanup(bridge.close)
        self.activate_running_state(bridge)

        self.wait_for(lambda: bridge.get_status()["keepalive_failure_count"] == 1)

        status = bridge.get_status()
        self.assertEqual(status["mode"], "hardware")
        self.assertEqual(status["last_keepalive_failure"]["result"], "SERIAL_UNAVAILABLE")
        self.assertTrue(status["gateway_locked"])

    def test_hardware_write_failure_locks(self) -> None:
        connection = FakeSerialConnection(raise_on_write=True)
        fake_serial = types.SimpleNamespace(Serial=mock.Mock(return_value=connection))
        with mock.patch.object(app, "serial", fake_serial):
            bridge = app.SerialBridge(
                mock_mode=False,
                port="/dev/write-failure-keepalive",
                baud=115200,
                safe_boot_locked=True,
                serial_ack_timeout_ms=25,
                mock_ack_delay_ms=0,
                keepalive_enabled=True,
                keepalive_interval_ms=10,
            )
        self.addCleanup(bridge.close)
        self.activate_running_state(bridge)

        self.wait_for(lambda: bridge.get_status()["keepalive_failure_count"] == 1)

        self.assertEqual(
            bridge.get_status()["last_keepalive_failure"]["result"],
            "SERIAL_WRITE_ERROR",
        )
        self.assertTrue(bridge.get_status()["gateway_locked"])

    def test_invalid_keepalive_constructor_configuration_is_rejected(self) -> None:
        for value in (0, -1, 7000, 9000, True):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    app.SerialBridge(
                        mock_mode=True,
                        port="/dev/invalid-config",
                        baud=115200,
                        keepalive_interval_ms=value,
                    )

        with self.assertRaises(ValueError):
            app.SerialBridge(
                mock_mode=True,
                port="/dev/invalid-config",
                baud=115200,
                keepalive_enabled="true",
            )


class KeepaliveDeploymentConfigurationTests(unittest.TestCase):
    def test_examples_enable_keepalive_with_safe_interval(self) -> None:
        root = Path(app.BASE_DIR)
        for relative in (
            "config.example.json",
            "deploy/config.mock.json",
            "deploy/config.hardware.json",
        ):
            with self.subTest(relative=relative):
                parsed = json.loads((root / relative).read_text(encoding="utf-8"))
                self.assertIs(parsed["keepalive_enabled"], True)
                self.assertEqual(parsed["keepalive_interval_ms"], 3000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
