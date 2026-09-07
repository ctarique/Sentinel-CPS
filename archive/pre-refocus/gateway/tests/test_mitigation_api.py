"""Phase 5B1 authenticated and idempotent mitigation STOP API tests.

The data directory is redirected before importing app. All tokens are obvious
test-only values, and no repository evidence file is read or written.
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
    TEST_DATA_DIR = tempfile.TemporaryDirectory(prefix="sentinel_mitigation_tests_")
    os.environ["SENTINEL_GATEWAY_DATA_DIR"] = TEST_DATA_DIR.name

import app  # noqa: E402


TEST_TOKEN = "t" * app.MITIGATION_TOKEN_MIN_LENGTH


class RespondingSerialConnection:
    def __init__(self, response_factory=None, *, fail_write: bool = False) -> None:
        self.is_open = True
        self.response_factory = response_factory
        self.fail_write = fail_write
        self.writes: list[bytes] = []
        self.rx: Queue[bytes] = Queue()

    def write(self, payload: bytes) -> int:
        if self.fail_write:
            raise OSError("simulated hardware write failure")
        self.writes.append(payload)
        if self.response_factory is not None:
            frame = payload.decode("utf-8").strip().split(",")
            response = self.response_factory(frame[1], frame[2])
            if response is not None:
                self.rx.put((response + "\n").encode("utf-8"))
        return len(payload)

    def flush(self) -> None:
        return None

    def readline(self) -> bytes:
        try:
            return self.rx.get(timeout=0.005)
        except Empty:
            return b""


class MitigationApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_bridge = app.bridge
        self.original_manager = app.mitigation_manager
        self.bridge = self.make_mock_bridge()
        self.manager = app.MitigationManager(
            self.bridge,
            enabled=True,
            loopback_only=True,
            cache_size=128,
            token=TEST_TOKEN,
        )
        app.bridge = self.bridge
        app.mitigation_manager = self.manager

    def tearDown(self) -> None:
        app.bridge = self.original_bridge
        app.mitigation_manager = self.original_manager
        self.bridge.close()

    def make_mock_bridge(
        self,
        *,
        timeout_ms: int = 80,
        delay_ms: int = 2,
        keepalive_enabled: bool = False,
        keepalive_interval_ms: int = 3000,
    ) -> app.SerialBridge:
        return app.SerialBridge(
            mock_mode=True,
            port="/dev/mitigation-test",
            baud=115200,
            safe_boot_locked=True,
            serial_ack_timeout_ms=timeout_ms,
            mock_ack_delay_ms=delay_ms,
            keepalive_enabled=keepalive_enabled,
            keepalive_interval_ms=keepalive_interval_ms,
        )

    @staticmethod
    def payload(key: str = "idem-001", **changes) -> dict:
        value = {
            "incident_id": "incident-001",
            "detection_id": "detection-001",
            "idempotency_key": key,
            "rule_id": "rule-stop-001",
            "severity": "HIGH",
            "score": 0.99,
            "detection_timestamp_utc": "2026-08-04T05:00:00Z",
        }
        value.update(changes)
        return value

    @staticmethod
    def headers(token: str = TEST_TOKEN) -> dict:
        return {"Authorization": f"Bearer {token}"}

    def post(self, payload=None, *, headers=None, remote="127.0.0.1", data=None):
        with app.app.test_client() as client:
            kwargs = {
                "headers": headers if headers is not None else self.headers(),
                "environ_base": {"REMOTE_ADDR": remote},
            }
            if data is not None:
                kwargs["data"] = data
                kwargs["content_type"] = "application/json"
            else:
                kwargs["json"] = self.payload() if payload is None else payload
            return client.post("/api/mitigation/stop", **kwargs)

    def install_manager(self, *, enabled=True, token=TEST_TOKEN, cache_size=128):
        self.manager = app.MitigationManager(
            self.bridge,
            enabled=enabled,
            loopback_only=True,
            cache_size=cache_size,
            token=token,
        )
        app.mitigation_manager = self.manager

    def replace_bridge(self, bridge: app.SerialBridge) -> None:
        self.bridge.close()
        self.bridge = bridge
        app.bridge = bridge
        self.install_manager()

    def test_endpoint_disabled_by_default_and_enabled_without_token_not_ready(self) -> None:
        self.install_manager(enabled=False)
        disabled = self.post()
        self.assertEqual(disabled.status_code, 404)
        self.assertEqual(disabled.get_json()["mitigation_status"], "ENDPOINT_DISABLED")

        self.install_manager(enabled=True, token=None)
        unavailable = self.post()
        self.assertEqual(unavailable.status_code, 503)
        self.assertFalse(self.manager.health_fields()["mitigation_api_ready"])

        self.install_manager(enabled=True, token="too-short")
        self.assertFalse(self.manager.health_fields()["mitigation_api_ready"])

    def test_health_exposes_only_nonsecret_mitigation_operations(self) -> None:
        with app.app.test_client() as client:
            health = client.get("/api/health").get_json()
        expected = {
            "mitigation_api_enabled",
            "mitigation_api_ready",
            "mitigation_loopback_only",
            "mitigation_active_requests",
            "mitigation_cached_results",
            "last_mitigation_status",
            "last_mitigation_timestamp",
            "last_mitigation_incident_id",
        }
        self.assertTrue(expected.issubset(health))
        self.assertTrue(health["mitigation_api_ready"])
        self.assertNotIn("token", json.dumps(health).lower())

    def test_missing_and_wrong_authorization_are_rejected(self) -> None:
        missing = self.post(headers={})
        wrong = self.post(headers=self.headers("wrong-test-value-that-is-not-the-token"))
        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(
            wrong.get_json()["mitigation_status"], "AUTHENTICATION_FAILED"
        )

    def test_non_loopback_and_forwarded_header_cannot_bypass(self) -> None:
        rejected = self.post(remote="192.0.2.10")
        forwarded = self.post(
            remote="192.0.2.10",
            headers={**self.headers(), "X-Forwarded-For": "127.0.0.1"},
        )
        self.assertEqual(rejected.status_code, 403)
        self.assertEqual(forwarded.status_code, 403)
        for address in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
            self.assertTrue(self.manager.is_loopback(address), address)

    def test_malformed_missing_and_unexpected_fields_are_rejected(self) -> None:
        malformed = self.post(data=b"{not-json")
        missing_payload = self.payload()
        del missing_payload["incident_id"]
        missing = self.post(missing_payload)
        command = self.post(self.payload(command="STOP"))
        verb = self.post(self.payload(verb="STOP"))
        self.assertEqual(malformed.status_code, 400)
        self.assertEqual(missing.status_code, 422)
        self.assertEqual(command.status_code, 422)
        self.assertEqual(verb.status_code, 422)

    def test_invalid_severity_score_timestamp_and_identifiers_are_rejected(self) -> None:
        invalid_payloads = (
            self.payload(severity="CRITICAL"),
            self.payload(score=float("inf")),
            self.payload(score=True),
            self.payload(detection_timestamp_utc="2026-08-04T05:00:00"),
            self.payload(detection_timestamp_utc="not-a-time"),
            self.payload(incident_id=""),
            self.payload(detection_id="line\nbreak"),
            self.payload(idempotency_key=" " * 3),
            self.payload(rule_id="x" * 129),
        )
        for index, invalid in enumerate(invalid_payloads):
            with self.subTest(index=index):
                response = self.post(invalid)
                self.assertEqual(response.status_code, 422)
                self.assertEqual(
                    response.get_json()["mitigation_status"], "REQUEST_REJECTED"
                )

    def test_valid_request_uses_existing_write_stop_path_exactly_once(self) -> None:
        with mock.patch.object(
            self.bridge, "write", wraps=self.bridge.write
        ) as write_spy, mock.patch.object(
            self.bridge, "_send_transaction", wraps=self.bridge._send_transaction
        ) as send_spy:
            response = self.post()

        self.assertEqual(response.status_code, 200)
        write_spy.assert_called_once_with("STOP", source="MITIGATION_API")
        self.assertEqual(send_spy.call_count, 1)
        self.assertEqual(send_spy.call_args.args[0].verb, "STOP")
        body = response.get_json()
        self.assertEqual(body["mitigation_status"], "SYNTHETIC_ACKNOWLEDGED")
        self.assertFalse(body["vehicle_stop_confirmed"])

    def test_duplicate_returns_stored_result_without_second_dispatch(self) -> None:
        with mock.patch.object(
            self.bridge, "_send_transaction", wraps=self.bridge._send_transaction
        ) as send_spy:
            first = self.post().get_json()
            duplicate_response = self.post()
            duplicate = duplicate_response.get_json()

        self.assertEqual(duplicate_response.status_code, 200)
        self.assertEqual(send_spy.call_count, 1)
        self.assertEqual(duplicate["transaction_id"], first["transaction_id"])
        self.assertEqual(duplicate["result"], first["result"])
        self.assertTrue(duplicate["duplicate_suppressed"])
        self.assertEqual(duplicate["mitigation_status"], "DUPLICATE_SUPPRESSED")
        self.assertEqual(
            duplicate["original_mitigation_status"], "SYNTHETIC_ACKNOWLEDGED"
        )

    def test_simultaneous_duplicate_dispatches_once_and_reports_in_progress(self) -> None:
        self.bridge.mock_ack_delay_ms = 60
        start = threading.Barrier(3)
        responses = []

        def send() -> None:
            start.wait()
            responses.append(self.post())

        with mock.patch.object(
            self.bridge, "_send_transaction", wraps=self.bridge._send_transaction
        ) as send_spy:
            threads = [threading.Thread(target=send) for _ in range(2)]
            for thread in threads:
                thread.start()
            start.wait()
            for thread in threads:
                thread.join(timeout=1)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(send_spy.call_count, 1)
        self.assertEqual(sorted(response.status_code for response in responses), [200, 202])
        statuses = {response.get_json()["mitigation_status"] for response in responses}
        self.assertIn("IN_PROGRESS", statuses)
        in_progress = next(
            response.get_json()
            for response in responses
            if response.status_code == 202
        )
        for field in (
            "mode",
            "serial_transport",
            "transaction_id",
            "result",
            "reason",
            "ack_state",
            "ack_origin",
            "gateway_local_lock_time_utc",
            "stop_dispatch_time_utc",
            "stop_ack_time_utc",
            "gateway_processing_ms",
            "ack_latency_ms",
            "command_total_ms",
        ):
            self.assertIn(field, in_progress)

    def test_different_mitigation_incidents_coalesce_during_stop_flight(self) -> None:
        self.bridge.mock_ack_delay_ms = 65
        responses = []
        first = threading.Thread(
            target=lambda: responses.append(self.post(self.payload(key="incident-a")))
        )
        with mock.patch.object(
            self.bridge, "_send_transaction", wraps=self.bridge._send_transaction
        ) as send_spy:
            first.start()
            deadline = time.monotonic() + 0.5
            while self.bridge.stop_inflight is None and time.monotonic() < deadline:
                time.sleep(0.001)
            second = self.post(
                self.payload(
                    key="incident-b",
                    incident_id="incident-002",
                    detection_id="detection-002",
                )
            )
            first.join(timeout=1)

        self.assertFalse(first.is_alive())
        self.assertEqual(send_spy.call_count, 1)
        self.assertEqual(second.status_code, 202)
        self.assertEqual(
            second.get_json()["mitigation_status"],
            "COALESCED_WITH_EXISTING_STOP",
        )
        self.assertIsNone(second.get_json()["transaction_id"])

    def make_hardware_bridge(self, response_factory=None, *, fail_write=False):
        connection = RespondingSerialConnection(
            response_factory=response_factory, fail_write=fail_write
        )
        fake_serial = types.SimpleNamespace(Serial=mock.Mock(return_value=connection))
        with mock.patch.object(app, "serial", fake_serial):
            bridge = app.SerialBridge(
                mock_mode=False,
                port="/dev/test-hardware",
                baud=115200,
                safe_boot_locked=True,
                serial_ack_timeout_ms=45,
                mock_ack_delay_ms=0,
                keepalive_enabled=False,
                keepalive_interval_ms=3000,
            )
        return bridge, connection

    def test_hardware_authoritative_ack_is_acknowledged_downstream(self) -> None:
        bridge, _ = self.make_hardware_bridge(
            lambda txid, verb: f"ACK,{txid},{verb},LOCKED,VEHICLE"
        )
        self.replace_bridge(bridge)
        body = self.post().get_json()
        self.assertEqual(body["mitigation_status"], "ACKNOWLEDGED_DOWNSTREAM")
        self.assertTrue(body["vehicle_stop_confirmed"])
        self.assertIsNotNone(body["stop_ack_time_utc"])

    def test_nack_timeout_unavailable_and_write_failure_are_execution_unknown(self) -> None:
        cases = []

        nack_bridge = self.make_mock_bridge()
        nack_bridge.set_mock_ack_behavior("NACK", reason="STOP_REJECTED")
        cases.append((nack_bridge, "NACK"))

        timeout_bridge = self.make_mock_bridge(timeout_ms=20)
        timeout_bridge.set_mock_ack_behavior("TIMEOUT")
        cases.append((timeout_bridge, "ACK_TIMEOUT"))

        fake_serial = types.SimpleNamespace(
            Serial=mock.Mock(side_effect=OSError("port unavailable"))
        )
        with mock.patch.object(app, "serial", fake_serial):
            unavailable_bridge = app.SerialBridge(
                False, "/dev/unavailable", 115200, True, 20, 0, False, 3000
            )
        cases.append((unavailable_bridge, "SERIAL_UNAVAILABLE"))

        failure_bridge = self.make_mock_bridge()
        failure_bridge.set_mock_ack_behavior("WRITE_ERROR")
        cases.append((failure_bridge, "SERIAL_WRITE_ERROR"))

        for index, (bridge, expected_result) in enumerate(cases):
            with self.subTest(index=index, result=expected_result):
                self.replace_bridge(bridge)
                body = self.post(self.payload(key=f"failure-{index}")).get_json()
                self.assertEqual(body["result"], expected_result)
                self.assertEqual(body["mitigation_status"], "EXECUTION_UNKNOWN")
                self.assertTrue(body["gateway_locked"])
                self.assertFalse(body["vehicle_stop_confirmed"])
                self.assertIsNone(body["stop_ack_time_utc"])

    def test_wrong_ack_state_and_origin_are_execution_unknown(self) -> None:
        for index, (state, origin) in enumerate(
            (("RUNNING", "VEHICLE"), ("LOCKED", "HUB"))
        ):
            with self.subTest(state=state, origin=origin):
                bridge = self.make_mock_bridge()
                bridge.set_mock_ack_behavior("ACK", state=state, origin=origin)
                self.replace_bridge(bridge)
                body = self.post(self.payload(key=f"wrong-ack-{index}")).get_json()
                self.assertEqual(body["mitigation_status"], "EXECUTION_UNKNOWN")
                self.assertIsNone(body["stop_ack_time_utc"])
                self.assertTrue(body["gateway_locked"])

    def test_unexpected_internal_dispatch_failure_is_sanitized_and_locked(self) -> None:
        with mock.patch.object(
            self.bridge, "write", side_effect=RuntimeError("private internal detail")
        ):
            response = self.post(self.payload(key="internal-failure"))
        body = response.get_json()
        self.assertEqual(response.status_code, 500)
        self.assertEqual(body["mitigation_status"], "EXECUTION_UNKNOWN")
        self.assertEqual(body["reason"], "MITIGATION_DISPATCH_INTERNAL_FAILURE")
        self.assertNotIn("private internal detail", json.dumps(body))
        self.assertTrue(body["gateway_locked"])
        self.assertIsNone(self.bridge.stop_inflight)

    def test_mitigation_disables_active_keepalive(self) -> None:
        bridge = self.make_mock_bridge(
            keepalive_enabled=True, keepalive_interval_ms=500
        )
        with bridge.state_lock:
            bridge.locked = False
            bridge.acknowledged_state = "RUNNING"
            bridge.state_generation += 1
        bridge.keepalive_wakeup.set()
        self.replace_bridge(bridge)
        self.assertTrue(self.bridge.get_status()["keepalive_active"])
        body = self.post().get_json()
        self.assertTrue(body["gateway_locked"])
        self.assertFalse(self.bridge.get_status()["keepalive_active"])

    def test_keepalive_safety_and_mitigation_stop_coalesce_without_deadlock(self) -> None:
        self.bridge.mock_ack_delay_ms = 70
        results = []
        safety = threading.Thread(
            target=lambda: results.append(
                self.bridge.write("STOP", source="AUTO_KEEPALIVE_SAFETY")
            )
        )
        with mock.patch.object(
            self.bridge, "_send_transaction", wraps=self.bridge._send_transaction
        ) as send_spy:
            safety.start()
            deadline = time.monotonic() + 0.5
            while self.bridge.stop_inflight is None and time.monotonic() < deadline:
                time.sleep(0.001)
            response = self.post(self.payload(key="keepalive-race"))
            safety.join(timeout=1)

        self.assertFalse(safety.is_alive())
        self.assertEqual(send_spy.call_count, 1)
        self.assertEqual(response.status_code, 202)
        self.assertEqual(
            response.get_json()["mitigation_status"],
            "COALESCED_WITH_EXISTING_STOP",
        )
        self.assertTrue(response.get_json()["gateway_locked"])

    def test_manual_and_mitigation_stop_do_not_corrupt_transaction_state(self) -> None:
        self.bridge.mock_ack_delay_ms = 60
        manual_results = []
        manual = threading.Thread(target=lambda: manual_results.append(self.bridge.write("STOP")))
        with mock.patch.object(
            self.bridge, "_send_transaction", wraps=self.bridge._send_transaction
        ) as send_spy:
            manual.start()
            deadline = time.monotonic() + 0.5
            while self.bridge.stop_inflight is None and time.monotonic() < deadline:
                time.sleep(0.001)
            response = self.post(self.payload(key="manual-race"))
            manual.join(timeout=1)

        self.assertFalse(manual.is_alive())
        self.assertEqual(send_spy.call_count, 1)
        self.assertEqual(manual_results[0].outcome, "ACKNOWLEDGED")
        self.assertEqual(response.get_json()["result"], "STOP_COALESCED")
        self.assertIsNone(response.get_json()["transaction_id"])

    def test_mitigation_local_lock_cannot_be_undone_by_inflight_reset(self) -> None:
        self.bridge.mock_ack_delay_ms = 55
        reset_results = []
        reset = threading.Thread(
            target=lambda: reset_results.append(self.bridge.write("RESET"))
        )
        reset.start()
        deadline = time.monotonic() + 0.5
        while (
            (
                self.bridge.pending_transaction is None
                or self.bridge.pending_transaction.verb != "RESET"
            )
            and time.monotonic() < deadline
        ):
            time.sleep(0.001)
        response = self.post(self.payload(key="reset-race"))
        reset.join(timeout=1)

        self.assertFalse(reset.is_alive())
        self.assertEqual(reset_results[0].outcome, "NACK")
        self.assertEqual(reset_results[0].reason, "AUTHORITATIVE_STATE_CHANGED")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["gateway_locked"])
        self.assertTrue(self.bridge.get_status()["gateway_locked"])

    def test_bounded_cache_evicts_completed_not_in_progress(self) -> None:
        self.install_manager(cache_size=1)
        first = self.post(self.payload(key="cache-one"))
        second = self.post(self.payload(key="cache-two"))
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(list(self.manager.records), ["cache-two"])

        self.bridge.mock_ack_delay_ms = 60
        worker = threading.Thread(
            target=lambda: self.post(self.payload(key="cache-three"))
        )
        worker.start()
        deadline = time.monotonic() + 0.5
        while "cache-three" not in self.manager.records and time.monotonic() < deadline:
            time.sleep(0.001)
        rejected = self.post(self.payload(key="cache-four"))
        worker.join(timeout=1)
        self.assertEqual(rejected.status_code, 503)
        self.assertIn("cache-three", self.manager.records)

    def test_shutdown_resolves_inflight_request(self) -> None:
        bridge = self.make_mock_bridge(timeout_ms=1200)
        bridge.set_mock_ack_behavior("TIMEOUT")
        self.replace_bridge(bridge)
        responses = []
        worker = threading.Thread(
            target=lambda: responses.append(self.post(self.payload(key="shutdown")))
        )
        worker.start()
        deadline = time.monotonic() + 0.5
        while self.bridge.pending_transaction is None and time.monotonic() < deadline:
            time.sleep(0.001)
        self.bridge.close()
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(
            responses[0].get_json()["mitigation_status"], "EXECUTION_UNKNOWN"
        )
        self.assertTrue(responses[0].get_json()["gateway_locked"])

    def test_token_never_appears_in_responses_health_or_ledger(self) -> None:
        response = self.post()
        duplicate = self.post()
        with app.app.test_client() as client:
            health = client.get("/api/health")

        combined = json.dumps(
            [response.get_json(), duplicate.get_json(), health.get_json()],
            sort_keys=True,
        )
        self.assertNotIn(TEST_TOKEN, combined)
        self.assertNotIn("Authorization", combined)
        self.assertNotIn(TEST_TOKEN, app.MITIGATION_CSV.read_text(encoding="utf-8"))
        with app.MITIGATION_CSV.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertTrue(any(row["phase"] == "FINALIZED" for row in rows))

    def test_success_response_and_ledger_have_complete_timing_evidence(self) -> None:
        body = self.post(self.payload(key="timing-evidence")).get_json()
        for field in (
            "gateway_request_received_time_utc",
            "gateway_local_lock_time_utc",
            "stop_dispatch_time_utc",
            "stop_ack_time_utc",
            "gateway_response_time_utc",
            "gateway_processing_ms",
            "ack_latency_ms",
            "command_total_ms",
        ):
            self.assertIn(field, body)
            self.assertIsNotNone(body[field], field)
        with app.MITIGATION_CSV.open(newline="", encoding="utf-8") as handle:
            phases = {
                row["phase"]
                for row in csv.DictReader(handle)
                if row["idempotency_key"] == "timing-evidence"
            }
        self.assertTrue(
            {
                "REQUEST_RECEIVED",
                "LOCALLY_LOCKED",
                "STOP_DISPATCHED",
                "RESPONSE_RECEIVED",
                "FINALIZED",
            }.issubset(phases)
        )

    def test_action_and_performance_ledgers_are_untouched(self) -> None:
        action_before = Path(app.ACTIONS_CSV).read_bytes()
        performance_before = Path(app.PERFORMANCE_CSV).read_bytes()
        response = self.post(self.payload(key="isolated-ledgers"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Path(app.ACTIONS_CSV).read_bytes(), action_before)
        self.assertEqual(Path(app.PERFORMANCE_CSV).read_bytes(), performance_before)


if __name__ == "__main__":
    unittest.main()
