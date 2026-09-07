from __future__ import annotations

import csv
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any, Mapping

PACKAGE_DIR = Path(__file__).resolve().parents[1]
if str(PACKAGE_DIR) not in sys.path:
    sys.path.insert(0, str(PACKAGE_DIR))

from anomaly_engine import DEFAULT_CONFIG  # noqa: E402
from live_anomaly_monitor import (  # noqa: E402
    ACTIONS_HEADER,
    DETECTION_FIELDS,
    EBPF_HEADER,
    MITIGATION_FIELDS,
    TELEMETRY_HEADER,
    GatewayTransportError,
    LiveAnomalyMonitor,
    LiveConfigurationError,
    SchemaError,
    load_live_configuration,
)


def action(ts: float, command: str = "BOOT", result: str = "ACKNOWLEDGED", mode: str = "hardware", index: int = 0) -> dict[str, str]:
    return {
        "timestamp": str(ts), "event_id": f"evt_{index}", "source": "web_ui",
        "command": command, "details": "redacted", "result": result, "mode": mode,
    }


def telemetry(ts: float, *, bad: bool = False, state: str = "RUNNING", source: str = "serial_protocol") -> dict[str, str]:
    return {
        "timestamp": str(ts), "vehicle_id": "fixture_vehicle", "adc_l": "bad" if bad else "2000",
        "adc_r": "2000", "steer": "0.0", "state": state, "source": source,
    }


def ebpf(ts: float) -> dict[str, str]:
    return {
        "timestamp": str(ts), "timestamp_iso": "", "monotonic_ns": "1", "pid": "1",
        "comm": "python3", "syscall": "write", "fd": "3", "count": "6",
        "retval": "6", "fd_path": "/dev/fixture", "device_match": "True", "notes": "",
    }


class FakeGateway:
    def __init__(self, *, mode: str = "hardware", locked: bool = False, active: int = 0, response: Mapping[str, Any] | None = None, error: GatewayTransportError | None = None) -> None:
        self.mode = mode
        self.locked = locked
        self.active = active
        self.response = response
        self.error = error
        self.health_calls = 0
        self.stop_calls = 0
        self.payloads: list[Mapping[str, Any]] = []
        self.tokens: list[str] = []
        self.before_stop = None

    def health(self, timeout: float) -> tuple[int, Mapping[str, Any]]:
        del timeout
        self.health_calls += 1
        return 200, {
            "mode": self.mode,
            "serial_transport": "available" if self.mode == "hardware" else "mock",
            "status": "ok",
            "connected": self.mode == "hardware",
            "mitigation_api_enabled": True,
            "mitigation_api_ready": True,
            "mitigation_loopback_only": True,
            "gateway_locked": self.locked,
            "mitigation_active_requests": self.active,
            "safety_status": "NORMAL",
            "vehicle_stop_confirmed": False,
            "last_mitigation_status": None,
        }

    def stop(self, payload: Mapping[str, Any], token: str, timeout: float) -> tuple[int, Mapping[str, Any]]:
        del timeout
        self.stop_calls += 1
        self.payloads.append(dict(payload))
        self.tokens.append(token)
        if self.before_stop:
            self.before_stop()
        if self.error:
            raise self.error
        if self.response is not None:
            return 200, self.response
        return 200, acknowledged_response(self.mode)


def acknowledged_response(mode: str = "hardware") -> dict[str, Any]:
    synthetic = mode == "mock"
    return {
        "mitigation_status": "SYNTHETIC_ACKNOWLEDGED" if synthetic else "ACKNOWLEDGED_DOWNSTREAM",
        "mode": mode,
        "serial_transport": "mock" if synthetic else "available",
        "transaction_id": "tx_fixture", "result": "ACKNOWLEDGED", "reason": "",
        "ack_state": "LOCKED", "ack_origin": "VEHICLE", "gateway_locked": True,
        "vehicle_stop_confirmed": not synthetic, "synthetic": synthetic,
        "duplicate_suppressed": False, "coalesced": False,
        "gateway_request_received_time_utc": "2026-08-04T00:00:00Z",
        "gateway_local_lock_time_utc": "2026-08-04T00:00:00Z",
        "stop_dispatch_time_utc": "2026-08-04T00:00:00Z",
        "stop_ack_time_utc": "2026-08-04T00:00:00Z",
        "gateway_response_time_utc": "2026-08-04T00:00:00Z",
    }


class Harness:
    def __init__(self, test: unittest.TestCase) -> None:
        self.test = test
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.actions = self.root / "actions.csv"
        self.telemetry = self.root / "telemetry.csv"
        self.ebpf = self.root / "serial_trace.csv"
        self.rules = self.root / "rules.json"
        self.config = self.root / "live.json"
        self.state = self.root / "state"
        self.evidence = self.root / "evidence"
        self.clock_value = 1000.0
        self.rules.write_text(json.dumps(DEFAULT_CONFIG), encoding="utf-8")
        self.write_csv(self.actions, ACTIONS_HEADER, [])
        self.write_csv(self.telemetry, TELEMETRY_HEADER, [])
        self.write_csv(self.ebpf, EBPF_HEADER, [])
        self.write_config()

    def cleanup(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write_csv(path: Path, header: tuple[str, ...], rows: list[Mapping[str, Any]]) -> None:
        with path.open("w", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=header)
            writer.writeheader()
            writer.writerows(rows)

    def append_csv(self, path: Path, header: tuple[str, ...], rows: list[Mapping[str, Any]]) -> None:
        with path.open("a", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=header)
            writer.writerows(rows)

    def write_config(self, **overrides: Any) -> None:
        raw: dict[str, Any] = {
            "rule_configuration": str(self.rules),
            "inputs": {
                "actions_csv": str(self.actions), "telemetry_csv": str(self.telemetry),
                "ebpf_serial_trace_csv": str(self.ebpf),
            },
            "response_mode": "observe_only", "minimum_severity": "HIGH",
            "response_rule_allowlist": ["R002", "R004"],
            "gateway_url": "http://127.0.0.1:8080", "polling_interval_ms": 10,
            "allow_mock_mitigation": False, "require_hardware_provenance": True,
            "quiet_period_sec": 5, "http_timeout_sec": 0.1,
            "max_read_bytes_per_poll": 65536, "max_rows_per_source": 32,
            "state_directory": str(self.state), "evidence_directory": str(self.evidence),
        }
        raw.update(overrides)
        self.config.write_text(json.dumps(raw), encoding="utf-8")

    def load(self, *, token: bool = False):
        return load_live_configuration(self.config, token_available=token)

    def monitor(self, *, gateway: FakeGateway | None = None, token: str | None = None, fixture: bool = False) -> LiveAnomalyMonitor:
        config = self.load(token=bool(token))
        return LiveAnomalyMonitor(
            config, token=token, gateway_client=gateway,
            clock=lambda: self.clock_value, fixture_mode=fixture,
        )


class LiveMonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness(self)

    def tearDown(self) -> None:
        self.h.cleanup()

    def test_01_configuration_defaults_to_observe_only(self) -> None:
        raw = json.loads(self.h.config.read_text())
        raw.pop("response_mode")
        self.h.config.write_text(json.dumps(raw))
        self.assertEqual("observe_only", self.h.load().response_mode)

    def test_02_mitigation_mode_requires_token(self) -> None:
        self.h.write_config(response_mode="mitigate")
        with self.assertRaisesRegex(LiveConfigurationError, "requires SENTINEL"):
            self.h.load(token=False)

    def test_03_non_loopback_gateway_rejected(self) -> None:
        self.h.write_config(gateway_url="http://192.0.2.10:8080")
        with self.assertRaisesRegex(LiveConfigurationError, "loopback"):
            self.h.load()

    def test_04_partial_line_retained_until_complete(self) -> None:
        monitor = self.h.monitor(fixture=True)
        with self.h.telemetry.open("ab") as output:
            output.write(b"999,fixture,2000,2000,0.0,RUN")
        monitor.process_once()
        first_offset = monitor.state["tailers"]["telemetry"]["offset"]
        expected_header_offset = self.h.telemetry.read_bytes().find(b"\n") + 1
        self.assertEqual(expected_header_offset, first_offset)
        with self.h.telemetry.open("ab") as output:
            output.write(b"NING,serial_protocol\n")
        monitor.process_once()
        self.assertGreater(monitor.state["tailers"]["telemetry"]["offset"], first_offset)
        self.assertEqual(1, len(monitor.state["rows"]["telemetry"]))
        monitor.close()

    def test_05_malformed_csv_diagnosed_without_crash(self) -> None:
        monitor = self.h.monitor(fixture=True)
        with self.h.telemetry.open("a", encoding="utf-8") as output:
            output.write("999,too,few\n")
        monitor.process_once()
        self.assertTrue(any("malformed row" in item for item in monitor.diagnostics))
        invalid_write = ebpf(999)
        invalid_write["timestamp"] = "not-a-time"
        monitor.ingest_rows({"ebpf": [invalid_write]})
        self.assertEqual([], monitor.state["r006"]["pending"])
        monitor.close()

    def test_06_incompatible_header_rejected(self) -> None:
        self.h.telemetry.write_text("timestamp,old_schema\n", encoding="utf-8")
        monitor = self.h.monitor(fixture=True)
        with self.assertRaises(SchemaError):
            monitor.process_once()
        monitor.close()

    def test_07_offset_persistence_across_restart(self) -> None:
        self.h.append_csv(self.h.telemetry, TELEMETRY_HEADER, [telemetry(999, bad=True)])
        first = self.h.monitor(fixture=True)
        first.process_once()
        offset = first.state["tailers"]["telemetry"]["offset"]
        incident_id = first.state["incidents"]["R005"]["incident_id"]
        first.close()
        second = self.h.monitor(fixture=True)
        second.process_once()
        self.assertEqual(offset, second.state["tailers"]["telemetry"]["offset"])
        self.assertEqual(incident_id, second.state["incidents"]["R005"]["incident_id"])
        second.close()

    def test_08_truncation_handling(self) -> None:
        self.h.append_csv(self.h.telemetry, TELEMETRY_HEADER, [telemetry(999)])
        monitor = self.h.monitor(fixture=True)
        monitor.process_once()
        self.h.write_csv(self.h.telemetry, TELEMETRY_HEADER, [])
        monitor.process_once()
        self.assertTrue(any("truncation" in item for item in monitor.diagnostics))
        monitor.close()

    def test_09_rotation_replacement_handling(self) -> None:
        monitor = self.h.monitor(fixture=True)
        monitor.process_once()
        replacement = self.h.root / "replacement.csv"
        self.h.write_csv(replacement, TELEMETRY_HEADER, [telemetry(999)])
        os.replace(replacement, self.h.telemetry)
        monitor.process_once()
        self.assertTrue(any("replacement/rotation" in item for item in monitor.diagnostics))
        monitor.close()

    def test_10_bounded_memory(self) -> None:
        monitor = self.h.monitor(fixture=True)
        rows = [telemetry(990 + index / 1000) for index in range(1000)]
        monitor.ingest_rows({"telemetry": rows})
        self.assertLessEqual(len(monitor.state["rows"]["telemetry"]), 32)
        monitor.close()

    def _detect_rule(self, rule_id: str) -> tuple[LiveAnomalyMonitor, dict[str, Any]]:
        monitor = self.h.monitor(fixture=True)
        if rule_id == "R001":
            rows = {"actions": [action(999 + i / 10, "TRACK_UPDATE", index=i) for i in range(5)]}
        elif rule_id == "R002":
            rows = {"telemetry": [telemetry(999 + i / 100) for i in range(9)]}
        elif rule_id == "R003":
            rows = {"actions": [action(995 + i, "START" if i % 2 == 0 else "STOP", index=i) for i in range(4)]}
        elif rule_id == "R004":
            rows = {"actions": [action(995, "STOP")], "ebpf": [ebpf(995.5)]}
        elif rule_id == "R005":
            rows = {"telemetry": [telemetry(999, bad=True)]}
        elif rule_id == "R006":
            rows = {"ebpf": [ebpf(990), ebpf(991), ebpf(992)]}
        else:
            rows = {"telemetry": [telemetry(995 + i) for i in range(6)]}
        anomalies = monitor.ingest_rows(rows)
        match = next(item for item in anomalies if item["rule_id"] == rule_id)
        return monitor, match

    def test_11_all_seven_rules_produce_live_detections(self) -> None:
        for rule_id in (f"R00{i}" for i in range(1, 8)):
            with self.subTest(rule_id=rule_id):
                monitor, match = self._detect_rule(rule_id)
                self.assertEqual(rule_id, match["rule_id"])
                monitor.close()
                self.h.cleanup()
                self.h = Harness(self)

    def test_12_live_ids_scores_and_severities_match_baseline(self) -> None:
        expected = {
            "R001": (85, "MEDIUM"), "R002": (95, "HIGH"), "R003": (80, "MEDIUM"),
            "R004": (100, "HIGH"), "R005": (80, "MEDIUM"), "R006": (60, "LOW"),
            "R007": (45, "LOW"),
        }
        for rule_id, score_severity in expected.items():
            monitor, match = self._detect_rule(rule_id)
            self.assertEqual(score_severity, (match["score"], match["severity"]))
            monitor.close()
            self.h.cleanup()
            self.h = Harness(self)

    def test_13_r006_live_interpretation_labeled(self) -> None:
        monitor, match = self._detect_rule("R006")
        self.assertEqual("CURRENT_MONITOR_FILE_EPOCH_CUMULATIVE", match["live_interpretation"])
        self.assertIn("Live interpretation", match["description"])
        monitor.close()

    def test_14_r007_regular_telemetry_limitation_visible(self) -> None:
        monitor, match = self._detect_rule("R007")
        self.assertIn("weak signal", match["recommended_response"])
        monitor.close()

    def test_15_16_rising_edge_one_incident_and_continuing_no_second(self) -> None:
        monitor = self.h.monitor(fixture=True)
        monitor.ingest_rows({"telemetry": [telemetry(999, bad=True)]})
        first = monitor.state["incidents"]["R005"]["incident_id"]
        monitor.ingest_rows({"telemetry": [telemetry(999.5, bad=True)]})
        self.assertEqual(first, monitor.state["incidents"]["R005"]["incident_id"])
        with (self.h.evidence / "live_anomaly_events.csv").open(newline="", encoding="utf-8") as source:
            detections = [row for row in csv.DictReader(source) if row["rule_id"] == "R005" and row["condition_transition"] == "INACTIVE_TO_ACTIVE"]
        self.assertEqual(1, len(detections))
        monitor.close()

    def test_17_quiet_period_alone_does_not_rearm(self) -> None:
        monitor = self.h.monitor(fixture=True)
        monitor.ingest_rows({"telemetry": [telemetry(999, bad=True)]})
        self.h.clock_value = 1010
        monitor.ingest_rows({})
        self.h.clock_value = 1020
        monitor.ingest_rows({})
        self.assertEqual("CLEARED_NOT_REARMED", monitor.state["incidents"]["R005"]["state"])
        monitor.close()

    def test_18_reset_alone_does_not_rearm(self) -> None:
        monitor = self.h.monitor(fixture=True)
        monitor.ingest_rows({"telemetry": [telemetry(999, bad=True)]})
        monitor.ingest_rows({"actions": [action(1000, "RESET")]})
        self.assertIn("R005", monitor.state["incidents"])
        monitor.close()

    def test_19_quiet_plus_later_authoritative_reset_rearms(self) -> None:
        monitor = self.h.monitor(fixture=True)
        monitor.ingest_rows({"telemetry": [telemetry(999, bad=True)]})
        self.h.clock_value = 1010
        monitor.ingest_rows({})
        self.h.clock_value = 1016
        monitor.ingest_rows({"actions": [action(1016, "RESET")]})
        self.assertNotIn("R005", monitor.state["incidents"])
        self.assertEqual("REARMED", monitor.state["incident_history"][-1]["state"])
        monitor.close()

    def test_20_unprovable_reset_keeps_latched(self) -> None:
        monitor = self.h.monitor(fixture=True)
        monitor.ingest_rows({"telemetry": [telemetry(999, bad=True)]})
        self.h.clock_value = 1010
        monitor.ingest_rows({})
        self.h.clock_value = 1020
        monitor.ingest_rows({"actions": [action(1020, "RESET", result="SUCCESS")]})
        self.assertTrue(monitor.state["incidents"]["R005"]["manual_review_required"])
        monitor.close()

    def _mitigation_monitor(self, *, gateway: FakeGateway | None = None, **overrides: Any) -> tuple[LiveAnomalyMonitor, FakeGateway]:
        self.h.write_config(response_mode="mitigate", **overrides)
        fake = gateway or FakeGateway()
        return self.h.monitor(gateway=fake, token="T" * 40), fake

    def _hardware_r002(self, monitor: LiveAnomalyMonitor) -> None:
        monitor.ingest_rows({
            "actions": [action(999, "BOOT")],
            "telemetry": [telemetry(999 + i / 100) for i in range(9)],
        })

    def test_21_observe_only_never_calls_gateway(self) -> None:
        fake = FakeGateway()
        monitor = self.h.monitor(gateway=fake)
        monitor.ingest_rows({"telemetry": [telemetry(999, bad=True)]})
        self.assertEqual(0, fake.health_calls)
        self.assertEqual("OBSERVE_ONLY", monitor.state["incidents"]["R005"]["state"])
        monitor.close()

    def test_22_nonallowlisted_rule_never_calls_gateway(self) -> None:
        monitor, fake = self._mitigation_monitor()
        monitor.ingest_rows({"telemetry": [telemetry(999, bad=True)]})
        self.assertEqual(0, fake.stop_calls)
        monitor.close()

    def test_23_medium_stop_text_does_not_authorize(self) -> None:
        monitor, fake = self._mitigation_monitor(response_rule_allowlist=["R003"], minimum_severity="HIGH")
        monitor.ingest_rows({"actions": [action(995 + i, "START" if i % 2 == 0 else "STOP", index=i) for i in range(4)]})
        self.assertEqual(0, fake.stop_calls)
        self.assertEqual("SUPPRESSED_POLICY", monitor.state["incidents"]["R003"]["state"])
        monitor.close()

    def test_24_missing_provenance_suppresses(self) -> None:
        monitor, fake = self._mitigation_monitor()
        monitor.ingest_rows({"telemetry": [telemetry(999 + i / 100) for i in range(9)]})
        self.assertEqual(0, fake.stop_calls)
        self.assertEqual("SUPPRESSED_PROVENANCE", monitor.state["incidents"]["R002"]["state"])
        monitor.close()

    def test_25_mixed_provenance_suppresses(self) -> None:
        monitor, fake = self._mitigation_monitor()
        monitor.ingest_rows({
            "actions": [action(999, mode="hardware")],
            "telemetry": [telemetry(999, source="mock_generator")] + [telemetry(999 + i / 100) for i in range(1, 9)],
        })
        self.assertEqual(0, fake.stop_calls)
        self.assertEqual("MIXED_UNSUITABLE", monitor.state["incidents"]["R002"]["evidence_class"])
        monitor.close()

    def test_26_hardware_preflight_failure_suppresses(self) -> None:
        fake = FakeGateway(mode="mock")
        monitor, _ = self._mitigation_monitor(gateway=fake)
        self._hardware_r002(monitor)
        self.assertEqual(0, fake.stop_calls)
        self.assertEqual("SUPPRESSED_PROVENANCE", monitor.state["incidents"]["R002"]["state"])
        monitor.close()

    def test_27_already_locked_suppresses_duplicate_stop(self) -> None:
        fake = FakeGateway(locked=True)
        monitor, _ = self._mitigation_monitor(gateway=fake)
        self._hardware_r002(monitor)
        self.assertEqual(0, fake.stop_calls)
        self.assertEqual("SUPPRESSED_ALREADY_LOCKED", monitor.state["incidents"]["R002"]["state"])
        monitor.close()

    def test_28_eligible_r002_sends_once(self) -> None:
        monitor, fake = self._mitigation_monitor()
        self._hardware_r002(monitor)
        self.assertEqual(1, fake.stop_calls)
        monitor.close()

    def test_29_eligible_r004_sends_once(self) -> None:
        monitor, fake = self._mitigation_monitor()
        monitor.ingest_rows({"actions": [action(995, "STOP")], "telemetry": [telemetry(995)], "ebpf": [ebpf(995.5)]})
        self.assertEqual(1, fake.stop_calls)
        self.assertEqual("R004", fake.payloads[0]["rule_id"])
        monitor.close()

    def test_30_request_has_no_caller_command_fields(self) -> None:
        monitor, fake = self._mitigation_monitor()
        self._hardware_r002(monitor)
        self.assertTrue({"command", "verb", "action", "target", "state"}.isdisjoint(fake.payloads[0]))
        monitor.close()

    def test_31_token_only_reaches_authorization_boundary_not_artifacts(self) -> None:
        token = "TOKEN_ONLY_IN_AUTHORIZATION_1234567890"
        self.h.write_config(response_mode="mitigate")
        fake = FakeGateway()
        monitor = self.h.monitor(gateway=fake, token=token)
        self._hardware_r002(monitor)
        monitor.close()
        self.assertEqual([token], fake.tokens)
        for path in list(self.h.state.rglob("*")) + list(self.h.evidence.rglob("*")):
            if path.is_file():
                self.assertNotIn(token, path.read_text(encoding="utf-8"))

    def test_32_acknowledged_downstream_classified_strictly(self) -> None:
        monitor, _ = self._mitigation_monitor()
        self._hardware_r002(monitor)
        self.assertEqual("ACKNOWLEDGED_DOWNSTREAM", monitor.state["incidents"]["R002"]["state"])
        monitor.close()

    def test_33_mock_ack_is_synthetic(self) -> None:
        self.h.write_config(
            response_mode="mitigate", allow_mock_mitigation=True,
            require_hardware_provenance=False,
        )
        fake = FakeGateway(mode="mock", response=acknowledged_response("mock"))
        monitor = self.h.monitor(gateway=fake, token="T" * 40)
        monitor.ingest_rows({
            "actions": [action(999, mode="mock")],
            "telemetry": [telemetry(999 + i / 100, source="mock_generator") for i in range(9)],
        })
        self.assertEqual("SYNTHETIC_ACKNOWLEDGED", monitor.state["incidents"]["R002"]["state"])
        monitor.close()

    def test_34_http_200_execution_unknown_remains_unknown(self) -> None:
        fake = FakeGateway(response={"mitigation_status": "EXECUTION_UNKNOWN", "reason": "TIMEOUT", "mode": "hardware"})
        monitor, _ = self._mitigation_monitor(gateway=fake)
        self._hardware_r002(monitor)
        self.assertEqual("EXECUTION_UNKNOWN", monitor.state["incidents"]["R002"]["state"])
        monitor.close()

    def test_35_nack_timeout_serial_failures_remain_unknown(self) -> None:
        for reason in ("NACK", "TIMEOUT", "SERIAL_UNAVAILABLE", "WRITE_ERROR"):
            with self.subTest(reason=reason):
                fake = FakeGateway(response={"mitigation_status": "EXECUTION_UNKNOWN", "reason": reason, "mode": "hardware"})
                monitor, _ = self._mitigation_monitor(gateway=fake)
                self._hardware_r002(monitor)
                self.assertEqual("EXECUTION_UNKNOWN", monitor.state["incidents"]["R002"]["state"])
                monitor.close()
                self.h.cleanup()
                self.h = Harness(self)

    def test_36_http_timeout_ambiguous_and_not_retried(self) -> None:
        fake = FakeGateway(error=GatewayTransportError("HTTP_TIMEOUT"))
        monitor, _ = self._mitigation_monitor(gateway=fake)
        self._hardware_r002(monitor)
        self._hardware_r002(monitor)
        self.assertEqual(1, fake.stop_calls)
        self.assertEqual("EXECUTION_UNKNOWN", monitor.state["incidents"]["R002"]["state"])
        monitor.close()

    def test_37_concurrent_continuing_input_cannot_send_second(self) -> None:
        monitor, fake = self._mitigation_monitor()
        threads = [threading.Thread(target=self._hardware_r002, args=(monitor,)) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(1, fake.stop_calls)
        monitor.close()

    def _restart_with_ambiguous_state(self, state: str) -> None:
        first = self.h.monitor(fixture=True)
        first.ingest_rows({"telemetry": [telemetry(999, bad=True)]})
        first.close()
        state_path = self.h.state / "monitor_state.json"
        persisted = json.loads(state_path.read_text())
        persisted["incidents"]["R005"]["state"] = state
        persisted["incidents"]["R005"]["request_attempted"] = True
        state_path.write_text(json.dumps(persisted))
        fake = FakeGateway()
        second = self.h.monitor(gateway=fake)
        self.assertEqual("RECOVERY_REQUIRES_REVIEW", second.state["incidents"]["R005"]["state"])
        self.assertEqual(0, fake.stop_calls)
        second.close()

    def test_38_restart_after_request_planned_does_not_resend(self) -> None:
        self._restart_with_ambiguous_state("REQUEST_PLANNED")

    def test_39_restart_after_request_sent_does_not_resend(self) -> None:
        self._restart_with_ambiguous_state("REQUEST_SENT")

    def test_40_durable_latch_exists_before_http_call(self) -> None:
        monitor, fake = self._mitigation_monitor()
        observed: list[str] = []
        def inspect() -> None:
            state = json.loads((self.h.state / "monitor_state.json").read_text())
            observed.append(state["incidents"]["R002"]["state"])
        fake.before_stop = inspect
        self._hardware_r002(monitor)
        self.assertEqual(["REQUEST_SENT"], observed)
        monitor.close()

    def test_41_ledgers_have_stable_column_order(self) -> None:
        monitor = self.h.monitor(fixture=True)
        monitor.close()
        for name, fields in (("live_anomaly_events.csv", DETECTION_FIELDS), ("mitigation_events.csv", MITIGATION_FIELDS)):
            with (self.h.evidence / name).open(newline="", encoding="utf-8") as source:
                self.assertEqual(fields, tuple(next(csv.reader(source))))
            with (PACKAGE_DIR / "templates" / name.replace(".csv", "_template.csv")).open(newline="", encoding="utf-8") as source:
                self.assertEqual(fields, tuple(next(csv.reader(source))))

    def test_42_state_and_offsets_are_atomic_valid_json(self) -> None:
        monitor = self.h.monitor(fixture=True)
        monitor.process_once()
        monitor.close()
        json.loads((self.h.state / "monitor_state.json").read_text())
        self.assertEqual([], list(self.h.state.glob(".monitor_state.json.*")))

    def test_43_source_secret_fields_absent_from_artifacts(self) -> None:
        marker = "DO_NOT_PERSIST_PRIVATE_MARKER"
        monitor = self.h.monitor(fixture=True)
        row = telemetry(999)
        row["vehicle_id"] = marker
        row["source"] = "serial_protocol"
        monitor.ingest_rows({"telemetry": [row]})
        monitor.close()
        combined = "".join(path.read_text(encoding="utf-8") for root in (self.h.state, self.h.evidence) for path in root.rglob("*") if path.is_file())
        self.assertNotIn(marker, combined)

    def test_44_dry_run_labeled_and_never_calls_gateway(self) -> None:
        fake = FakeGateway()
        monitor = self.h.monitor(gateway=fake, fixture=True)
        monitor.ingest_rows({"telemetry": [telemetry(999, bad=True)]})
        monitor.close()
        manifest = next(self.h.evidence.glob("run_manifest_*.json")).read_text()
        self.assertIn("NON_PHYSICAL_FIXTURE", manifest)
        self.assertEqual(0, fake.stop_calls)

    def test_45_sigterm_style_shutdown_persists_cleanly(self) -> None:
        monitor = self.h.monitor(fixture=True)
        monitor.request_stop()
        monitor.run()
        monitor.close("COMPLETED")
        state = json.loads((self.h.state / "monitor_state.json").read_text())
        self.assertEqual("sentinel-live-v1", state["schema_version"])

    def test_46_paths_cannot_overlap_sources(self) -> None:
        self.h.write_config(state_directory=str(self.h.actions))
        with self.assertRaisesRegex(LiveConfigurationError, "overlap"):
            self.h.load()

    def test_47_allow_mock_conflict_rejected(self) -> None:
        self.h.write_config(allow_mock_mitigation=True, require_hardware_provenance=True)
        with self.assertRaisesRegex(LiveConfigurationError, "conflicts"):
            self.h.load()

    def test_48_configuration_forbids_secret_fields(self) -> None:
        self.h.write_config(token="forbidden")
        with self.assertRaisesRegex(LiveConfigurationError, "forbidden"):
            self.h.load()

    def test_49_state_root_has_single_process_owner(self) -> None:
        first = self.h.monitor(fixture=True)
        with self.assertRaisesRegex(LiveConfigurationError, "another monitor"):
            self.h.monitor(fixture=True)
        first.close()


if __name__ == "__main__":
    unittest.main()
