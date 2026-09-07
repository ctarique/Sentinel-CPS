from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any


PACKAGE_DIR = Path(__file__).resolve().parents[1]
TOOLS_DIR = PACKAGE_DIR / "tools"
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "golden"
if str(PACKAGE_DIR) not in sys.path:
    sys.path.insert(0, str(PACKAGE_DIR))

from anomaly_engine import (  # noqa: E402
    DEFAULT_CONFIG,
    OUTPUT_FIELDNAMES,
    ConfigurationError,
    SourceFiles,
    build_output_row,
    deduplicate,
    evaluate_anomalies,
    load_configuration,
    severity_for_score,
    validate_configuration,
)


def action(timestamp: Any, command: str = "TRACK_UPDATE", index: int = 0) -> dict[str, Any]:
    return {
        "timestamp": timestamp,
        "event_id": f"action_{index}",
        "source": "automation" if index % 2 else "web_ui",
        "command": command,
        "result": "REJECTED" if index % 2 else "SUCCESS",
    }


def telemetry(timestamp: Any, adc_l: Any = "2000", adc_r: Any = "2000", steer: Any = "0.0", state: str = "RUNNING") -> dict[str, Any]:
    return {
        "timestamp": timestamp,
        "adc_l": adc_l,
        "adc_r": adc_r,
        "steer": steer,
        "state": state,
    }


def ebpf(timestamp: Any, syscall: str = "write", device_match: str = "true") -> dict[str, Any]:
    return {
        "timestamp": timestamp,
        "syscall": syscall,
        "device_match": device_match,
    }


def rows_for_rule(rows: list[dict[str, Any]], rule_id: str) -> list[dict[str, Any]]:
    return [row for row in rows if row["rule_id"] == rule_id]


def normalized_csv_values(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [{name: str(row[name]) for name in OUTPUT_FIELDNAMES} for row in rows]


class EngineRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.original_timezone = os.environ.get("TZ")
        os.environ["TZ"] = "UTC"
        if hasattr(time, "tzset"):
            time.tzset()

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.original_timezone is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = cls.original_timezone
        if hasattr(time, "tzset"):
            time.tzset()

    def evaluate(
        self,
        actions: list[dict[str, Any]] | None = None,
        telemetry_rows: list[dict[str, Any]] | None = None,
        ebpf_rows: list[dict[str, Any]] | None = None,
        **overrides: Any,
    ) -> list[dict[str, Any]]:
        config = dict(DEFAULT_CONFIG)
        config.update(overrides)
        return evaluate_anomalies(actions or [], telemetry_rows or [], ebpf_rows or [], config)

    def test_r001_below_equal_and_above_threshold(self) -> None:
        for count, expected in ((3, 0), (4, 0), (5, 1)):
            with self.subTest(count=count):
                actions = [action(100 + index * 0.1, index=index) for index in range(count)]
                detected = rows_for_rule(self.evaluate(actions=actions), "R001")
                self.assertEqual(expected, len(detected))
        self.assertEqual("5 commands observed within 5.0s.", detected[0]["description"])

    def test_r002_below_equal_and_above_threshold(self) -> None:
        for count, expected in ((7, 0), (8, 0), (9, 1)):
            with self.subTest(count=count):
                rows = [telemetry(200 + index * 0.1) for index in range(count)]
                detected = rows_for_rule(self.evaluate(telemetry_rows=rows), "R002")
                self.assertEqual(expected, len(detected))

    def test_r003_below_equal_and_above_threshold(self) -> None:
        for count, expected in ((2, 0), (3, 0), (4, 1)):
            with self.subTest(count=count):
                actions = [
                    action(300 + index, "START" if index % 2 == 0 else "STOP", index)
                    for index in range(count)
                ]
                detected = rows_for_rule(self.evaluate(actions=actions), "R003")
                self.assertEqual(expected, len(detected))
        self.assertEqual("4 START/STOP commands observed within 10.0s.", detected[0]["description"])

    def test_r004_inside_and_outside_inclusive_window(self) -> None:
        stop = [action(400, "STOP", 1)]
        inside = [ebpf(400.5), ebpf(410.0)]
        detected = rows_for_rule(self.evaluate(actions=stop, ebpf_rows=inside), "R004")
        self.assertEqual(1, len(detected))
        self.assertIn("2 serial write event(s)", detected[0]["description"])

        outside = [ebpf(400.499999), ebpf(410.000001)]
        self.assertEqual([], rows_for_rule(self.evaluate(actions=stop, ebpf_rows=outside), "R004"))

    def test_r004_preserves_locked_telemetry_marker(self) -> None:
        locked = [telemetry(420, state="LOCKED")]
        detected = rows_for_rule(self.evaluate(telemetry_rows=locked, ebpf_rows=[ebpf(420.5)]), "R004")
        self.assertEqual(1, len(detected))
        self.assertEqual("locked_marker_420.000", detected[0]["evidence_reference"])

    def test_r005_accepts_valid_finite_values(self) -> None:
        rows = [telemetry(500, "1.9", "-2", "0.125")]
        self.assertEqual([], rows_for_rule(self.evaluate(telemetry_rows=rows), "R005"))

    def test_r005_flags_malformed_numeric_values(self) -> None:
        rows = [
            telemetry(510, "DROP", "2", "0"),
            telemetry(511, "1", "", "0"),
            telemetry(512, "1", "2", "ERR"),
        ]
        self.assertEqual(3, len(rows_for_rule(self.evaluate(telemetry_rows=rows), "R005")))

    def test_r005_flags_nan_and_infinity(self) -> None:
        rows = [
            telemetry(520, "NaN", "2", "0"),
            telemetry(521, "1", "inf", "0"),
            telemetry(522, "1", "2", "-inf"),
        ]
        self.assertEqual(3, len(rows_for_rule(self.evaluate(telemetry_rows=rows), "R005")))

    def test_r006_below_equal_and_above_whole_file_threshold(self) -> None:
        for count, expected in ((1, 0), (2, 0), (3, 1)):
            with self.subTest(count=count):
                writes = [ebpf(600 + index * 100) for index in range(count)]
                detected = rows_for_rule(self.evaluate(ebpf_rows=writes), "R006")
                self.assertEqual(expected, len(detected))
        self.assertIn("3 serial write event(s)", detected[0]["description"])

    def test_r007_requires_enough_intervals(self) -> None:
        rows = [telemetry(700 + index) for index in range(5)]
        self.assertEqual([], rows_for_rule(self.evaluate(telemetry_rows=rows), "R007"))

    def test_r007_matches_highly_regular_one_second_intervals(self) -> None:
        rows = [telemetry(710 + index) for index in range(6)]
        detected = rows_for_rule(self.evaluate(telemetry_rows=rows), "R007")
        self.assertEqual(1, len(detected))
        self.assertEqual("telemetry_interval_start_1", detected[0]["evidence_reference"])

    def test_r007_rejects_irregular_intervals(self) -> None:
        rows = [telemetry(value) for value in (720, 721, 722.2, 723, 724.5, 726)]
        self.assertEqual([], rows_for_rule(self.evaluate(telemetry_rows=rows), "R007"))

    def test_forward_and_correlation_window_boundaries_are_inclusive(self) -> None:
        r001 = rows_for_rule(self.evaluate(
            actions=[action(1000, index=0), action(1005, index=1)],
            max_commands_per_window=1,
        ), "R001")
        r002 = rows_for_rule(self.evaluate(
            telemetry_rows=[telemetry(1100), telemetry(1102)],
            max_telemetry_rows_per_window=1,
        ), "R002")
        r003 = rows_for_rule(self.evaluate(
            actions=[action(1200, "START", 0), action(1210, "STOP", 1)],
            max_start_stop_toggles_per_window=1,
        ), "R003")
        r006_at_boundary = rows_for_rule(self.evaluate(
            actions=[action(1302)],
            ebpf_rows=[ebpf(1300)],
            max_orphan_serial_writes=0,
        ), "R006")
        r006_outside_boundary = rows_for_rule(self.evaluate(
            actions=[action(1302.000001)],
            ebpf_rows=[ebpf(1300)],
            max_orphan_serial_writes=0,
        ), "R006")
        self.assertEqual((1, 1, 1), (len(r001), len(r002), len(r003)))
        self.assertEqual([], r006_at_boundary)
        self.assertEqual(1, len(r006_outside_boundary))

    def test_default_score_to_severity_boundaries(self) -> None:
        config = validate_configuration({})
        expected = {
            39: "INFO",
            40: "LOW",
            69: "LOW",
            70: "MEDIUM",
            89: "MEDIUM",
            90: "HIGH",
        }
        self.assertEqual(expected, {score: severity_for_score(score, config) for score in expected})

    def test_configurable_r005_and_r006_penalties(self) -> None:
        malformed = rows_for_rule(
            self.evaluate(telemetry_rows=[telemetry(800, "bad")], malformed_telemetry_penalty=41),
            "R005",
        )[0]
        orphan = rows_for_rule(
            self.evaluate(
                ebpf_rows=[ebpf(810), ebpf(820), ebpf(830)],
                orphan_serial_activity_penalty=71,
            ),
            "R006",
        )[0]
        self.assertEqual((41, "LOW"), (malformed["score"], malformed["severity"]))
        self.assertEqual((71, "MEDIUM"), (orphan["score"], orphan["severity"]))

    def test_integer_second_output_deduplication(self) -> None:
        config = validate_configuration({})
        anomalies = [
            build_output_row(ts, "COMMAND_BURST", "actions.csv", "X", 85, "R001", "d", "r", str(ts), config)
            for ts in (2.0, 1.9, 1.1)
        ]
        output = deduplicate(anomalies)
        self.assertEqual(["1.100000", "2.000000"], [row["timestamp"] for row in output])

    def test_deterministic_timestamp_ordering(self) -> None:
        rows = self.evaluate(
            actions=[action(920 + index * 0.1, index=index) for index in range(5)],
            telemetry_rows=[telemetry(900, "bad")],
            ebpf_rows=[ebpf(910), ebpf(911), ebpf(912)],
        )
        timestamps = [float(row["timestamp"]) for row in rows]
        self.assertEqual(sorted(timestamps), timestamps)
        self.assertEqual(rows, self.evaluate(
            actions=[action(920 + index * 0.1, index=index) for index in range(5)],
            telemetry_rows=[telemetry(900, "bad")],
            ebpf_rows=[ebpf(910), ebpf(911), ebpf(912)],
        ))

    def test_empty_inputs(self) -> None:
        self.assertEqual([], self.evaluate())

    def test_malformed_or_missing_timestamps_are_ignored(self) -> None:
        invalid = ["", "NaN", "inf", "not-a-time", None]
        rows = self.evaluate(
            actions=[action(value, index=index) for index, value in enumerate(invalid)],
            telemetry_rows=[telemetry(value, "bad") for value in invalid] + [{"adc_l": "bad"}],
            ebpf_rows=[ebpf(value) for value in invalid] + [{"syscall": "write", "device_match": "true"}],
        )
        self.assertEqual([], rows)

    def test_golden_fixture_parity_for_all_rules(self) -> None:
        with (FIXTURE_DIR / "actions.csv").open(newline="", encoding="utf-8") as source:
            actions = list(csv.DictReader(source))
        with (FIXTURE_DIR / "telemetry.csv").open(newline="", encoding="utf-8") as source:
            telemetry_rows = list(csv.DictReader(source))
        with (FIXTURE_DIR / "serial_trace.csv").open(newline="", encoding="utf-8") as source:
            ebpf_rows = list(csv.DictReader(source))
        with (FIXTURE_DIR / "expected_rows.json").open(encoding="utf-8") as source:
            expected = json.load(source)

        actual = evaluate_anomalies(
            actions,
            telemetry_rows,
            ebpf_rows,
            load_configuration(PACKAGE_DIR / "config" / "anomaly_rules.example.json"),
            SourceFiles("actions.csv", "telemetry.csv", "serial_trace.csv"),
        )
        self.assertEqual(expected, normalized_csv_values(actual))
        self.assertEqual({f"R00{index}" for index in range(1, 8)}, {row["rule_id"] for row in actual})

    def test_engine_rows_can_be_extended_without_changing_offline_schema(self) -> None:
        row = self.evaluate(telemetry_rows=[telemetry(950, "bad")])[0]
        extended = {**row, "provenance": "future-live-only"}
        self.assertEqual("future-live-only", extended["provenance"])
        self.assertNotIn("provenance", OUTPUT_FIELDNAMES)


class ConfigurationValidationTests(unittest.TestCase):
    def test_missing_fields_receive_baseline_defaults(self) -> None:
        self.assertEqual(DEFAULT_CONFIG, validate_configuration({}))

    def test_malformed_values_are_rejected_clearly(self) -> None:
        invalid_configs = [
            {"command_burst_window_sec": float("nan")},
            {"telemetry_flood_window_sec": float("inf")},
            {"toggle_window_sec": 0},
            {"locked_write_grace_sec": -0.1},
            {"max_commands_per_window": -1},
            {"max_telemetry_rows_per_window": 2.5},
            {"replay_like_sequence_length": 0},
            {"malformed_telemetry_penalty": -1},
            {
                "anomaly_score_threshold_low": 70,
                "anomaly_score_threshold_medium": 40,
                "anomaly_score_threshold_high": 90,
            },
        ]
        for config in invalid_configs:
            with self.subTest(config=config), self.assertRaisesRegex(ConfigurationError, "Configuration|Severity"):
                validate_configuration(config)

        with self.assertRaisesRegex(ConfigurationError, "JSON object"):
            validate_configuration([])  # type: ignore[arg-type]

    def test_malformed_json_is_rejected_clearly(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bad.json"
            path.write_text("{not-json", encoding="utf-8")
            with self.assertRaisesRegex(ConfigurationError, "Malformed JSON configuration"):
                load_configuration(path)


class OfflineCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.original_timezone = os.environ.get("TZ")
        os.environ["TZ"] = "UTC"
        if hasattr(time, "tzset"):
            time.tzset()

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.original_timezone is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = cls.original_timezone
        if hasattr(time, "tzset"):
            time.tzset()

    def run_cli(
        self,
        output_dir: Path,
        actions: Path,
        telemetry_path: Path,
        ebpf_path: Path,
    ) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment.update({"TZ": "UTC", "PYTHONDONTWRITEBYTECODE": "1"})
        return subprocess.run(
            [
                sys.executable,
                str(TOOLS_DIR / "score_anomalies.py"),
                "--actions", str(actions),
                "--telemetry", str(telemetry_path),
                "--ebpf", str(ebpf_path),
                "--config", str(PACKAGE_DIR / "config" / "anomaly_rules.example.json"),
                "--output-dir", str(output_dir),
            ],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )

    @staticmethod
    def read_only_output(output_dir: Path) -> tuple[list[str], list[dict[str, str]]]:
        outputs = list(output_dir.glob("anomaly_scores_*.csv"))
        if len(outputs) != 1:
            raise AssertionError(f"Expected one scorer output, found {outputs}")
        with outputs[0].open(newline="", encoding="utf-8") as source:
            reader = csv.DictReader(source)
            return reader.fieldnames or [], list(reader)

    def test_missing_files_keep_warning_and_empty_output_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            result = self.run_cli(
                root / "output",
                root / "missing_actions.csv",
                root / "missing_telemetry.csv",
                root / "missing_ebpf.csv",
            )
            self.assertEqual(3, result.stdout.count("[WARN] Input file not found:"))
            self.assertIn("[*] Anomalies written: 0", result.stdout)
            fields, rows = self.read_only_output(root / "output")
            self.assertEqual(OUTPUT_FIELDNAMES, fields)
            self.assertEqual([], rows)

    def test_empty_files_and_offline_schema_column_order(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            files = []
            for name, header in (
                ("actions.csv", "timestamp,event_id,source,command,details,result\n"),
                ("telemetry.csv", "timestamp,vehicle_id,adc_l,adc_r,steer,state,source\n"),
                ("ebpf.csv", "timestamp,syscall,device_match\n"),
            ):
                path = root / name
                path.write_text(header, encoding="utf-8")
                files.append(path)
            self.run_cli(root / "output", *files)
            fields, rows = self.read_only_output(root / "output")
            self.assertEqual(OUTPUT_FIELDNAMES, fields)
            self.assertEqual([], rows)

    def test_cli_matches_direct_engine_and_golden_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "output"
            self.run_cli(
                output_dir,
                FIXTURE_DIR / "actions.csv",
                FIXTURE_DIR / "telemetry.csv",
                FIXTURE_DIR / "serial_trace.csv",
            )
            fields, cli_rows = self.read_only_output(output_dir)
            with (FIXTURE_DIR / "expected_rows.json").open(encoding="utf-8") as source:
                expected = json.load(source)
            self.assertEqual(OUTPUT_FIELDNAMES, fields)
            self.assertEqual(expected, cli_rows)

            loaded = []
            for filename in ("actions.csv", "telemetry.csv", "serial_trace.csv"):
                with (FIXTURE_DIR / filename).open(newline="", encoding="utf-8") as source:
                    loaded.append(list(csv.DictReader(source)))
            direct = evaluate_anomalies(*loaded, load_configuration(PACKAGE_DIR / "config" / "anomaly_rules.example.json"))
            self.assertEqual(cli_rows, normalized_csv_values(direct))

    def test_repeated_cli_execution_has_identical_normalized_results(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            results = []
            for run_number in (1, 2):
                output_dir = root / f"run_{run_number}"
                self.run_cli(
                    output_dir,
                    FIXTURE_DIR / "actions.csv",
                    FIXTURE_DIR / "telemetry.csv",
                    FIXTURE_DIR / "serial_trace.csv",
                )
                results.append(self.read_only_output(output_dir)[1])
            self.assertEqual(results[0], results[1])

    def test_incident_report_keeps_medium_row_stop_recommendation_discrepancy(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_path = root / "scores.csv"
            row = {
                name: "" for name in OUTPUT_FIELDNAMES
            }
            row.update({
                "timestamp": "1000.000000",
                "severity": "MEDIUM",
                "score": "80",
                "rule_id": "R003",
                "event_type": "REPEATED_START_STOP_TOGGLE",
                "recommended_response": "Keep system in STOP/LOCKED if unsafe.",
            })
            with input_path.open("w", newline="", encoding="utf-8") as output:
                writer = csv.DictWriter(output, fieldnames=OUTPUT_FIELDNAMES)
                writer.writeheader()
                writer.writerow(row)
            subprocess.run(
                [
                    sys.executable,
                    str(TOOLS_DIR / "make_val05_incident_report.py"),
                    "--input", str(input_path),
                    "--output-dir", str(root / "reports"),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            report = next((root / "reports").glob("val05_incident_report_*.md")).read_text(encoding="utf-8")
            self.assertIn("HIGH severity: **0**", report)
            self.assertIn("STOP recommended by offline analysis: **YES**", report)

    def test_engine_import_has_no_runtime_side_effects(self) -> None:
        script = f"""
import json
import math
import os
import socket
import sys
import threading
from pathlib import Path
from typing import Any

class GuardedEnvironment(dict):
    def __getitem__(self, key: str) -> str:
        raise AssertionError(f'environment secret read: {{key}}')
    def get(self, key: str, default: Any = None) -> Any:
        raise AssertionError(f'environment secret read: {{key}}')

def forbidden(*args: Any, **kwargs: Any) -> None:
    raise AssertionError('thread or network activity during import')

threading.Thread.start = forbidden
socket.create_connection = forbidden
socket.socket.connect = forbidden
os.environ = GuardedEnvironment()
before_files = set(Path.cwd().iterdir())
before_threads = tuple(threading.enumerate())
sys.path.insert(0, {str(PACKAGE_DIR)!r})
import anomaly_engine
assert set(Path.cwd().iterdir()) == before_files
assert tuple(threading.enumerate()) == before_threads
assert anomaly_engine.OUTPUT_FIELDNAMES
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            environment = dict(os.environ)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            result = subprocess.run(
                [sys.executable, "-c", script],
                cwd=temp_dir,
                capture_output=True,
                text=True,
                env=environment,
            )
        self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
