from __future__ import annotations

import ast
import csv
from dataclasses import replace
import hashlib
import json
import math
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

import joblib


PACKAGE_DIR = Path(__file__).resolve().parents[1]
TOOLS_DIR = PACKAGE_DIR / "tools"
if str(PACKAGE_DIR) not in sys.path:
    sys.path.insert(0, str(PACKAGE_DIR))

from isolation_forest_component import (  # noqa: E402
    ACTIONS_HEADER,
    EBPF_HEADER,
    FEATURE_NAMES,
    MANIFEST_FIELDS,
    SCHEMA_VERSION,
    SUMMARY_FIELDS,
    TELEMETRY_HEADER,
    WINDOW_RESULT_FIELDS,
    Capture,
    ACTION_RESULT_NON_SUCCESS,
    ACTION_RESULT_SUCCESS,
    RECOGNIZED_ACTION_RESULTS,
    StudyError,
    build_capture_windows,
    feature_matrix,
    load_manifest,
    run_study,
)


def iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def write_csv(path: Path, header: tuple[str, ...], rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def action(timestamp: float, tag: str, command: str = "TRACK_UPDATE", result: str = "SUCCESS") -> dict[str, str]:
    return {"timestamp": str(timestamp), "event_id": f"{tag}_{timestamp}", "source": "fixture", "command": command, "details": "", "result": result, "mode": "mock"}


def telemetry(timestamp: float, tag: str, adc_l: float = 10, adc_r: float = 20, steer: float = 1) -> dict[str, str]:
    return {"timestamp": str(timestamp), "vehicle_id": tag, "adc_l": str(adc_l), "adc_r": str(adc_r), "steer": str(steer), "state": "RUNNING", "source": "fixture"}


def ebpf(timestamp: float, tag: str, syscall: str = "write", count: float = 4, match: str = "true") -> dict[str, str]:
    return {"timestamp": str(timestamp), "timestamp_iso": "", "monotonic_ns": "1", "pid": "1", "comm": tag, "syscall": syscall, "fd": "1", "count": str(count), "retval": str(count), "fd_path": "/dev/null", "device_match": match, "notes": ""}


class IsolationForestStudyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps({"schema_version": SCHEMA_VERSION, "window_seconds": 30}), encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def capture(self, name: str, start: float = 0, end: float = 30, split: str = "train", evidence: str = "SYNTHETIC", scenario: str = "NOMINAL", coverage: bool = True, clock: str = "CONSISTENT", actions: list[dict[str, str]] | None = None, telemetry_rows: list[dict[str, str]] | None = None, ebpf_rows: list[dict[str, str]] | None = None, deterministic: list[dict[str, str]] | None = None) -> Capture:
        actions_path, telemetry_path, ebpf_path = (self.root / f"{name}_{suffix}.csv" for suffix in ("actions", "telemetry", "ebpf"))
        write_csv(actions_path, ACTIONS_HEADER, actions or [])
        write_csv(telemetry_path, TELEMETRY_HEADER, telemetry_rows or [])
        write_csv(ebpf_path, EBPF_HEADER, ebpf_rows or [])
        deterministic_path = None
        if deterministic is not None:
            deterministic_path = self.root / f"{name}_rules.csv"
            write_csv(deterministic_path, ("timestamp", "rule_id"), deterministic)
        return Capture(name, split, evidence, scenario, start, end, actions_path, telemetry_path, ebpf_path, coverage, clock, deterministic_path, "")

    def manifest(self, captures: list[Capture]) -> Path:
        path = self.root / "manifest.csv"
        rows = []
        for item in captures:
            rows.append({
                "schema_version": SCHEMA_VERSION, "capture_id": item.capture_id, "split": item.split, "evidence_class": item.evidence_class, "scenario_id": item.scenario_id,
                "capture_start_utc": iso(item.start), "capture_end_utc": iso(item.end), "actions_csv": item.actions_path.name, "telemetry_csv": item.telemetry_path.name,
                "ebpf_csv": item.ebpf_path.name, "ebpf_coverage_complete": str(item.ebpf_coverage_complete).lower(), "clock_assessment": item.clock_assessment,
                "deterministic_results_csv": item.deterministic_path.name if item.deterministic_path else "", "notes": "test fixture",
            })
        write_csv(path, MANIFEST_FIELDS, rows)
        return path

    def nominal_capture(self, name: str, start: float, split: str, evidence: str = "SYNTHETIC", windows: int = 50, scenario: str = "NOMINAL") -> Capture:
        actions, telemetry_rows, ebpf_rows = [], [], []
        for i in range(windows):
            base = start + 30 * i
            actions.append(action(base + 1, name))
            telemetry_rows += [telemetry(base + 2, name, 10 + (i % 2), 20, 1), telemetry(base + 10, name, 20 + (i % 2), 30, 3)]
            ebpf_rows.append(ebpf(base + 3, name))
        return self.capture(name, start, start + windows * 30, split, evidence, scenario, actions=actions, telemetry_rows=telemetry_rows, ebpf_rows=ebpf_rows)

    def complete_study_captures(self, physical_test: bool = False) -> list[Capture]:
        return [
            self.nominal_capture("train_a", 0, "train"), self.nominal_capture("train_b", 2000, "train"),
            self.nominal_capture("val_a", 4000, "validation"), self.nominal_capture("val_b", 6000, "validation"),
            self.nominal_capture("controlled", 8000, "test", "PHYSICAL" if physical_test else "FIXTURE", windows=2, scenario="CONTROLLED_VARIATION"),
        ]

    def test_exact_feature_values_and_order(self) -> None:
        capture = self.capture("hand", actions=[action(1, "h", "START"), action(2, "h", "STOP", "REJECTED"), action(20, "h", "X", "NACK")], telemetry_rows=[telemetry(2, "h", 1, 10, -2), telemetry(12, "h", 7, 30, 4), telemetry(22, "h", 4, 20, 1)], ebpf_rows=[ebpf(3, "h", "write", 7), ebpf(8, "h", "read", 9), ebpf(29, "h", "write", 5)])
        windows, _, _ = build_capture_windows(capture)
        self.assertEqual(FEATURE_NAMES, tuple(windows[0].features))
        self.assertEqual([3, 2, 2, 3, 10, 6, 20, 6, 2, 12, 1, 1], list(feature_matrix(windows)[0]))

    def test_thirty_second_boundaries_and_capture_boundaries(self) -> None:
        capture = self.capture("boundary", end=60, telemetry_rows=[telemetry(0, "b"), telemetry(29.9, "b"), telemetry(30, "b"), telemetry(59.9, "b")])
        windows, _, _ = build_capture_windows(capture)
        self.assertEqual(2, len(windows))
        self.assertEqual(2, windows[0].features["telemetry_row_count"])
        self.assertEqual(2, windows[1].features["telemetry_row_count"])
        other = self.capture("other", start=60, end=90, telemetry_rows=[telemetry(60, "o"), telemetry(61, "o")])
        self.assertEqual("other", build_capture_windows(other)[0][0].capture.capture_id)

    def test_duplicate_timestamps_are_retained_and_regressions_exclude_capture(self) -> None:
        duplicates = self.capture("duplicates", telemetry_rows=[telemetry(5, "t"), telemetry(5, "t"), telemetry(10, "t")])
        duplicate_windows, _, _ = build_capture_windows(duplicates)
        self.assertEqual(3, duplicate_windows[0].features["telemetry_row_count"])
        capture = self.capture("time", telemetry_rows=[telemetry(5, "t"), telemetry(5, "t"), telemetry(4, "t"), telemetry(10, "t")])
        windows, quality, _ = build_capture_windows(capture)
        self.assertEqual("ORIGINAL_ORDER_TIMESTAMP_REGRESSION", windows[0].reason)
        self.assertIsNone(windows[0].features)
        self.assertEqual(1, quality["telemetry_timestamp_regressions"])

    def test_malformed_nonfinite_and_schema_failures(self) -> None:
        capture = self.capture("bad", telemetry_rows=[telemetry(1, "b", "nan"), telemetry(2, "b"), telemetry(3, "b")])
        windows, quality, _ = build_capture_windows(capture)
        self.assertEqual("EXCLUDED", windows[0].status)
        self.assertEqual("TELEMETRY_INVALID_REQUIRED_VALUE_ROW_2", windows[0].reason)
        self.assertEqual(1, quality["telemetry_invalid_required_value_rows"])
        self.assertEqual([2], quality["telemetry_invalid_required_value_rows_row_numbers"])
        action_missing = self.capture("action_missing", actions=[action(1, "a", command="")], telemetry_rows=[telemetry(2, "a"), telemetry(10, "a")])
        self.assertEqual("ACTIONS_INVALID_REQUIRED_VALUE_ROW_2", build_capture_windows(action_missing)[0][0].reason)
        ebpf_missing = self.capture("ebpf_missing", telemetry_rows=[telemetry(2, "e"), telemetry(10, "e")], ebpf_rows=[ebpf(3, "e", syscall="", count=4)])
        self.assertEqual("EBPF_INVALID_REQUIRED_VALUE_ROW_2", build_capture_windows(ebpf_missing)[0][0].reason)
        capture.actions_path.write_text("timestamp,wrong\n1,x\n", encoding="utf-8")
        with self.assertRaisesRegex(StudyError, "incompatible header"):
            build_capture_windows(capture)

    def test_action_result_vocabulary_is_closed_and_fail_closed(self) -> None:
        self.assertEqual(RECOGNIZED_ACTION_RESULTS, ACTION_RESULT_SUCCESS | ACTION_RESULT_NON_SUCCESS)
        for result in sorted(ACTION_RESULT_SUCCESS):
            with self.subTest(result=result):
                capture = self.capture(f"success_{result}", actions=[action(1, "a", result=result)], telemetry_rows=[telemetry(2, "a"), telemetry(10, "a")])
                self.assertEqual(0, build_capture_windows(capture)[0][0].features["non_success_action_count"])
        for result in sorted(ACTION_RESULT_NON_SUCCESS):
            with self.subTest(result=result):
                capture = self.capture(f"failure_{result}", actions=[action(1, "a", result=result)], telemetry_rows=[telemetry(2, "a"), telemetry(10, "a")])
                self.assertEqual(1, build_capture_windows(capture)[0][0].features["non_success_action_count"])
        for result in ("", "UNRECOGNIZED_RESULT"):
            with self.subTest(result=result or "blank"):
                capture = self.capture("invalid_" + (result or "blank"), actions=[action(1, "a", result=result)], telemetry_rows=[telemetry(2, "a"), telemetry(10, "a")])
                window, quality, _ = build_capture_windows(capture)
                self.assertEqual("ACTIONS_INVALID_RESULT_ROW_2", window[0].reason)
                self.assertEqual(1, quality["actions_invalid_result_rows"])

    def test_timestamp_and_clock_quality_exclude_without_scores(self) -> None:
        capture = self.capture("unassigned", end=60, telemetry_rows=[telemetry(1, "u"), telemetry(10, "u"), telemetry(31, "u"), telemetry(40, "u")])
        rows = read_csv(capture.telemetry_path)
        rows[0]["timestamp"] = "NaN"
        write_csv(capture.telemetry_path, TELEMETRY_HEADER, rows)
        windows, quality, _ = build_capture_windows(capture)
        self.assertTrue(all(w.reason == "UNASSIGNABLE_TIMESTAMP_ROW" and w.features is None for w in windows))
        self.assertEqual(1, quality["telemetry_unassignable_timestamp_rows"])
        clock = self.capture("clock", clock="UNACCEPTABLE", telemetry_rows=[telemetry(1, "c"), telemetry(2, "c")])
        self.assertEqual("CLOCK_INCONSISTENT", build_capture_windows(clock)[0][0].reason)
        malformed = self.capture("malformed_output", start=9000, end=9030, split="test", telemetry_rows=[telemetry(9001, "m", "inf"), telemetry(9002, "m")])
        output = self.root / "malformed_output"
        run_study(self.manifest(self.complete_study_captures() + [malformed]), self.config, output)
        row = next(item for item in read_csv(output / "iforest_window_results.csv") if item["capture_id"] == "malformed_output")
        self.assertEqual(("EXCLUDED", "TELEMETRY_INVALID_REQUIRED_VALUE_ROW_2", "", "", ""), (row["window_status"], row["exclusion_reason"], row["anomaly_score"], row["threshold"], row["iforest_flag"]))
        metadata = json.loads((output / "isolation_forest_model_metadata.json").read_text())
        self.assertEqual(1, metadata["exclusion_and_data_quality_counts"]["telemetry_invalid_required_value_rows"])

    def test_device_matched_ebpf_features_and_requested_bytes(self) -> None:
        capture = self.capture("ebpfmatch", telemetry_rows=[telemetry(1, "e"), telemetry(10, "e")], ebpf_rows=[ebpf(2, "e", "write", 7, "true"), ebpf(3, "e", "write", 99, "false"), ebpf(4, "e", "read", 5, "true")])
        values = build_capture_windows(capture)[0][0].features
        self.assertEqual(1, values["matched_serial_write_count"])
        self.assertEqual(7, values["matched_serial_write_requested_bytes"])
        self.assertEqual(1, values["matched_serial_read_count"])

    def test_manifest_required_values_and_canonical_replay_are_rejected(self) -> None:
        left = self.nominal_capture("semantic_left", 0, "train", windows=1)
        right = self.nominal_capture("semantic_right", 100, "validation", windows=1)
        manifest = self.manifest([left, right])
        original = read_csv(manifest)
        for field in ("schema_version", "capture_id", "split", "evidence_class", "scenario_id", "capture_start_utc", "capture_end_utc", "actions_csv", "telemetry_csv", "ebpf_csv", "ebpf_coverage_complete", "clock_assessment", "notes"):
            with self.subTest(field=field):
                rows = [dict(row) for row in original]
                rows[0][field] = ""
                write_csv(manifest, MANIFEST_FIELDS, rows)
                with self.assertRaisesRegex(StudyError, "requires nonblank"):
                    load_manifest(manifest)
        rows = [dict(row) for row in original]
        rows[0]["ebpf_coverage_complete"] = "perhaps"
        write_csv(manifest, MANIFEST_FIELDS, rows)
        with self.assertRaisesRegex(StudyError, "true or false"):
            load_manifest(manifest)
        rows = [dict(row) for row in original]
        rows[0]["capture_end_utc"] = rows[0]["capture_start_utc"]
        write_csv(manifest, MANIFEST_FIELDS, rows)
        with self.assertRaisesRegex(StudyError, "after"):
            load_manifest(manifest)
        # Same parsed action rows, but different physical bytes: row order, CRLF, and quoting.
        action_rows = list(reversed(read_csv(left.actions_path)))
        with right.actions_path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=ACTIONS_HEADER, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
            writer.writeheader()
            writer.writerows(action_rows)
        write_csv(manifest, MANIFEST_FIELDS, original)
        with self.assertRaisesRegex(StudyError, "Canonical parsed-content"):
            load_manifest(manifest)

    def test_missing_input_and_partial_window_are_explicit_failures(self) -> None:
        capture = self.capture("missing", end=59, telemetry_rows=[telemetry(1, "m"), telemetry(2, "m")])
        windows, _, _ = build_capture_windows(capture)
        self.assertEqual(1, len(windows))  # The incomplete trailing interval is never normalized into a window.
        capture.ebpf_path.unlink()
        with self.assertRaisesRegex(StudyError, "does not exist"):
            build_capture_windows(capture)

    def test_fewer_than_two_telemetry_and_ebpf_coverage(self) -> None:
        insufficient = self.capture("few", telemetry_rows=[telemetry(1, "f")])
        self.assertEqual("INSUFFICIENT_TELEMETRY", build_capture_windows(insufficient)[0][0].reason)
        missing = self.capture("coverage", coverage=False, telemetry_rows=[telemetry(1, "c"), telemetry(2, "c")])
        self.assertEqual("EBPF_COVERAGE_MISSING", build_capture_windows(missing)[0][0].reason)
        zero = self.capture("zero", telemetry_rows=[telemetry(1, "z"), telemetry(2, "z")])
        self.assertEqual("ELIGIBLE", build_capture_windows(zero)[0][0].status)

    def test_plus_minus_two_second_correlation_is_inclusive(self) -> None:
        capture = self.capture("corr", actions=[action(3, "c"), action(7, "c")], telemetry_rows=[telemetry(1, "c"), telemetry(2, "c")], ebpf_rows=[ebpf(1, "c"), ebpf(5, "c"), ebpf(9.001, "c")])
        values = build_capture_windows(capture)[0][0].features
        self.assertEqual(1, values["uncorrelated_matched_write_count"])

    def test_manifest_capture_leakage_and_byte_reuse_are_rejected(self) -> None:
        left = self.nominal_capture("left", 0, "train", windows=1)
        right = self.nominal_capture("right", 100, "validation", windows=1)
        # Reusing the exact action bytes across splits is leakage even with a distinct path.
        right.actions_path.write_bytes(left.actions_path.read_bytes())
        with self.assertRaisesRegex(StudyError, "Byte-identical"):
            load_manifest(self.manifest([left, right]))
        overlap = self.nominal_capture("overlap", 10, "validation", windows=1)
        with self.assertRaisesRegex(StudyError, "overlap"):
            load_manifest(self.manifest([left, overlap]))

    def test_train_validation_nominal_only_and_minimum_training_gate(self) -> None:
        bad = self.nominal_capture("badtrain", 0, "train", windows=1, scenario="CONTROLLED_X")
        with self.assertRaisesRegex(StudyError, "must use scenario_id NOMINAL"):
            load_manifest(self.manifest([bad]))
        small = [self.nominal_capture("small_a", 0, "train", windows=1), self.nominal_capture("small_b", 100, "train", windows=1)]
        with self.assertRaisesRegex(StudyError, "Training gate"):
            run_study(self.manifest(small), self.config, self.root / "out")

    def test_reproducibility_threshold_and_labels_do_not_affect_it(self) -> None:
        captures = self.complete_study_captures()
        manifest = self.manifest(captures)
        first = run_study(manifest, self.config, self.root / "out_a")
        second = run_study(manifest, self.config, self.root / "out_b")
        self.assertEqual(first["threshold"], second["threshold"])
        a_rows = read_csv(self.root / "out_a" / "iforest_window_results.csv")
        b_rows = read_csv(self.root / "out_b" / "iforest_window_results.csv")
        self.assertEqual([(r["split"], r["window_id"], r["anomaly_score"], r["iforest_flag"]) for r in a_rows], [(r["split"], r["window_id"], r["anomaly_score"], r["iforest_flag"]) for r in b_rows])
        # Canonical reproducibility ignores only per-run identity and wall-clock metadata.
        def canonical_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
            return [{key: value for key, value in row.items() if key not in {"run_id"}} for row in rows]
        self.assertEqual(canonical_rows(a_rows), canonical_rows(b_rows))
        self.assertEqual(canonical_rows(read_csv(self.root / "out_a" / "iforest_evaluation_summary.csv")), canonical_rows(read_csv(self.root / "out_b" / "iforest_evaluation_summary.csv")))
        a_metadata = json.loads((self.root / "out_a" / "isolation_forest_model_metadata.json").read_text())
        b_metadata = json.loads((self.root / "out_b" / "isolation_forest_model_metadata.json").read_text())
        for metadata in (a_metadata, b_metadata):
            metadata.pop("run_id")
            metadata.pop("generated_at_utc")
        self.assertEqual(a_metadata, b_metadata)
        self.assertEqual(hashlib.sha256((self.root / "out_a" / "isolation_forest_model.joblib").read_bytes()).hexdigest(), hashlib.sha256((self.root / "out_b" / "isolation_forest_model.joblib").read_bytes()).hexdigest())
        captures[-1].scenario_id  # Test-only scenario is not a threshold input by construction.
        metadata = json.loads((self.root / "out_a" / "isolation_forest_model_metadata.json").read_text())
        self.assertEqual("nearest_rank_99th_percentile_nominal_validation", metadata["threshold"]["method"])
        validation_scores = sorted(float(row["anomaly_score"]) for row in a_rows if row["split"] == "validation")
        self.assertAlmostEqual(validation_scores[98], first["threshold"], places=10)
        # Altering an explicitly supplied test-only deterministic row and scenario label cannot alter validation threshold.
        deterministic = self.root / "test_rules.csv"
        write_csv(deterministic, ("timestamp", "rule_id"), [{"timestamp": "8001", "rule_id": "R001"}])
        manifest_rows = read_csv(manifest)
        manifest_rows[-1]["scenario_id"] = "CONTROLLED_RENAMED"
        manifest_rows[-1]["deterministic_results_csv"] = deterministic.name
        write_csv(manifest, MANIFEST_FIELDS, manifest_rows)
        changed = run_study(manifest, self.config, self.root / "out_c")
        self.assertEqual(first["threshold"], changed["threshold"])

    def test_ranking_only_and_excluded_rows_have_no_score(self) -> None:
        captures = [self.nominal_capture("ta", 0, "train"), self.nominal_capture("tb", 2000, "train"), self.nominal_capture("va", 4000, "validation", windows=1), self.nominal_capture("vb", 5000, "validation", windows=1)]
        result = run_study(self.manifest(captures), self.config, self.root / "ranking")
        self.assertTrue(result["ranking_only"])
        rows = read_csv(self.root / "ranking" / "iforest_window_results.csv")
        self.assertTrue(all(not row["threshold"] and not row["iforest_flag"] for row in rows))
        excluded = self.capture("excluded", start=7000, end=7030, split="test", telemetry_rows=[])
        # Add an excluded capture to a separate successful study and verify blank model fields.
        result = run_study(self.manifest(captures + [excluded]), self.config, self.root / "ranking_excluded")
        self.assertTrue(result["ranking_only"])
        row = next(r for r in read_csv(self.root / "ranking_excluded" / "iforest_window_results.csv") if r["capture_id"] == "excluded")
        self.assertEqual(("", "", ""), (row["anomaly_score"], row["threshold"], row["iforest_flag"]))

    def test_ranking_only_has_no_classification_claim_or_metrics(self) -> None:
        captures = [self.nominal_capture("ta2", 0, "train"), self.nominal_capture("tb2", 2000, "train"), self.nominal_capture("va2", 4000, "validation", windows=1), self.nominal_capture("vb2", 5000, "validation", windows=1)]
        run_study(self.manifest(captures), self.config, self.root / "ranking_contract")
        metadata = json.loads((self.root / "ranking_contract" / "isolation_forest_model_metadata.json").read_text())
        self.assertEqual("RANKING_ONLY", metadata["threshold"]["status"])
        self.assertIsNone(metadata["threshold"]["actual_threshold"])
        summaries = read_csv(self.root / "ranking_contract" / "iforest_evaluation_summary.csv")
        self.assertTrue(all(not row["threshold"] and not row["false_positive_rate"] and not row["abnormal_window_detection_rate"] and not row["scenario_detected"] for row in summaries))
        self.assertTrue(all(row["notes"] == "RANKING_ONLY" for row in summaries))

    def test_model_contract_score_orientation_threshold_and_metadata_hashes(self) -> None:
        output = self.root / "model_contract"
        result = run_study(self.manifest(self.complete_study_captures()), self.config, output)
        model = joblib.load(output / "isolation_forest_model.joblib")
        self.assertEqual(200, model.n_estimators)
        self.assertEqual(69201, model.random_state)
        self.assertEqual(100, model.max_samples_)
        self.assertEqual(1.0, model.max_features)
        self.assertFalse(model.bootstrap)
        self.assertEqual("auto", model.contamination)
        self.assertEqual(1, model.n_jobs)
        rows = read_csv(output / "iforest_window_results.csv")
        eligible = [row for row in rows if row["window_status"] == "ELIGIBLE"]
        # The stored score is exactly the negative sklearn score_samples value.
        ordered = sorted(eligible, key=lambda row: (row["capture_id"], row["window_id"]))
        captures = load_manifest(self.manifest(self.complete_study_captures()))
        reconstructed = []
        for capture in sorted(captures, key=lambda item: item.capture_id):
            reconstructed.extend(w for w in build_capture_windows(capture)[0] if w.status == "ELIGIBLE")
        expected = -model.score_samples(feature_matrix(reconstructed))
        self.assertEqual(len(ordered), len(expected))
        self.assertTrue(all(math.isclose(float(row["anomaly_score"]), score, rel_tol=0, abs_tol=1e-12) for row, score in zip(ordered, expected)))
        raw_by_window = {row["window_id"]: float(score) for row, score in zip(ordered, expected)}
        validation = [row for row in rows if row["split"] == "validation" and row["window_status"] == "ELIGIBLE"]
        scores = sorted(raw_by_window[row["window_id"]] for row in validation)
        threshold = result["threshold"]
        self.assertAlmostEqual(scores[math.ceil(.99 * len(scores)) - 1], threshold, places=12)
        self.assertTrue(any(raw_by_window[row["window_id"]] == threshold and row["iforest_flag"] == "false" for row in validation))
        self.assertTrue(all((raw_by_window[row["window_id"]] > threshold) == (row["iforest_flag"] == "true") for row in validation))
        metadata = json.loads((output / "isolation_forest_model_metadata.json").read_text())
        self.assertEqual(hashlib.sha256((output / "isolation_forest_model.joblib").read_bytes()).hexdigest(), metadata["model_sha256"])
        self.assertEqual(hashlib.sha256(",".join(FEATURE_NAMES).encode()).hexdigest(), metadata["feature_schema_sha256"])
        required = {"schema_version", "model_id", "run_id", "model_sha256", "feature_names", "feature_schema_sha256", "source_file_sha256", "versions", "seed", "resolved_isolation_forest_parameters", "training_eligible_window_count", "validation_eligible_window_count", "capture_ids_by_split", "evidence_classes", "scenario_ids", "threshold", "deterministic_rule_comparison", "exclusion_and_data_quality_counts", "quality_diagnostics_by_capture", "claim_boundary"}
        self.assertTrue(required <= metadata.keys())
        self.assertIn("do not prove an attack", metadata["claim_boundary"].lower())
        for capture in captures:
            self.assertEqual(hashlib.sha256(capture.actions_path.read_bytes()).hexdigest(), metadata["source_file_sha256"][capture.capture_id]["actions_csv"])
            self.assertEqual(hashlib.sha256(capture.telemetry_path.read_bytes()).hexdigest(), metadata["source_file_sha256"][capture.capture_id]["telemetry_csv"])
            self.assertEqual(hashlib.sha256(capture.ebpf_path.read_bytes()).hexdigest(), metadata["source_file_sha256"][capture.capture_id]["ebpf_csv"])
        self.assertEqual(["train_a", "train_b"], metadata["capture_ids_by_split"]["train"])
        self.assertEqual(["FIXTURE", "SYNTHETIC"], metadata["evidence_classes"])
        self.assertEqual(0.01, metadata["threshold"]["target_fpr"])
        self.assertEqual(sum(row["iforest_flag"] == "true" for row in validation) / len(validation), metadata["threshold"]["empirical_validation_fpr"])

    def test_output_artifact_set_and_forbidden_input_invariance(self) -> None:
        captures = self.complete_study_captures()
        output = self.root / "artifacts"
        run_study(self.manifest(captures), self.config, output)
        self.assertEqual({"isolation_forest_model.joblib", "isolation_forest_model_metadata.json", "iforest_window_results.csv", "iforest_evaluation_summary.csv"}, {path.name for path in output.iterdir()})
        empty = self.root / "empty"
        empty.mkdir()
        run_study(self.manifest(captures), self.config, empty)
        nonempty = self.root / "nonempty"
        nonempty.mkdir()
        (nonempty / "not_an_artifact").write_text("x")
        with self.assertRaisesRegex(StudyError, "new or empty"):
            run_study(self.manifest(captures), self.config, nonempty)
        base = captures[-1]
        altered = replace(base, capture_id="other_capture", evidence_class="MOCK", scenario_id="OTHER_LABEL", notes="changed descriptive notes")
        base_windows = build_capture_windows(base)[0]
        altered_windows = build_capture_windows(altered)[0]
        self.assertEqual(feature_matrix(base_windows).tolist(), feature_matrix(altered_windows).tolist())
        self.assertEqual(FEATURE_NAMES, tuple(base_windows[0].features))

    def test_no_scaler_search_second_estimator_or_model_loading_in_component(self) -> None:
        source = (PACKAGE_DIR / "isolation_forest_component.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "IsolationForest"]
        self.assertEqual(1, len(calls))
        self.assertNotIn("joblib.load", source)
        self.assertNotIn("StandardScaler", source)
        self.assertNotIn("GridSearch", source)
        self.assertNotIn("partial_fit", source)

    def test_evidence_classes_physical_separation_and_deterministic_mapping(self) -> None:
        nonphysical = self.complete_study_captures()
        run_study(self.manifest(nonphysical), self.config, self.root / "nonphysical_evidence")
        nonphysical_summary = read_csv(self.root / "nonphysical_evidence" / "iforest_evaluation_summary.csv")
        self.assertTrue(all(not row["abnormal_window_detection_rate"] and not row["scenario_detected"] for row in nonphysical_summary if row["scenario_id"] == "NOMINAL"))
        controlled_summary = next(row for row in nonphysical_summary if row["scenario_id"] == "CONTROLLED_VARIATION")
        self.assertNotEqual("", controlled_summary["abnormal_window_detection_rate"])
        self.assertNotEqual("", controlled_summary["scenario_detected"])
        captures = self.complete_study_captures(physical_test=True)
        captures[-1] = self.capture("controlled", 8000, 8060, "test", "PHYSICAL", "CONTROLLED_VARIATION", actions=[action(8001, "p")], telemetry_rows=[telemetry(8002, "p"), telemetry(8010, "p"), telemetry(8032, "p"), telemetry(8040, "p")], ebpf_rows=[ebpf(8003, "p")], deterministic=[{"timestamp": "8001", "rule_id": "R007"}, {"timestamp": "8035", "rule_id": "R001"}])
        run_study(self.manifest(captures), self.config, self.root / "evidence")
        rows = read_csv(self.root / "evidence" / "iforest_window_results.csv")
        physical = [r for r in rows if r["evidence_class"] == "PHYSICAL"]
        self.assertEqual(["R007", "R001"], [r["rule_ids_in_window"] for r in physical])
        summary = [r for r in read_csv(self.root / "evidence" / "iforest_evaluation_summary.csv") if r["evidence_class"] == "PHYSICAL"]
        self.assertTrue(all(not r["abnormal_window_detection_rate"] and not r["scenario_detected"] for r in summary))
        metadata = json.loads((self.root / "evidence" / "isolation_forest_model_metadata.json").read_text())
        self.assertEqual(["R001", "R007"], metadata["deterministic_rule_comparison"]["rule_ids_observed"])
        self.assertTrue(metadata["deterministic_rule_comparison"]["comparison_is_descriptive_only"])

    def test_output_columns_cli_and_safe_output_handling(self) -> None:
        captures = self.complete_study_captures()
        manifest = self.manifest(captures)
        output = self.root / "cli_output"
        completed = subprocess.run([sys.executable, str(TOOLS_DIR / "run_isolation_forest_study.py"), "--manifest", str(manifest), "--config", str(self.config), "--output-dir", str(output)], text=True, capture_output=True, check=False)
        self.assertEqual(0, completed.returncode, completed.stderr)
        with (output / "iforest_window_results.csv").open() as stream:
            self.assertEqual(WINDOW_RESULT_FIELDS, tuple(csv.reader(stream).__next__()))
        with (output / "iforest_evaluation_summary.csv").open() as stream:
            self.assertEqual(SUMMARY_FIELDS, tuple(csv.reader(stream).__next__()))
        rejected = subprocess.run([sys.executable, str(TOOLS_DIR / "run_isolation_forest_study.py"), "--manifest", str(manifest), "--config", str(self.config), "--output-dir", str(output)], text=True, capture_output=True, check=False)
        self.assertNotEqual(0, rejected.returncode)
        forbidden_runtime_names = {
            "isolation_forest_model.joblib", "isolation_forest_model_metadata.json",
            "iforest_window_results.csv", "iforest_evaluation_summary.csv",
        }
        self.assertFalse(any(path.name in forbidden_runtime_names for path in PACKAGE_DIR.rglob("*")))

    def test_safe_overwrite_refuses_unknown_content_and_allows_known_artifacts(self) -> None:
        captures = self.complete_study_captures()
        output = self.root / "safe"
        run_study(self.manifest(captures), self.config, output)
        run_study(self.manifest(captures), self.config, output, safe_overwrite=True)
        (output / "unexpected.txt").write_text("not a study artifact", encoding="utf-8")
        with self.assertRaisesRegex(StudyError, "unknown files"):
            run_study(self.manifest(captures), self.config, output, safe_overwrite=True)

    def test_empty_windows_never_receive_fabricated_features(self) -> None:
        capture = self.capture("empty", telemetry_rows=[])
        window = build_capture_windows(capture)[0][0]
        self.assertEqual("EMPTY_WINDOW", window.reason)
        self.assertIsNone(window.features)

    def test_config_is_fixed_and_no_model_file_exists_before_success(self) -> None:
        self.config.write_text(json.dumps({"schema_version": SCHEMA_VERSION, "window_seconds": 31}), encoding="utf-8")
        with self.assertRaisesRegex(StudyError, "window_seconds 30"):
            run_study(self.manifest([self.nominal_capture("a", 0, "train", windows=1)]), self.config, self.root / "invalid")
        self.assertFalse((self.root / "invalid").exists())

    def test_static_no_live_or_transport_dependencies(self) -> None:
        forbidden = {"flask", "requests", "urllib", "http", "socket", "serial", "live_anomaly_monitor", "anomaly_engine"}
        for path in (PACKAGE_DIR / "isolation_forest_component.py", TOOLS_DIR / "run_isolation_forest_study.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.add(node.module.split(".")[0])
            self.assertFalse(imports & forbidden, f"{path}: {imports & forbidden}")


if __name__ == "__main__":
    unittest.main()
