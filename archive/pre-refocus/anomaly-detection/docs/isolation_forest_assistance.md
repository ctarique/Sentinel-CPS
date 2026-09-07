# Offline Isolation Forest analyst assistance

`tools/run_isolation_forest_study.py` is a separate, offline-only study. It uses exactly one fixed-seed scikit-learn `IsolationForest` to rank 30-second `[start, end)` evidence windows for analyst review. It neither imports nor changes the deterministic R001--R007 engine, which remains the only automatic mitigation policy.

## Operator inputs

Supply all three required paths explicitly: `--manifest`, `--config`, and `--output-dir`. The manifest header and the application/eBPF input headers must exactly match the tracked templates/current schemas. Relative source paths resolve from the manifest directory. The manifest must declare a unique capture ID, split, evidence class, UTC capture interval, all three source files, eBPF coverage, clock assessment, and optional deterministic-results CSV for every capture.

Use `NOMINAL` as the `scenario_id` for every train and validation capture. A non-nominal controlled test condition must begin `CONTROLLED_` (for example, `CONTROLLED_BURST`); this only enables descriptive test metrics, never model fitting or threshold selection. `SYNTHETIC`, `FIXTURE`, `MOCK`, and `PHYSICAL` stay explicit and are summarized separately. No physical metric or conclusion is emitted from synthetic/mock/fixture data.

The tool checks duplicate capture IDs, overlapping capture intervals across splits, and both byte-identical and canonical parsed-content source reuse across splits. The canonical check is insensitive to harmless CSV line-ending, quoting, and row-order changes; it is bounded exact-content replay protection, not sophisticated near-duplicate or adversarial similarity detection. It hashes all supplied source files. It does not discover repository logs or train automatically from them.

## Features and eligibility

The fixed ordered feature schema is: `action_count`, `start_stop_action_count`, `non_success_action_count`, `telemetry_row_count`, `telemetry_interval_median_sec`, `adc_l_range`, `adc_r_range`, `steer_range`, `matched_serial_write_count`, `matched_serial_write_requested_bytes`, `matched_serial_read_count`, and `uncorrelated_matched_write_count`.

eBPF `count` is requested bytes, not confirmed delivery. An eBPF syscall is not payload interpretation or downstream execution. Matching action/write correlation is inclusive at plus/minus two seconds, consistent with R006. Original row order is checked for timestamp regressions; valid rows are then stable-sorted by timestamp and original row number, so duplicate timestamps remain distinct.

Windows are excluded, never imputed, for empty data, fewer than two valid telemetry rows, missing declared eBPF coverage, or material clock inconsistency. A valid-timestamp row with a missing, malformed, invalid, or non-finite required value excludes its containing window and records a source-specific reason with row number (for example, `TELEMETRY_INVALID_REQUIRED_VALUE_ROW_7`). A missing, malformed, or non-finite timestamp cannot be assigned safely and excludes every window in that capture as `UNASSIGNABLE_TIMESTAMP_ROW`. Any original-order timestamp regression excludes every window in the capture as `ORIGINAL_ORDER_TIMESTAMP_REGRESSION`; timestamps are never shifted or repaired. `CONSISTENT`, `ALIGNED`, and `COMPATIBLE` are the accepted clock assessments for scoring. Metadata contains excluded/eligible window counts, row-quality counts, and per-capture row diagnostics.

## Action-result classification

Action results use a closed, case-insensitive vocabulary from the tracked Gateway action log. Recognized success values are `SUCCESS`, `ACKNOWLEDGED`, and `STOP_CONFIRMED`; they add zero to `non_success_action_count`. Recognized non-success values are `REJECTED`, `REJECTED_LOCKED`, `SERIAL_UNAVAILABLE`, `SERIAL_WRITE_ERROR`, `ACK_TIMEOUT`, `NACK`, `INVALID_ACK`, `LOCALLY_LOCKED`, and `STOP_EXECUTION_UNKNOWN`; each increments that feature. Blank, missing, malformed, or unknown results are not inferred as failures: they exclude the containing window as `ACTIONS_INVALID_RESULT_ROW_<row>`. No free-text interpretation or `result != "SUCCESS"` classification is permitted.

## Model, threshold, and artifacts

The exact model is one `IsolationForest(random_state=69201, n_estimators=200, max_samples=min(256, eligible_training_window_count), max_features=1.0, bootstrap=False, contamination="auto", n_jobs=1)`, with no scaler, search, second model, or incremental training. At least 100 eligible nominal training windows from two sessions are required to fit. At least 100 eligible nominal validation windows from two sessions are required to define a threshold.

`anomaly_score = -model.score_samples(X)`. When validation gates pass, the threshold is the nearest-rank 99th percentile of held-out nominal validation scores and a window flags only when its score is strictly greater. With insufficient validation the output is `RANKING_ONLY`: it contains scores but no threshold, flags, false-positive rate, or scenario-detected conclusion.

The requested output directory must be new or empty unless `--safe-overwrite` is supplied. A successful run writes only `isolation_forest_model.joblib`, `isolation_forest_model_metadata.json`, `iforest_window_results.csv`, and `iforest_evaluation_summary.csv`. Joblib artifacts are trusted local binary artifacts; never load an artifact from an untrusted source.

Optional deterministic results are mapped by their emitted timestamp to the containing window, where sorted rule IDs/count are descriptive only. They are never fitting features, labels, threshold inputs, or mitigation inputs.

## Claim boundary

A model flag ranks statistically unusual evidence windows for analyst review. It does **not** prove an attack, malicious intent, compromise, RF delivery, vehicle actuation, motor cessation, successful mitigation, or physical safety. The study has no live monitor, response endpoint, serial path, firmware, or physical-control connection.
