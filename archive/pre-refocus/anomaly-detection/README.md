# Sentinel-CPS AI Anomaly Detection MVP v0.1.1

## Purpose

This package provides both the established offline deterministic anomaly scorer and a separate bounded live-monitor process for Sentinel-CPS. The monitor tails Gateway/eBPF CSVs, creates durable rising-edge incidents, and defaults to observe-only. Its optional mitigation path is guarded and calls only the authenticated Gateway STOP endpoint.

This package supports **VAL-05 Threat Detection and Mitigation Preparation**. Offline scoring remains unchanged. Live software evidence does not by itself establish physical mitigation.

The numeric score is a deterministic prioritization value. It is not a probability, learned confidence, or statistical likelihood.

## Offline Isolation Forest analyst assistance

`isolation_forest_component.py` and `tools/run_isolation_forest_study.py` add a separate offline-only, fixed-configuration Isolation Forest study for analyst review. It requires an explicit dataset manifest and config, trains only from eligible nominal training windows, and writes only to an explicit operator output directory. It does not discover repository logs, alter R001--R007, connect to any live component, or trigger a response.

Its score ranks statistically unusual evidence windows; a flag does **not** prove an attack, malicious intent, compromise, RF delivery, vehicle actuation, motor cessation, successful mitigation, or physical safety. See `docs/isolation_forest_assistance.md` for the manifest, feature, eligibility, threshold, artifact-trust, and claim-boundary contracts.

For action evidence, the study uses a closed Gateway-derived result vocabulary: `SUCCESS`, `ACKNOWLEDGED`, and `STOP_CONFIRMED` are successes; `REJECTED`, `REJECTED_LOCKED`, `SERIAL_UNAVAILABLE`, `SERIAL_WRITE_ERROR`, `ACK_TIMEOUT`, `NACK`, `INVALID_ACK`, `LOCALLY_LOCKED`, and `STOP_EXECUTION_UNKNOWN` are recognized non-successes. Blank or unknown results exclude their window rather than being guessed from free text.

## Shared-engine architecture

- `anomaly_engine.py` owns configuration validation, input normalization, severity mapping, R001--R007 evaluation, row construction, ordering, and integer-second deduplication.
- `tools/score_anomalies.py` remains the compatible offline CSV command-line adapter. Its arguments, warnings, output filename pattern, columns, column order, and result counts are unchanged.
- `live_anomaly_monitor.py` places bounded tailing and incident state around the engine; it does not copy R001--R007.
- `tools/monitor_live_anomalies.py` is the operator CLI. It does not daemonize or access serial hardware.
- Engine results remain ordinary dictionaries and the offline 11-column schema is unchanged.

Importing either module does not open inputs, create outputs, start threads, read environment secrets, or make network calls. Runtime I/O begins only when the CLI constructs a monitor.

## Offline scorer versus live monitor

The offline scorer loads finite files and preserves the validated R001--R007 behavior, output ordering, descriptions, scores, severities, inclusivity, local-time `timestamp_iso`, and 11-column schema. The live monitor reads only appended complete records, retains bounded windows, and writes separate detection and mitigation ledgers. Do not substitute live ledgers for offline golden-parity output or combine their schemas.

The live monitor creates one incident on each inactive-to-active rule transition. A continuing condition cannot create a second incident or STOP request. Clearing the condition is not enough to rearm: the configured quiet period must elapse and a later action row must prove `RESET`, `ACKNOWLEDGED`, and `mode=hardware`. Generic `IDLE`, mock RESET, `SUCCESS`, telemetry alone, or operator assumptions do not prove that epoch; the latch remains `CLEARED_NOT_REARMED` and requires review.

Before any network transmission the monitor appends/flushed `REQUEST_PLANNED`, atomically persists the incident, records `REQUEST_SENT`, and persists again. A restart after either ambiguous state changes the incident to `RECOVERY_REQUIRES_REVIEW`; it never retries and never creates a new idempotency key for the active incident.

## What this package does

- Generates synthetic sample logs for home testing.
- Scores explainable anomaly rules against:
  - `actions.csv`
  - `telemetry.csv`
  - `serial_trace.csv`
- Flags suspicious patterns such as:
  - command bursts
  - telemetry floods
  - repeated START/STOP toggling
  - serial writes after LOCKED
  - malformed telemetry
  - serial activity without nearby Gateway action
  - replay-like timing patterns
- Generates an anomaly summary and incident report.

## Deterministic baseline rules

- **R001 COMMAND_BURST (85):** more than the configured number of all timestamped action rows in an inclusive forward window. Rejected and non-operator rows are intentionally counted.
- **R002 TELEMETRY_FLOOD (95):** more than the configured number of timestamped telemetry rows in an inclusive forward window.
- **R003 REPEATED_START_STOP_TOGGLE (80):** more than the configured number of `START`/`STOP` command rows in an inclusive forward window. Commands are counted regardless of result; successful state transitions are not reconstructed.
- **R004 SERIAL_WRITE_AFTER_LOCKED (100):** more than the allowed matching serial writes from the inclusive grace boundary through the inclusive locked-window end after any current `STOP` action or `LOCKED` telemetry marker.
- **R005 MALFORMED_TELEMETRY (default 80):** timestamped telemetry with a non-numeric or non-finite `adc_l`, `adc_r`, or `steer` value.
- **R006 SERIAL_ACTIVITY_WITHOUT_GATEWAY_ACTION (default 60):** one whole-file aggregate when matching serial writes without an action within the inclusive plus/minus correlation window exceed the configured threshold.
- **R007 REPLAY_LIKE_TIMING_PATTERN (45):** the first sufficiently long positive interval sequence whose rounded intervals all match the average within the configured tolerance. Highly regular one-second telemetry can trigger this weak signal.

Scores 40, 70, and 90 are the default inclusive boundaries for `LOW`, `MEDIUM`, and `HIGH`; lower scores are `INFO`. R005 and R006 scores are configurable through their existing penalty fields.

## What this package does not do

- It does not use deep learning.
- It does not call cloud services.
- It does not modify the live Gateway.
- It does not directly access the serial device or dispatch any command other than requesting the Gateway's fixed STOP endpoint when explicitly enabled.
- It does not equate detection, local locking, HTTP delivery, HTTP 200, mock ACK, or protocol ACK with observed physical motor cessation.
- It does not claim live or physical anomaly detection.
- It does not replace physical lab evidence.

## Setup

From the package root:

```bash
cd anomaly-detection
python3 --version
```

No external Python packages are required for the MVP.

The existing JSON configuration fields are validated before scoring. Non-finite thresholds, nonpositive windows, invalid counts, negative penalties, and inconsistently ordered severity thresholds fail with a clear configuration error.

## Generate sample logs

```bash
python3 tools/generate_sample_logs.py
```

This creates:

```text
sample_data/actions_sample.csv
sample_data/telemetry_sample.csv
sample_data/serial_trace_sample.csv
```

## Score sample logs

```bash
python3 tools/score_anomalies.py \
  --actions sample_data/actions_sample.csv \
  --telemetry sample_data/telemetry_sample.csv \
  --ebpf sample_data/serial_trace_sample.csv \
  --config config/anomaly_rules.example.json
```

The output is saved under:

```text
evidence/VAL-05_Threat_Mitigation_Preparation/anomaly_scores/
```

## Summarize anomaly scores

Use the anomaly score file printed by the previous command:

```bash
python3 tools/summarize_anomaly_scores.py \
  --input evidence/VAL-05_Threat_Mitigation_Preparation/anomaly_scores/anomaly_scores_<timestamp>.csv
```

## Generate incident report

```bash
python3 tools/make_val05_incident_report.py \
  --input evidence/VAL-05_Threat_Mitigation_Preparation/anomaly_scores/anomaly_scores_<timestamp>.csv
```

The report is saved under:

```text
evidence/VAL-05_Threat_Mitigation_Preparation/reports/
```

## Later use with real lab evidence

After the Gateway, Hub, and eBPF trace packages have been executed in the lab, use real paths:

```bash
python3 tools/score_anomalies.py \
  --actions ../gateway/data/actions.csv \
  --telemetry ../gateway/data/telemetry.csv \
  --ebpf ../observability-ebpf/evidence/VAL-04_Observability/ebpf_traces/serial_trace_<timestamp>.csv \
  --config config/anomaly_rules.example.json
```

Raw logs, anomaly outputs, and incident reports should be stored privately in OneDrive unless sanitized for public GitHub use.

## Tests

Run the hardware-free engine and CLI suite from this package root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

The deterministic golden fixture under `tests/fixtures/golden/` covers all seven rules. Its expected rows were captured from the pre-refactor scorer with a fixed UTC test timezone and exclude only the generated output filename timestamp.

## Live monitor configuration and operation

Copy `config/live_integration.example.json` to an untracked operator configuration and replace the input paths. The tracked example is safe: `response_mode` is `observe_only`, minimum severity is `HIGH`, only R002/R004 are allowlisted, mock mitigation is disabled, hardware provenance is required, and the Gateway origin is loopback HTTP.

Validate without creating state or evidence:

```bash
python3 tools/monitor_live_anomalies.py \
  --config config/live_integration.example.json \
  --validate-config
```

Process currently available complete new rows once in a nonphysical fixture boundary:

```bash
python3 tools/monitor_live_anomalies.py \
  --config config/live_integration.example.json \
  --once --dry-run \
  --state-root /path/to/operator/state \
  --evidence-root /path/to/operator/evidence
```

Omit `--once` for continuous foreground monitoring; SIGINT/SIGTERM flush state and ledgers. The process does not daemonize. Runtime state/evidence belongs in operator-controlled untracked directories.

Mitigation requires all configured policy gates, actionable provenance, compatible `/api/health`, and an environment-only bearer value named `SENTINEL_MITIGATION_TOKEN`. No token value belongs in JSON, arguments, logs, ledgers, manifests, or examples. The monitor sends only incident/detection metadata to `POST /api/mitigation/stop`; it never sends a caller-selected command, action, verb, state, or target.

`ACKNOWLEDGED_DOWNSTREAM` means the Gateway reported a matching hardware protocol acknowledgement and `vehicle_stop_confirmed=true`. It is not physical observation. An allowed mock response is always `SYNTHETIC_ACKNOWLEDGED`; fixture runs are `NON_PHYSICAL_FIXTURE` and do not call the Gateway.

Live evidence files are:

- `live_anomaly_events.csv` for detections, transitions, provenance, and policy decisions;
- `mitigation_events.csv` for request planning/delivery/result phases;
- one secret-free `run_manifest_<detector_run_id>.json` per process run;
- atomic `monitor_state.json` under the state root for offsets, bounded windows, and latches.

## Preserved baseline limitations

This extraction deliberately does not change R001 action-row counting, R003 command counting, R004 marker interpretation, R006 whole-file aggregation, R007's exact-periodic false-positive risk, quadratic batch scans, or local-time `timestamp_iso` formatting. See `docs/limitations_and_safety.md`.

The incident-report tool also retains its current policy discrepancy: a `MEDIUM` row can make the report say that STOP is recommended when the row text contains `STOP`. This is regression-tested and remains visible for a later policy phase.

## Thesis mapping summary

This MVP supports:

- **VAL-05 Threat Detection and Mitigation Preparation**
- **SR-O2 anomaly detection preparation**
- **SR-O3 local AI/ML preparation**
- **SR-R1 STOP response preparation**
- **SR-R2 recovery logging preparation**
- Gateway/eBPF/telemetry correlation for review

Use this package as evidence of an explainable offline scorer plus bounded, guarded live integration. Do not describe Phase 5B2B software tests as complete real-time physical mitigation; physical validation remains separate.
