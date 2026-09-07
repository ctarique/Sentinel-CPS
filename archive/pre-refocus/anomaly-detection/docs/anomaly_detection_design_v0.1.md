# Sentinel-CPS Anomaly Detection Design v0.1.1 / Phase 5B2B

## Purpose

This module prepares the analytical foundation for the “AI Threat Detection” portion of Sentinel-CPS. At this stage, the detector is deliberately lightweight, offline, and explainable.

The purpose is not to claim a complete AI defense system. The offline path shows how finite Gateway, telemetry, and eBPF inputs become reviewable anomaly evidence. Phase 5B2B adds bounded live ingestion and guarded integration, but makes no physical-effect claim.

## Why rule-based detection is appropriate at this stage

The thesis build needs a reliable validation path before introducing live automated response. A rule-based MVP is useful because:

- every rule is explainable;
- thresholds can be documented;
- outputs can be manually reviewed;
- failures are easier to debug;
- no cloud or heavyweight model dependency is introduced;
- it prepares feature definitions that could later feed a lightweight ML model.

## Inputs

The scorer reads three log sources:

1. `actions.csv` — application-level command intent.
2. `telemetry.csv` — Hub/vehicle telemetry behavior.
3. `serial_trace.csv` — eBPF/BCC serial syscall metadata.

Rows without a finite timestamp are ignored, as in the original scorer. Remaining rows are normalized with their original input row numbers and sorted by timestamp before rule evaluation.

## Architecture

`anomaly_engine.py` is the reusable pure-Python rule layer. It contains:

- validation and defaulting for the current configuration fields;
- normalized action, telemetry, and eBPF row representations;
- local-time timestamp formatting and severity mapping;
- deterministic R001--R007 evaluation;
- baseline output-row construction;
- deterministic timestamp ordering and integer-second deduplication.

`tools/score_anomalies.py` is the offline adapter. It retains CSV loading, missing-file warnings, the existing command-line interface, timestamped output naming, and the exact 11-column CSV schema. It calls the shared engine and contains no duplicate rule implementation.

The engine accepts loaded rows and returns ordinary row dictionaries. The live monitor extends their context outside the engine without changing offline `OUTPUT_FIELDNAMES`. The engine itself performs no HTTP, Gateway, serial, Flask, cloud, thread, environment-secret, or deployment operation.

## Scoring model

Rules generate anomaly rows with a severity and numeric score. The score is not a probability, learned confidence, or calibrated likelihood. It is a deterministic prioritization value used to order review.

Current rules:

- **R001 command burst, score 85:** for each timestamped action, count all action rows in the inclusive forward command window and flag when count is greater than the configured maximum.
- **R002 telemetry flood, score 95:** for each timestamped telemetry row, count telemetry rows in the inclusive forward telemetry window and flag when count is greater than the configured maximum.
- **R003 repeated START/STOP toggling, score 80:** filter command text to `START`/`STOP`, count command rows in the inclusive forward toggle window, and flag when count is greater than the configured maximum.
- **R004 serial writes after LOCKED, score 100:** treat current `STOP` action timestamps and `LOCKED` telemetry timestamps as markers, then count device-matching `write` rows from `marker + grace` through `marker + locked window`, inclusive.
- **R005 malformed telemetry, default score 80:** flag timestamped rows when `adc_l` or `adc_r` cannot be converted through the baseline integer conversion, or `steer` is non-numeric/non-finite.
- **R006 serial activity without nearby Gateway action, default score 60:** collect device-matching `write` rows with no action within the inclusive plus/minus orphan window across the whole input and emit one row when the total is greater than the configured maximum.
- **R007 replay-like timing, score 45:** round telemetry intervals to six decimals, find the first positive sequence of configured length whose intervals differ from their average by no more than the configured tolerance, and emit one weak-signal row.

Default severity boundaries are inclusive: `LOW >= 40`, `MEDIUM >= 70`, and `HIGH >= 90`; otherwise severity is `INFO`. R005 and R006 use their existing configurable penalty values. Other rule scores remain fixed.

After all rules run, anomalies are sorted by rule and timestamp for deduplication. Only the first row for a `(rule_id, event_type, integer timestamp second)` key is retained. Results are then stably sorted by numeric timestamp. Descriptions, recommendations, evidence references, source basenames, timestamp precision, and local-time ISO formatting match the v0.1.1 baseline.

## Configuration validation

Missing current fields receive their existing defaults. Every current numeric field must be finite; window durations and replay sequence length must be positive; configured counts must be nonnegative integers; tolerance and penalties must be nonnegative; and severity thresholds must satisfy `low <= medium <= high`. Malformed JSON or invalid values fail explicitly. No live-response policy field or new rule category is introduced.

## Golden parity

Before extraction, deterministic fixed-timestamp CSV fixtures were run through the original scorer. Generated output filename timestamps were excluded from comparison, while all ordered CSV row fields were retained. The refactored CLI produces byte-identical CSV content for those inputs under the same fixed UTC test timezone, and direct engine evaluation produces the same normalized rows. Repeated runs are regression-tested.

## Phase 5B2B live architecture

`live_anomaly_monitor.py` is a separate process boundary around the unchanged engine. An advisory exclusive lock gives one process ownership of a state root; that local ownership prevents competing monitors but says nothing about mitigation or physical state. Each source tailer validates the current exact header, tracks device/inode identity plus committed byte offset, reads a configured maximum per poll, parses only complete newline-terminated logical CSV records (including quoted multiline records), and leaves an incomplete final record uncommitted. Normal restart resumes after committed rows. Truncation or identity replacement starts a diagnosed file epoch. Malformed rows are skipped by generated location/reason diagnostics without logging their contents. Offsets, bounded rule inputs, operation epoch, and incidents are committed together by same-directory temporary file, `fsync`, and `os.replace`.

Only rule-required fields enter durable state: action metadata excluding details, telemetry values/state/source excluding vehicle ID, and eBPF timestamp/syscall/device-match excluding PID, process, device path, and notes. Per-source lists are capped by `max_rows_per_source`; threshold validation prevents a cap smaller than a required trigger. The live state mapping is:

- R001: recent bounded action window; engine retains its inclusive forward count.
- R002: recent bounded telemetry window; engine retains its inclusive flood count.
- R003: recent bounded START/STOP action window; command rows, not transitions, remain the baseline.
- R004: bounded STOP/LOCKED marker and later device-write window with the original inclusive grace/end boundaries.
- R005: row-level numeric validation within the current live telemetry horizon.
- R006: matching writes wait through the plus-side correlation window, then the engine is invoked with `max_orphans=0` to classify each candidate against retained actions. Confirmed orphan representatives accumulate only to threshold-plus-one in the current monitor/eBPF file epoch. The unchanged offline rule remains whole-file aggregate; live output explicitly says `CURRENT_MONITOR_FILE_EPOCH_CUMULATIVE`.
- R007: the last configured interval-history length is retained by count and evaluated by the engine. It remains a weak signal and can flag normal periodic telemetry. Stale retained replay history cannot keep unrelated rules active.

The monitor calls `evaluate_anomalies`; it has no copied scores, severity mapping, threshold comparisons, descriptions, or response-text parser. Live window/cumulative interpretations are state-management boundaries, not changes to offline scoring.

## Incident and rearming state machine

An engine condition rising edge creates cryptographically random detector-run, detector-instance, detection, incident, and request identifiers. The idempotency key is SHA-256 over nonsensitive stable incident metadata. The incident is persisted in `DETECTED` before response policy runs. Continuing output finds the same rule latch and produces neither a second incident nor a second request.

When output becomes inactive the latch becomes `CLEARED_NOT_REARMED`. It reaches `REARMED` only after both the quiet period and a later authoritative operational epoch. Under the current schema, only an action with command `RESET`, result `ACKNOWLEDGED`, and mode `hardware` proves that epoch. RESET text with another result, mock mode, and telemetry `IDLE` are insufficient. R006's cumulative condition normally remains active for its eBPF file epoch and therefore cannot silently clear merely because time passed.

Before HTTP, the mitigation ledger is flushed at `REQUEST_PLANNED`, the latch is atomically persisted, `REQUEST_SENT` is recorded, and state is persisted again. On restart, unfinished `REQUEST_PLANNED`/`REQUEST_SENT` becomes `RECOVERY_REQUIRES_REVIEW`; the monitor does not infer whether STOP dispatched, regenerate a key, or retry. Gateway in-memory idempotency is supplementary and never the durable authority.

## Response and provenance boundary

Observe-only is the default. Mitigation requires `response_mode=mitigate`, severity at/above the configured minimum, explicit rule allowlisting (example R002/R004 only), actionable provenance, an unrequested latch, a present environment token, and compatible preflight. Recommendation text never authorizes response.

Provenance is one of `SYNTHETIC`, `HARDWARE_PROTOCOL`, `MIXED_UNSUITABLE`, or `UNKNOWN_UNACTIONABLE`. Hardware protocol classification requires a Gateway action mode of hardware plus consistent non-mock telemetry or matching serial trace source evidence. Telemetry/eBPF alone cannot establish Gateway mode. Missing or mixed evidence is nonactionable. Mock is disabled by default and, when explicitly enabled with hardware provenance disabled, remains synthetic.

Preflight uses loopback `GET /api/health` and requires the current health fields, enabled/ready/loopback-only mitigation, compatible mode/transport, and for hardware an available connected serial transport with healthy status. A local lock, active mitigation, pending safety STOP, or in-progress mitigation suppresses another STOP.

The POST body contains only `incident_id`, `detection_id`, `idempotency_key`, `rule_id`, `severity`, `score`, `detection_timestamp_utc`, and optional `evidence_class`/`detector_run_id`. HTTP 200 is not success. Only a matching hardware `ACKNOWLEDGED_DOWNSTREAM` with available transport, transaction ID, `ACKNOWLEDGED`, `LOCKED`, `VEHICLE`, and `vehicle_stop_confirmed=true` is retained as downstream protocol acknowledgement. Mock ACK is `SYNTHETIC_ACKNOWLEDGED`. Ambiguous transport, timeout, malformed response, NACK, wrong ACK, serial failure, coalescing, or other uncertain result is never upgraded; no automatic retry, RESET, START, PING, recovery, or second STOP follows.

## Evidence separation

Detection and mitigation are append-only ledgers with template-defined stable columns. Detection rows record rising/falling/rearm transitions and decisions. Mitigation rows record planning, transmission boundary, response, and final classification separately. A secret-free run manifest records version/schema, Git status, configuration hashes, input paths, response mode, timestamps, and the explicit protocol-versus-physical boundary. UTC is used for every new live evidence timestamp.

The current incident-report policy remains separate from rule severity: it reports STOP as recommended for any `HIGH` row or any row whose recommendation text contains `STOP`. Therefore a `MEDIUM` anomaly can currently produce a report-level STOP recommendation. This discrepancy is documented and regression-tested, not silently changed here.

## Out of scope

- Deep learning
- Cloud AI
- Production SOC alerting
- Direct serial access or caller-selectable mitigation commands
- Automatic retry or automated recovery/rearming guesses
- Proof of physical motor cessation from a protocol acknowledgement
- Claims of guaranteed detection
- Replacement for physical lab evidence
