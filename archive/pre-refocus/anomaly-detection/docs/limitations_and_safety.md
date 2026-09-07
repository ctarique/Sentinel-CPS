# Limitations and Safety

## Rule-based scoring is limited

This MVP uses deterministic thresholds and sliding windows. It is explainable, but it may produce false positives or false negatives.

The score is a deterministic prioritization value, not a probability, learned confidence, or calibrated likelihood.

## Preserved v0.1.1 baseline behavior

Phase 5B2A extracts the rules into `anomaly_engine.py` without silently correcting known limitations:

- R001 counts every timestamped action row, including non-operator sources and rejected actions.
- R003 counts `START`/`STOP` command rows rather than confirmed successful state transitions.
- R004 treats every current `STOP` action and `LOCKED` telemetry row as a marker, without reconstructing the actual current state.
- R006 aggregates orphan writes across the whole file rather than a bounded rolling incident window.
- R007 can flag highly regular one-second telemetry and should remain a weak signal.
- Several batch rules retain quadratic full-list scans. The offline scorer is not presented as a performance-bounded live monitor.
- `timestamp_iso` continues to use host local time rather than UTC, so identical epoch values can render differently across host timezones.

The output still deduplicates on rule ID, event type, and integer timestamp second. Forward rule windows, correlation boundaries, the R004 grace boundary, and the R004 locked-window end are inclusive.

## Synthetic data does not replace lab evidence

The sample log generator is only for home testing and software verification. Thesis validation still requires physical Gateway, Hub, vehicle, Smart TV, and captured lab evidence.

## Live response is observe-only by default

The offline scorer never writes to the Gateway, serial device, or vehicle. The Phase 5B2B monitor defaults to observe-only. When an operator explicitly enables mitigation, it can send one authenticated metadata-only request to the Gateway's fixed STOP endpoint after every policy, provenance, health, and durable-latch gate passes. It never accesses serial hardware or sends RESET/START/PING/recovery.

The bearer value exists only in `SENTINEL_MITIGATION_TOKEN`. It is forbidden in configuration, arguments, logs, ledgers, manifests, and examples. The monitor is a separate unprivileged-process candidate and receives no serial-device permissions. No service is installed or enabled by this phase.

## Durable ambiguity is intentional

The incident latch is written before POST. A timeout, lost/malformed response, connection failure, NACK, unavailable/degraded serial transport, wrong state/origin, coalescing, or other uncertain result becomes `EXECUTION_UNKNOWN` or recovery review and is never automatically retried. This can require operator review even when a request provably did not execute; conservative ambiguity avoids a duplicate STOP after monitor or Gateway restart.

Detection, `REQUEST_SENT`, Gateway local lock, HTTP status, and mock acknowledgement are distinct facts. `ACKNOWLEDGED_DOWNSTREAM` establishes only a matching hardware protocol acknowledgement. It does not independently observe the motors. Physical motor cessation still needs separately synchronized physical evidence.

## Live interpretation limitations

- CSV identity uses filesystem device/inode plus byte offset. Rotation and truncation begin a diagnosed epoch, but upstream copying practices and delayed/out-of-order timestamps can still affect correlation.
- Per-poll bytes and per-source rows are capped. Extreme bursts beyond the cap remain detectable once thresholds are crossed, but live count text can reflect the retained cap rather than a whole-file total.
- R001/R002/R003/R004/R005 use bounded live horizons while preserving engine thresholds and inclusive boundaries.
- R006 waits through its correlation window and accumulates confirmed orphan writes only for the current monitor/eBPF file epoch, capped after threshold crossing. This is explicitly not the offline whole-file aggregate.
- R007 retains bounded interval history and can flag completely normal periodic telemetry. It is nonallowlisted by default and should remain weak corroboration only.
- A successful hardware RESET action is the only current authoritative rearm proof. If that row is missing, delayed, rotated away before observation, or schema-incompatible, the latch requires manual review.

## Incident-report policy discrepancy

`make_val05_incident_report.py` currently reports STOP as recommended when any anomaly is `HIGH` **or** when any row's `recommended_response` text contains `STOP`. A `MEDIUM` anomaly can therefore produce a report-level STOP recommendation. This behavior is covered by a regression test and intentionally remains unchanged in this engine-refactor phase.

## Replay detection is a weak signal

Replay-like timing may also appear in normal periodic telemetry. Treat R007 as a low-confidence signal unless supported by other evidence.

## No physical-effect claim

Golden fixtures and hardware-free tests prove deterministic software behavior, bounded ingestion, latching, and classification only. They do not prove timing under sustained physical load, provenance correctness in the lab, RF delivery, vehicle actuation, motor cessation, or safety effectiveness. Live capture and synchronized physical validation remain required.

## Privacy and evidence handling

Raw Gateway logs, eBPF traces, device paths, hostnames, usernames, and network details should remain private in OneDrive. Public GitHub examples should use synthetic or redacted evidence.
