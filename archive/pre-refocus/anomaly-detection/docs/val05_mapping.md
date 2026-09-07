# VAL-05 Threat Detection and Mitigation Preparation Mapping

## VAL-05 preparation

This package supports VAL-05 through unchanged offline anomaly scores/reports and a bounded Phase 5B2B monitor that records detections separately from guarded mitigation requests and protocol results.

It supports the claim that suspicious behavior can be detected through correlated Gateway and host-level observability and that response integration can be conservatively gated. It does not establish physical mitigation.

## SR-O2 anomaly detection preparation

The package transforms raw logs into simple features and rule-triggered anomaly rows. These outputs can later inform a lightweight model or threshold-based live detector.

## SR-O3 local AI/ML preparation

The package runs locally and avoids cloud services. It prepares a local analytics path that can later be integrated into the Gateway.

## SR-R1 STOP response preparation

Offline incident-report recommendation text remains unchanged and cannot authorize live response. The live example allowlists only high-severity R002/R004. An explicitly enabled monitor may make one authenticated request to the Gateway's fixed STOP endpoint after durable latching, actionable provenance, and health preflight. HTTP delivery and downstream protocol acknowledgement remain distinct from physical effect.

## SR-R2 recovery logging preparation

The live ledgers document rising/falling/rearm transitions, policy decisions, request planning, Gateway transaction fields, ambiguous execution, and recovery-review latches. Rearming requires quiet plus a later authoritative hardware RESET; it is never inferred from generic IDLE text.

## Gateway/eBPF/telemetry correlation

The rules compare application action intent, telemetry behavior, and eBPF-observed serial activity. This supports review of the Gateway serial chokepoint and prepares later VAL-05 mitigation correlation.

## Evidence claim boundary

`SYNTHETIC` and `NON_PHYSICAL_FIXTURE` evidence is software-only. `HARDWARE_PROTOCOL` requires consistent Gateway hardware mode plus protocol-source evidence. `ACKNOWLEDGED_DOWNSTREAM` means the Gateway received a matching `STOP/LOCKED/VEHICLE` protocol acknowledgement and reported `vehicle_stop_confirmed=true`; it is not observed motor cessation. VAL-05 physical completion still requires synchronized Gateway, eBPF, vehicle, and physical test evidence under the approved lab procedure.
