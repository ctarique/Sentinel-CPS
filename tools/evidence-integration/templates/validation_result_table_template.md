# Validation Result Table Templates

## VAL-01 Access Control and Gateway Hardening

| Test Scenario | Expected Outcome | Observed Outcome | Evidence Ref | Status | Notes |
|---|---|---|---|---|---|
| Port 22 probe from approved admin endpoint | SSH reachable with key-only authentication | [Fill in] | [EVID] | [PASS/FAIL/PARTIAL] | [Notes] |
| Port 8080 probe from display/dashboard endpoint | Dashboard reachable | [Fill in] | [EVID] | [PASS/FAIL/PARTIAL] | [Notes] |
| Port 22 probe from display endpoint | SSH unavailable or not usable | [Fill in] | [EVID] | [PASS/FAIL/PARTIAL] | [Notes] |
| Service inventory | Only intended services are listening | [Fill in] | [EVID] | [PASS/FAIL/PARTIAL] | [Notes] |

## VAL-03 TV-as-a-Track Physical Navigation

| Test Scenario | Expected Outcome | Observed Outcome | Evidence Ref | Status | Notes |
|---|---|---|---|---|---|
| Black/white ADC calibration | Distinguishable ADC ranges | [Fill in] | [EVID] | [PASS/FAIL/PARTIAL] | [Notes] |
| Dry-run steering test | Steering output changes with sensor position | [Fill in] | [EVID] | [PASS/FAIL/PARTIAL] | [Notes] |
| Low-speed live movement | Vehicle attempts to follow track | [Fill in] | [EVID] | [PASS/FAIL/PARTIAL] | [Notes] |
| STOP during dry-run/live test | State changes to LOCKED and motor output stops | [Fill in] | [EVID] | [PASS/FAIL/PARTIAL] | [Notes] |

## VAL-04 Gateway Observability

| Test Scenario | Expected Outcome | Observed Outcome | Evidence Ref | Status | Notes |
|---|---|---|---|---|---|
| Gateway command logging | START/STOP/RESET appear in actions.csv | [Fill in] | [EVID] | [PASS/FAIL/PARTIAL] | [Notes] |
| Telemetry logging | telemetry.csv records Hub/vehicle rows | [Fill in] | [EVID] | [PASS/FAIL/PARTIAL] | [Notes] |
| eBPF trace capture | serial_trace.csv records metadata for target device | [Fill in] | [EVID] | [PASS/FAIL/PARTIAL] | [Notes] |
| Correlation report | Action timestamps align with nearby serial activity | [Fill in] | [EVID] | [PASS/FAIL/PARTIAL] | [Notes] |

## VAL-05 Threat Detection and Mitigation Preparation

| Test Scenario | Expected Outcome | Observed Outcome | Evidence Ref | Status | Notes |
|---|---|---|---|---|---|
| Offline scoring on synthetic data | Rules trigger on known suspicious patterns | [Fill in] | [EVID] | [PASS/FAIL/PARTIAL] | [Notes] |
| Offline scoring on lab logs | Suspicious patterns are scored and summarized | [Fill in] | [EVID] | [PASS/FAIL/PARTIAL] | [Notes] |
| STOP evidence | STOP command creates action and LOCKED telemetry evidence | [Fill in] | [EVID] | [PASS/FAIL/PARTIAL] | [Notes] |
| Incident report | Markdown report explains rule triggers and recommended response | [Fill in] | [EVID] | [PASS/FAIL/PARTIAL] | [Notes] |
