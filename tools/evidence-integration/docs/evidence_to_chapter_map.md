# Evidence to Chapter Map

This document maps Sentinel-CPS artifacts and lab evidence to the likely thesis chapter structure. It should be updated as real evidence is collected.

## Chapter 1: Introduction

**Supports:** problem motivation, remote CPS lab risk, need for a scoped Zero-Trust Gateway design.

**Artifacts and evidence:**

- Thesis synopsis and scope statement
- High-level architecture diagram
- Sentinel-CPS simulator as a concept/schema planning artifact
- Problem statement and research questions

**Safe claims:**

- Sentinel-CPS proposes a scoped architecture for reducing exposure in remote CPS lab operation.
- The project studies a Gateway-centered design using one Gateway, one Hub, one vehicle, and one Smart TV track.

**Claims that must wait:**

- Claims about physical validation, security effectiveness, observability, or anomaly detection results.

## Chapter 2: Literature Review and Background

**Supports:** academic context for Zero Trust, remote labs, CPS/IoT security, eBPF observability, embedded PID navigation, and lightweight anomaly detection.

**Artifacts and evidence:**

- Preliminary literature alignment
- Zotero source library
- Requirement-to-literature notes

**Safe claims:**

- Prior work motivates strict trust boundaries, host-level observability, and constrained edge control in CPS/IoT settings.

**Claims that must wait:**

- Claims that Sentinel-CPS outperforms existing systems unless measured directly.

## Chapter 3: System Design and Methodology

**Supports:** architecture, threat model, trust boundaries, validation plan, and methodology.

**Artifacts and evidence:**

- System Architecture Document
- Functional Requirements Document
- Security Requirements Document
- Serial Protocol v0.1.1
- Lab Execution Master Runbook v0.1.1
- Evidence-to-thesis integration files

**Potential figures/tables:**

- Sentinel-CPS architecture diagram
- Remote access trust boundary diagram
- Gateway-to-Hub serial chokepoint diagram
- Validation target matrix
- Public/private evidence boundary table

**Safe claims:**

- The design routes remote control through a Gateway and serial chokepoint.
- The methodology evaluates access control, physical navigation preparation, Gateway observability, and threat-detection preparation within a bounded lab prototype.

**Claims that must wait:**

- Final validation outcomes and measured performance.

## Chapter 4: Implementation

**Supports:** what was built and how the system components were implemented.

**Artifacts and evidence:**

- Gateway MVP v0.1.1
- Serial Chokepoint MVP v0.1.1
- Vehicle Firmware MVP v0.1.1
- Security Validation Scripts v0.1.1
- eBPF/BCC Trace MVP v0.1.1
- AI Anomaly Detection MVP v0.1.1

**Potential figures/tables:**

- Gateway dashboard screenshot
- File tree overview
- Serial protocol table
- Firmware state-machine summary
- eBPF trace schema
- Anomaly rule table

**Safe claims:**

- The prototype implements a native Flask Gateway, structured logging, a serial abstraction, ESP32 firmware skeletons, and offline analysis tools within the scoped MVP.

**Claims that must wait:**

- Claims about successful physical navigation, real serial testing, or eBPF trace capture unless lab evidence exists.

## Chapter 5: Validation and Evaluation

**Supports:** results, evidence, and validation claims.

**Artifacts and evidence:**

- VAL-01 Access Control evidence
- VAL-03 TV-as-a-Track photos/videos/calibration CSVs
- VAL-04 actions.csv, telemetry.csv, eBPF traces, correlation reports
- VAL-05 anomaly scores, summaries, incident reports, STOP logs

**Potential figures/tables:**

- VAL-01 endpoint access matrix
- VAL-03 calibration result table
- VAL-04 trace summary table
- VAL-05 incident report summary
- STOP behavior evidence table

**Safe claims:**

- Observed results during the validation run support specific claims within the tested configuration.

**Claims that must wait:**

- Any claim not directly tied to collected evidence.

## Chapter 6: Discussion, Limitations, and Future Work

**Supports:** honest scope limits and future improvements.

**Artifacts and evidence:**

- Limitations docs from each package
- Failed test notes
- Troubleshooting notes
- Evidence quality checklist

**Safe claims:**

- Limitations include a single-vehicle scope, best-effort fd-to-path resolution for eBPF, offline anomaly scoring, synthetic data limits, and lab-specific network constraints.
