# Sentinel-CPS Evidence-to-Thesis Integration Kit v0.1.1

## Purpose

This package connects Sentinel-CPS engineering artifacts, lab evidence, and thesis writing. It helps ensure that each script, firmware package, screenshot, CSV log, trace, video, and runbook supports a specific validation target and a thesis-safe claim.

This kit is an organization and traceability artifact. It does not validate the system by itself. Validation claims should only be finalized after evidence is collected, reviewed, indexed, and mapped to a requirement or validation objective.

## How this prevents scope creep

Use this package to keep the thesis focused on the approved MVP scope:

- One Raspberry Pi Gateway
- One ESP32 Hub
- One ESP32 vehicle
- One Smart TV track
- Native Flask dashboard on Port 8080
- `/dev/ttyUSB0` serial chokepoint
- eBPF/BCC metadata observability
- Offline anomaly scoring and STOP-response preparation

Do not expand the thesis into Docker deployment, camera navigation, multi-agent robotics, cloud control, production-grade AI, or enterprise-scale security claims.

## How to use after each lab session

1. Copy raw evidence into the private OneDrive evidence folder.
2. Add each file to `master_evidence_index_template.csv` or your working master evidence index.
3. Map evidence to claims using `claim_evidence_traceability_template.csv`.
4. Update the figure/table plan if the evidence is visually useful.
5. Write 1-2 thesis paragraphs while the test details are fresh.
6. Record limitations and unexpected behavior immediately.
7. Create redacted public copies only when needed.

## Public/private boundary

Public GitHub may contain source code, templates, sanitized configs, runbooks, and redacted examples. Private OneDrive should contain raw evidence, lab photos/videos, raw network information, hostnames, usernames, IP addresses, MAC addresses, firewall output, and any logs that reveal university environment details.

## Thesis-safe wording

Prefer wording such as:

- “supports evidence for”
- “was observed during the validation run”
- “within the tested configuration”
- “prepares offline anomaly scoring”
- “supports correlation”

Avoid wording such as:

- “guarantees”
- “complete visibility”
- “unbypassable”
- “production-ready”
- “fully secure”
- “proves all attacks are blocked”
