# Figure and Table Plan

Use this plan to decide what visual material belongs in the thesis and what must be redacted before public use.

| Item | Working Title | Chapter | Source Evidence | Caption Draft | Public/Private Handling |
|---|---|---|---|---|
| Figure 1 | Sentinel-CPS Architecture Diagram | Ch. 3 | System Architecture Document / sanitized diagram | High-level Sentinel-CPS architecture showing the remote access path, Raspberry Pi Gateway, ESP32 Hub, ESP32 vehicle, and Smart TV substrate. | Public if sanitized. |
| Figure 2 | Remote Access Trust Boundary | Ch. 3 | Architecture docs / security runbook | Trust boundary separating admin access, dashboard access, Gateway services, and display endpoint privileges. | Public if IPs/usernames removed. |
| Figure 3 | Gateway-to-Hub Serial Chokepoint | Ch. 3 or 4 | Serial protocol doc | The Gateway-to-Hub serial interface used as the scoped command and telemetry chokepoint. | Public. |
| Figure 4 | Gateway Dashboard Interface | Ch. 4 | Dashboard screenshot | Sentinel-CPS Flask dashboard showing command controls, telemetry state, and Lane Builder placeholder. | Public if URL/IP redacted. |
| Figure 5 | TV-as-a-Track Physical Setup | Ch. 4 or 5 | Lab photo | ESP32 vehicle and downward-facing analog sensors positioned over the Smart TV track. | Private or redacted if lab identifiers appear. |
| Table 1 | Serial Protocol v0.1.1 | Ch. 4 | serial_protocol_v0.1.md | Gateway-to-Hub command and telemetry message schema used by the MVP. | Public. |
| Table 2 | VAL-01 Endpoint Access Results | Ch. 5 | endpoint test matrix | Observed Port 22 and Port 8080 access results by endpoint role. | Redact IPs/MACs/hostnames. |
| Table 3 | VAL-03 ADC Calibration Results | Ch. 5 | adc_calibration_template.csv | Black/white ADC readings used to calibrate the TV-as-a-Track sensor threshold. | Public if no sensitive identifiers. |
| Table 4 | VAL-04 Observability Summary | Ch. 5 | eBPF summary and correlation report | Summary of application actions, telemetry rows, and serial syscall metadata during validation. | Redact environment details. |
| Figure 6 | eBPF Trace Pipeline | Ch. 4 or 5 | eBPF docs | Metadata-only host observability path from syscall tracepoints to CSV evidence and correlation report. | Public. |
| Figure 7 | VAL-05 Anomaly Scoring Workflow | Ch. 5 | anomaly detection docs | Offline anomaly scoring workflow using Gateway logs, telemetry logs, and eBPF traces. | Public. |
| Table 5 | VAL-05 Incident Summary | Ch. 5 | anomaly summary and incident report | Triggered rules, severity counts, and operator-response recommendations from offline scoring. | Public if data is redacted or synthetic. |
