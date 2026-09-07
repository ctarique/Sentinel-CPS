# Sentinel-CPS

**Sentinel-CPS** is a Zero-Trust-oriented cyber-physical systems (CPS) laboratory prototype developed as my master's thesis in Cybersecurity at Southeast Missouri State University.

The project investigates how an **instructor-administered Raspberry Pi 4 Gateway** can provide students with meaningful access to a physical ESP32-based experiment while keeping administrative authority, unrestricted device access, and recovery control separate from ordinary student operation.

The Raspberry Pi Gateway serves as the central **policy, workflow, evidence, and coordination point**. Students interact through a bounded browser workflow for authorized ESP32 source-code submission and permitted experiment activity. The Gateway communicates with one ESP32 CPS over **Wi-Fi** and drives a local Smart TV directly through **HDMI**.

Sentinel-CPS applies selected Zero Trust principles at prototype scale, including explicit authorization, least privilege, role separation, bounded exposure, controlled workflow acceptance, and evidence-aware validation. It is not intended to represent a complete enterprise Zero Trust Architecture.

## Architecture

The final architecture separates four primary responsibilities:

- **Instructor Administration** — Gateway configuration, laboratory policy, recovery, exceptional approval, and evidence review.
- **Student / Lab-User Workflow** — bounded browser-based submission and permitted experiment interaction.
- **Raspberry Pi 4 Sentinel Gateway** — authorization, workflow control, preparation, Wi-Fi communication, evidence recording, and recovery coordination.
- **Physical CPS Environment** — one ESP32 CPS testbed and a Smart TV connected directly to the Raspberry Pi through HDMI.

Primary paths:

**Student / Lab User → Bounded Browser Workflow → Raspberry Pi 4 Sentinel Gateway → Wi-Fi → ESP32 CPS**

**Raspberry Pi 4 Sentinel Gateway → HDMI → Smart TV**

Instructor administration remains separately authorized from student operation.

## Bounded Workflow

Sentinel-CPS defines five workflow stages:

1. **Submit** — receive ESP32 source code through the authorized Gateway interface.
2. **Check and Authorize** — evaluate role, requested activity, permitted work item, and approved laboratory configuration.
3. **Prepare** — prepare only the permitted deployment or interaction activity.
4. **Communicate** — communicate with the ESP32 CPS through the Gateway-mediated Wi-Fi path.
5. **Record and Recover** — preserve evidence and support bounded instructor-governed status, stop, reset, or recovery handling.

Each stage has a separate evidentiary meaning. Successful submission, preparation, communication, and physical operation are not treated as interchangeable claims.

## Security Model

The prototype emphasizes:

- explicit authorization,
- least privilege,
- instructor/student role separation,
- bounded student interaction,
- limited Gateway service exposure,
- protected credentials and private configuration,
- instructor-governed recovery, and
- evidence-proportional security claims.

Network or browser reachability does not automatically grant administrative authority.

## Validation

Evaluation is organized around five validation targets:

| Target | Focus |
| --- | --- |
| **VAL-01** | Gateway roles and workflow boundary |
| **VAL-02** | Bounded Wi-Fi deployment / interaction |
| **VAL-03** | HDMI display and physical laboratory substrate |
| **VAL-04** | Evidence and supporting observability |
| **VAL-05** | Supporting monitoring, mitigation, and offline analysis |

Sentinel-CPS distinguishes Web/Gateway evidence, preparation/build evidence, Wi-Fi/device-response evidence, Gateway host-observability evidence, and direct physical evidence.

Physical claims require direct laboratory observation or another approved physical evidence source associated with the documented run.

## Supporting Security Capabilities

### eBPF / BCC

Selected eBPF/BCC instrumentation may provide Gateway-side host metadata for correlation and diagnosis. It is supporting observability and does not independently prove ESP32 or physical behavior.

### Deterministic Monitoring and Mitigation

Selected deterministic safeguards may identify documented abnormal patterns. Mitigation remains bounded, authorized, recorded, and instructor-governed.

### Isolation Forest

Isolation Forest is limited to **offline analyst assistance**. It may rank unusual eligible evidence windows for later investigation, but it does not control the Gateway or ESP32, authorize activity, modify live policy, or trigger mitigation.

## Repository Organization

The repository separates the current Sentinel-CPS architecture from superseded research and implementation work.

- `gateway/` — current Raspberry Pi Gateway implementation area
- `firmware/` — current ESP32 CPS firmware area
- `docs/architecture/` — current architecture documentation
- `host/` — Gateway host configuration area
- `overwatch/` — supporting observability and analysis areas
- `tools/` — reusable security-validation and evidence-integration tooling
- `archive/pre-refocus/` — preserved development from earlier Sentinel-CPS architectures

## Historical Development

Sentinel-CPS underwent a major architecture refocus on August 19, 2026.

Earlier development included an ESP32 Hub, Raspberry Pi-to-Hub USB serial communication, `/dev/ttyUSB0`, ESP-NOW, serial command and telemetry protocols, vehicle-oriented embedded communication, serial-focused eBPF/BCC observability, and earlier Smart TV/network arrangements.

That work is preserved under `archive/pre-refocus/` as part of the project's engineering and research history, but it does **not** define or validate the final Gateway/Wi-Fi/HDMI architecture.

## Current Status

The final Gateway-centered architecture, requirements, research methodology, security boundaries, and validation framework have been defined and reconciled.

Implementation and laboratory validation of the final architecture remain ongoing. Historical software results are preserved as development evidence rather than being presented as validation of the final system.

## Public Repository Notice

This repository is a **sanitized research and portfolio representation** of Sentinel-CPS.

Credentials, private keys, private network addresses, device identifiers, institution-specific infrastructure details, and other sensitive deployment information are intentionally excluded.

## Author

**Tarique Chowdhury**  
M.S. Cybersecurity Candidate  
Southeast Missouri State University

## License

This project is licensed under the MIT License.
