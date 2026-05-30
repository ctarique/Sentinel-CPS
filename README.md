# Sentinel-CPS

**Sentinel-CPS** is a zero-trust edge gateway architecture for securing remote cyber-physical systems education. The project is being developed as a master's thesis prototype for safely exposing autonomous IoT/CPS hardware to remote users without giving those users direct access to protected gateway services, edge devices, or broader enterprise infrastructure.

The system combines a hardened Raspberry Pi gateway, an authorized remote-access workflow, ESP32-based autonomous edge vehicles, encrypted ESP-NOW communication, a Smart TV-based dynamic physical track, and planned eBPF/AI-assisted anomaly detection at the gateway chokepoint.

---

## Research Purpose

Remote IoT and robotics labs create a difficult security problem: students need meaningful hands-on access to physical devices, but exposing development hosts, control interfaces, or edge devices can introduce risks involving lateral movement, unauthorized control, telemetry abuse, and unsafe physical behavior.

Sentinel-CPS addresses this problem by separating the system into explicit trust boundaries:

* **Remote Educational Sandbox:** controlled user access through an authorized bastion workflow
* **Zero-Trust Gateway:** Raspberry Pi enforcement node for access control, command mediation, logging, and observability
* **Encrypted Edge Telemetry:** ESP32 hub-and-spoke communication using ESP-NOW with encrypted peer communication
* **TV-as-a-Track Execution Layer:** Smart TV surface that renders dynamic tracks followed by ESP32 vehicles using analog light sensors and PID control
* **eBPF/AI Mitigation Layer:** planned gateway-side monitoring of serial I/O behavior and telemetry patterns for anomaly detection and emergency STOP/severance response

---

## Core Security Goals

* Prevent direct remote exposure of protected CPS control infrastructure
* Enforce least-privilege access between student workflows, gateway services, display endpoints, and edge devices
* Use the gateway as a central policy enforcement and observability chokepoint
* Replace manual track construction with repeatable software-defined physical test generation
* Detect abnormal command, telemetry, replay, injection, or DoS-like behavior through application logs, serial tracing, and AI-assisted anomaly scoring
* Preserve physical safety through emergency STOP and controlled serial-path severance logic

---

## Current Thesis Scope

The current Sentinel-CPS architecture focuses on:

* Bare-metal Raspberry Pi gateway execution using `systemd`
* Default-deny `nftables` access control with service-level segmentation
* Ed25519 key-based administrative access
* Flask-based command-and-control web application on TCP Port `8080`
* Lane Builder and digital twin telemetry interface
* Smart TV-as-a-Track physical execution model
* ESP32 vehicles using downward-facing analog light sensors and onboard PID logic
* ESP32 hub mediation between gateway serial commands and encrypted ESP-NOW edge communication
* Planned eBPF tracing of gateway serial read/write behavior
* Lightweight AI-assisted anomaly detection and mitigation

---

## Architecture Overview

Sentinel-CPS is organized into four major layers:

| Layer                         | Purpose                                                                         | Core Components                                                                         |
| ----------------------------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Remote Educational Sandbox    | Provides controlled remote access for students, reviewers, or administrators    | Authorized VPN workflow, bastion host, isolated development hardware                    |
| Zero-Trust Gateway            | Mediates access, commands, logging, web services, and observability             | Raspberry Pi 4, Linux, `nftables`, Flask, `systemd`, Ed25519 SSH, eBPF tooling          |
| Encrypted Edge Telemetry      | Carries command and telemetry traffic between the gateway hub and edge vehicles | ESP32 hub, ESP-NOW, CCMP encryption, ESP32 vehicle nodes                                |
| TV-as-a-Track Execution Layer | Converts a digital control interface into a physical navigation surface         | Smart TV display, Lane Builder, digital twin overlay, analog light sensors, PID control |

---

## TV-as-a-Track Execution Model

A major design feature of Sentinel-CPS is the use of a horizontally mounted Smart TV as a dynamic physical track.

Instead of relying on static tape tracks, printed lanes, or camera-based navigation, the system renders a high-contrast digital lane pattern on the TV surface. ESP32 vehicles use downward-facing analog light sensors to read pixel luminance differences and follow the generated track using onboard PID control.

This creates a repeatable cyber-physical test surface where track layouts can be changed through software while the physical vehicles respond to the rendered environment in real time.

---

## Gateway Security Model

The Raspberry Pi gateway acts as the central enforcement point for the system. It is responsible for hosting the control interface, mediating commands, logging system behavior, and preparing telemetry for anomaly detection.

Key controls include:

* Default-deny inbound access control using `nftables`
* Separation of administrative access and display/control access
* Ed25519 key-based SSH administration
* Service-level access restrictions for the web interface
* Serial chokepoint between the gateway and ESP32 hub
* Native host execution through `systemd` to preserve low-level observability
* Planned eBPF tracing of serial read/write behavior for runtime monitoring

The gateway is intentionally treated as the only authorized mediator between remote users and the physical CPS environment.

---

## eBPF and AI-Assisted Threat Mitigation

The planned monitoring layer focuses on behavior at the gateway chokepoint. Application logs alone may not reveal abnormal low-level activity, so Sentinel-CPS is designed to incorporate eBPF-based tracing of serial read/write behavior associated with the gateway-to-hub communication path.

The anomaly detection pipeline is intended to evaluate:

* Command frequency
* Telemetry timing
* Serial read/write behavior
* Expected ESP-NOW payload patterns
* PID and vehicle response behavior
* Replay, injection, flooding, or DoS-like conditions

When critical anomalies are detected, the gateway is designed to issue an emergency STOP command and initiate controlled serial-path severance to protect the physical system.

---

## Repository Structure

```text
.
├── docs/          # Thesis documentation, architecture notes, diagrams, and validation planning
├── firmware/      # ESP32 hub and vehicle firmware
├── .env.example   # Sanitized environment configuration template
├── .gitignore
├── LICENSE
└── README.md
```

Additional gateway, telemetry, and validation code will be organized as implementation continues.

---

## Current Status

Sentinel-CPS is currently in active thesis development.

The current architecture has been updated to focus on:

* Zero-trust gateway mediation
* Remote educational access through a controlled bastion workflow
* Smart TV-based dynamic track generation
* ESP32 light-sensor/PID vehicle navigation
* Encrypted ESP-NOW hub-and-spoke edge communication
* eBPF/AI-assisted gateway anomaly detection and mitigation

This repository is intended to serve as a public, sanitized portfolio version of the project. Sensitive deployment details, internal network identifiers, credentials, and institution-specific configuration values are intentionally excluded.

---

## Validation Plan

The thesis validation plan focuses on five major areas:

1. **Access Control Validation**
   Confirm that only approved endpoints can access gateway services and that display endpoints are not granted administrative privileges.

2. **Remote Operation Validation**
   Demonstrate that users can generate tracks, observe telemetry, and interact with the CPS through a controlled workflow without direct gateway exposure.

3. **Physical Navigation Validation**
   Evaluate whether ESP32 vehicles can reliably follow TV-rendered tracks using analog light sensors and onboard PID control.

4. **Observability Validation**
   Collect application logs, serial I/O traces, and edge telemetry to establish baseline behavior.

5. **Threat Mitigation Validation**
   Simulate injection, replay, abnormal command frequency, or DoS-like behavior and evaluate whether the gateway can trigger safe STOP/severance behavior.

---

## Documentation

Supporting thesis documentation is maintained in the `docs/` directory.

Planned documentation includes:

* System Architecture Document
* Thesis Scope Statement
* Thesis Synopsis
* Sanitized architecture blueprint
* Validation plan
* Threat model and security assumptions
* Implementation notes

---

## Public Repository Notice

This repository is a public portfolio and research-development version of Sentinel-CPS. It is not a production deployment guide.

The repository intentionally avoids publishing:

* Real IP addresses
* MAC addresses
* Hostnames tied to live infrastructure
* Credentials or private keys
* Internal network diagrams
* Sensitive firewall rules
* Institution-specific access details

All public diagrams and configuration examples should be treated as sanitized representations of the thesis architecture.

---

## Author

**Tarique Chowdhury**
M.S. Cybersecurity Candidate
Southeast Missouri State University

---

## License

This project is licensed under the MIT License.
