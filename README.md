# Sentinel-CPS

### **Project Overview**
Sentinel is a hardened, zero-trust edge gateway designed to secure Cyber-Physical Systems (CPS) within a remote IoT laboratory. Operating within a highly restrictive university enterprise network, this architecture establishes an isolated command-and-control boundary between a shared student sandbox and autonomous edge nodes. 

This **monorepo** houses the complete Cyber-Physical System stack, including the bare-metal Linux Gateway Infrastructure (Python/Flask), the autonomous Edge Firmware (ESP32 C++), and the comprehensive thesis documentation.

---

### **Project Scope & Phases**
The Sentinel architecture is developed and deployed across three distinct academic phases:

* **Phase I: Secure Infrastructure (Foundation)**
  Establishing the Zero-Trust perimeter. This includes Layer 2 network micro-segmentation, SSH cryptographic lockouts, and the bare-metal deployment of the Python Gateway daemon to manage the air-gapped physical hardware.
* **Phase II: Autonomous Edge & Digital Twin (Active)**
  Deploying the Hub-and-Spoke physical topology. This phase introduces the "Split-Channel" ESP-NOW wireless bridge, computer vision lane tracking, and the Mission Control Smart TV acting as a live "Digital Twin" telemetry dashboard.
* **Phase III: K-Space Observability & AI Inference (Upcoming)**
  Securing the runtime environment. Leveraging the bare-metal execution of the Gateway, this phase integrates eBPF (Extended Berkeley Packet Filter) kernel hooks to monitor raw serial syscalls. An AI-driven anomaly detection model will evaluate this telemetry to identify and mitigate threats (e.g., DoS flooding, injection attacks) in real-time.

---

### **Hardware Topology: The Dual-Zone Boundary**
To prevent unauthorized lateral movement and secure the flashing process, the physical architecture is strictly divided into two distinct zones connected via a single ethernet switch:

#### **Zone 1: The Student Sandbox**
* **Shared Enterprise Workstation (Windows):** Students authenticate via enterprise AD to access this machine remotely.
* **Secondary ESP32 Hub:** Connected directly to the workstation via USB. Students use the Arduino IDE to safely compile and flash secondary microcontrollers without ever touching the primary infrastructure.

#### **Zone 2: The Sentinel Boundary**
* **The Gateway (Raspberry Pi):** The core routing and security layer. It hosts the Python Flask web portal (located in `/gateway`) that operates natively on **bare-metal via systemd** to ensure uninterrupted host-level observability for Phase III eBPF integration. It features a "Digital Twin" JSON Lane Builder to visually map physical tracks and render real-time vehicle telemetry.
* **Primary ESP32 Controller (Hub):** Connected to the Pi via secure USB serial on `/dev/ttyUSB0`.
* **Mission Control Smart TV:** Acts as the physical visual boundary for the vehicles and connects exclusively to the isolated Gateway AP to display the Zero-Trust dashboard.
* **Autonomous Edge Nodes:** The vehicles utilize a **Split-Channel model**: an **encrypted ESP-NOW wireless bridge** for low-latency control commands and a **private, isolated Gateway-hosted Access Point** (`Sentinel_Vision`) for high-bandwidth video ingestion.

---

### **Security & Access Control Constraints**
Because the gateway operates in a shared enterprise environment, it employs a strict "Default-Deny" inbound policy and identity-based access controls.

* **Network Micro-segmentation (Tiered HLAC):** Inbound traffic is regulated via `nftables`. SSH access is strictly constrained to authorized administrators, while the Smart TV is whitelisted strictly for Port 5000 to access the web UI.
* **Zero-Trust Identity Enforcement:** Transitioning away from IP-based micro-segmentation, the gateway employs an **SSH Cryptographic Lockout**. Password authentication is completely disabled. Access to the Raspberry Pi is exclusively restricted to **Ed25519 key pairs** stored securely on the administrative profiles of authorized management workstations.
* **Interaction Model:** Students cannot directly flash or SSH into the Sentinel Boundary. All interaction with the autonomous cars occurs strictly through the Pi’s **bare-metal Flask web portal**.
* **Remote Access:** Off-campus management is **architected to utilize** the existing university VPN and a designated **Windows Bastion Host** to ensure the gateway remains shielded from the public internet.

---

### **Tech Stack**
* **Security & Infrastructure:** Linux (`nftables`), Ed25519 Cryptography, **systemd**, eBPF (`bcc-tools`).
* **Backend Gateway:** Python 3, Flask, PySerial, JSON Parsing, `fcntl` (Thread-safe concurrent logging).
* **Hardware & Wireless:** Raspberry Pi 4, ESP32 (C++/Arduino), **ESP-NOW (CCMP Encrypted)**, OpenCV, **hostapd / dnsmasq** (Private AP).

---

### **Architecture Blueprint**
![Sentinel Architecture Blueprint](docs/Unified_Zero-Trust_CPS_Blueprint_v9.0.png)

**Author:** Tarique Chowdhury  
**License:** MIT