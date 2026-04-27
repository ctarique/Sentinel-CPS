# Project Sentinel: Zero-Trust Edge Gateway Architecture

### **Project Overview**
Sentinel is a hardened, zero-trust edge gateway designed to secure Cyber-Physical Systems (CPS) within a remote IoT laboratory. Operating within a highly restrictive university enterprise network, this architecture establishes an isolated command-and-control boundary between a shared student sandbox and autonomous edge nodes. 

This repository houses **Phase I: Secure Infrastructure**, focusing on identity-based access controls, cryptographic lockouts, and network micro-segmentation.

---

### **Hardware Topology: The Dual-Zone Boundary**
To prevent unauthorized lateral movement and secure the flashing process, the physical architecture is strictly divided into two distinct zones connected via a single ethernet switch:

#### **Zone 1: The Student Sandbox**
* **Shared Enterprise Workstation (Windows):** Students authenticate via enterprise AD to access this machine remotely.
* **Secondary ESP32 Hub:** Connected directly to the workstation via USB. Students use the Arduino IDE to safely compile and flash secondary microcontrollers without ever touching the primary infrastructure.

#### **Zone 2: The Sentinel Boundary**
* **The Gateway (Raspberry Pi):** The core routing and security layer. It hosts the Flask web portal (located in `/gateway`) that students use to interact with the physical hardware. The portal operates natively on **bare-metal via systemd** (see `sentinel.service.template`) to ensure uninterrupted host-level observability for Phase II eBPF integration.
* **Primary ESP32 Controller (Hub):** Connected to the Pi via secure USB serial on `/dev/ttyUSB0`.
* **Autonomous Edge Nodes:** The vehicles utilize a **Split-Channel model**: an **encrypted ESP-NOW wireless bridge** for low-latency control commands and a **private, isolated Gateway-hosted Access Point** (`Sentinel_Vision`) for high-bandwidth video ingestion.

---

### **Security & Access Control Constraints**
Because the gateway operates in a shared enterprise environment, it employs a strict "Default-Deny" inbound policy and identity-based access controls.

* **Network Micro-segmentation:** Inbound traffic is regulated via `nftables` (see `docs/firewall_setup.md`). SSH access is strictly constrained, and only explicitly whitelisted MAC addresses can reach the Flask web UI.
* **Zero-Trust Identity Enforcement:** Transitioning away from IP-based micro-segmentation, the gateway employs an **SSH Cryptographic Lockout**. Password authentication is completely disabled. Access to the Raspberry Pi is exclusively restricted to **Ed25519 key pairs** stored securely on the administrative profiles of authorized management workstations.
* **Interaction Model:** Students cannot directly flash or SSH into the Sentinel Boundary. All interaction with the autonomous cars occurs strictly through the Pi’s **bare-metal Flask web portal**.
* **Remote Access:** Off-campus management is **architected to utilize** the existing university VPN and a designated **Windows Bastion Host** to ensure the gateway remains shielded from the public internet.

---

### **Tech Stack**
* **Security & Infrastructure:** Linux (`nftables`), Ed25519 Cryptography, **systemd**.
* **Backend Gateway:** Python 3, Flask, PySerial, `fcntl` (Thread-safe concurrent logging).
* **Hardware & Wireless:** Raspberry Pi 4, ESP32, **ESP-NOW (CCMP Encrypted)**, **hostapd** (Private AP).

---

### **Roadmap: Phase II**
This secure gateway serves as the foundational infrastructure for Phase II threat detection capabilities. Upcoming developments include implementing **eBPF (Extended Berkeley Packet Filter) kernel hooks** and **AI-driven anomaly detection** directly on the Raspberry Pi to monitor and mitigate runtime threats targeting the edge nodes.

**Author:** Tarique Chowdhury  
**License:** MIT