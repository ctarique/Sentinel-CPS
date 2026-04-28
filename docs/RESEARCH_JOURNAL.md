# Research Journal: Sentinel Gateway Project

## [ENTRY 01] Foundational Milestones & Architecture (March 2026)
**Project Phase:** Phase 1: Infrastructure & Hardening

### Daily Objective
Establish the physical and logical "Zero-Trust" baseline for the Sentinel Gateway.

### Experimental Log
- **Sentinel Identity:** Hardened Raspberry Pi by disabling password-based SSH and enforcing Ed25519 cryptographic keys.
- **Surface Reduction:** Physically disabled Wi-Fi/BT interfaces on the ESP32-CAM.
- **Firewall:** Initialized `nftables` with a "Drop All" default inbound policy.
- **Air-Gap Protocol:** Formulated the "Air-Gap Courier" workflow for secure code deployment via physical media.

---

## [ENTRY 02] Hardware Resilience & Concurrency (April 8, 2026)
**Project Phase:** Phase 1.5: Stability & Logic Hardening

### Daily Objective
Resolve environment-specific deployment errors and ensure thread-safe hardware communication.

### Technical Challenges & Resolutions
| Issue | Root Cause | Resolution |
| :--- | :--- | :--- |
| **Docker Failure** | `iptables` dependency in air-gap | Set `"iptables": false` in `daemon.json` |
| **Kernel Error -32** | USB 2.0 Power Sag (500mA) | Migrated to USB 3.0 Blue Port (900mA) |
| **Buffer Scrambling**| Race conditions on serial port | Implemented `threading.Lock()` (Mutex) |

### Results
- Achieved 100% data integrity across 10 simultaneous threads. ESP32-CAM successfully returned `LED_ON_OK` responses without stalling.

---

## [ENTRY 03] Multi-Endpoint Identity & Sanitization (April 13, 2026)
**Project Phase:** Phase 1: Infrastructure & Hardening

### Daily Objective
Establish unique cryptographic identities for management endpoints and implement a sanitization workflow for version control.

### Experimental Log
- **Identity Hardening:** Deployed unique Ed25519 key pairs for the MacBook Pro and Windows workstation.
- **SSH Lockdown:** Neutralized a configuration override in `/etc/ssh/sshd_config.d/50-cloud-init.conf` to permanently disable password fallbacks.
- **Client Automation:** Configured `~/.ssh/config` for seamless identity mapping and keychain integration.
- **Repository Sanitization:** Implemented a `.env` architecture to decouple sensitive enterprise infrastructure data from the GitHub-hosted codebase.

---

## [ENTRY 04] Logical Isolation & Bare-Metal Pivot (April 18, 2026)
**Project Phase:** Phase 2: Advanced Monitoring Transition

### Daily Objective
Formalize the architectural response to enterprise IT network restrictions and optimize for kernel-level monitoring.

### Experimental Log
- **IT Constraints:** Enterprise IT officially denied VPN, external RDP access, and DHCP reservations for the lab subnet. The gateway will operate on a dynamic DHCP lease.
- **Bare-Metal Pivot:** Replaced Docker with a native `systemd` service (`sentinel.service`). This eliminates the container abstraction layer, allowing Phase 2 eBPF C-scripts to hook directly into host-level syscalls.
- **Resolution:** Configured `avahi-daemon` for mDNS (`.local` hostname routing) to bypass the dynamic IP limitation.

---

## [ENTRY 05] Layer 2 HLAC Enforcement (April 21, 2026)
**Project Phase:** Phase 1: Infrastructure & Hardening

### Daily Objective
Synchronize directory architecture and enforce hardware-level access control.

### Experimental Log
- **Structural Mirroring:** Migrated to a professional `~/GitHub_Projects/sentinel-zero-trust-gateway/` structure to ensure path-parity across environments.
- **Layer 2 HLAC Implementation:** Transitioned to Hardware Level Access Control (HLAC) via `nftables`. Explicitly whitelisted MAC addresses for the MacBook and Windows workstations for Port 22 (SSH) and Port 5000 (Web Gateway).
- **Persistence:** Updated `sentinel.service` to map to the new repository paths and ensure startup persistence.

---

## [ENTRY 06] Connectivity Optimization & OPSEC (April 22, 2026)
**Project Phase:** Phase 1: Infrastructure & Hardening

### Daily Objective
Streamline management access and formalize sanitized academic documentation.

### Experimental Log
- **SSH Aliases:** Abstracted IP addresses in `~/.ssh/config` using `sentinel` and `iot-pi` aliases to reduce command overhead and connection errors.
- **OPSEC:** Deployed a sanitized `CONNECTIVITY_GUIDE.md` utilizing placeholders for internal IPs and usernames, preserving lab security during academic review.

---

## [ENTRY 07] Digital Twin & Split-Channel Integration (April 27, 2026)
**Project Phase:** Phase 2: Advanced Monitoring Transition

### Daily Objective
Architect a visual telemetry dashboard ("Mission Control") that integrates physical hardware tracking without compromising the Zero-Trust boundary.

### Experimental Log
- **Digital Twin Architecture:** Formally scoped a "Lane Builder" JSON parsing module within the Flask application. This will dynamically map the physical track layout on the lab floor and visually render ESP32 telemetry in real-time.
- **Split-Channel Telemetry:** The ESP32 endpoints will utilize computer vision to read their physical location and transmit this data via a low-latency, CCMP-encrypted ESP-NOW link to the Gateway.
- **Zero-Trust Display Enforcement:** A horizontal Smart TV (acting as both the physical track and telemetry dashboard) will be connected to a private `hostapd` Access Point on the Gateway. The TV’s MAC address has been designated for Tiered HLAC whitelisting—permitting access to Port 5000 while remaining cryptographically barred from SSH.

### Next Immediate Action
1. Configure `hostapd` and `dnsmasq` on the Raspberry Pi to establish the `wlan0` Access Point for the Smart TV.
2. Draft the C++ firmware logic for the encrypted ESP-NOW handshake.