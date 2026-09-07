# IoT Lab Network Architecture: Project Sentinel

## Overview
The Sentinel Gateway utilizes a multi-tiered network architecture to isolate autonomous hardware from the university enterprise infrastructure. The architecture enforces a Zero-Trust perimeter where remote management traffic is mediated through a secure Bastion Host, and all high-bandwidth sensor data is contained within a private, air-gapped wireless segment.

## Components

* **SEMO Student VPN & Bastion Host:** The architected secure tunnel for off-campus access, terminating at a physically co-located Windows lab workstation.
* **Sentinel Gateway (Raspberry Pi):** The central enforcement node running a bare-metal Flask daemon and an `nftables` firewall.
* **ESP32 Hub Bridge:** A hardwired serial translator connected to the Gateway via USB (`/dev/ttyUSB0`).
* **Autonomous Edge (ESP32 Cars):** Mobile units operating autonomously and communicating via a Split-Channel wireless model.

## Network Layout

    [OFF-CAMPUS USER] --(SSO Auth)--> [SEMO VPN]
                                         |
                                    [WINDOWS BASTION HOST] --(RDP)
                                         |
    [SENTINEL GATEWAY (Raspberry Pi)] <---(Layer 2 HLAC/nftables)
        |                |
        | (USB Serial)   +-- (Private Wi-Fi AP) <---- [VIDEO STREAM]
        |                |                                ^
    [ESP32 HUB] <---(Encrypted ESP-NOW)---> [AUTONOMOUS ESP32 CARS]

## Security Controls
The Gateway enforces hardware-level security to minimize the attack surface:

* **Default-Deny Policy:** The `nftables` firewall implements a strict `DROP` policy for all unsolicited inbound traffic.
* **Layer 2 HLAC:** SSH (port 22) and Web Gateway (port 5000) access is explicitly restricted to the MAC addresses of authorized management workstations.
* **Split-Channel Isolation:** High-bandwidth video data is ingested via a private `hostapd` Access Point that lacks routing to the university network, preserving the outbound air-gap.
* **Control Integrity:** All wireless command and telemetry packets utilize CCMP-encrypted ESP-NOW to reject spoofed or injected payloads.