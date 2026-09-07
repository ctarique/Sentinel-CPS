# Sentinel-CPS Sanitized Network Asset Inventory

This document describes the Sentinel-CPS lab asset roles without exposing live IP addresses, MAC addresses, or institutional hostnames.

## 1. Raspberry Pi 4 Gateway

- Interface: eth0
- IP Address: <GATEWAY_LAB_IP>
- MAC Address: <GATEWAY_MAC>
- mDNS Hostname: iot-pi.local
- Role: Zero-Trust Gateway, C2 host, serial chokepoint, firewall enforcement point, and observability node.

## 2. Windows Bastion Host

- Hostname: <BASTION_HOSTNAME>
- IP Address: <BASTION_LAB_IP>
- MAC Address: <BASTION_MAC>
- Role: VPN/RDP-accessed remote educational ingress point.

## 3. Administrative Client

- Interface: <ADMIN_INTERFACE>
- IP Address: <ADMIN_CLIENT_IP>
- MAC Address: <ADMIN_CLIENT_MAC>
- Role: Approved administrative endpoint for Gateway management.

## 4. Hub ESP32

- Chip Type: ESP32-D0WDQ6
- MAC Address: <HUB_ESP32_MAC>
- Role: Tethered serial-to-ESP-NOW bridge connected through /dev/ttyUSB0.

## 5. Mission Control Smart TV

- IP Address: <DISPLAY_NODE_IP>
- MAC Address: <DISPLAY_NODE_MAC>
- Role: Display endpoint and TV-as-a-Track physical substrate. Authorized for dashboard/track rendering only, not administration.

## 6. Edge ESP32 Vehicles

- MAC Address: <EDGE_NODE_MAC>
- Role: Autonomous light-sensor/PID vehicle nodes communicating through the Hub.

## Public sharing note

This sanitized inventory may be used for documentation or GitHub-style architecture explanation. The private version containing live lab addresses should remain in private OneDrive evidence only.
