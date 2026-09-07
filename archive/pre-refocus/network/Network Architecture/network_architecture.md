# IoT Lab Network Architecture (v10.0)

## Overview
The Sentinel-CPS lab utilizes a bare-metal Raspberry Pi gateway connected to an ESP32 Hub via a physical USB 3.0 serial tether. The Gateway exposes one Flask service on Port 8080 with a credentialed operator dashboard and a dedicated read-only Smart TV route. A later nftables deployment will restrict network reachability for administrative and display endpoints; this reachability filter is distinct from application authorization.

## Components
* **Windows Bastion Host:** Used as the secure remote ingress point for IoT students via the University VPN, allowing safe firmware flashing and SSH access to the Pi.
* **Raspberry Pi Gateway:** Runs the Flask web application natively via `systemd` and acts as the central policy enforcement node.
* **Hub ESP32:** A physical serial-to-wireless translator tethered to the Pi.
* **Mission Control Smart TV:** Connected directly to the enterprise network. It acts as the dynamic, light-emitting physical track and opens only the Gateway `/display` workflow without an operator credential.

## Network Layout

        University Enterprise Network
                     |
              Ethernet Switch
               |           |          |
    Bastion Host     Raspberry Pi   Smart TV (Reads :8080)
      (VLAN)           (eth0)       (GameNet VLAN)
                         |
                         |-- (USB 3.0) -- Hub ESP32
                                              |
                                              |-- (ESP-NOW) -- Edge Vehicles

## Security Controls
The intended Raspberry Pi network boundary is enforced by `nftables` after
deployment. The firewall decides which clients can reach a port; it does not
authorize HTTP state changes.
* **Default firewall policy:** `DROP` (Inbound and Forward).
* **Allowed connections:**
  * Local loopback traffic (`lo`).
  * Multicast DNS (UDP 5353) to broadcast `iot-pi.local`.
  * SSH (TCP Port 22) locked strictly to authorized administrative MAC addresses.
  * Flask service (TCP Port 8080) reachable by administrative clients and the Smart TV according to the deployed network policy.

Application authorization is separate: ordinary command and track-replacement
requests require `SENTINEL_OPERATOR_TOKEN`, while the Smart TV uses read-only
`GET /display` resources. SSH administration is enforced by sshd and authorized
public keys. The anomaly mitigation endpoint retains a different bearer token
and a direct-loopback restriction. Neither the operator token nor MAC/IP
filtering is a complete production identity system, and the private laboratory
HTTP path does not provide production-equivalent TLS.
