# Raspberry Pi Gateway Firewall Configuration

## Objective

Implement a host-based firewall on the Raspberry Pi gateway to restrict inbound network access and enforce a default-deny security policy for the IoT lab environment.

The firewall ensures that only trusted devices on the lab network can access management and application services.

---

## Network Environment

Raspberry Pi IP address  
<RASPBERRY_PI_IP>

Workstation IP address  
<WORKSTATION_IP>

The subnet allows communication between devices in the range above.

---

## Firewall Strategy

The firewall uses nftables with a default deny inbound policy.

Only explicitly permitted traffic is allowed.

Allowed traffic:

Loopback traffic (lo) for local system communication

Established and related connections using connection tracking

ICMP echo requests from the trusted lab subnet for diagnostics

SSH access on port 22 from the trusted subnet

Flask gateway web interface on port 5000 from the trusted subnet

All other inbound traffic is dropped.

---

## Final nftables Configuration

chain input {
        type filter hook input priority 0;
        policy drop;

        ct state invalid drop;
        iif "lo" accept;
        ct state established,related accept;

        # Layer 2 HLAC: SSH Admin Access ONLY for approved physical workstations
        ether saddr { <MAC_MACBOOK_ETH>, <MAC_WORKSTATION_ETH> } tcp dport 22 accept;

        # Layer 2 HLAC: Web Gateway Access for workstations AND the Smart TV Dashboard
        ether saddr { <MAC_MACBOOK_ETH>, <MAC_WORKSTATION_ETH>, <SMART_TV_MAC> } tcp dport 5000 accept;
    }
---

## Validation Steps

The firewall configuration was validated using the following commands:

sudo nft -c -f /etc/nftables.conf

sudo systemctl restart nftables

sudo nft list ruleset

sudo ss -tuln

SSH connectivity from the workstation was confirmed after the firewall was applied.

Access to the Flask gateway interface on port 5000 was also verified.

---

## Security Rationale

The gateway enforces a default deny inbound policy, which follows the principle of least privilege.

Only specific trusted network ranges are allowed to access management and application services.

Stateful packet filtering ensures that legitimate traffic associated with existing connections is permitted while blocking unsolicited inbound connections.

This approach reduces the attack surface of the gateway and prevents unauthorized access to IoT devices connected through the Raspberry Pi.

The Smart TV acting as the Mission Control display is treated as an untrusted endpoint; it is whitelisted exclusively for Port 5000 and cryptographically barred from SSH access.

## Notes
ESP32 communication is local over USB (not affected by firewall rules)

---

## Phase 1.5: Zero-Trust Identity Enforcement (SSH Cryptographic Lockout)

While the `nftables` configuration provides robust network-level micro-segmentation, true Zero-Trust requires identity-based enforcement at the application layer. 

To eliminate the risk of credential brute-forcing and unauthorized lateral movement from within the trusted subnet, password authentication for the Raspberry Pi gateway has been completely disabled. 

**Implementation Details:**
* **Key Algorithm:** Ed25519 (chosen for its high security margin and performance efficiency).
* **Access Boundary:** The private key is securely housed exclusively on the local administrative profile of the Zone 1 Workstation. 
* **Enforcement:** The `sshd_config` on the Raspberry Pi is explicitly configured to reject all `PasswordAuthentication` and `PermitRootLogin`. 

This ensures that even if an unauthorized device successfully spoofs an IP address within the trusted lab subnet, access to the Sentinel boundary remains cryptographically impossible without the physical workstation's private key.