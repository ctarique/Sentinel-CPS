# Sentinel-CPS Sanitized Firewall Ruleset Overview

This document summarizes the Sentinel-CPS Gateway firewall design without exposing live MAC addresses or institutional network details.

## Purpose

This planned nftables default-deny policy is intended to constrain network
reachability at the local lab boundary. A later deployment task will implement
and validate it; this document does not claim the rules are currently active.
The proposed firewall separates administrative access, display/web access,
local name resolution, and forwarding behavior.

## Security Design

- Default-deny inbound policy
- Default-deny forwarding policy to prevent rogue bridging
- Loopback traffic allowed
- Established/related traffic allowed
- Invalid connection states dropped
- mDNS permitted for local `iot-pi.local` resolution
- ICMP echo requests rate-limited for troubleshooting
- SSH access restricted to approved administrative endpoints
- C2 web dashboard access restricted to approved admin/display endpoints
- Display endpoints are not granted SSH privileges

These rules control network reachability only. MAC or IP filtering is not
application authorization and cannot make a client read-only after it reaches
the shared Flask port. The Smart TV uses `GET /display`; ordinary state-changing
APIs separately require `SENTINEL_OPERATOR_TOKEN`. sshd public keys and the
loopback-only mitigation bearer token remain independent controls. No nftables
implementation is contained in or applied by this sanitized design note. It is
not a deployable ruleset and must not be treated as evidence of active policy.

## Planned sanitized nftables structure

```nft
flush ruleset

table inet filter {
    set admin_macs {
        type ether_addr
        elements = { <ADMIN_ENDPOINT_MAC_1>, <ADMIN_ENDPOINT_MAC_2> }
    }

    set dashboard_macs {
        type ether_addr
        elements = { <DISPLAY_ENDPOINT_MAC> }
    }

    chain input {
        type filter hook input priority filter; policy drop;

        ct state invalid drop
        iif "lo" accept
        ct state { established, related } accept

        udp dport 5353 ip daddr 224.0.0.251 accept
        udp dport 5353 ip6 daddr ff02::fb accept

        ip protocol icmp icmp type echo-request limit rate 1/second accept

        tcp dport 22 ether saddr @admin_macs accept

        tcp dport 8080 ether saddr @admin_macs accept
        tcp dport 8080 ether saddr @dashboard_macs accept
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
