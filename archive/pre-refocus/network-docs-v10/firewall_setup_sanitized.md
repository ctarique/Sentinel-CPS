# Sentinel-CPS Sanitized Firewall Configuration

## Objective

This document summarizes the public-safe nftables firewall design for the Sentinel-CPS Raspberry Pi Gateway. It intentionally uses placeholder MAC addresses and avoids live institutional network details.

The Gateway enforces a default-deny inbound policy, separates administrative access from display/dashboard access, supports local mDNS resolution for `iot-pi.local`, and prevents the Gateway from acting as an unmanaged bridge.

## Security Strategy

The Gateway firewall uses nftables with the following controls:

- Default-deny inbound policy
- Default-deny forwarding policy
- Loopback traffic allowed
- Established and related traffic allowed
- Invalid connection states dropped
- mDNS permitted for local hostname resolution
- ICMP echo requests rate-limited for troubleshooting
- SSH on TCP Port 22 restricted to approved administrative endpoints
- C2 web dashboard on TCP Port 8080 restricted to approved admin/display endpoints
- Display endpoints are not granted SSH privileges

## Sanitized nftables Configuration

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
