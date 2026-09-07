# Public and Private Evidence Boundary

This document defines what may be placed in the public GitHub repository and what must remain in private OneDrive storage.

## Public GitHub safe

- Source code for Gateway, firmware, scripts, and analysis tools
- `config.example.json` files
- Blank templates
- Runbooks and design documentation
- Redacted example outputs
- High-level architecture diagrams
- Sanitized screenshots with IPs, hostnames, usernames, and lab identifiers removed
- Synthetic sample data

## Private OneDrive only

- Raw IP addresses, MAC addresses, hostnames, and usernames
- Raw `ip addr`, `ip route`, `ss`, `nft list ruleset`, and firewall outputs
- Raw `journalctl`, `systemctl`, and service logs if they expose host or network details
- `authorized_keys` contents
- Any private key material, including `id_ed25519`, `id_rsa`, `.pem`, `.key`, and similar files
- Lab photos/videos containing identifying details, faces, network equipment labels, or restricted areas
- Raw CSV logs collected from the physical lab before review/redaction
- Any university-sensitive network or infrastructure details

## Recommended workflow

1. Save raw evidence to OneDrive.
2. Create a sanitized copy only when needed.
3. Review sanitized copy manually.
4. Commit only sanitized artifacts to public GitHub.
5. Keep raw evidence referenced in the thesis evidence index, not in the public repository.
