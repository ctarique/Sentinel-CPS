# Sanitized Public Evidence Notes

This document separates public repository material from private lab evidence.

## Safe for public GitHub

- Scripts and templates in this package.
- High-level descriptions of intended security posture.
- Redacted examples that have been manually reviewed.
- Blank checklists and matrices.
- Sanitized commands that do not expose real network details.

## Keep private in OneDrive

- Actual IPv4/IPv6 addresses.
- MAC addresses.
- Hostnames and usernames.
- `ip addr`, `ip route`, and `nft list ruleset` output if it reveals real topology.
- `authorized_keys` contents.
- SSH usernames or key comments tied to real people.
- Screenshots showing IPs, MACs, hostnames, usernames, or university network details.
- Raw `journalctl` logs if they include private paths, IP addresses, or usernames.

## Redaction workflow

1. Save raw evidence privately first.
2. Run the redaction helper on a copy or on the private evidence folder.
3. Review the redacted copy manually.
4. Remove any remaining sensitive values before using an example publicly.

## Wording guidance

Public notes should say:

- “default-deny intent” rather than revealing exact rules.
- “approved endpoint” rather than a real device name.
- “private lab subnet” rather than a real subnet.
- “redacted host” rather than the Gateway hostname.
