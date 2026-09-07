# Sentinel-CPS Security Validation Scripts Package v0.1.1

This package contains safe, mostly read-only scripts and runbooks for collecting evidence toward **VAL-01 Access Control and Gateway Hardening** for the Sentinel-CPS Raspberry Pi Gateway.

It is intended for lab execution after the Gateway MVP is installed. It does not change firewall rules, SSH settings, systemd services, or network configuration.

## What this package does

- Collects host, network, SSH, firewall, service, and Gateway service evidence into timestamped folders.
- Runs client-side port reachability probes for Port 22 and Port 8080.
- Provides a small endpoint test logger for manually recording endpoint access results.
- Provides a redaction helper for creating sanitized public copies of raw evidence.
- Provides templates for evidence manifests, port test results, and SSH hardening review.

## What this package does not do

- It does not apply firewall rules.
- It does not modify SSH configuration.
- It does not restart services.
- It does not collect private key material.
- It does not prove security by itself.

The package prepares evidence for review. VAL-01 claims should only be made after the scripts are executed, the results are inspected, and the endpoint tests match the expected access-control policy.

## Recommended private evidence location

Raw evidence should be copied to private OneDrive storage, for example:

```text
Sentinel-CPS_Evidence_Master/
└── VAL-01_Access_Control/
    ├── gateway_collector_runs/
    ├── endpoint_port_tests/
    ├── screenshots/
    ├── redacted_examples/
    └── notes/
```

Only sanitized examples, scripts, templates, and high-level summaries should be committed to the public GitHub repository.

## Quick start on the Raspberry Pi Gateway

```bash
cd security-validation/tools
chmod +x val01_collect_gateway_evidence.sh
./val01_collect_gateway_evidence.sh
```

The collector writes output to:

```text
security-validation/evidence/VAL-01_Access_Control/<timestamp>/
```

## Quick client-side port probe

Run this from an endpoint such as your admin laptop, Bastion Host, or another test client:

```bash
cd security-validation/tools
chmod +x val01_port_probe.sh
./val01_port_probe.sh <GATEWAY_IP_OR_HOSTNAME>
```

Optional custom ports:

```bash
./val01_port_probe.sh <GATEWAY_IP_OR_HOSTNAME> 22 8080
```

The probe writes output to:

```text
security-validation/evidence/VAL-01_Access_Control/endpoint_port_tests/
```

## Manual endpoint test logger

```bash
cd security-validation/tools
python3 val01_endpoint_test_logger.py
```

This appends to:

```text
security-validation/evidence/VAL-01_Access_Control/endpoint_port_tests/port_test_results.csv
```

## Redaction helper

Create a sanitized copy of a file:

```bash
cd security-validation/tools
python3 redact_private_evidence.py ../evidence/VAL-01_Access_Control/<timestamp>/05_ip_addr.txt
```

Create sanitized copies for every `.txt`, `.csv`, `.log`, and `.md` file in a directory:

```bash
python3 redact_private_evidence.py ../evidence/VAL-01_Access_Control/<timestamp> --recursive
```

Redacted copies are written under a `redacted/` subfolder. Originals are not changed.

## Thesis mapping

This package supports evidence collection for:

- **VAL-01 Access Control and Gateway Hardening**
- **SR-A1 / SR-A2 / SR-A5**: identity, key-based administrative access, least-privilege endpoint assumptions
- **SR-N1 / SR-N2 / SR-N3 / SR-N5**: firewall posture, service-specific access, mDNS/display access notes, service minimization
- Smart TV display least-privilege review: Port 8080 display access without SSH/admin access

Port reachability evidence is only one layer. nftables will determine which
clients can connect; it does not authorize Flask operations. Smart TV testing
must use `GET /display` and verify that ordinary command and track-replacement
POSTs fail without `X-Sentinel-Operator-Token`. SSH administration remains a
separate sshd/public-key boundary, and anomaly mitigation retains its separate
loopback bearer credential. MAC or IP filtering must not be described as
application authorization.

The Gateway collector targets the current managed
`sentinel-gateway.service`; archived prototype units named `sentinel.service`
are not deployment targets for this validation package.

The operator token is a bounded laboratory control rather than a production
identity or session platform. Transport encryption is a separate control; a
private-lab HTTP test is not equivalent to a production TLS deployment.

Use cautious wording in the thesis: “supports validation of,” “collects evidence for,” and “prepares VAL-01 review.” Avoid phrases such as “proves zero trust” or “guarantees security.”
