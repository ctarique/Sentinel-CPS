# VAL-01 Security Validation Runbook v0.1.1

This runbook guides collection of security evidence for the Sentinel-CPS Raspberry Pi Gateway. It prepares VAL-01 review; it does not by itself prove security.

## 1. Scope

VAL-01 focuses on Gateway access control and hardening evidence:

- Raspberry Pi host and network posture
- Port 22 SSH management boundary
- Port 8080 Gateway dashboard boundary
- SSH configuration and authorized-key metadata
- nftables/ufw posture, if present
- mDNS/Avahi status, if used
- running service inventory
- endpoint reachability test results

## 2. Before running scripts

Confirm you are on the correct Gateway and that raw evidence will stay private.

```bash
hostname
whoami
pwd
```

Do not paste raw IP addresses, MAC addresses, usernames, hostnames, firewall rules, or screenshots into a public repository.

## 3. Collect Gateway host evidence

Run on the Raspberry Pi Gateway:

```bash
cd security-validation/tools
chmod +x val01_collect_gateway_evidence.sh
./val01_collect_gateway_evidence.sh
```

The output folder will be printed and will look like:

```text
security-validation/evidence/VAL-01_Access_Control/20260621_153000/
```

Copy the entire timestamped folder into private OneDrive.

Recommended destination:

```text
Sentinel-CPS_Evidence_Master/VAL-01_Access_Control/gateway_collector_runs/
```

## 4. Probe from approved admin laptop

Run from the admin laptop or MacBook:

```bash
cd security-validation/tools
chmod +x val01_port_probe.sh
./val01_port_probe.sh <GATEWAY_IP_OR_HOSTNAME>
```

Expected result depends on your final access-control design, but a typical expected result is:

- Port 22: reachable from approved admin endpoint
- Port 8080: reachable from approved admin endpoint

Then log the endpoint result:

```bash
python3 val01_endpoint_test_logger.py
```

## 5. Probe from Windows Bastion Host

Use equivalent PowerShell commands if the shell script is not convenient:

```powershell
Test-NetConnection <GATEWAY_IP_OR_HOSTNAME> -Port 22
Test-NetConnection <GATEWAY_IP_OR_HOSTNAME> -Port 8080
Invoke-WebRequest http://<GATEWAY_IP_OR_HOSTNAME>:8080/api/health -UseBasicParsing
```

Save the output or screenshot privately. Record the result with the endpoint test logger when possible.

## 6. Probe from Smart TV / display endpoint

Most Smart TVs cannot run shell scripts. For the display endpoint:

1. Open the browser on the TV.
2. Navigate to `http://<GATEWAY_IP_OR_HOSTNAME>:8080/display`.
3. Record whether the read-only track display loads without an operator
   credential.
4. Treat SSH as `N/A` unless the endpoint can actually initiate SSH. Do not overclaim that SSH was blocked if you did not test it.
5. Verify that the page contains no command, track-editing, configuration, or
   credential controls. Automated Gateway tests separately verify that direct
   ordinary POST requests without the operator header return HTTP 401.
6. Capture a photo of the display on the TV if allowed and safe.

Expected display behavior:

- Port 8080: allowed if the TV is intended to display the Gateway dashboard/track.
- Port 22: not needed and should not be available as an administrative path.

This result establishes reachability, not authorization. nftables MAC/IP
selection cannot make a shared application read-only. The Flask operator
credential protects ordinary state changes; sshd public keys protect SSH; and
the loopback mitigation bearer credential remains independent. Do not include
either credential in screenshots or evidence output.

## 7. Probe from unapproved client

Run the probe from an unapproved client if allowed in the lab environment.

```bash
./val01_port_probe.sh <GATEWAY_IP_OR_HOSTNAME>
```

Expected behavior depends on the actual network placement and firewall rules. If the unapproved client is on a network segment where blocking is not yet configured, record that honestly as a limitation or incomplete validation.

## 8. Fill endpoint test matrix

Use:

```text
security-validation/docs/endpoint_test_matrix_template.md
```

Record:

- Endpoint role
- Expected Port 22 result
- Expected Port 8080 result
- Actual Port 22 result
- Actual Port 8080 result
- Evidence filename
- Notes and limitations

## 9. Sanitize evidence for public examples

Create redacted copies only after saving raw evidence privately.

```bash
cd security-validation/tools
python3 redact_private_evidence.py ../evidence/VAL-01_Access_Control/<timestamp> --recursive
```

Review redacted copies manually before publishing. Automated redaction is helpful but not perfect.

## 10. Minimum VAL-01 evidence set

A minimally useful VAL-01 package should include:

- Gateway host evidence collector output
- `ss -tulpen` or `ss -tuln` listening-port evidence
- SSH service status and effective SSH configuration dump
- authorized-key metadata without key material
- nftables or ufw status, if available
- `sentinel-gateway.service` status and logs from the managed deployment
- endpoint port test results from at least one approved endpoint
- endpoint matrix with notes and limitations

## 11. Thesis-safe wording

Use wording such as:

- “The Gateway evidence collector captured host, service, SSH, firewall, and listening-port state for VAL-01 review.”
- “Endpoint probes supported validation of expected Port 22 and Port 8080 reachability from selected roles.”
- “The results indicate whether the implemented configuration matched the intended access-control policy during the test window.”

Avoid:

- “This proves the system is zero-trust.”
- “The Gateway is unhackable.”
- “All unauthorized clients are blocked” unless every relevant client class was tested and evidence supports it.
- “The Smart TV is read-only because nftables allows only its MAC/IP.”
- “Private laboratory HTTP provides production-equivalent TLS.”

The operator credential is a bounded prototype control, not complete identity,
attribution, revocation, or production session management. Transport encryption
must be assessed separately.
