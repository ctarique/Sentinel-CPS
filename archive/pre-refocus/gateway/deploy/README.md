# Sentinel-CPS Gateway Deployment

This directory contains the repeatable Linux deployment workflow for the
Sentinel-CPS Gateway.

## Deployment targets

- ARM64 Linux UTM environment for rehearsal
- Raspberry Pi OS on the Sentinel-CPS Gateway

## Fixed filesystem structure

- Application: `/opt/sentinel-cps/gateway`
- Backups: `/opt/sentinel-cps/backups`
- Service: `sentinel-gateway.service`
- Service account: `sentinel`
- Runtime data: `/opt/sentinel-cps/gateway/data`
- Required Gateway environment: `/etc/sentinel-cps/gateway.env`

## Safety requirement

All deployment configurations retain:

    "safe_boot_locked": true

They also define the transaction timing controls:

    "serial_ack_timeout_ms": 1000
    "mock_ack_delay_ms": 10
    "keepalive_enabled": true
    "keepalive_interval_ms": 3000
    "mitigation_api_enabled": false
    "mitigation_loopback_only": true
    "mitigation_idempotency_cache_size": 128

A new or restarted Gateway process must reject START until an explicit RESET.
Hardware mode remains hardware mode when its serial port is unavailable and
reports degraded health; it never generates mock acknowledgements as fallback.
The keepalive interval must be positive and less than 7000 ms so it retains a
comfortable margin below the vehicle's documented ten-second communication
timeout.

While the acknowledged state is `RUNNING`, the managed Gateway worker sends
transaction-correlated PING commands through the same one-in-flight command
path used by API commands. Its only success response is a matching
`ACK,<txid>,PING,RUNNING,VEHICLE`. On the first failure, the Gateway locks
locally and attempts one transaction-aware STOP after the PING transaction has
released the command lock. Health reports `STOP_ACKNOWLEDGED` only for a
matching vehicle `STOP/LOCKED` ACK; `STOP_EXECUTION_UNKNOWN` means the vehicle's
independent ten-second timeout is still the final downstream protection.

The mitigation endpoint remains disabled unless explicitly enabled in the
local deployment configuration. When enabled, it also requires a valid
`SENTINEL_MITIGATION_TOKEN` supplied through its optional assignment in the
mandatory Gateway environment file. The token minimum is 32 characters. Do
not add it to JSON, service units, shell history, source, or documentation.

Every Gateway process also requires a separate `SENTINEL_OPERATOR_TOKEN` of
exactly 64 lowercase hexadecimal characters. Uppercase, quotes, whitespace,
escapes, shell substitutions, inline comments, and duplicate active assignments
are rejected. Hardware mode refuses startup if it is missing, empty, or
invalid; mock mode follows the same rule. There is no repository default or
normalization behavior.

Create `/etc/sentinel-cps/gateway.env` only on the deployed host. Generate the
value with `python3 -c 'import secrets; print(secrets.token_hex(32))'`, then use
a root-controlled editor or approved secret-handling workflow to create one
exact active assignment. Install the file as a root-only regular file:

```bash
sudo install -d -o root -g root -m 0755 /etc/sentinel-cps
sudo chown root:root /etc/sentinel-cps/gateway.env
sudo chmod 0600 /etc/sentinel-cps/gateway.env
```

When mitigation is enabled, add `SENTINEL_MITIGATION_TOKEN` with a different
independently generated value using a root-controlled editing workflow. Never
reuse either credential for the other role. The checked-in
`gateway.env.example` contains only comments and generation instructions, so it
cannot accidentally satisfy the installer or become a deployed credential.

The managed unit uses mandatory
`EnvironmentFile=/etc/sentinel-cps/gateway.env`. systemd reads this root-owned
file before reducing privileges to `User=sentinel`, so the runtime account
does not require direct file-read permission. Before changing accounts, groups,
installation directories, ownership, installed files, or systemd state,
`install.sh` rejects a missing path, symbolic link, non-regular file, malformed
or duplicate operator assignment, placeholder, or invalid value. It then sets
and verifies `root:root` ownership and mode `0600` without printing contents.

## Security boundary

- nftables will later control network reachability to ports 22 and 8080.
- `SENTINEL_OPERATOR_TOKEN` controls ordinary state-changing Flask requests.
- sshd authorized public keys control host administration.
- `SENTINEL_MITIGATION_TOKEN` controls only the loopback mitigation endpoint.

MAC or IP matching is a reachability filter, not application authorization.
The Smart TV must open `/display`; permitting it to reach port 8080 does not
authorize ordinary POST APIs. This shared bearer token is not per-user identity
or attribution. Ordinary HTTP does not protect it from an observer on an
untrusted network, so TLS or a protected network path is required outside the
bounded laboratory setup. Repeated authorization failures can increase
audit-log volume. Display status can briefly reflect adjacent snapshots, and
process-local track state resets on restart. This milestone does not add
identity management, TLS infrastructure, rate limiting, or persistent track
storage.

## Static validation

Run from the Gateway source directory:

    ./deploy/test-bundle.sh

## UTM mock installation

    sudo ./deploy/install.sh --mode mock

The installer creates an automatic backup when an existing deployment is
present.

## Raspberry Pi hardware installation

Run only after completing the read-only Raspberry Pi inventory:

    sudo ./deploy/install.sh \
        --mode hardware \
        --serial-port /dev/ttyUSB0 \
        --serial-baud 115200

## Health checking

Verify service and API availability:

    /opt/sentinel-cps/gateway/deploy/health-check.sh

The health JSON includes keepalive configuration/activity, the last automatic
PING result and ACK latency, failure count, local lock reason, safety STOP
result, whether a vehicle STOP ACK was confirmed, and non-secret mitigation
enablement/readiness/cache fields. It contains no bearer token, token-derived
value, radio key, or radio configuration value. The health check fails when
the mitigation API is configured as enabled but is not ready.

Verify a newly started service is fail-safe locked:

    /opt/sentinel-cps/gateway/deploy/health-check.sh \
        --require-locked

After connecting the ESP32 Hub, also require the physical serial connection:

    /opt/sentinel-cps/gateway/deploy/health-check.sh \
        --require-connected

Passing this workflow in UTM does not prove Raspberry Pi hardware, ESP32
serial acknowledgements, ESP-NOW, eBPF, vehicle movement, or physical recovery.

## Backup and rollback

Create a deployment backup:

    sudo /opt/sentinel-cps/gateway/deploy/backup.sh

List available backups:

    sudo find /opt/sentinel-cps/backups         -mindepth 1         -maxdepth 1         -type d         -print | sort

Restore a specific backup:

    sudo /opt/sentinel-cps/gateway/deploy/rollback.sh         /opt/sentinel-cps/backups/YYYYMMDD_HHMMSS_PID

Rollback verifies the SHA-256 manifest, creates a safety backup of the current
deployment, restores the selected application version, preserves active runtime
data, restarts the service, and requires the recovered Gateway to start LOCKED.
