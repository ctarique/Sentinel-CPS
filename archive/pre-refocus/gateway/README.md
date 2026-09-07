# Sentinel-CPS Gateway Phase 5B1

Bare-metal Flask Gateway running on TCP Port 8080. The Gateway provides the
command API, telemetry/status reporting, centerline path submission,
transaction-aware serial communication, automatic RUNNING-state keepalive,
fail-closed STOP/LOCKED handling, and structured logging in explicit mock or
hardware mode. Phase 5B1 adds a disabled-by-default, local-only mitigation STOP
API with bearer authentication and bounded in-memory idempotency.

## Application role separation

The Gateway exposes two browser workflows on the same service:

- `/` is the operator dashboard. Every ordinary state-changing request requires
  `X-Sentinel-Operator-Token`, matched in constant time against the value loaded
  from `SENTINEL_OPERATOR_TOKEN`.
- `/display` is the Smart TV workflow. It has no controls, forms, credential
  entry, or state-changing JavaScript and refreshes only `GET /api/track` and
  the reduced, non-configuration `GET /api/display/status` resource.

`POST /api/command` is protected for every accepted verb. This includes
`STATUS` and `PING`: despite their names, these requests dispatch serial
transactions and write evidence, so they are operational commands rather than
read-only HTTP status checks. `POST /api/track` is also protected and replaces
the process-local rendered track after existing validation succeeds.
`GET /api/track` returns a copy of the current rendered track without changing
it. Missing operator headers receive HTTP 401 and present-but-invalid values
receive HTTP 403; both responses use the same generic error text and never echo
the credential.

The operator credential is required at process startup in both mock and
hardware modes. It must be exactly 64 lowercase hexadecimal characters and is
loaded only from the process environment; uppercase hexadecimal is rejected and
there is no default, normalization, or automatic generation.
The browser stores an entered value only in `sessionStorage`, clears the input
after entry, can clear the session value, and attaches the header only to
protected POST requests. It does not use cookies, URLs, or `localStorage`.

These controls are intentionally separate:

1. A later nftables deployment will limit which network clients can reach TCP
   ports; reachability is not application authorization.
2. `SENTINEL_OPERATOR_TOKEN` authorizes ordinary state changes.
3. SSH administration remains controlled by sshd and authorized public keys.
4. `SENTINEL_MITIGATION_TOKEN` independently authorizes the loopback-only
   mitigation endpoint and cannot substitute for the operator credential.

The operator token is a shared bearer credential, not per-user identity, user
attribution, revocation, or production session management. Ordinary HTTP does
not protect it from an observer on an untrusted network; TLS or a separately
protected network path is required outside the bounded laboratory setup.
Repeated authorization failures each create a generic audit row and can
increase log volume; this milestone intentionally adds no rate limiter.

The display's status fields are assembled from adjacent synchronized snapshots,
so a refresh can briefly combine state observed across a transition. Track
state is process-local and resets to the default track on restart. This
milestone intentionally adds no identity platform, TLS infrastructure, rate
limiter, or persistent track database.

## Phase 1 ACK-aware serial protocol

The Gateway emits one command transaction at a time and waits for a response
that matches both its generated transaction ID and command verb:

```text
CMD,<txid>,<verb>
ACK,<txid>,<verb>,<state>,<origin>
NACK,<txid>,<verb>,<reason>,<state>,<origin>
TEL,<vehicle_id>,<adc_l>,<adc_r>,<steer>,<state>
```

Accepted verbs are `START`, `STOP`, `RESET`, `STATUS`, and `PING`. API results
are `ACKNOWLEDGED`, `NACK`, `ACK_TIMEOUT`, `SERIAL_UNAVAILABLE`,
`SERIAL_WRITE_ERROR`, or `REJECTED_LOCKED`.

- `gateway_processing_ms` measures local validation, transaction creation,
  state handling, command serialization, and related Gateway work. It excludes
  the blocking ACK/NACK wait.
- `ack_latency_ms` measures successful serial dispatch to receipt of the
  matching ACK/NACK. It is null when dispatch fails or no matching response
  arrives.
- `command_total_ms` measures the complete command-handler transaction duration,
  including ACK/NACK waiting.

Explicit hardware mode never falls back to mock acknowledgements. Health reports
`serial_transport` as `mock`, `available`, `unavailable`, or `degraded`.

The current Hub and vehicle implement this correlated protocol. The Hub does
not manufacture successful vehicle acknowledgements: `ACKNOWLEDGED` requires a
matching vehicle-originated ACK.

## Phase 4 automatic keepalive

`keepalive_enabled` defaults to `true`; `keepalive_interval_ms` defaults to
`3000`. The interval must be a positive integer below `7000`, leaving at least
three seconds of margin below the vehicle's independent ten-second
running-state communication timeout.

One managed worker is started with each `SerialBridge`. It schedules no work
while disabled, locally locked, shutting down, or in any acknowledged state
other than `RUNNING`. A vehicle-originated `ACK,<txid>,PING,RUNNING,VEHICLE`
with the matching transaction ID and verb is the only successful automatic
keepalive. Telemetry never completes a command. Explicit mock mode may generate
the same response for development; hardware mode never falls back to it.

The keepalive state machine is:

```text
LOCKED or acknowledged state != RUNNING -> INACTIVE
RESET ACK/IDLE                         -> INACTIVE and unlocked
START ACK/RUNNING                      -> ACTIVE and interval scheduled
PING ACK/RUNNING/VEHICLE               -> ACTIVE and next interval scheduled
STOP, RESET, local lock, shutdown      -> INACTIVE immediately
first failed automatic PING            -> locally LOCKED -> evidence append
completed evidence append attempt      -> publish failure health -> one guarded STOP
STOP ACK/LOCKED/VEHICLE                -> STOP_ACKNOWLEDGED
any other STOP result                  -> STOP_EXECUTION_UNKNOWN
```

The automatic PING and safety STOP both call the normal one-in-flight command
transaction implementation. A state-generation guard cancels queued or stale
keepalive work after a later STOP, RESET, local lock, or shutdown. The state
lock is never held during ACK waiting, and the safety STOP is invoked only
after the failed PING has returned and released the command lock.

On the first keepalive failure, the Gateway locks locally and deactivates
keepalive before attempting file I/O. It appends and flushes the structured
`KEEPALIVE_FAILURE` action before publishing the completed failure counter and
health fields, then makes exactly one best-effort transaction-aware STOP
attempt. An append failure is reported explicitly in health and cannot prevent
the local lock or STOP attempt. The Gateway remains locked if STOP is rejected,
times out, is unavailable, or cannot be written. Only an authoritative
`ACK,<txid>,STOP,LOCKED,VEHICLE` sets `vehicle_stop_confirmed=true`; otherwise
health reports `STOP_EXECUTION_UNKNOWN`, and the vehicle's independent timeout
remains the downstream fail-safe.

## Phase 5B1 mitigation STOP API

`POST /api/mitigation/stop` is a dedicated safety endpoint. It always calls the
existing transaction-aware `SerialBridge.write("STOP")` path; there is no
caller-supplied command, action, verb, target, or state. Detection metadata
cannot select another command. The endpoint never retries and never performs
START, RESET, recovery, or resumption.

The API is disabled by default:

```json
{
  "mitigation_api_enabled": false,
  "mitigation_loopback_only": true,
  "mitigation_idempotency_cache_size": 128
}
```

For this thesis baseline, `mitigation_loopback_only` must remain `true`, and
the cache size must be an integer from 1 through 1024. When enabled, the
Gateway reads the bearer token only from `SENTINEL_MITIGATION_TOKEN`. The token
must be at least 32 characters, contain no whitespace or control characters,
and is never stored in JSON, returned by an API, emitted by health, or written
to a ledger. If the environment value is absent or invalid, health reports the
API as not ready and the endpoint remains unavailable.

Every request requires `Authorization: Bearer <token>` and a direct loopback
client address. IPv4, IPv6, and IPv4-mapped IPv6 loopback addresses are
accepted. Proxy forwarding headers, including `X-Forwarded-For`, are ignored.

The JSON object must contain exactly these required fields:

- `incident_id`: non-empty string, at most 128 characters;
- `detection_id`: non-empty string, at most 128 characters;
- `idempotency_key`: non-empty string, at most 128 characters;
- `rule_id`: non-empty string, at most 128 characters;
- `severity`: one of `HIGH`, `MEDIUM`, `LOW`, or `INFO`;
- `score`: finite JSON number;
- `detection_timestamp_utc`: valid, timezone-aware UTC ISO 8601 timestamp, at
  most 64 characters.

The only optional fields are `evidence_class` and `detector_run_id`, each a
non-empty string of at most 128 characters when present. Strings may not have
leading or trailing whitespace or contain control characters. Unexpected
fields are rejected.

A request contract example, intentionally without any token value, is:

```json
{
  "incident_id": "incident-001",
  "detection_id": "detection-001",
  "idempotency_key": "incident-001-stop-v1",
  "rule_id": "rule-stop-001",
  "severity": "HIGH",
  "score": 0.99,
  "detection_timestamp_utc": "2026-08-04T05:00:00Z"
}
```

The endpoint synchronously returns the raw transaction result plus
`mitigation_status`. A representative field set is:

```text
incident_id, detection_id, idempotency_key
duplicate_suppressed, coalesced, mitigation_status
mode, serial_transport, transaction_id, result, reason
ack_state, ack_origin, gateway_locked, vehicle_stop_confirmed, synthetic
gateway_request_received_time_utc, gateway_local_lock_time_utc
stop_dispatch_time_utc, stop_ack_time_utc, gateway_response_time_utc
gateway_processing_ms, ack_latency_ms, command_total_ms
```

HTTP status communicates request handling, not physical mitigation success:
disabled is 404; enabled but not ready is 503; authentication failure is 401;
non-loopback is 403; malformed JSON is 400; schema rejection is 422; a
completed original or stored duplicate result is 200; an in-progress duplicate
or STOP coalesced with another source is 202; an unexpected internal dispatch
failure is 500. In particular, HTTP 200 must not be interpreted as observed
motor cessation.

`ACKNOWLEDGED_DOWNSTREAM` requires hardware mode and a non-empty transaction ID
with the matching `ACKNOWLEDGED/STOP/LOCKED/VEHICLE` result. Only that status
sets `vehicle_stop_confirmed=true`, which confirms a protocol acknowledgement,
not physical motor observation. The equivalent explicit mock result is labeled
`SYNTHETIC_ACKNOWLEDGED` and never confirms the vehicle. NACK, timeout,
unavailable transport, write failure, shutdown, invalid ACK state/origin,
ambiguous coalescing, or lost association is `EXECUTION_UNKNOWN`.

The first request registers its idempotency key before dispatch. A duplicate
never dispatches another STOP while its record remains cached: it returns the
stored raw result as `DUPLICATE_SUPPRESSED`, or a stable `IN_PROGRESS` response
while the owner is active. Completed records are evicted oldest-first when the
bounded cache is full; active records are never evicted, and a new key is
rejected if every slot is active. The cache is process-local and resets on
Gateway restart.

All STOP sources share one bridge-level in-flight marker and the existing
one-command transaction lock. A mitigation arriving during manual or keepalive
safety STOP is conservatively `COALESCED_WITH_EXISTING_STOP`, carries no
transaction ID or downstream confirmation, and does not dispatch. Every STOP
locks locally before its transport attempt and disables active keepalive. The
Gateway remains locked after every failure or coalescing outcome.

`data/mitigation.csv` is an append-only ledger separate from action and
performance CSVs. Its stable schema records request, local-lock, dispatch,
response, finalization, duplicate, and coalescing phases without headers or
secrets. Wall-clock evidence uses microsecond UTC timestamps. On failure,
`stop_ack_time_utc` is null. Monotonic `gateway_processing_ms`,
`ack_latency_ms`, and `command_total_ms` retain their timing roles.

## Thesis alignment

This MVP supports initial **VAL-04 Gateway Observability** by generating structured `actions.csv` and `telemetry.csv` logs from a real Flask Gateway process. The `actions.csv` schema includes a `mode` column so mock and hardware-backed actions can be distinguished during evidence review.

It prepares for **VAL-05 STOP/mitigation** with a strictly logged STOP path,
automatic communication-loss response, and hardware serial bridge for
`/dev/ttyUSB0`.

This phase does **not** connect the anomaly detector to the endpoint and does
not validate physical TV-as-a-Track navigation, ESP32 telemetry,
ESP-NOW/CCMP integrity, eBPF/BCC tracing, vehicle movement, or physical motor
cessation.

## File tree

```text
sentinel-gateway/
├── app.py
├── operator_token.py
├── requirements.txt
├── config.example.json
├── README.md
├── deploy/
│   └── sentinel-gateway.service
└── templates/
    ├── display.html
    └── index.html
```

The `data/` directory and CSV files are created automatically on first run.
Tests set `SENTINEL_GATEWAY_DATA_DIR` to a temporary directory so test traffic
does not append to repository evidence CSVs.

## Dashboard boundary

The browser dashboard is intentionally styled to resemble the Sentinel-CPS simulator, but it is not the standalone simulator. It is the live Gateway interface served by Flask. The centerline surface supports FR-C2 centerline path definition and logging only; it does not claim lane-boundary containment, live vehicle position tracking, completed autonomous navigation validation, or live AI/eBPF mitigation from the browser.

The vehicle marker reflects reported steering/state only. Its canvas position is a local UI preview, not telemetry-derived position evidence.

The Smart TV must use `/display`, not `/`. Firewall MAC or IP selection may
limit reachability to port 8080, but it cannot make the shared Flask service
read-only. The application-layer route and protected POST APIs enforce that
separation.

## Local setup

```bash
cd sentinel-gateway
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp config.example.json config.json
export SENTINEL_OPERATOR_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
```

## Run manually

```bash
source venv/bin/activate
python3 app.py
```

Open the dashboard:

```text
http://localhost:8080
```

Open the read-only Smart TV view at `http://localhost:8080/display`. The
ephemeral shell export above is suitable only for local mock development; the
managed deployment uses the root-protected environment file documented under
`deploy/`.

On another machine on the same allowed network, replace `localhost` with the Raspberry Pi hostname or IP.

## Verify Port 8080

```bash
ss -tuln | grep 8080
```

## Command API test with curl

```bash
printf 'header = "X-Sentinel-Operator-Token: %s"\n' \
  "$SENTINEL_OPERATOR_TOKEN" | \
curl -s -K - -X POST http://localhost:8080/api/command \
  -H "Content-Type: application/json" \
  -d '{"command":"START"}' | python3 -m json.tool
```

## Centerline Path API test with curl

```bash
printf 'header = "X-Sentinel-Operator-Token: %s"\n' \
  "$SENTINEL_OPERATOR_TOKEN" | \
curl -s -K - -X POST http://localhost:8080/api/track \
  -H "Content-Type: application/json" \
  -d '{"centerline_points":[{"x":0.10,"y":0.50},{"x":0.45,"y":0.25},{"x":0.80,"y":0.50}]}' | python3 -m json.tool
```

## Health and telemetry checks

```bash
curl -s http://localhost:8080/api/health | python3 -m json.tool
curl -s http://localhost:8080/api/telemetry | python3 -m json.tool
curl -s http://localhost:8080/api/track | python3 -m json.tool
```

`/api/health` includes:

- keepalive configuration: `keepalive_enabled`, `keepalive_interval_ms`;
- scheduling/state: `keepalive_active`, `acknowledged_state`,
  `local_lock_reason`;
- most recent result: `last_keepalive_timestamp`, `last_keepalive_result`,
  `last_keepalive_ack_latency_ms`;
- safety history: `keepalive_failure_count`, `last_keepalive_failure`,
  `keepalive_failure_evidence_status`, `keepalive_failure_evidence_error`,
  `last_safety_stop_result`, `vehicle_stop_confirmed`, and `safety_status`;
- mitigation operation: `mitigation_api_enabled`, `mitigation_api_ready`,
  `mitigation_loopback_only`, `mitigation_active_requests`,
  `mitigation_cached_results`, `last_mitigation_status`,
  `last_mitigation_timestamp`, and `last_mitigation_incident_id`.

`LOCALLY_LOCKED_EVIDENCE_PENDING` means the Gateway has locked and deactivated
keepalive while the structured append is unresolved.
`LOCALLY_LOCKED_STOP_PENDING` means the append attempt has completed but the
safety STOP has not.
`APPENDED_AND_FLUSHED` confirms the structured row was flushed before completed
failure health was published; `APPEND_FAILED` is paired with an explicit error
and does not claim evidence exists. `STOP_ACKNOWLEDGED` confirms the vehicle's
authoritative STOP ACK. `STOP_EXECUTION_UNKNOWN` does not claim that the vehicle
stopped.
Health does not expose bearer tokens, token-derived values, radio keys, or
radio configuration values.

Automatic transactions are logged with source `AUTO_KEEPALIVE`. Their
`gateway_processing_ms`, `ack_latency_ms`, and `command_total_ms` retain the
same definitions as user commands. `/api/metrics` separates the labeled
`automatic_keepalive` block from its user-command `overall` and `by_command`
summaries.

## Inspect CSV logs

```bash
cat data/actions.csv | column -s, -t

tail -n 15 data/telemetry.csv | column -s, -t
```

## Raspberry Pi systemd setup

Use the authoritative managed workflow under `deploy/`, including its mandatory
root-protected `/etc/sentinel-cps/gateway.env` preparation. The only current
unit is `deploy/sentinel-gateway.service`; the obsolete root-level legacy unit
and HTML copy have been removed. Follow `deploy/README.md`; do not place either
credential directly in a service unit.

## VAL-04 evidence capture commands

Run these after you have started the service, opened the dashboard, saved a centerline path, issued `START`, issued `STOP`, and confirmed CSV rows exist.

```bash
mkdir -p evidence/VAL-04_Observability
cp data/actions.csv evidence/VAL-04_Observability/actions.csv
cp data/telemetry.csv evidence/VAL-04_Observability/telemetry.csv
sudo systemctl status sentinel-gateway.service --no-pager > evidence/VAL-04_Observability/systemctl_status.txt
sudo journalctl -u sentinel-gateway.service -n 100 --no-pager > evidence/VAL-04_Observability/journalctl_last100.txt
ss -tuln | grep 8080 > evidence/VAL-04_Observability/port_8080_listening.txt
```

Optional API evidence:

```bash
curl -s http://localhost:8080/api/health | python3 -m json.tool > evidence/VAL-04_Observability/api_health.json
curl -s http://localhost:8080/api/telemetry | python3 -m json.tool > evidence/VAL-04_Observability/api_telemetry.json
```

## Hardware validation boundary

The correlated Hub/vehicle protocol is source-compatible with this Gateway,
but the automated suite is hardware-free. Physical radio delivery, motor stop,
and ten-second vehicle timeout behavior still require a separate controlled
hardware validation; no software test or mock ACK proves those outcomes.

## Schema note for v0.1.1-fixed

This revision adds a `mode` column to `data/actions.csv`. Archive or delete older `actions.csv` files before running this version, otherwise old and new evidence rows may use different schemas.

The `/api/track` route is retained for compatibility, but its required JSON field is now `centerline_points`. This aligns the Gateway UI and evidence logs with FR-C2 centerline/line-following semantics rather than lane-boundary semantics.


## Final V1 schema note

`actions.csv` uses the Final V1 schema: `timestamp,event_id,source,command,details,result,mode`. Archive or delete old `actions.csv` files from earlier versions before running this package, otherwise the Gateway exits with a schema mismatch warning to prevent mixed evidence.

Recommended archive command before first Final V1 run:

```bash
mkdir -p evidence/archive_pre_final_v1
mv data/actions.csv evidence/archive_pre_final_v1/actions_pre_final_v1.csv 2>/dev/null || true
mv data/telemetry.csv evidence/archive_pre_final_v1/telemetry_pre_final_v1.csv 2>/dev/null || true
```
