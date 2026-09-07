# Sentinel-CPS Vehicle Firmware Phase 3B

## Purpose and implementation boundary

The vehicle is the command-execution authority for the physical Sentinel-CPS
path. Direct USB and authorized encrypted ESP-NOW payloads share one bounded
`processCommandFrame(const char *, size_t, CommandOrigin)` parser and one state
machine. The transport layer does not duplicate command semantics.

`MOTORS_ENABLED` remains compile-time false. Phase 3B implements source-level
radio transport but does not prove radio reachability, correct physical peer
values, RF loss behavior, navigation, sensor calibration, or motor output.

## Framing and response origin

The only command is `CMD,<txid>,<verb>`. Frames are at most 128 bytes. `txid` is
1 through 64 bytes and preserved exactly; the 1-through-16-letter verb is
uppercased. Empty, oversized, control-containing, extra-field, and otherwise
malformed inputs are rejected without changing state or refreshing timeouts.

Canonical responses are:

```text
ACK,<txid>,<verb>,<state>,VEHICLE
NACK,<txid>,<verb>,<reason>,<state>,VEHICLE
```

USB-origin responses use USB. Authorized ESP-NOW-origin responses are placed in
the encrypted transmit queue for the Hub. The response is generated only after
the state-machine action; ESP-NOW send completion is not execution authority.
If the response cannot be queued or sent, no fallback USB ACK is substituted,
and the vehicle forces a LOCKED motor-off safe state.

## State transitions retained from Phase 3A

| Current state | Command | Response and next state |
|---|---|---|
| `LOCKED` | `START` | `NACK,...,LOCKED_REQUIRE_RESET,LOCKED,VEHICLE`; remains LOCKED |
| `IDLE` | `START` | `ACK,...,START,RUNNING,VEHICLE`; enters RUNNING |
| `RUNNING` | `START` | Same RUNNING ACK; idempotent and refreshes timeout |
| Any | `RESET` | Outputs off, control cleared, then `ACK,...,RESET,IDLE,VEHICLE` |
| Any | `STOP` | Outputs off, control cleared, then `ACK,...,STOP,LOCKED,VEHICLE` |
| Any | `STATUS` | ACK with current state; state/deadline unchanged |
| Any | `PING` | ACK with current state; refreshes only while RUNNING |
| Any | Unsupported alphabetic verb | Correlated `UNSUPPORTED_VERB` NACK; unchanged |

STOP and RESET call `forceMotorsOff()` before clearing control state, changing
state, and generating their ACK. Physical actuation remains disabled regardless
of logical RUNNING state.

## Communication-loss behavior

The RUNNING communication deadline remains 10,000 ms. Accepted START and PING
while RUNNING refresh it. On expiry, firmware forces outputs off, clears PID and
steering, enters LOCKED, then emits
`EVENT,VEHICLE,COMMUNICATION_TIMEOUT,LOCKED` and immediate LOCKED telemetry.
Both records are printed on USB before any best-effort radio queueing.

## Radio initialization and authorization

The firmware validates the local configured flag, nonzero unicast 6-byte Hub station
MAC, compile-time 16-byte PMK and LMK sizes, nonzero key contents, and channel
1–11. It starts Wi-Fi station mode, sets that channel, initializes ESP-NOW,
sets PMK, registers the ESP-IDF 5.5 callbacks used by Arduino ESP32 core 3.3.7,
and adds exactly one encrypted `WIFI_IF_STA` peer using the LMK. Peer queries
must then report one total and one encrypted peer.

The receive callback compares `esp_now_recv_info_t::src_addr` against the
configured Hub before copying. Unauthorized senders receive nothing. Missing or
invalid local configuration and any initialization failure leave the radio
unavailable, state LOCKED, and outputs off. There is no unencrypted fallback.

## Callback and queue concurrency

The receive and send callbacks run as short Wi-Fi-task callbacks. The receive
callback rejects null, empty, or over-128-byte payloads, copies accepted bytes
into one of four fixed slots, and appends a terminator after the bounded copy.
It does not parse, allocate dynamically, print, or touch motors. Shared indexes
and flags use an ESP32 critical-section lock.

`loop()` revalidates controls and terminator bounds before passing the command
to the shared parser. If all four slots are occupied, the new command is
dropped, diagnosed later on USB, and produces no ACK.

An eight-slot loop-owned transmit queue serializes ESP-NOW output so only one
send is outstanding until the core 3.3.7 send callback runs. Transaction
responses are inserted ahead of queued asynchronous records. Queueing or
sending a transaction response can fail safely but is never retried. A send
failure reported immediately or by callback disables radio availability,
forces outputs off, clears control, and locks state. Asynchronous queue overflow
drops that asynchronous record and produces a USB diagnostic.

## Telemetry and direct USB evidence

Telemetry is emitted every second and immediately after RESET, START, STOP, and
communication timeout:

```text
TEL,<vehicle_id>,<adc_l>,<adc_r>,<steer>,<state>
```

Every TEL is printed to vehicle USB. While radio is available it is also queued
to the Hub. Dry-run PWM DIAG and safety EVENT records may use the same dual path.
No asynchronous record completes a transaction.

The existing direct serial smoke test validates state-machine behavior only.
It bypasses the Hub and ESP-NOW. End-to-end evidence must correlate a Gateway
command with the matching `VEHICLE` response forwarded by the Hub. Neither test
proves physical motors; controlled hardware validation is still required.
