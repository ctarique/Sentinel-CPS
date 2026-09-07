# Sentinel-CPS Transaction and Transport Contract — Phase 3B

## Purpose and evidence boundary

This is the canonical transaction contract for the physical
Gateway → Hub → vehicle path. The Gateway-to-Hub link remains 115200-baud USB
serial. The Hub-to-vehicle link is authorized-peer, encrypted ESP-NOW in Wi-Fi
station mode.

In the physical path, Gateway `ACKNOWLEDGED` requires an unchanged,
vehicle-originated ACK correlated by both transaction ID and verb. Acceptance
by `esp_now_send()` and ESP-NOW link-layer send completion are not evidence of
command execution and never generate a Hub ACK. Source compilation and direct
USB tests do not prove physical radio delivery, peer configuration, motor
behavior, or end-to-end timing; those claims require hardware validation.

## Canonical ASCII frames

Commands and transaction responses remain:

```text
CMD,<txid>,<verb>
ACK,<txid>,<verb>,<state>,<origin>
NACK,<txid>,<verb>,<reason>,<state>,<origin>
```

Vehicle telemetry remains asynchronous:

```text
TEL,<vehicle_id>,<adc_l>,<adc_r>,<steer>,<state>
```

The Hub accepts LF or CRLF command termination from USB serial and emits one
line per serial record. Over ESP-NOW, the ASCII frame itself is the payload: no
line terminator and no second binary envelope are added. A frame is at most 128
bytes excluding a serial terminator.

`txid` is opaque and case-sensitive, is 1 through 64 bytes, excludes comma,
C0 controls, and DEL, and is preserved byte-for-byte. `verb` is 1 through 16
ASCII letters and is the only field normalized to uppercase. Supported verbs
are:

```text
START
STOP
RESET
STATUS
PING
```

A syntactically valid unsupported verb receives a correlated
`UNSUPPORTED_VERB` NACK. Empty, oversized, truncated, control-containing, or
malformed radio payloads are rejected without an ACK.

## Hub transaction behavior

The Hub permits one downstream transaction in flight. For a valid supported
Gateway command it sends exactly:

```text
CMD,<same-txid>,<UPPERCASE-verb>
```

The Hub completes that transaction only when an authorized vehicle payload is
a canonical ACK or NACK whose `txid` and `verb` both match the pending command.
That complete vehicle frame, including `VEHICLE` origin and authoritative
vehicle state, is forwarded unchanged to Gateway serial. Malformed, mismatched,
duplicate, or late ACK/NACK records are diagnosed and ignored. A second command
while one is pending receives:

```text
NACK,<txid>,<verb>,DOWNSTREAM_BUSY,LOCKED,HUB
```

Hub-local failure responses are:

```text
NACK,<txid>,<verb>,NO_DOWNSTREAM_TRANSPORT,LOCKED,HUB
NACK,<txid>,<verb>,DOWNSTREAM_SEND_FAILED,LOCKED,HUB
NACK,<txid>,<verb>,DOWNSTREAM_TIMEOUT,LOCKED,HUB
```

`NO_DOWNSTREAM_TRANSPORT` means configuration or initialization is unavailable.
`DOWNSTREAM_SEND_FAILED` means the immediate `esp_now_send()` call rejected the
payload. `DOWNSTREAM_TIMEOUT` means no matching authoritative response arrived
within 750 ms. There are no automatic retries or transaction deduplication
caches in Phase 3B. The 750 ms Hub timeout is below the repository-default
Gateway ACK timeout of 1000 ms, allowing Gateway normally to receive the
correlated Hub timeout NACK before its own deadline. A deployment that lowers
the Gateway timeout below 750 ms is incompatible and must be corrected outside
this phase.

The Hub sets or retains its own local `LOCKED` state before transmitting STOP.
A STOP send failure, timeout, or Hub NACK never proves that the vehicle stopped.
The Hub never synthesizes vehicle telemetry or a local execution ACK.

## Vehicle authority and response routing

Both USB and authorized ESP-NOW commands enter the same vehicle
`processCommandFrame()` parser and state machine. Response routing is by command
origin:

- USB command → ACK/NACK over USB serial.
- ESP-NOW command → ACK/NACK over encrypted ESP-NOW to the configured Hub.

STOP and RESET force direction and PWM outputs off and clear control state
before their ACK is generated. START, STOP, RESET, STATUS, PING, and the
10-second vehicle communication timeout retain the Phase 3A state semantics.
`MOTORS_ENABLED` remains compile-time `false`.

Periodic and immediate TEL records are always printed on vehicle USB for
diagnostics and are queued to the Hub while radio transport is available.
Vehicle EVENT and useful DIAG records may also be sent to both paths. TEL,
EVENT, DIAG, ERR, and BOOT never complete a transaction.

## ESP-NOW authorization and encryption

Each device uses Wi-Fi station mode, one explicitly configured opposite peer,
one common channel from 1 through 11, a 16-byte PMK, and a 16-byte LMK. The peer
entry uses `WIFI_IF_STA` and `encrypt = true`; initialization verifies exactly
one total and one encrypted peer. Each receive callback compares the source
station MAC to the configured peer before queueing the payload. Unauthorized
traffic is ignored without a response.

Real settings exist only in ignored `sentinel_radio_config.h` files beside each
sketch. Tracked `sentinel_radio_config.example.h` files contain disabled,
all-zero placeholders. Missing configuration, `configured=false`, an all-zero
peer MAC, an all-zero PMK or LMK, wrong array length, or a channel outside 1–11
leaves ESP-NOW unavailable. There is no unencrypted fallback. See
[`radio_configuration.md`](radio_configuration.md).

## Callback and queue behavior

ESP-NOW receive callbacks verify the peer and payload length, copy at most 128
bytes into a fixed queue slot, add a terminator only after the bounded copy, and
return. Parsing, serial output, transaction matching, and safety work run in
`loop()`. Shared callback/loop state uses an ESP32 critical-section lock.

The Hub receive queue has eight slots for transaction responses and asynchronous
records. The vehicle receive queue has four command slots. On overflow the new
payload is dropped, diagnosed outside callback context, and cannot generate an
ACK. Vehicle radio transmission uses an eight-slot loop-owned queue, prioritizes
transaction responses ahead of queued telemetry, and allows only one ESP-NOW
send in flight; there are no retries. An immediate or callback-reported vehicle
send failure locks the vehicle and forces outputs off. Asynchronous queue
overflow drops the asynchronous record and is diagnosed on USB.

## Startup diagnostics

The Hub emits one of:

```text
BOOT,HUB,LOCKED,ESP_NOW_READY
BOOT,HUB,LOCKED,ESP_NOW_UNAVAILABLE
```

The vehicle emits one of:

```text
BOOT,VEHICLE,LOCKED,ESP_NOW_READY
BOOT,VEHICLE,LOCKED,ESP_NOW_UNAVAILABLE
```

These are readiness diagnostics, not proof of peer reachability or command
execution. The vehicle also reports `DIAG,VEHICLE,MOTORS_DISABLED`.

## Validation boundary

Direct vehicle USB testing validates the parser and state machine without the
Hub. End-to-end testing must use Gateway USB serial through both correctly
configured devices and correlate the vehicle-originated ACK/NACK. Neither mode
alone proves physical motor behavior; Phase 3B remains a motors-disabled,
hardware-unvalidated implementation until controlled hardware evidence exists.
