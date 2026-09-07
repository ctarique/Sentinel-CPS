# Sentinel-CPS Serial Chokepoint v0.1.1 — Phase 3B

This package implements the transaction-aware Gateway USB serial to encrypted
ESP-NOW Hub boundary. The Gateway serial protocol is unchanged. The Hub forwards
one command at a time and reports success only by forwarding an unchanged,
matching vehicle ACK. ESP-NOW API acceptance and link-layer delivery are not
command execution.

## Contents

- `docs/serial_protocol_contract.md` — canonical Phase 3B contract
- `docs/radio_configuration.md` — safe local peer/key/channel setup
- `firmware/hub_esp32/hub_esp32.ino` — transaction-aware Hub firmware
- `firmware/hub_esp32/sentinel_radio_config.example.h` — disabled placeholders
- `tools/serial_smoke_test.py` — radio-unavailable serial fallback test
- `tests/test_serial_smoke_test.py` — hardware-free smoke parser tests

The legacy `docs/serial_protocol_v0.1.md` is only a supersession notice.

## Transaction behavior

Gateway sends `CMD,<txid>,<verb>`. The Hub preserves `txid`, normalizes only the
verb, and forwards the same structured ASCII frame as the encrypted ESP-NOW
payload. It never ACKs from local execution, `esp_now_send()` acceptance, or the
send callback. Only a canonical vehicle ACK/NACK matching both pending fields is
forwarded unchanged.

The Hub permits one in-flight downstream transaction. Its 750 ms downstream
timeout is below the Gateway repository default of 1000 ms and has no retries.
Radio unavailable, immediate send rejection, timeout, and busy conditions are
correlated Hub NACKs. STOP locks the Hub locally before transmission, but a STOP
failure or timeout is not evidence that the vehicle stopped.

Valid vehicle TEL frames are forwarded asynchronously. Useful EVENT and DIAG
frames are forwarded as diagnostics. None can complete a transaction, and the
Hub produces no synthetic telemetry.

## Radio configuration

The tracked example is disabled and all-zero. Copy it locally to
`firmware/hub_esp32/sentinel_radio_config.h`; that filename is ignored. Configure
only the opposite device's station MAC, the shared 16-byte PMK, shared 16-byte
LMK, the common channel from 1 through 11, and then the explicit configured
flag. Do not commit or print those values. Full paired-device instructions and
failure checks are in [`docs/radio_configuration.md`](docs/radio_configuration.md).

Without a valid local file, startup is:

```text
BOOT,HUB,LOCKED,ESP_NOW_UNAVAILABLE
```

Valid initialization uses station mode, exactly one encrypted STA peer, and
prints `BOOT,HUB,LOCKED,ESP_NOW_READY`. READY proves local initialization only,
not reachability or vehicle execution.

## Build and tests

The documented generic target is `esp32:esp32:esp32`. With an existing Arduino
CLI and ESP32 core, compile the sketch directory; flashing is a separate,
hardware-authorized action and is outside this source phase.

Hardware-free package tests use only the existing environment:

```text
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

`tools/serial_smoke_test.py` retains the fail-safe, radio-unavailable serial
test and expects `NO_DOWNSTREAM_TRANSPORT`. It is not an end-to-end Phase 3B
test. A configured end-to-end test must receive vehicle-originated responses
and asynchronous real telemetry through the Hub.

## Evidence boundary

Compilation and host tests validate source/API consistency. Direct USB vehicle
tests validate the vehicle state machine without ESP-NOW. Physical peer
authorization, encrypted exchange, loss behavior, radio timing, STOP behavior,
sensor telemetry, and motor outputs remain unproven until controlled hardware
validation. `MOTORS_ENABLED` remains false on the vehicle.
