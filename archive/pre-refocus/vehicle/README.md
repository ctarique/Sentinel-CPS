# Sentinel-CPS Vehicle Firmware Phase 3B

This package implements the authoritative vehicle command state machine over
both direct USB serial and encrypted, authorized-peer ESP-NOW. Both transports
enter the same `processCommandFrame()` implementation; only response routing
depends on command origin.

`MOTORS_ENABLED` remains compile-time `false`. Source builds and direct USB
tests do not prove physical ESP-NOW, navigation, STOP behavior, or actuation.

## Files

- `firmware/vehicle_esp32/vehicle_esp32.ino` — shared state machine and transport
- `firmware/vehicle_esp32/sentinel_radio_config.example.h` — disabled placeholders
- `docs/vehicle_firmware_v0.1.md` — detailed behavior and phase boundary
- `docs/radio_configuration.md` — local secret and peer setup
- `tools/vehicle_serial_smoke_test.py` — direct USB state-machine test
- `tests/test_vehicle_serial_smoke_test.py` — hardware-free response tests

## Protocol and routing

Both paths accept only `CMD,<txid>,<verb>` with the existing 128-byte frame,
64-byte transaction-ID, and 16-letter verb bounds. Supported verbs remain
START, STOP, RESET, STATUS, and PING. Transaction IDs are preserved exactly;
only verbs are uppercased.

Responses retain the canonical forms:

```text
ACK,<txid>,<verb>,<state>,VEHICLE
NACK,<txid>,<verb>,<reason>,<state>,VEHICLE
```

- USB command responses return over USB.
- ESP-NOW command responses are queued to the configured Hub over ESP-NOW.

Malformed radio payloads and receive-queue overflow are dropped without an ACK.
Unauthorized peers are ignored without a response. Transaction responses are
prioritized ahead of queued telemetry, only one ESP-NOW send is in flight, and
Phase 3B performs no retry or deduplication.

## State and safety behavior

The Phase 3A command semantics are unchanged. The vehicle boots LOCKED, requires
RESET before START, forces outputs off before STOP and RESET ACK generation,
and locks after the 10-second RUNNING communication timeout. START while RUNNING
is idempotent. STATUS does not refresh the deadline; PING does only while
RUNNING.

Radio configuration or initialization failure leaves the vehicle LOCKED and
motor outputs off. An immediate or callback-reported ESP-NOW transmit failure
also forces LOCKED state and outputs off. Direct USB testing remains available
through the same state machine.

## Telemetry and diagnostics

Periodic and immediate telemetry is always printed to vehicle USB:

```text
TEL,<vehicle_id>,<adc_l>,<adc_r>,<steer>,<state>
```

When radio is available, the same frame is queued to the Hub. Safety EVENT and
useful DIAG frames may follow the same dual path. TEL, EVENT, DIAG, ERR, and BOOT
never serve as transaction completion.

## Encrypted peer configuration

Copy the adjacent tracked example to the ignored local filename
`sentinel_radio_config.h`. Configure the Hub station MAC as the sole peer, the
same exactly 16-byte PMK and LMK used on the Hub, the same channel from 1
through 11, and enable the configured flag last. Do not commit or print real
values. Missing, disabled, zero, wrong-sized, or unsupported settings cannot
enable plaintext transport. See [`docs/radio_configuration.md`](docs/radio_configuration.md).

## Testing boundary

Hardware-free direct USB response tests:

```text
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

With already-flashed hardware and an existing `pyserial` environment, the
vehicle smoke tool exercises direct USB only. Passing proves direct USB-to-
vehicle behavior only. End-to-end testing must instead pass Gateway commands
through the Hub and observe correlated vehicle-originated ACK/NACK and real TEL.
Physical behavior remains unproven until controlled hardware validation.
