# TV-as-a-Track Calibration Runbook

This runbook prepares later VAL-03 physical navigation evidence. Phase 3A only
supports direct USB testing with physical motor actuation disabled; it does not
validate the Gateway/Hub path or ESP-NOW delivery.

## Phase 0: Safety Setup

1. Confirm `MOTORS_ENABLED = false` in `vehicle_esp32.ino`.
2. Load the Phase 3A firmware only during an authorized hardware session.
3. Open a serial terminal at `115200` baud.
4. Confirm `BOOT,VEHICLE,LOCKED,MOTORS_DISABLED` appears.
5. Confirm the initial `TEL,...,LOCKED` frame appears.
6. Verify sensor pins and wiring against `vehicle_pinmap_template.md`.

## Phase 1: Static ADC Calibration

1. Display a pure black background on the Smart TV.
2. Place both downward-facing sensors over the black region.
3. Record the periodic `TEL` ADC values in `tools/adc_calibration_template.csv`.
4. Display a pure white track or white test rectangle on the Smart TV.
5. Place both sensors over the white region.
6. Record the periodic `TEL` ADC values in `tools/adc_calibration_template.csv`.
7. Repeat at multiple TV brightness settings if time allows.
8. Estimate a threshold midpoint between black and white readings.

## Phase 2: Dry-Run PID Test

1. Keep `MOTORS_ENABLED = false`.
2. Display a white lane on a black background.
3. Raise the vehicle so wheels are not touching the TV.
4. Send `CMD,<unique-txid>,RESET` and require
   `ACK,<same-txid>,RESET,IDLE,VEHICLE`.
5. Send `CMD,<unique-txid>,START` and require
   `ACK,<same-txid>,START,RUNNING,VEHICLE`.
6. Move the vehicle manually left and right across the lane.
7. Observe `DIAG,VEHICLE,DRY_RUN_PWM,...` output.
8. Verify left/right intended PWM changes logically as the vehicle moves.
9. Send `CMD,<unique-txid>,STOP` and require the matching LOCKED ACK.
10. Confirm LOCKED telemetry follows and physical outputs remain off.

## Deferred live motor test

Live motor testing is outside Phase 3A. Do not change `MOTORS_ENABLED` for this
phase. A later authorized phase must define verified pin mapping, wheel
direction, power isolation, emergency-stop procedure, transport behavior, and
evidence handling before motor actuation is enabled.

## Evidence to Capture

- Photo of TV setup.
- Photo of vehicle sensor placement.
- Serial monitor output showing calibration values.
- `adc_calibration_template.csv` filled with readings.
- `pid_test_log_template.csv` filled with test observations.
- Short video of dry-run tracking preparation.
- STOP/LOCKED telemetry row.
