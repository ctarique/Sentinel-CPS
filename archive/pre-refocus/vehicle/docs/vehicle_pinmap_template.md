# ESP32 Vehicle Pin Map and Hardware Verification Template

**Vehicle ID:** `vehicle_01`  
**Board:** [Enter exact ESP32 board]  
**Chassis:** [Enter chassis type]  
**Motor Driver:** [Enter driver, e.g., TB6612FNG or L298N]  
**Firmware Version:** v0.1.1

> Safety note: Do not set `MOTORS_ENABLED = true` until every row below is verified.

| Component | Firmware Placeholder Pin | Final ESP32 Pin | Expected Function | Confirmed in Lab? | Notes |
|---|---:|---:|---|---|---|
| Left Light Sensor | 34 | ____ | ADC input | [ ] | GPIO34 is input-only. |
| Right Light Sensor | 35 | ____ | ADC input | [ ] | GPIO35 is input-only. |
| Motor L FWD | 25 | ____ | Digital output | [ ] | Confirm direction with wheels raised. |
| Motor L REV | 26 | ____ | Digital output | [ ] | Confirm direction with wheels raised. |
| Motor L PWM | 27 | ____ | PWM output | [ ] | Confirm PWM channel. |
| Motor R FWD | 14 | ____ | Digital output | [ ] | Confirm direction with wheels raised. |
| Motor R REV | 33 | ____ | Digital output | [ ] | Avoid ESP32 strapping pins unless verified. |
| Motor R PWM | 32 | ____ | PWM output | [ ] | Confirm PWM channel. |
| Battery Positive | N/A | ____ | Motor power | [ ] | Measure voltage before connecting. |
| ESP32 GND | N/A | ____ | Common ground | [ ] | Must share ground with motor driver. |
| Sensor VCC | N/A | ____ | Sensor power | [ ] | Prefer 3.3V for ESP32 ADC safety. |

## Power and Safety Checklist

- [ ] ESP32 GND and motor-driver GND are tied together.
- [ ] Sensor VCC verified as 3.3V unless sensor circuit is designed otherwise.
- [ ] Battery voltage measured: ______ V.
- [ ] Wheels elevated for first motor test.
- [ ] `MOTORS_ENABLED` remains false during ADC calibration.
- [ ] Motor direction verified before placing vehicle on TV glass.
- [ ] No pins conflict with ESP32 boot/strapping behavior.
