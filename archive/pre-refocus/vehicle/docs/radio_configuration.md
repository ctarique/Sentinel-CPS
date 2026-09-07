# Vehicle Phase 3B radio configuration

The tracked `firmware/vehicle_esp32/sentinel_radio_config.example.h` is safe and
disabled. Copy it locally to `sentinel_radio_config.h` in the same sketch
directory. The local filename is ignored by Git.

In the local copy only:

1. configure the Hub's Wi-Fi station MAC as the sole peer;
2. configure the same exactly 16-byte PMK and LMK as the Hub;
3. configure the same channel from 1 through 11 as the Hub; and
4. change the configured flag last.

Do not commit, print, or place real values in evidence. The example's false flag
and all-zero placeholders cannot initialize transport. Wrong array sizes fail
compilation; missing, zero, disabled, or unsupported runtime values produce
`BOOT,VEHICLE,LOCKED,ESP_NOW_UNAVAILABLE`. The firmware never creates an
unencrypted peer or falls back to plaintext.

READY proves only local station/channel/ESP-NOW/peer initialization. Hardware
testing must still demonstrate authorized bidirectional encrypted exchange,
unauthorized-peer rejection, matching channel behavior, response timeout and
loss behavior, telemetry forwarding, and STOP/RESET output safety.
