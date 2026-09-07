# Phase 3B local radio configuration

## Secret boundary

Each sketch directory contains a tracked
`sentinel_radio_config.example.h` with `configured=false`, a zero peer address,
zero 16-byte keys, and channel zero. Those placeholders cannot enable transport.
The real filename is `sentinel_radio_config.h`; it is ignored in both sketch
directories and must remain local. Never commit, paste into evidence, log, or
print the real station MAC addresses, PMK, or LMK.

## Paired configuration

For each device, copy its adjacent example header to the local filename and edit
only the local copy:

1. Set the peer address to the other device's unicast Wi-Fi station MAC.
2. Set the same exactly 16-byte PMK on Hub and vehicle.
3. Set the same exactly 16-byte LMK on Hub and vehicle.
4. Select the same Wi-Fi channel on both devices; Phase 3B accepts 1 through 11.
5. Set the configured flag true only after every other field is complete.

The firmware does not discover peers, accept broadcast peers, or derive keys.
There is no unencrypted fallback. Each side initializes station mode and exactly one
`WIFI_IF_STA` peer with encryption required.

## Validation and failure behavior

Compile-time assertions require a 6-byte peer array and 16-byte PMK/LMK arrays.
Runtime validation requires the local header, configured flag, nonzero unicast peer
address, nonzero PMK and LMK, and supported channel. Initialization then checks
the Wi-Fi channel, PMK, callbacks, encrypted peer addition, and peer counts.

Any failure produces ESP-NOW UNAVAILABLE startup while retaining LOCKED state.
The Hub returns `NO_DOWNSTREAM_TRANSPORT`; it never sends unencrypted. The
vehicle still supports direct USB testing through the shared state machine, but
radio unavailability itself never enters RUNNING. Both devices must be rebuilt
after local configuration changes.

## Testing boundary

Do not infer that matching source files or READY startup lines prove a working
pair. Hardware validation must confirm the selected channel, opposite station
addresses, encrypted bidirectional commands/responses, unauthorized-peer
rejection, timeout behavior, telemetry forwarding, and STOP/RESET output safety.
