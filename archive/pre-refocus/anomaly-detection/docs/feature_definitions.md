# Sentinel-CPS Anomaly Feature Definitions

## Command rate

Measures how many Gateway actions occur within a sliding time window. A high command rate may indicate scripted misuse, repeated operator error, or compromised access.

## Command repetition / START-STOP toggling

Measures repeated START and STOP transitions inside a short window. This may stress the physical system and is useful as an operator-safety warning.

## Telemetry row rate

Measures the number of telemetry rows inside a sliding time window. Excessive telemetry volume may indicate flooding, firmware malfunction, or unauthorized peer behavior.

## Serial write rate after LOCKED

Checks for eBPF-observed serial `write` syscalls after a STOP/LOCKED marker. This supports review of whether serial activity continued after the system should have entered a safe state.

## Action-to-syscall correlation gap

Detects serial writes that do not have a nearby Gateway action. This can suggest non-Gateway code writing to the serial device or an incomplete correlation window.

## Malformed telemetry detection

Checks whether `adc_l`, `adc_r`, and `steer` parse as numeric values. Malformed rows may indicate parsing failure, firmware issues, or intentionally malformed input.

## Replay-like interval similarity

Checks whether telemetry intervals are unusually identical across a short sequence. This is a weak signal only. It should be interpreted with physical test notes and other evidence.
