# Pre-Refocus Sentinel-CPS Development

This directory preserves Sentinel-CPS implementation artifacts developed before the August 19, 2026 architecture refocus.

Earlier versions of the project used an ESP32 Hub, Raspberry Pi-to-Hub USB serial communication, `/dev/ttyUSB0`, serial command and telemetry protocols, ESP-NOW, vehicle-oriented embedded communication, serial-focused eBPF/BCC observability, and earlier Smart TV/network arrangements.

These artifacts remain part of the project's research and engineering history, but they do **not** define the final Sentinel-CPS architecture.

The final architecture centers on an instructor-administered Raspberry Pi 4 Gateway, a bounded student/lab-user browser workflow, Gateway-to-ESP32 communication over Wi-Fi, and a Smart TV connected directly to the Raspberry Pi through HDMI.

Historical results must not be interpreted as validation of the final Gateway/Wi-Fi/HDMI configuration.
