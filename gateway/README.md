# Sentinel-CPS Gateway

This directory is the current implementation area for the final Sentinel-CPS Raspberry Pi 4 Gateway.

The final architecture separates instructor administration from a bounded student/lab-user browser workflow. The Gateway mediates permitted interaction with one ESP32 CPS over Wi-Fi and drives the laboratory Smart TV directly through HDMI.

The previous Hub, USB-serial, ESP-NOW, and serial-chokepoint implementation is preserved under `archive/pre-refocus/` as historical development work.

Current implementation is being reconciled with the final thesis architecture and validation methodology.
