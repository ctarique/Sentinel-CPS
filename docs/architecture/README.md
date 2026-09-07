# Sentinel-CPS Architecture

The final Sentinel-CPS architecture is centered on an instructor-administered Raspberry Pi 4 Gateway.

The Gateway separates instructor administration from bounded student/lab-user operation, mediates permitted interaction with one ESP32 CPS over Wi-Fi, records workflow evidence, and drives the laboratory Smart TV directly through HDMI.

The required paths are:

```text
Student / Lab User
        |
        v
Bounded Browser Workflow
        |
        v
Raspberry Pi 4 Sentinel Gateway
        |
      Wi-Fi
        |
        v
     ESP32 CPS
```

The HDMI display path is:

```text
Raspberry Pi 4
      |
     HDMI
      |
      v
   Smart TV
```

Earlier Hub, USB-serial, ESP-NOW, serial-chokepoint, networked-TV, and related architectures are preserved under `archive/pre-refocus/` as historical development material.
