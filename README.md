# Sentinel-CPS

Sentinel-CPS is a secure remote cyber-physical systems (CPS) education lab
architecture. It is being developed as a master's thesis prototype for giving
remote users meaningful access to physical IoT experiments without directly
exposing protected gateway services, edge devices, or the broader enterprise
network.

The v10.0 architecture uses a Zero-Trust Raspberry Pi Gateway as the central
policy, command, logging, and observability point. A native Flask command and
control (C2) application is planned to run through `systemd` on TCP port
`8080`. The Gateway communicates with a tethered ESP32 Hub over
`/dev/ttyUSB0`, and the Hub exchanges encrypted ESP-NOW commands and telemetry
with autonomous ESP32 vehicles.

## Physical Execution Model

Sentinel-CPS uses a horizontally mounted Smart TV as a dynamic physical track.
The TV renders a high-contrast digital lane, while ESP32 vehicles use
downward-facing analog light sensors and onboard PID control to follow the
displayed path. This TV-as-a-Track model provides repeatable,
software-defined physical experiments without rebuilding a manual track.

## Security Model

The Raspberry Pi Gateway is the only authorized mediator between remote users
and the physical CPS environment. The v10.0 design includes:

* Controlled remote educational access through an authorized bastion workflow
* Native host execution for Gateway services
* Default-deny network policy and least-privilege endpoint access
* A serial chokepoint between the Gateway and ESP32 Hub
* Encrypted ESP-NOW edge telemetry
* Planned eBPF tracing of Gateway serial activity
* Planned lightweight AI anomaly detection
* Planned emergency STOP and controlled serial-severance responses

Sensitive deployment details, credentials, private keys, live network
identifiers, and institution-specific operational configuration are excluded
from this public repository.

## Repository Layout

```text
.
├── docs/
│   ├── architecture/       # Sanitized diagrams and architecture history
│   ├── evidence/           # Placeholder for reviewed validation evidence
│   ├── formal/             # Current shareable v10.0 thesis PDFs
│   ├── network/            # Sanitized and legacy network documentation
│   ├── research_logs/      # Preserved repository research history
│   └── validation/         # Reconciliation and validation planning
├── firmware/
│   ├── hub/                # ESP32 Hub firmware placeholder
│   ├── vehicle/            # ESP32 vehicle firmware placeholder
│   └── esp32_serial_protocol.md
├── gateway/
│   ├── data/               # Ignored runtime data
│   ├── sentinel/           # Gateway package placeholder
│   ├── static/             # Static asset placeholder
│   ├── templates/          # Flask template placeholder
│   └── tests/              # Gateway test placeholder
├── host/
│   ├── nftables/           # Reviewed host firewall configuration placeholder
│   ├── systemd/            # Reviewed service configuration placeholder
│   └── udev/               # Reviewed device policy placeholder
├── lane-subsystem/         # TV-as-a-Track and light-sensor lane material
├── logs/                   # Ignored runtime logs
└── overwatch/
    ├── ebpf/               # Planned eBPF implementation placeholder
    └── inference/          # Planned anomaly-inference placeholder
```

## Current Build Status

Repository reconciliation for Sentinel-CPS v10.0 is complete. The repository
now contains organized, selected shareable thesis PDFs, preserved architecture and
research history, the current serial protocol note, a reviewed lane-subsystem
artifact, and placeholders for planned implementation areas.

The Gateway application, ESP32 firmware, host policy, eBPF monitoring, and AI
inference are not yet implemented in this repository. A staged Gateway
prototype was intentionally not imported because it requires sanitization and
alignment with the v10.0 architecture.

## Next Implementation Step

The next implementation task is **Gateway MVP refinement**: review and
sanitize the existing Flask prototype, define its configuration boundaries,
align it with TCP port `8080` and the repository layout, then add focused tests
before integrating hardware behavior.

## Documentation

* Imported v10.0 formal thesis PDFs: `docs/formal/`
* Architecture material: `docs/architecture/`
* Network documentation: `docs/network/`
* Reconciliation decisions and manual-review queue:
  `docs/validation/repository_reconciliation_v10.md`

## Public Repository Notice

This repository is a sanitized research and portfolio version of Sentinel-CPS,
not a production deployment guide. Public examples and diagrams must use
placeholders rather than live infrastructure identifiers.

## Author

**Tarique Chowdhury**

M.S. Cybersecurity Candidate

Southeast Missouri State University

## License

This project is licensed under the MIT License.
