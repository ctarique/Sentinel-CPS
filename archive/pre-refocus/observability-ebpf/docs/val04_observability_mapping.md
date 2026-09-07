# VAL-04 Observability Mapping v0.1.1

## VAL-04 Gateway Observability

This package supports evidence collection for host-level observability at the Raspberry Pi Gateway. It prepares a trace workflow for serial read/write activity around the Gateway-to-Hub chokepoint.

## SR-O1 eBPF/BCC telemetry preparation

The BCC tracer attaches to Linux syscall tracepoints and records read/write metadata. This supports the thesis claim that a bare-metal Gateway can expose host-level observability unavailable through a heavily abstracted deployment.

## SR-O2 anomaly detection preparation

The trace CSV can later provide simple features such as read count, write count, byte volume, burst timing, and process identity. These features can support later anomaly-detection experiments, but this package does not implement the AI model.

## Gateway-to-Hub serial chokepoint observability

The tracer attempts to match syscall activity to `/dev/ttyUSB0` using best-effort file descriptor resolution. This allows later correlation between Gateway commands such as START/STOP and serial read/write behavior.

## VAL-05 preparation

The correlation script prepares a report showing nearby serial activity around application-layer commands. This supports later STOP/mitigation analysis, but mitigation validation requires actual execution evidence.

## Safe wording

Use:

- supports evidence collection
- prepares traceability
- enables correlation
- records metadata under test conditions

Avoid:

- guarantees detection
- captures every command
- unbypassable visibility
- complete observability
