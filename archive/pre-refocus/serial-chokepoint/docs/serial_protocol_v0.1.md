# Sentinel-CPS Serial Protocol v0.1.1 (Superseded)

The legacy mock protocol and Phase 2 transport boundary are superseded. Bare
commands, `TRACK`, synthetic telemetry, Hub-local `RUNNING`/`IDLE` transitions,
and legacy `ACK_*` responses remain disabled.

Use [`serial_protocol_contract.md`](serial_protocol_contract.md) as the
canonical Phase 3B contract. It preserves `CMD,<txid>,<verb>` framing while
adding encrypted, authorized-peer ESP-NOW forwarding and vehicle-authoritative
ACK/NACK correlation. A Hub READY diagnostic or ESP-NOW send completion is not
proof of vehicle execution.
