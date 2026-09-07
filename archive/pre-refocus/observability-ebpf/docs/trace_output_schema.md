# Trace Output Schemas v0.1.1

## serial_trace CSV

| Field | Description |
|---|---|
| `timestamp` | Float Unix timestamp generated in user space. |
| `timestamp_iso` | ISO 8601 timestamp generated in user space. |
| `monotonic_ns` | Kernel monotonic timestamp from `bpf_ktime_get_ns()`. |
| `pid` | Process ID. |
| `comm` | Process name. |
| `syscall` | `read` or `write`. |
| `fd` | File descriptor integer. |
| `count` | Requested byte count from syscall entry. |
| `retval` | Return value. In this MVP it is `NOT_CAPTURED_V1`. |
| `fd_path` | Best-effort user-space path resolution from `/proc/<pid>/fd/<fd>`. |
| `device_match` | `True` if `fd_path` appears to match the configured device. |
| `notes` | Optional notes such as `FD_PATH_UNKNOWN`. |

## trace summary CSV

| Field | Description |
|---|---|
| `source_file` | Input trace file path. |
| `first_timestamp_iso` | First event timestamp. |
| `last_timestamp_iso` | Last event timestamp. |
| `duration_sec` | Time between first and last event. |
| `total_reads` | Number of read events. |
| `total_writes` | Number of write events. |
| `bytes_read` | Sum of read byte counts. |
| `bytes_written` | Sum of write byte counts. |
| `target_device_hits` | Number of events matched to the target device. |
| `top_processes` | Top process names by event count. |
| `notes` | Summary notes. |

## correlation report structure

The correlation report is Markdown and includes:

- input file paths
- correlation window
- generated timestamp
- per-command sections for PING, START, STOP, RESET, and TRACK_UPDATE if present
- nearby eBPF read/write counts
- nearby byte totals
- relevant telemetry rows within the same window
