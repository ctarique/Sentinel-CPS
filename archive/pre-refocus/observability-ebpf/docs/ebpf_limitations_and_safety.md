# eBPF/BCC Limitations and Safety v0.1.1

## Privileges

BCC tracing usually requires root privileges because BPF programs are loaded into the kernel. The tracer checks for root and exits with a clear message if it is not running with sufficient privileges.

## Kernel and package dependency

This package depends on Linux kernel support, BCC/BPFCC packages, and Python bindings for BCC. The environment checker reports readiness but does not install anything automatically.

## File descriptor resolution is best effort

The BPF program captures syscall metadata in kernel space. The Python process then attempts to resolve `/proc/<pid>/fd/<fd>` in user space. This can fail if the process closes the file descriptor before the event is processed or if permission restrictions prevent access.

## Metadata-only default

The tracer records syscall metadata such as PID, process name, syscall type, file descriptor, byte count, and best-effort path. It does not capture serial payload contents by default. This is intentional for privacy, simplicity, and thesis safety.

## Not absolute visibility

This package should not be described as “absolute visibility,” “unbypassable visibility,” or guaranteed detection. It supports Gateway-level observability evidence for the serial chokepoint under the specific test conditions executed in the lab.

## No destructive changes

The scripts do not modify kernel settings, services, firewall rules, serial device permissions, or Gateway code. They collect evidence and generate derived reports.
