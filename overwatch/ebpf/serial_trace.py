#!/usr/bin/python3
from bcc import BPF
import time

# ==========================================
# THESIS CONSTRAINT: BARE-METAL TRACING
# ==========================================
# This C program is injected directly into the Linux kernel using eBPF.
# It hooks into the sys_enter_write system call to monitor serial activity.
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_PERF_OUTPUT(events);

struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    u64 fd;
};

// Hook into the 'write' system call
TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    struct data_t data = {};
    
    // We are only interested in file descriptor 3 or higher (ignoring stdin/out/err)
    // In a production deployment, this will strictly filter for /dev/ttyUSB0's FD.
    if (args->fd > 2) {
        data.pid = bpf_get_current_pid_tgid() >> 32;
        data.ts = bpf_ktime_get_ns();
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        data.fd = args->fd;
        
        events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_text)

print("[OVERWATCH] eBPF Kernel Tracing Initialized.")
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "FILE_DESCRIPTOR"))

# Process and print events from the kernel
def print_event(cpu, data, size):
    event = b["events"].event(data)
    # Filter to only show our Flask app's background listener writing to the log or serial
    if b"python" in event.comm:
        print("%-18.9f %-16s %-6d %d" % (
            event.ts / 1000000000.0,
            event.comm.decode('utf-8', 'replace'),
            event.pid,
            event.fd
        ))

# Loop with callbacks
b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
