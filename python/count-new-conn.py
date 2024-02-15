#!/usr/bin/python
from bcc import BPF
from ctypes import c_int
from time import sleep

# BPF program
prog = """
#include <uapi/linux/ptrace.h>

BPF_HASH(conn_count, u64, int);

int count_connection(struct __sk_buff *skb) {
    u64 pid = bpf_get_current_pid_tgid();
    int *count = conn_count.lookup(&pid);
    if (!count) {
        int initial_count = 1;
        conn_count.update(&pid, &initial_count);
    } else {
        (*count)++;
    }
    return 0;
}
"""

# Initialize BPF
b = BPF(text=prog)

# Attach the BPF program to trace TCP connect events
b.attach_kprobe(event="tcp_v4_connect", fn_name="count_connection")
b.attach_kprobe(event="tcp_v6_connect", fn_name="count_connection")

# Dictionary to store connection counts per PID
connection_count = {}

# Read and display connection counts
try:
    while True:
        sleep(3)
        for (k, v) in b["conn_count"].items():
            connection_count[k.value] = c_int(v.value).value
        for pid, count in connection_count.items():
            print("PID {}: {} TCP connections".format(pid, count))
except KeyboardInterrupt:
    pass
