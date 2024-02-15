from bcc import BPF
from ctypes import c_uint
from ctypes import c_int
from time import sleep

# Define the eBPF program code (same as provided earlier)
bpf_code = """
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <linux/skbuff.h>
BPF_HASH(cwnd_map, u32, u32);

int trace_cwnd(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct tcp_sock* tsk;
    u32 cwnd = 0;
    tsk = (struct tcp_sock *)sk;

    // Access cwnd value from the TCP control block (TCB)
    // bpf_probe_read_kernel(&cwnd, sizeof(cwnd), &sk->__sk_common.skc_cbuf[TCP_CWND]);
    bpf_probe_read_kernel(&cwnd, sizeof(cwnd), &tsk->rcv_wnd);
    // cwnd = tsk->rcv_wnd;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    cwnd_map.update(&pid, &cwnd);

    return 0;
}
"""

# Load the eBPF program
b = BPF(text=bpf_code)

# Attach the eBPF program to the tcp_cwnd_set tracepoint
# b.attach_tracepoint(tp="tcp: tcp_cong_state_set", fn_name="trace_cwnd")

# Attach the program to a Kprobe on the tcp_sendmsg function
b.attach_kprobe(event="tcp_ack", fn_name="trace_cwnd")
# b.attach_kretprobe(event="tcp_enter_cwr", fn_name="trace_cwnd")
print("Tracing tcp conneection...")

try:
    while True:
        for k, v in b["cwnd_map"].items():
            pid = c_uint(k.value)
            cwnd = c_uint(v.value)
            print(f"PID {pid.value}, cwnd: {cwnd.value}")
        b["cwnd_map"].clear()
except KeyboardInterrupt:
    pass
