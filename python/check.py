from bcc import BPF

# Define the eBPF program
ebpf_program = """
#include <uapi/linux/bpf.h>
#include <linux/tcp.h>

int congestion_window(struct __sk_buff *skb) {
    struct tcphdr *tcp;
    struct iphdr *ip = (struct iphdr *)next_hdr;
    if ((void *)ip + sizeof(*ip) > data_end) {
        return XDP_PASS;
    }

    if (ip->protocol != IPPROTO_TCP) {
        return 0;
    }

    tcp = (struct tcphdr *)((void *)ip + ip->ihl * 4);

    // Get the TCP header
    tcp = (struct tcp_hdr*)skb;
    if (!tcp)
        return 0;

    // Set the congestion window size to 2048
    bpf_trace_printk("%d", ntohs(tcp->window));
    //tcp->window = htons(2048); // Change this value to set the desired congestion window size

    return 0;
}
"""

# Load the eBPF program
b = BPF(text=ebpf_program)
syscall = b.get_syscall_fnname("execve")
# Attach the eBPF program to the socket
b.attach_kprobe(event=syscall, fn_name="congestion_window")

# Print any error messages
b.trace_print()
