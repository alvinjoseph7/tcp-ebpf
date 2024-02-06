from bcc import BPF

# BPF program code
bpf_code = """
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
//#include <netinet/in.h>

BPF_HASH(connections, struct sock *, int);

int count_tcp_connections(struct __sk_buff *skb) {
    struct ethhdr *eth = bpf_hdr_pointer(skb);
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

    if (ip->protocol == IPPROTO_TCP) {
        if (tcp->syn) {
            // Increment connection count on SYN (connection establishment).
            connections.update(&tcp->dest, &(int){1});
        } else if (tcp->fin || tcp->rst) {
            // Decrement connection count on FIN or RST (connection termination).
            connections.delete(&tcp->dest);
        }
    }

    return 0;
}
"""

# Create a BPF object
b = BPF(text=bpf_code)

# Attach the BPF program to the appropriate trace point
function_name = "count_tcp_connections"
b.attach_kprobe(event=function_name, fn_name=function_name)

# Monitor the kernel trace
while True:
    try:
        sleep(3)
        for (k, v) in b["connections"].items():
            print(f'{k.value}')
    except KeyboardInterrupt:
        break
