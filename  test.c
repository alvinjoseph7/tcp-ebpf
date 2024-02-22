#include <linux/bpf.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <linux/tcp.h>
#include <linux/version.h>
#include <stdint.h>
#include <bpf/bpf_helpers.h>

SEC("congestion_window")
int congestion_window(struct __sk_buff *skb) {
    // Get the transport header
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    // Check if this is a TCP packet
    if (tcp + 1 > data_end)
        return TC_ACT_OK;

    // Set the congestion window size to 2048
    // tcp->window = htons(2048); // Change this value to set the desired congestion window size

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";