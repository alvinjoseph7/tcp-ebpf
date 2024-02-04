from bcc import BPF

# Define the BPF program in Python
bpf_program = """
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/tcp.h>
//#include <stddef.h>
//#include <1inux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
// #include <bpf/bpf_helpers.h>
#include < bpf/bpf_endian.h>
#include <linux/ip.h>
struct tcp_option {
    u8 kind;
    u8 len;
    u16 data;
};
//SEC("sockops");
int bpf_insert_option(struct __sk_buff *skb) {
    struct tcp_option opt = {
        .kind = 66,
        .len = 4,
        .data = 20,
    };
    int rv = 0;
    int option_buffer;

    // Access the socket operations data
    struct bpf_sock_ops *skops = (struct bpf_sock_ops *)skb->data;

    switch (skops->op) {
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            // Activate option writing flag
            rv = bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_RTO_CB_FLAG);
            //trace.printk("BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB");
            break;
        case BPF_TCP_OPTIONS_SIZE_CALC:
            // Adjust total option len, not over 40 Bytes
            //trace.printk("BPF_TCP_OPTIONS_SIZE_CALC");
            int option_len = sizeof(opt);
            int total_len = skops->args[1];
            if (total_len + option_len <= 40)
                rv = option_len;
            break;
        case BPF_TCP_OPTIONS_WRITE:
            // Put struct option into reply field
            //trace.printk("BPF_TCP_OPTIONS_WRITE");
            memcpy(&option_buffer, &opt, sizeof(int));
            rv = option_buffer;
            // Will not insert option after 1st data packet
            if (skops->data_segs_in > 1)
                bpf_sock_ops_cb_flags_set(skops, 0);
            break;
        default:
            rv = -1;
    }
    skops->reply = rv;
    return 1;
}
"""

# Load the BPF program
b = BPF(text=bpf_program)

# Attach the program to the socket operations hook
b.attach_socket_op("bpf_insert_option")

# Print the BPF program's BPF bytecode
print(b.dump_func("bpf_insert_option"))

# Main loop (replace with your specific use case)
while True:
    try:
        # Trace and process events here
        b.trace_print()
    except KeyboardInterrupt:
        break
