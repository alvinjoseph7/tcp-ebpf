/* Copyright (c) 2017 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * BPF program to set initial congestion window and initial receive
 * window to 40 packets and send and receive buffers to 1.5MB. This
 * would usually be done after doing appropriate checks that indicate
 * the hosts are far enough away (i.e. large RTT).
 *
 * Use "bpftool cgroup attach $cg sock_ops $prog" to load this BPF program.
 */

// #include <uapi/linux/bpf.h>
// #include <uapi/linux/if_ether.h>
// #include <uapi/linux/if_packet.h>
// #include <uapi/linux/ip.h>
#include <linux/bpf.h>
#include <linux/socket.h>
#include <linux/types.h>
// #include <linux/tcp.h>
// #include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <netinet/tcp.h> 
#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
// #include <linux/if_ether.h>
// #include <linux/if_packet.h>
// #include <linux/ipv6.h>
// #include <linux/ip.h>
// #include <linux/icmpv6.h>



#define DEBUG 1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} wnd_map SEC(".maps");


SEC("sockops")
int bpf_iw(struct bpf_sock_ops *skops)
// int bpf_iw(struct sock *skops)
{
	// int rwnd_init = 40;
	// int iw = 40;
	int rv = 0;		// stores retval 
	struct in_addr addr;
	int key = 0;
	int val = 0;
	int op;
	int* user_wnd;

	addr.s_addr = skops->remote_ip4;


	// user_wnd = bpf_map_lookup_elem(&wnd_map, &key);
		

	/* For testing purposes, only execute rest of BPF program
	 * if neither port numberis 55601
	 */
	/* if (bpf_ntohl(skops->remote_port) != 55601 &&
	// if (bpf_ntohl(skops->dport) != 55601 &&
	    // skops->sk_num != 55601) {
	    skops->local_port != 55601) {
		skops->reply = -1;
		bpf_printk("Local port %d", skops -> local_port);
		return 1;
	} */

	op = (int) skops->op;
	if (op != 4 && op != 5)
		return 0;

#ifdef DEBUG
	bpf_printk("Opcode: %d\n", op);
#endif

	/* Usually there would be a check to insure the hosts are far
	 * from each other so it makes sense to increase buffer sizes
	 */
	switch (op) {
	// case BPF_SOCK_OPS_RWND_INIT:
		// rv = rwnd_init;
		// break;
	// case BPF_SOCK_OPS_TCP_CONNECT_CB:
	// 	/* Set sndbuf and rcvbuf of active connections */
	// 	rv = bpf_setsockopt(skops, SOL_SOCKET, SO_SNDBUF, &bufsize,
	// 			    sizeof(bufsize));
	// 	rv += bpf_setsockopt(skops, SOL_SOCKET, SO_RCVBUF,
	// 			     &bufsize, sizeof(bufsize));
	// 	break;
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:

		user_wnd = bpf_map_lookup_elem(&wnd_map, &key);
		if (!user_wnd) {
			rv = bpf_map_update_elem(&wnd_map, &key, &val, BPF_NOEXIST);
			if ( !rv ) {
				bpf_printk("Screw BPF. RV: %d", rv);
			}
			
		}  else {	// userspace has defined cwnd in map
			if (*user_wnd == 0) 
				return 0;
			rv = bpf_setsockopt(skops, SOL_TCP, TCP_BPF_IW, user_wnd, sizeof(int));
			if (rv < 0) {
				bpf_printk("Socket cwnd not set. Sock err: %d", rv);
			}
			bpf_printk("Init cwnd %d, IP: %pI4", *user_wnd, &addr.s_addr);
		}

		break;


	// iw = 20;

	// rv = bpf_setsockopt(skops, SOL_TCP, TCP_BPF_IW, &iw, sizeof(iw));
	// 	bpf_printk("Passive cwnd %d", iw );
	// 	break;
	// 	/* Set sndbuf and rcvbuf of passive connections */
	// 	rv = bpf_setsockopt(skops, SOL_SOCKET, SO_SNDBUF, &bufsize,
	// 			    sizeof(bufsize));
	// 	rv +=  bpf_setsockopt(skops, SOL_SOCKET, SO_RCVBUF,
	// 			      &bufsize, sizeof(bufsize));
	// 	break;
	// default:
		// rv = -1;
	}
#ifdef DEBUG
	bpf_printk("RV Val:  %d\n", rv);
#endif
	skops->reply = rv;
	return 1;
}



// SEC("kprobe/tcp_v4_connect")
// int BPF_KPROBE(tcp_v4_connect, struct bpf_sock_ops *sk)
// {
// 	return bpf_iw(sk);
// }


char _license[] SEC("license") = "GPL";