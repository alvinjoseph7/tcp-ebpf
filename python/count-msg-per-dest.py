#!/usr/bin/python
from bcc import BPF
from ctypes import c_int
from time import sleep

# BPF program
prog = """
#include <uapi/linux/ptrace.h>
// #include <libbpf/include/uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/in6.h>
//#include <linux/filter.h>
#include <linux/socket.h>
struct data_t { 
    long long int source_ip_addr;
    long long int dest_ip_addr;
    long long int source_port;
    long long int dest_port;
};
BPF_HASH(tcp_connection_map,struct data_t,int);
int count_connection(struct pt_regs *ctx) {
struct sock *sk=(struct sock *)PT_REGS_PARM1(ctx);
    if(sk==NULL){
        bpf_trace_printk("Null socket");
        return 0;
    }
    struct data_t data1={};
    if(sk->__sk_common.skc_family == AF_INET){
        data1.source_ip_addr= sk->__sk_common.skc_rcv_saddr;
        data1.dest_ip_addr= sk->__sk_common.skc_daddr;
        data1.source_port= sk->__sk_common.skc_num;
        data1.dest_port= sk->__sk_common.skc_dport;
        //bpf_trace_printk("Source ip = %lld",data1.source_ip_addr);
        //bpf_trace_printk("Source port = %lld",data1.source_port);
        //bpf_trace_printk("Destination ip = %lld",data1.dest_ip_addr);
        //bpf_trace_printk("Destination port = %lld",data1.dest_port);
        //bpf_trace_printk("Success");
    }
    bpf_trace_printk("Hello World");
    int * count=tcp_connection_map.lookup(&data1);
    int number=0;
    if(count!=0){
        number=*count;
    }
    number=number+1;
    tcp_connection_map.update(&data1,&number);
    bpf_trace_printk("Bye World");
    return 0;
}
"""

# Initialize BPF
b = BPF(text=prog)

# Attach the BPF program to trace TCP connect events
b.attach_kprobe(event="tcp_recvmsg", fn_name="count_connection")
#b.attach_kprobe(event="tcp_v4_connect", fn_name="count_connection")



# # Read and display connection counts
try:
    while True:
        sleep(3)
        for (k, v) in b["tcp_connection_map"].items():
            #print(type(v),type(k))
            print(f"Source IP={k.source_ip_addr} \t Source Port= {k.source_port} \t Destination IP={k.dest_ip_addr} \t Destination Port ={k.dest_port} \t\t Count={c_int(v.value).value}")
            print()
            
except KeyboardInterrupt:
    pass

#b.trace_print()
