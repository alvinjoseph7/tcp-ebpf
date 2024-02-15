#!/usr/bin/python3

from bcc import BPF

# Load the existing eBPF program
b = BPF(src_file="kernel-cwnd.bpf.c")

# Retrieve the map by its name
# map_fd = b.get_map_fd_by_name("your_ebpf_map")

# Access the map in user space
b["your_ebpf_map"][0] = 123   # Example: Write value 123 to the first entry of the map

# Retrieve a value from the map
value = b["your_ebpf_map"][0]   # Example: Read the value from the first entry of the map

print("Value from the eBPF map:", value)

# Close the map
b.cleanup()