#!/bin/bash
set -x


# detach and clear the bpf programs
sudo bpftool cgroup detach "/sys/fs/cgroup/" sock_ops pinned "/sys/fs/bpf/bpf_sockops" 
sudo unlink /sys/fs/bpf/bpf_sockops
ls /sys/fs/bpf
sudo rm -rf /sys/fs/bpf/*