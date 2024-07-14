#!/bin/bash
set -x

BUILD_NAME=bpf_sockops

sudo bpftool cgroup detach /sys/fs/cgroup/unified/${BUILD_NAME} sock_ops pinned /sys/fs/bpf/${BUILD_NAME}

if [ -e "/sys/fs/bpf/bpf_sockops" ]; then
	sudo rm -rf /sys/fs/bpf/*
fi
