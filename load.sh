#!/bin/bash
set -xe

BUILD_NAME=bpf_sockops

sudo mount -t bpf bpf /sys/fs/bpf/
sudo mkdir -p /sys/fs/cgroup/unified/${BUILD_NAME}

./unload.sh

sudo bpftool prog load ./build/${BUILD_NAME}.o /sys/fs/bpf/${BUILD_NAME} type sockops pinmaps /sys/fs/bpf/
sudo bpftool cgroup attach /sys/fs/cgroup/unified/${BUILD_NAME} sock_ops pinned /sys/fs/bpf/${BUILD_NAME}
