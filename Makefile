default: clean build load

BPF_PROG = kernel-cwnd.bpf.c
BUILD_NAME = bpf_sockops
VAL ?= 00
MAP ?= CwndMap

build: $(BPF_PROG) vmlinux.h clean
	mkdir -p build
	clang \
		-target bpf \
		-D __TARGET_ARCH_$(ARCH) \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g -O2 -c $(BPF_PROG) -o ./build/$(BUILD_NAME).o
	llvm-strip -g ./build/$(BUILD_NAME).o

vmlinux.h:
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./vmlinux.h

load:
	sudo bash ./load.sh

trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

map.update: 
	sudo bpftool map update name $(MAP) key hex 00 00 00 00 value hex 00 00 00 $(VAL)

map.dump:
	sudo bpftool map dump name $(MAP)

unload:
	sudo bash ./unload.sh

show:
	sudo bpftool prog show name $(BUILD_NAME) --pretty

clean: 
	rm -rf ./build/*
