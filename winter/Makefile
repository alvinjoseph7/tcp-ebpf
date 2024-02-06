BINDIR=bin
BPFDIR=ebpf
BPFBIN=${BINDIR}/bpf

.PHONY: all
.default: ebpf

ebpf: ${BPFBIN}
	clang -O2 -g -Wall -emit-llvm -c map-test.c -o ${BPFBIN}/map.bc
	clang -O2 -g -Wall -emit-llvm -c proto-parse.c -o ${BPFBIN}/parse.bc
	llc -march=bpf -mcpu=probe -filetype=obj ${BPFBIN}/map.bc -o ${BPFBIN}/map.o
	llc -march=bpf -mcpu=probe -filetype=obj ${BPFBIN}/parse.bc -o ${BPFBIN}/parse.o

${BINDIR}:
	mkdir -p ${BINDIR}

${BPFBIN}:
	mkdir -p ${BPFBIN}

clean:
	rm -r ${BINDIR}
	sudo rm -rf /sys/fs/bpf/ebpf
	sudo bpftool net detach xdp dev veth1

