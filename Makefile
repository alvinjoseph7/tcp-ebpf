all: clean
	clang -O2 -g -Wall -emit-llvm -c kernel-cwnd.bpf.c -o haha.bc
	llc -march=bpf -mcpu=probe -filetype=obj haha.bc -o haha.o

clean: 
	rm -rf haha.o haha.bc