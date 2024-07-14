An eBPF program to modify the congestion window only if the fallback is set; stored in an eBPF map by user space code using the bpftool map update command.

## Quick start
- `make`: for building `vmlinux.h` and the program and loading it.
- `make load`: for attaching the hooks and loading the program.
- `make show`: for dumping details of the loaded program.<br><br>
  <image src="https://github.com/hyouteki/tcp-ebpf/assets/108230497/df596c59-1567-4ba1-9422-50e9256f89ab" width="1000">
- `make trace`: for dumping the trace_pipe onto stdout.<br><br>
  <image src="https://github.com/hyouteki/tcp-ebpf/assets/108230497/760b4ca6-8743-4576-b520-47155e3c6128" width="1000">
- `make map.update MAP=CwndMap VAL=00`: dummy client for testing the loaded program instead of any user space program.
- `make map.dump MAP=CwndMap`: dump the contents of `CwndMap` onto the stdout.
- `make unload`: for detaching the hooks and unloading the program.
> [!Important]
> Unloading the program is crucial; otherwise, the program and map will remain persistent until the system restarts.

## Dependency
- [libbpf-dev](https://packages.ubuntu.com/search?keywords=libbpf-dev)
- [bpftool](https://github.com/libbpf/bpftool)

## References
- [Learning eBPF - lizrice](https://github.com/lizrice/learning-ebpf)
- [BPF helpers - man](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)
