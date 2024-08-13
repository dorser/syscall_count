# Syscall Count Gadget

Generates count metrics for syscalls called within containers.

Build:
```
make build
```

Run:
```
PARAMS="--verify-image=false --map-fetch-interval 5s -o json" make run
```

Output:
Emits the number of calls for each syscall in a given time period. For example:
```
[{"count":3,"syscall":"SYS_EXECVE","syscall_raw":59},{"count":34,"syscall":"SYS_OPENAT","syscall_raw":257}]
[]{"count":2,"syscall":"SYS_SETGID","syscall_raw":106},{"count":1,"syscall":"SYS_SETSID","syscall_raw":112}]
```
## License

The user space components are licensed under the [Apache License, Version
2.0](LICENSE). The BPF code templates are licensed under the [General Public
License, Version 2.0, with the Linux-syscall-note](LICENSE-bpf.txt).
