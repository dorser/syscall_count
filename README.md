# Syscall Count Gadget

Generates count metrics for syscalls called within containers.

Build:
```
make build
```

Run:
```
make run
```

Output:
Emits the number of calls for each syscall in a given time period. For example:
```
{"accept4":3,"access":16,"arch_prctl":24}    
{"getsockopt":58,"gettid":22,"getuid":5,"ioctl":52,"ioprio_get":2}   
```
## License

The user space components are licensed under the [Apache License, Version
2.0](LICENSE). The BPF code templates are licensed under the [General Public
License, Version 2.0, with the Linux-syscall-note](LICENSE-bpf.txt).
