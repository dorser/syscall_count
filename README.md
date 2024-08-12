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
[{"count":1,"syscall_nr":231},{"count":5,"syscall_nr":0},{"count":1,"syscall_nr":109}]
[{"count":2,"syscall_nr":14},{"count":7,"syscall_nr":1},{"count":6,"syscall_nr":13}]
```
## License

The user space components are licensed under the [Apache License, Version
2.0](LICENSE). The BPF code templates are licensed under the [General Public
License, Version 2.0, with the Linux-syscall-note](LICENSE-bpf.txt).
