# Syscall Count Gadget

Collects count metrics for selected syscalls called within containers.

**Build**
```
make build
```

**Run**
```
PARAMS="--trace_all=true --verify-image=false --map-fetch-interval 5s -o json" make run
```

**Output**
Emits the number of calls for each syscall in a given time period. For example:
```
[{"count":3,"syscall":"SYS_EXECVE","syscall_raw":59},{"count":34,"syscall":"SYS_OPENAT","syscall_raw":257}]
[]{"count":2,"syscall":"SYS_SETGID","syscall_raw":106},{"count":1,"syscall":"SYS_SETSID","syscall_raw":112}]
```

**Tracing and Filtering**
This gadget collects a selected list of syscalls. By default, the gadget doesn't trace any syscall.
To trace all selected syscalls pass the `--trace_all=true` flag when running the gadget.

It's also possible to trace only a subset of syscalls by passing multiple `--trace_<SYSCALL>=true` flags.

**Supported Syscalls**
|syscall|x86_64|aarch64|
|-|-|-|
|accept|X|X|
|accept4|X|X|
|access|X||
|all|X|X|
|bind|X|X|
|bpf|X|X|
|brk|X|X|
|capset|X|X|
|chdir|X|X|
|chmod|X||
|chown|X||
|chroot|X|X|
|clone|X|X|
|clone3|X|X|
|close|X|X|
|connect|X|X|
|copy_file_range|X|X|
|creat|X||
|dup|X|X|
|dup2|X||
|dup3|X|X|
|epoll_create|X||
|epoll_create1|X|X|
|epoll_wait|X||
|eventfd|X||
|eventfd2|X|X|
|execve|X|X|
|execveat|X|X|
|fchdir|X|X|
|fchmod|X|X|
|fchmodat|X|X|
|fchown|X|X|
|fchownat|X|X|
|fcntl|X|X|
|flock|X|X|
|fork|X||
|fsconfig|X|X|
|fstat|X|X|
|futex|X|X|
|getcwd|X|X|
|getdents|X||
|getdents64|X|X|
|getegid|X|X|
|geteuid|X|X|
|getgid|X|X|
|getpeername|X|X|
|getresgid|X|X|
|getresuid|X|X|
|getrlimit|X|X|
|getsockname|X|X|
|getsockopt|X|X|
|getuid|X|X|
|inotify_init|X||
|inotify_init1|X|X|
|io_uring_enter|X|X|
|io_uring_register|X|X|
|io_uring_setup|X|X|
|ioctl|X|X|
|kill|X|X|
|lchown|X||
|link|X||
|linkat|X|X|
|listen|X|X|
|lseek|X|X|
|lstat|X||
|mkdir|X||
|mkdirat|X|X|
|mlock|X|X|
|mlock2|X|X|
|mlockall|X|X|
|mmap|X|X|
|mount|X|X|
|mprotect|X|X|
|munlock|X|X|
|munlockall|X|X|
|munmap|X|X|
|nanosleep|X|X|
|open|X||
|open_by_handle_at|X|X|
|openat|X|X|
|openat2|X|X|
|pipe|X||
|pipe2|X|X|
|poll|X||
|ppoll|X|X|
|prctl|X|X|
|preadv|X|X|
|ptrace|X|X|
|pwritev|X|X|
|quotactl|X|X|
|read|X|X|
|readv|X|X|
|recvfrom|X|X|
|recvmmsg|X|X|
|recvmsg|X|X|
|rename|X||
|renameat|X|X|
|renameat2|X|X|
|rmdir|X||
|seccomp|X|X|
|select|X||
|semctl|X|X|
|semget|X|X|
|semop|X|X|
|sendfile|X|X|
|sendmmsg|X|X|
|sendmsg|X|X|
|sendto|X|X|
|setgid|X|X|
|setns|X|X|
|setpgid|X|X|
|setresgid|X|X|
|setresuid|X|X|
|setrlimit|X|X|
|setsid|X|X|
|setsockopt|X|X|
|setuid|X|X|
|shutdown|X|X|
|signalfd|X||
|signalfd4|X|X|
|socket|X|X|
|socketpair|X|X|
|splice|X|X|
|stat|X||
|symlink|X||
|symlinkat|X|X|
|tgkill|X|X|
|timerfd_create|X|X|
|tkill|X|X|
|umount2|X|X|
|unlink|X||
|unlinkat|X|X|
|unshare|X|X|
|userfaultfd|X|X|
|vfork|X||
|write|X|X|
|writev|X|X|

## License

The user space components are licensed under the [Apache License, Version
2.0](LICENSE). The BPF code templates are licensed under the [General Public
License, Version 2.0, with the Linux-syscall-note](LICENSE-bpf.txt).
