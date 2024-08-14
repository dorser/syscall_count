#define FOR_EACH_TRACE_SYSCALL(F)                                              \
  F(accept)                                                                    \
  F(accept4)                                                                   \
  F(bind)                                                                      \
  F(bpf)                                                                       \
  F(brk)                                                                       \
  F(capset)                                                                    \
  F(chdir)                                                                     \
  F(chroot)                                                                    \
  F(clone)                                                                     \
  F(clone3)                                                                    \
  F(close)                                                                     \
  F(connect)                                                                   \
  F(copy_file_range)                                                           \
  F(dup)                                                                       \
  F(dup3)                                                                      \
  F(epoll_create1)                                                             \
  F(eventfd2)                                                                  \
  F(execve)                                                                    \
  F(execveat)                                                                  \
  F(fchdir)                                                                    \
  F(fchmod)                                                                    \
  F(fchmodat)                                                                  \
  F(fchown)                                                                    \
  F(fchownat)                                                                  \
  F(fcntl)                                                                     \
  F(flock)                                                                     \
  F(fsconfig)                                                                  \
  F(fstat)                                                                     \
  F(futex)                                                                     \
  F(getcwd)                                                                    \
  F(getdents64)                                                                \
  F(getegid)                                                                   \
  F(geteuid)                                                                   \
  F(getgid)                                                                    \
  F(getpeername)                                                               \
  F(getresgid)                                                                 \
  F(getresuid)                                                                 \
  F(getrlimit)                                                                 \
  F(getsockname)                                                               \
  F(getsockopt)                                                                \
  F(getuid)                                                                    \
  F(inotify_init1)                                                             \
  F(ioctl)                                                                     \
  F(io_uring_enter)                                                            \
  F(io_uring_register)                                                         \
  F(io_uring_setup)                                                            \
  F(kill)                                                                      \
  F(linkat)                                                                    \
  F(listen)                                                                    \
  F(lseek)                                                                     \
  F(mkdirat)                                                                   \
  F(mlock)                                                                     \
  F(mlock2)                                                                    \
  F(mlockall)                                                                  \
  F(mmap)                                                                      \
  F(mount)                                                                     \
  F(mprotect)                                                                  \
  F(munlock)                                                                   \
  F(munlockall)                                                                \
  F(munmap)                                                                    \
  F(nanosleep)                                                                 \
  F(openat)                                                                    \
  F(openat2)                                                                   \
  F(open_by_handle_at)                                                         \
  F(pipe2)                                                                     \
  F(ppoll)                                                                     \
  F(prctl)                                                                     \
  F(preadv)                                                                    \
  F(ptrace)                                                                    \
  F(pwritev)                                                                   \
  F(quotactl)                                                                  \
  F(read)                                                                      \
  F(readv)                                                                     \
  F(recvfrom)                                                                  \
  F(recvmmsg)                                                                  \
  F(recvmsg)                                                                   \
  F(renameat)                                                                  \
  F(renameat2)                                                                 \
  F(seccomp)                                                                   \
  F(semctl)                                                                    \
  F(semget)                                                                    \
  F(semop)                                                                     \
  F(sendfile)                                                                  \
  F(sendmmsg)                                                                  \
  F(sendmsg)                                                                   \
  F(sendto)                                                                    \
  F(setgid)                                                                    \
  F(setns)                                                                     \
  F(setpgid)                                                                   \
  F(setresgid)                                                                 \
  F(setresuid)                                                                 \
  F(setrlimit)                                                                 \
  F(setsid)                                                                    \
  F(setsockopt)                                                                \
  F(setuid)                                                                    \
  F(shutdown)                                                                  \
  F(signalfd4)                                                                 \
  F(socket)                                                                    \
  F(socketpair)                                                                \
  F(splice)                                                                    \
  F(symlinkat)                                                                 \
  F(tgkill)                                                                    \
  F(timerfd_create)                                                            \
  F(tkill)                                                                     \
  F(umount2)                                                                   \
  F(unlinkat)                                                                  \
  F(unshare)                                                                   \
  F(userfaultfd)                                                               \
  F(write)                                                                     \
  F(writev)
