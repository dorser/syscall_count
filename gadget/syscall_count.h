#include "syscall_compat.h"
#include "syscall_trace.h"

#define MAX_ENTRIES 500

#define ENUM_ITEM(name) name,

#define DECLARE_TRACE_PARAMETER(name)                                          \
  const volatile bool trace_##name = false;                                    \
  GADGET_PARAM(trace_##name);

FOR_EACH_SYSCALL(DECLARE_TRACE_PARAMETER)

#define SHOULD_TRACE_SYSCALL(name)                                             \
  if (trace_##name || trace_all) {                                             \
    syscall_nr = __NR_##name;                                                  \
    bpf_map_update_elem(&syscall_filters, &syscall_nr, &true_value,            \
                        BPF_NOEXIST);                                          \
  }

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(bool));
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, MAX_ENTRIES);
} syscall_filters SEC(".maps");

const volatile bool trace_all = false;
GADGET_PARAM(trace_all);

static __always_inline bool init_syscall_filters_map() {
  __u64 syscall_nr;
  const bool true_value = true;
  FOR_EACH_TRACE_SYSCALL(SHOULD_TRACE_SYSCALL)
}
