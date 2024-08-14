// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 syscall_count-Authors */

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#include "syscall_count.h"

bool filters_init = false;

struct syscall_id {
  gadget_syscall syscall_raw;
};

struct syscall_count {
  __u64 count;
};

static struct syscall_count zero_value = {0};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, struct syscall_id);
  __type(value, struct syscall_count);
} counts SEC(".maps");

GADGET_MAPITER(syscall_count, counts);

static __always_inline bool should_trace_syscall(__u64 syscall_nr) {
  if (!filters_init) {
    init_syscall_filters_map();
    filters_init = true;
  }

  return bpf_map_lookup_elem(&syscall_filters, &syscall_nr) != NULL;
}

SEC("raw_tracepoint/sys_enter")
int tracepoint__sys_enter(struct bpf_raw_tracepoint_args *ctx) {
  __u64 mntns_id;
  __u64 syscall_nr;
  struct syscall_id key = {};
  struct syscall_count *valuep;

  syscall_nr = ctx->args[1];

  mntns_id = gadget_get_mntns_id();
  if (gadget_should_discard_mntns_id(mntns_id))
    return 0;

  if (!should_trace_syscall(syscall_nr))
    return 0;

  key.syscall_raw = syscall_nr;

  valuep = bpf_map_lookup_elem(&counts, &key);
  if (!valuep) {
    bpf_map_update_elem(&counts, &key, &zero_value, BPF_NOEXIST);
    valuep = bpf_map_lookup_elem(&counts, &key);
    if (!valuep)
      return 0;
  }
  valuep->count++;

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
