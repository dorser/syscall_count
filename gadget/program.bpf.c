// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 syscall_count-Authors */

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#include "syscall_compat.h"

struct event {
  int syscall_nr;
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(syscall_count, events, event);

static __always_inline bool should_filter_out_syscall(u64 syscall_nr) {
  // return syscall_nr != __NR_execve && __NR_openat;
  return false;
}

SEC("raw_tracepoint/sys_enter")
int tracepoint__sys_enter(struct bpf_raw_tracepoint_args *ctx) {
  int syscall_nr;
  __u64 mntns_id;
  struct event *event;

  syscall_nr = ctx->args[1];
  if (should_filter_out_syscall(syscall_nr))
    return 0;

  mntns_id = gadget_get_mntns_id();
  if (gadget_should_discard_mntns_id(mntns_id))
    return 0;

  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event)
    return 0;

  event->syscall_nr = syscall_nr;

  gadget_submit_buf(ctx, &events, event, sizeof(*event));

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
