#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define EVENT_ENTER 0
#define EVENT_EXIT 1

struct event {
  __u32 pid;
  __u32 syscall;
  __u32 type;
  __s64 retval;
  char comm[16];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16384);
  __type(key, __u64);
  __type(value, __u32);
} active_syscalls SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int syscall_entry(struct bpf_raw_tracepoint_args *ctx) {
  __u64 pid_tgid;
  __u32 syscall;
  struct event *e;

  pid_tgid = bpf_get_current_pid_tgid();
  syscall = (__u32)ctx->args[1];

  bpf_map_update_elem(&active_syscalls, &pid_tgid, &syscall, BPF_ANY);

  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) {
    return 0;
  }
  e->pid = pid_tgid >> 32;
  e->syscall = syscall;
  e->type = EVENT_ENTER;
  e->retval = 0;

  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  bpf_ringbuf_submit(e, 0);

  return 0;
}

SEC("raw_tracepoint/sys_exit")
int syscall_exit(struct bpf_raw_tracepoint_args *ctx) {
  __u64 pid_tgid;
  __u32 *syscall;
  struct event *e;

  pid_tgid = bpf_get_current_pid_tgid();
  syscall = bpf_map_lookup_elem(&active_syscalls, &pid_tgid);

  if (!syscall) {
    return 0;
  }

  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) {
    goto cleanup;
  }

  e->pid = pid_tgid >> 32;
  e->syscall = *syscall;
  e->type = EVENT_EXIT;
  e->retval = (__s64)ctx->args[1];

  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  bpf_ringbuf_submit(e, 0);

cleanup:
  bpf_map_delete_elem(&active_syscalls, &pid_tgid);

  return 0;
}
char LICENSE[] SEC("license") = "GPL";
