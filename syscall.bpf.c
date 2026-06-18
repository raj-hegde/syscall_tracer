#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct event {
  __u32 pid;
  __u32 syscall;
  char comm[16];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int trace_syscall(struct bpf_raw_tracepoint_args *ctx) {
  bpf_printk("Program attached");
  struct event *e;

  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) {
    return 0;
  }
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->syscall = ctx->args[1];

  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  bpf_ringbuf_submit(e, 0);

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
