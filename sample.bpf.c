// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

typedef struct {
  u32 pid;
  u32 pid_ns;
  u32 mnt_ns;
  u8 comm[80];
  u8 rc;
} event;

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

static bool isequal(const char *a, const char *b) {
#pragma unroll
  for (int i = 0; i < 32; i++) {
    if (a[i] == '\0' || b[i] == '\0')
      break;

    if (a[i] != b[i])
      return false;
  }
  return true;
}

// Force emitting struct event into the ELF.
const event *unused __attribute__((unused));

SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;
  u32 mnt_ns = BPF_CORE_READ(t, nsproxy, mnt_ns, ns).inum;
  struct pt_regs *real_regs;
  real_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;

  event *task_info;

  task_info = bpf_ringbuf_reserve(&events, sizeof(event), 0);
  if (!task_info) {
    return 0;
  }

  const char block[80] = "/usr/bin/sleep";
  const char val[80] = "";

  task_info->pid = tgid;
  task_info->pid_ns = pid_ns;
  task_info->mnt_ns = mnt_ns;
  task_info->rc = 0;
  bpf_probe_read_str(&task_info->comm, 80,
                     (void *)PT_REGS_PARM1_CORE(real_regs));
  bpf_probe_read_str(val, 80,
                     (void *)PT_REGS_PARM1_CORE(real_regs));

  
  if (isequal(block, val)){
    task_info->rc = 1;
    bpf_send_signal(9);
  }

  bpf_ringbuf_submit(task_info, 0);

  return 0;
}