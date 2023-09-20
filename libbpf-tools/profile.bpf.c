#include "profile.h"
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>



int pid_ns_dev = 0;
int pid_ns_ino = 0;
char use_pid_ns = 0;
char stack_flags = 0xFF;
char idle_filter = 1;
char pid_filtering = 0;
char tgid_filtering = 0;

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, struct counter_key_t);
  __type(value, u64);
} counts SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, int);
  __type(value, u8);
} pid_filter SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, int);
  __type(value, u8);
} tgid_filter SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_STACK_TRACE);
  __uint(key_size, sizeof(u32));
  __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
  __uint(max_entries, MAX_ENTRIES);
} stack_traces SEC(".maps");

static int increment_map(void *map, void *key, u64 increment) {
  u64 zero = 0, *count = (u64 *)bpf_map_lookup_elem(map, key);
  if (!count) {
    bpf_map_update_elem(map, key, &zero, BPF_NOEXIST);
    count = (u64 *)bpf_map_lookup_elem(map, key);
    if (!count) {
      return 0;
    }
  }

  __sync_fetch_and_add(count, increment);

  return *count;
}

// This code gets a bit complex. Probably not suitable for casual hacking.

SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx) {
  u32 tgid = 0;
  u32 pid = 0;

  struct bpf_pidns_info ns = {};
  if (use_pid_ns &&
      !bpf_get_ns_current_pid_tgid(pid_ns_dev, pid_ns_ino, &ns,
                                   sizeof(struct bpf_pidns_info))) {
    tgid = ns.tgid;
    pid = ns.pid;
  } else {
    u64 id = bpf_get_current_pid_tgid();
    tgid = id >> 32;
    pid = id;
  }

  struct task_struct *task;
  u32 ppid;

  task = (struct task_struct *)bpf_get_current_task();
  ppid = BPF_CORE_READ(task, real_parent, tgid);

  if (idle_filter && pid == 0)
    return 0;

  // NOTE: Temporary hack to allow tracing of direct children of filtered processes
  if (pid_filtering && bpf_map_lookup_elem(&pid_filter, &pid) == NULL && bpf_map_lookup_elem(&pid_filter, &ppid) == NULL)
    return 0;

  if (tgid_filtering && bpf_map_lookup_elem(&tgid_filter, &pid) == NULL)
    return 0;

  // TODO
  //   if (container_should_be_filtered()) {
  //     return 0;
  //   }

  // create map key
  struct counter_key_t key = {.pid = tgid};
  bpf_get_current_comm(&key.name, sizeof(key.name));

  // get stacks
  key.user_stack_id =
      (stack_flags & STACK_FLAGS_USER_STACK)
          ? bpf_get_stackid(&ctx->regs, &stack_traces, BPF_F_USER_STACK)
          : -1;
  key.kernel_stack_id = (stack_flags & STACK_FLAGS_KERNEL_STACK)
                            ? bpf_get_stackid(&ctx->regs, &stack_traces, 0)
                            : -1;

  if (key.kernel_stack_id >= 0) {
    // populate extras to fix the kernel stack
    u64 ip = PT_REGS_IP(&ctx->regs);
    u64 page_offset;

// There is a better way to do this
#if defined(CONFIG_DYNAMIC_MEMORY_LAYOUT) && defined(CONFIG_X86_5LEVEL)
    page_offset = __PAGE_OFFSET_BASE_L5;
#else
    page_offset = __PAGE_OFFSET_BASE_L4;
#endif

    if (ip > page_offset) {
      key.kernel_ip = ip;
    }
  }

  increment_map(&counts, &key, 1);
  return 0;
}

char _license[] SEC("license") = "GPL";
