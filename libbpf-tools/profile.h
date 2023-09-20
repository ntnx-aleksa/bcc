#ifndef __PROFILE_H_
#define __PROFILE_H_

#define MAX_CPU_NR 16

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

#define MAX_ENTRIES 10000

// Flags
#define STACK_FLAGS_USER_STACK (1 << 1)
#define STACK_FLAGS_KERNEL_STACK (1 << 2)

// From kernel source code
#define TASK_COMM_LEN 16
#define __PAGE_OFFSET_BASE_L5 0xff11000000000000UL
#define __PAGE_OFFSET_BASE_L4 0xffff888000000000UL

// Shared types

struct counter_key_t {
  unsigned int pid;
  unsigned long long kernel_ip;
  unsigned int user_stack_id;
  unsigned int kernel_stack_id;
  unsigned char name[TASK_COMM_LEN];
};

#endif /* __PROFILE_H_ */