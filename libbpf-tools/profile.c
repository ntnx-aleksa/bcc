#include "profile.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "profile.skel.h"
#include "trace_helpers.h"

static struct profile_bpf *skel = NULL;
static volatile int exit_requested = 0;
static struct syms_cache *syms_cache;
static struct ksyms *ksyms;
static int nr_cpus = 0;

static void sig_handler(int sig) { exit_requested = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level != LIBBPF_DEBUG)
    return vfprintf(stderr, format, args);
  else
    return 0;
}

static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
                                      struct bpf_link *links[]) {
  struct perf_event_attr attr = {
      .type = PERF_TYPE_SOFTWARE,
      .freq = 1,
      .sample_period = (__u64)freq,
      .config = PERF_COUNT_SW_CPU_CLOCK,
  };
  int i, fd;

  for (i = 0; i < nr_cpus; i++) {
    fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
    if (fd < 0) {
      /* Ignore CPU that is offline */
      if (errno == ENODEV)
        continue;
      fprintf(stderr, "failed to init perf sampling: %s\n", strerror(errno));
      return -1;
    }
    links[i] = bpf_program__attach_perf_event(prog, fd);
    if (!links[i]) {
      fprintf(stderr, "failed to attach perf event on cpu: %d\n", i);
      close(fd);
      return -1;
    }
  }

  return 0;
}

// Outputs same format as stackcollapse scripts
// Directly feed into flamegraph.pl
static void print_stack_collapsed(struct counter_key_t *key,
                                  unsigned long long count) {
  if (key == NULL)
    return;

  size_t ip[PERF_MAX_STACK_DEPTH] = {}, uip[PERF_MAX_STACK_DEPTH] = {};

  // Process name
  printf("  %d-%s;", key->pid,  key->name);

  // User symbols
  const struct syms *syms = syms_cache__get_syms(syms_cache, key->pid);
  if (syms != NULL) {
    if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.stack_traces),
                            &key->user_stack_id, uip) != 0) {
      printf("-");
    } else {
      for (int i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--) {
        if (uip[i] == 0)
          continue;

        char *dso_name;
        uint64_t dso_offset;
        const struct sym *sym =
            syms__map_addr_dso(syms, uip[i], &dso_name, &dso_offset);
        if (sym != NULL) {
          printf("%s", sym->name);
        } else {
          printf("[unknown]");
        }

        if (i != 0)
          printf(";");
      }
    }
  } else {
    printf("-");
  }
  printf(";");

  // Kernel symbols
  if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.stack_traces),
                          &key->kernel_stack_id, ip) != 0) {
    printf("-");
  } else {
    for (int i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--) {
      if (ip[i] == 0)
        continue;

      const struct ksym *ksym = ksyms__map_addr(ksyms, ip[i]);
      if (ksym != NULL)
        printf("%s_[k]", ksym->name);
      else
        printf("[unknown]");

      if (i != 0)
        printf(";");
    }
  }

  // Stack frequency
  printf(" %llu\n", count);
}

// static void print_stack(struct counter_key_t *key, unsigned long long count)
// {
//   if (key == NULL)
//     return;

//   printf("Process: [%8u]%s (%llu)\n", key->pid, key->name, count);
//   size_t ip[PERF_MAX_STACK_DEPTH] = {}, uip[PERF_MAX_STACK_DEPTH] = {};

//   const struct syms *syms = syms_cache__get_syms(syms_cache, key->pid);
//   if (!syms) {
//     printf("Failed to get syms\n");
//   }
//   if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.stack_traces),
//                           &key->user_stack_id, uip) != 0) {
//     printf("---;\n");
//   } else {
//     for (int i = 0; i < PERF_MAX_STACK_DEPTH; i++) {
//       if (uip[i] == 0)
//         break;
//       char *dso_name;
//       uint64_t dso_offset;

//       const struct sym *sym = NULL;
//       if (syms)
//         sym = syms__map_addr_dso(syms, uip[i], &dso_name, &dso_offset);
//       if (sym) {
//         printf("\t%d [<%016lx>] %s+0x%lx", i, uip[i], sym->name,
//         sym->offset); if (dso_name)
//           printf(" [%s]", dso_name);
//         printf("\n");
//       } else {
//         printf("\t%d [<%016lx>] <%s>\n", i, uip[i], "null sym");
//       }
//     }
//   }

//   printf("----KERNEL----\n");
//   if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.stack_traces),
//                           &key->kernel_stack_id, ip) != 0) {
//     printf("---;\n");
//   } else {
//     for (int i = 0; i < PERF_MAX_STACK_DEPTH; i++) {
//       if (ip[i] == 0)
//         break;
//       const struct ksym *ksym = ksyms__map_addr(ksyms, ip[i]);
//       if (ksym)
//         printf("\t%d [<%016lx>] %s+0x%lx\n", i, ip[i], ksym->name,
//                ip[i] - ksym->addr);
//       else
//         printf("\t%d [<%016lx>] <%s>\n", i, ip[i], "null sym");
//     }
//   }
// }

static void print_stacks() {
  if (skel == NULL)
    return;

  struct counter_key_t *key = NULL;
  struct counter_key_t next_key;
  unsigned long long value;

  while (bpf_map_get_next_key(bpf_map__fd(skel->maps.counts), key, &next_key) ==
         0) {
    bpf_map_lookup_elem(bpf_map__fd(skel->maps.counts), &next_key, &value);
    print_stack_collapsed(&next_key, value);
    key = &next_key;
  }
}

int main(int argc, char **argv) {
  int err = 0;
  int freq = 49;

  // Set sampling frequency
  if (argc > 2) {
    freq = atoi(argv[1]);
  }

  // libbpf errors and debug info callback
  libbpf_set_print(libbpf_print_fn);

  struct bpf_link *links[MAX_CPU_NR] = {};
  nr_cpus = libbpf_num_possible_cpus();
  if (nr_cpus < 0) {
    printf("Failed to get number of possible CPUs: '%s'!\n",
           strerror(-nr_cpus));
    return 1;
  }
  if (nr_cpus > MAX_CPU_NR) {
    fprintf(stderr,
            "The number of CPU cores is too big, please "
            "increase MAX_CPU_NR's value and recompile.");
    return 1;
  }

  // Signals for ending program
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  skel = profile_bpf__open_and_load();
  if (skel == NULL) {
    fprintf(stderr, "Failed to open or load BPF skeleton.\n");
    return -1;
  }

  if (argc > 2) {
    fprintf(stderr, "PID filtering enabled.\n");
    skel->bss->pid_filtering = 1;
    for (int i = 3; i < argc; i++) {
      int pid = atoi(argv[i]);
      char one = 1;
      bpf_map_update_elem(bpf_map__fd(skel->maps.pid_filter), &pid, &one, 0);
    }
  }

  // Load kernel symbols
  ksyms = ksyms__load();
  if (!ksyms) {
    fprintf(stderr, "Failed to load ksyms\n");
    err = -ENOMEM;

    goto cleanup;
  }

  // Userspace symbols
  syms_cache = syms_cache__new(100);
  if (!syms_cache) {
    fprintf(stderr, "Failed to create syms_cache\n");
    err = -ENOMEM;

    goto cleanup;
  }

  err = open_and_attach_perf_event(freq, skel->progs.do_perf_event, links);
  if (err) {
    fprintf(stderr, "Failed to attach to perf event.\n");
    goto cleanup;
  }

  while (!exit_requested) {
    sleep(10);
  }
  print_stacks();

cleanup:
  if (syms_cache)
    syms_cache__free(syms_cache);
  if (ksyms)
    ksyms__free(ksyms);
  if (skel != NULL) {
    int i;
    for (i = 0; i < nr_cpus; i++)
      bpf_link__destroy(links[i]);
    profile_bpf__destroy(skel);
  }

  return 0;
}
