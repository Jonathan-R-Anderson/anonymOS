#ifndef __SYSCALLANOM_H
#define __SYSCALLANOM_H
#include "argus.h"

/* forward-declare the BPF skeleton type used in argus.c */
struct argus_bpf;

void syscallanom_init(int check_interval_secs);
/* Called periodically from the main event loop; reads BPF syscall_counts map */
void syscallanom_check(struct argus_bpf *skel);
/* Called on EVENT_EXIT to clean up per-comm state */
void syscallanom_purge(const char *comm);
#endif
