#ifndef __SEQDETECT_H
#define __SEQDETECT_H

#include "argus.h"

/*
 * Syscall sequence / attack-chain detection.
 *
 * Maintains a per-PID state machine that recognises dangerous event
 * sequences observed in real-world attacks:
 *
 *  Chain 1 — Shellcode injection:
 *    MEMEXEC  (anon mmap/mprotect PROT_EXEC)
 *      → EXEC  within SEQDETECT_WINDOW_SECS
 *    Indicates shellcode written to anonymous memory then executed.
 *
 *  Chain 2 — Proc-mem write injection:
 *    PTRACE (PTRACE_POKETEXT/DATA, PTRACE_SETREGS, VM_WRITE)
 *      → EXEC on the target PID within SEQDETECT_WINDOW_SECS
 *    Indicates ptrace-based code injection.
 *
 *  Chain 3 — PrivEsc then shell:
 *    PRIVESC (uid → 0)
 *      → EXEC of a known shell binary within SEQDETECT_WINDOW_SECS
 *    Indicates successful privilege escalation followed by shell launch.
 *
 *  Chain 4 — Namespace escape + exec:
 *    NS_ESCAPE
 *      → EXEC within SEQDETECT_WINDOW_SECS
 *    Indicates container escape attempt.
 */

#define SEQDETECT_WINDOW_SECS 10    /* how long a partial chain stays "open" */
#define SEQDETECT_MAX_PIDS    4096  /* max simultaneous tracked PIDs          */

void seqdetect_init(void);

/*
 * Feed an event into the state machine.
 * Emits a [SEQDETECT] alert to stderr if a complete attack chain fires.
 * Returns 1 if a chain completed, 0 otherwise.
 */
int seqdetect_check(const event_t *ev);

/* Remove state for a PID (call on EVENT_EXIT). */
void seqdetect_remove(int pid);

#endif /* __SEQDETECT_H */
