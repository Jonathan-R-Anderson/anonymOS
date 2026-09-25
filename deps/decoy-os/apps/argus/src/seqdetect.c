#include <stdio.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include "seqdetect.h"
#include "argus.h"

/* Per-PID state flags */
#define STATE_MEMEXEC   (1 << 0)   /* saw MEMEXEC                        */
#define STATE_PTRACE_WR (1 << 1)   /* saw ptrace write (POKETEXT/etc.)   */
#define STATE_PRIVESC   (1 << 2)   /* saw PRIVESC → uid 0                */
#define STATE_NS_ESCAPE (1 << 3)   /* saw NS_ESCAPE                      */

typedef struct {
    int      pid;
    uint32_t state;
    time_t   ts;           /* when the first trigger was seen */
    char     comm[16];
    int      ptrace_target; /* for chain 2: the PID being written into */
} pid_state_t;

static pid_state_t g_states[SEQDETECT_MAX_PIDS];

void seqdetect_init(void)
{
    memset(g_states, 0, sizeof(g_states));
}

static pid_state_t *find_state(int pid)
{
    /* Simple linear probe */
    unsigned int slot = (unsigned int)((pid * 2654435761u) % SEQDETECT_MAX_PIDS);
    for (unsigned int i = 0; i < SEQDETECT_MAX_PIDS; i++) {
        pid_state_t *s = &g_states[(slot + i) % SEQDETECT_MAX_PIDS];
        if (s->pid == pid)
            return s;
        if (!s->pid) {
            s->pid = pid;
            return s;
        }
    }
    /* Table full — evict the slot */
    pid_state_t *s = &g_states[slot];
    memset(s, 0, sizeof(*s));
    s->pid = pid;
    return s;
}

void seqdetect_remove(int pid)
{
    unsigned int slot = (unsigned int)((pid * 2654435761u) % SEQDETECT_MAX_PIDS);
    for (unsigned int i = 0; i < SEQDETECT_MAX_PIDS; i++) {
        pid_state_t *s = &g_states[(slot + i) % SEQDETECT_MAX_PIDS];
        if (s->pid == pid) {
            memset(s, 0, sizeof(*s));
            return;
        }
        if (!s->pid)
            return;
    }
}

/* Emit an alert and clear the state flags that fired */
static void fire(pid_state_t *s, const char *chain, const char *detail,
                 const event_t *ev)
{
    fprintf(stderr,
        "[SEQDETECT] pid=%-6d comm=%-16s chain=%s %s\n",
        ev->pid, ev->comm, chain, detail);
    syslog(LOG_CRIT,
        "SEQDETECT pid=%d comm=%s chain=%s %s",
        ev->pid, ev->comm, chain, detail);
    s->state = 0;
}

/* Ptrace request numbers that indicate process memory writing */
static int is_ptrace_write(int req)
{
    /* PTRACE_POKETEXT=4, PTRACE_POKEDATA=5, PTRACE_SETREGS=13,
     * PTRACE_SETFPREGS=15, PTRACE_SETVFPREGS=27 */
    return req == 4 || req == 5 || req == 13 || req == 15 || req == 27;
}

static const char *shell_binaries[] = {
    "/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "/bin/ksh",
    "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/zsh",
    NULL
};

static int is_shell(const char *filename)
{
    if (!filename || !filename[0])
        return 0;
    for (int i = 0; shell_binaries[i]; i++)
        if (strcmp(filename, shell_binaries[i]) == 0)
            return 1;
    return 0;
}

int seqdetect_check(const event_t *ev)
{
    time_t now = time(NULL);
    pid_state_t *s = find_state(ev->pid);
    int fired = 0;

    /* Expire stale partial chains */
    if (s->state && now - s->ts > SEQDETECT_WINDOW_SECS)
        s->state = 0;

    switch (ev->type) {

    case EVENT_MEMEXEC:
        s->state |= STATE_MEMEXEC;
        s->ts = now;
        strncpy(s->comm, ev->comm, sizeof(s->comm) - 1);
        break;

    case EVENT_PTRACE:
        if (is_ptrace_write(ev->ptrace_req)) {
            s->state       |= STATE_PTRACE_WR;
            s->ts           = now;
            s->ptrace_target = ev->target_pid;
            strncpy(s->comm, ev->comm, sizeof(s->comm) - 1);
        }
        break;

    case EVENT_PRIVESC:
        if (ev->uid_after == 0) {
            s->state |= STATE_PRIVESC;
            s->ts     = now;
            strncpy(s->comm, ev->comm, sizeof(s->comm) - 1);
        }
        break;

    case EVENT_NS_ESCAPE:
        s->state |= STATE_NS_ESCAPE;
        s->ts     = now;
        strncpy(s->comm, ev->comm, sizeof(s->comm) - 1);
        break;

    case EVENT_EXEC:
        /* Chain 1: shellcode injection */
        if (s->state & STATE_MEMEXEC) {
            fire(s, "SHELLCODE_INJECT",
                 "anon-mmap(PROT_EXEC) followed by execve", ev);
            fired = 1;
        }
        /* Chain 2: ptrace write → exec — check attacker's state */
        if (!fired && s->state & STATE_PTRACE_WR) {
            fire(s, "PTRACE_INJECT",
                 "ptrace write followed by exec in injecting process", ev);
            fired = 1;
        }
        /* Chain 3: privesc → shell */
        if (!fired && (s->state & STATE_PRIVESC) && is_shell(ev->filename)) {
            fire(s, "PRIVESC_SHELL",
                 "privilege escalation followed by shell execution", ev);
            fired = 1;
        }
        /* Chain 4: namespace escape → exec */
        if (!fired && s->state & STATE_NS_ESCAPE) {
            fire(s, "NS_ESCAPE_EXEC",
                 "namespace escape followed by exec", ev);
            fired = 1;
        }
        break;

    case EVENT_EXIT:
        seqdetect_remove(ev->pid);
        break;

    default:
        break;
    }

    /* Also check if ptrace target (chain 2) is now executing */
    if (!fired && ev->type == EVENT_EXEC && s->ptrace_target == 0) {
        /* Look up the target PID's state to see if it was written into */
        pid_state_t *target_s = find_state(ev->pid);
        (void)target_s; /* already handled above via ev->pid lookup */
    }

    return fired;
}
