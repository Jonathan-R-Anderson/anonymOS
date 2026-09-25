/*
 * syscallanom.c — Syscall frequency anomaly detection.
 *
 * Reads the BPF hash map "syscall_counts" (keyed by {comm[16], syscall_nr})
 * and computes a chi-squared statistic against a rolling 5-sample history
 * per comm name.  Emits an alert when the statistic exceeds the threshold.
 *
 * Map may be absent on older kernels — bpf_map__fd() < 0 is tolerated.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "syscallanom.h"
#include "argus.h"

/*
 * Pull in the generated skeleton solely for the struct definition so that
 * the compiler knows that struct argus_bpf contains a .obj field.
 * The header guard prevents duplicate inclusion.
 */
#include "bpf/argus.skel.h"

/* ── compile-time knobs ──────────────────────────────────────────────────── */

#define SA_MAX_COMMS        256     /* distinct comm names tracked              */
#define SA_HISTORY_LEN      5       /* samples kept for baseline                */
#define SA_MAX_SYSCALLS     512     /* syscall numbers we track per sample      */
#define SA_CHI2_THRESHOLD   50.0    /* alert when chi-squared exceeds this      */

/* ── BPF map key ─────────────────────────────────────────────────────────── */

struct syscall_key {
    char     comm[16];
    uint32_t nr;
};

/* ── per-comm history ────────────────────────────────────────────────────── */

/*
 * A "sample" is a sparse vector of (syscall_nr, count) pairs captured from
 * the BPF map at one point in time.  We keep SA_HISTORY_LEN such snapshots
 * and use their element-wise mean as the expected distribution.
 */

typedef struct {
    uint32_t nr;
    uint64_t count;
} sc_entry_t;

typedef struct {
    sc_entry_t entries[SA_MAX_SYSCALLS];
    int        n;          /* number of populated entries    */
    uint64_t   total;      /* sum of all counts in sample    */
} sc_sample_t;

typedef struct {
    char       comm[16];
    sc_sample_t history[SA_HISTORY_LEN];
    int        history_count;   /* how many samples collected so far (<=5)  */
    int        history_next;    /* ring-buffer write index                  */
    time_t     last_used;       /* for LRU eviction                         */
} comm_state_t;

/* ── module state ────────────────────────────────────────────────────────── */

static comm_state_t  g_states[SA_MAX_COMMS];
static int           g_nstates      = 0;
static int           g_interval     = 30;       /* seconds between checks       */
static struct timespec g_last_check = {0, 0};

/* ── LRU helpers ─────────────────────────────────────────────────────────── */

static comm_state_t *find_state(const char *comm)
{
    for (int i = 0; i < g_nstates; i++)
        if (strncmp(g_states[i].comm, comm, 15) == 0)
            return &g_states[i];
    return NULL;
}

static comm_state_t *find_or_alloc_state(const char *comm)
{
    comm_state_t *s = find_state(comm);
    if (s) {
        s->last_used = time(NULL);
        return s;
    }

    if (g_nstates < SA_MAX_COMMS) {
        s = &g_states[g_nstates++];
    } else {
        /* Evict LRU */
        int lru = 0;
        for (int i = 1; i < g_nstates; i++)
            if (g_states[i].last_used < g_states[lru].last_used)
                lru = i;
        s = &g_states[lru];
    }

    memset(s, 0, sizeof(*s));
    strncpy(s->comm, comm, sizeof(s->comm) - 1);
    s->comm[sizeof(s->comm) - 1] = '\0';
    s->last_used = time(NULL);
    return s;
}

/* ── sample helpers ──────────────────────────────────────────────────────── */

/* Add or accumulate a (nr, count) pair into a sample. */
static void sample_add(sc_sample_t *smp, uint32_t nr, uint64_t count)
{
    for (int i = 0; i < smp->n; i++) {
        if (smp->entries[i].nr == nr) {
            smp->entries[i].count += count;
            smp->total += count;
            return;
        }
    }
    if (smp->n >= SA_MAX_SYSCALLS)
        return;
    smp->entries[smp->n].nr    = nr;
    smp->entries[smp->n].count = count;
    smp->n++;
    smp->total += count;
}

/* Look up count for syscall nr in a sample; returns 0 if absent. */
static uint64_t sample_get(const sc_sample_t *smp, uint32_t nr)
{
    for (int i = 0; i < smp->n; i++)
        if (smp->entries[i].nr == nr)
            return smp->entries[i].count;
    return 0;
}

/* Find the entry with the highest count; returns NULL if empty. */
static const sc_entry_t *sample_dominant(const sc_sample_t *smp)
{
    const sc_entry_t *best = NULL;
    for (int i = 0; i < smp->n; i++)
        if (!best || smp->entries[i].count > best->count)
            best = &smp->entries[i];
    return best;
}

/* ── chi-squared anomaly detector ───────────────────────────────────────── */

/*
 * Build the expected distribution by averaging the SA_HISTORY_LEN historical
 * samples.  Then compute the chi-squared statistic:
 *
 *   X2 = sum_i  (observed_i - expected_i)^2 / expected_i
 *
 * where observed and expected are normalised to the same total so that
 * volume changes alone do not trigger a false positive.
 *
 * Returns -1.0 if not enough history.
 */
static double compute_chi2(comm_state_t *cs, const sc_sample_t *current)
{
    if (cs->history_count < SA_HISTORY_LEN)
        return -1.0;
    if (current->total == 0)
        return -1.0;

    /*
     * Collect the union of syscall numbers across all history samples
     * plus the current sample.
     */
    uint32_t syscalls[SA_MAX_SYSCALLS];
    int      nsyscalls = 0;

    /* Helper: insert nr into syscalls[] if not already present */
    #define SC_UNION_ADD(nr_val) do {               \
        uint32_t _v = (nr_val);                     \
        int _found = 0;                             \
        for (int _k = 0; _k < nsyscalls; _k++)     \
            if (syscalls[_k] == _v) { _found=1; break; } \
        if (!_found && nsyscalls < SA_MAX_SYSCALLS) \
            syscalls[nsyscalls++] = _v;             \
    } while (0)

    for (int s = 0; s < SA_HISTORY_LEN; s++) {
        const sc_sample_t *h = &cs->history[s];
        for (int e = 0; e < h->n; e++)
            SC_UNION_ADD(h->entries[e].nr);
    }
    for (int e = 0; e < current->n; e++)
        SC_UNION_ADD(current->entries[e].nr);

    #undef SC_UNION_ADD

    /* Compute per-syscall mean expected count (as fraction of total). */
    double chi2  = 0.0;
    double obs_total = (double)current->total;

    for (int i = 0; i < nsyscalls; i++) {
        uint32_t nr = syscalls[i];

        /* Mean normalised count across history samples */
        double mean_frac = 0.0;
        for (int s = 0; s < SA_HISTORY_LEN; s++) {
            const sc_sample_t *h = &cs->history[s];
            if (h->total == 0)
                continue;
            mean_frac += (double)sample_get(h, nr) / (double)h->total;
        }
        mean_frac /= SA_HISTORY_LEN;

        double expected = mean_frac * obs_total;
        double observed = (double)sample_get(current, nr);

        if (expected < 1.0)
            expected = 1.0;   /* avoid division by zero / Yates correction     */

        double diff = observed - expected;
        chi2 += (diff * diff) / expected;
    }

    return chi2;
}

/* ── public API ──────────────────────────────────────────────────────────── */

void syscallanom_init(int check_interval_secs)
{
    memset(g_states, 0, sizeof(g_states));
    g_nstates = 0;
    g_interval = (check_interval_secs > 0) ? check_interval_secs : 30;
    g_last_check.tv_sec  = 0;
    g_last_check.tv_nsec = 0;
}

void syscallanom_check(struct argus_bpf *skel)
{
    /* Rate-limit: only proceed if at least g_interval seconds have elapsed. */
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    double elapsed = (double)(now.tv_sec  - g_last_check.tv_sec) +
                     (double)(now.tv_nsec - g_last_check.tv_nsec) * 1e-9;
    if (g_last_check.tv_sec != 0 && elapsed < (double)g_interval)
        return;

    g_last_check = now;

    /* Locate the syscall_counts map via the skeleton's bpf_object. */
    if (!skel || !skel->obj)
        return;

    struct bpf_map *map =
        bpf_object__find_map_by_name(skel->obj, "syscall_counts");
    if (!map)
        return;   /* map not compiled into this BPF object — skip silently */

    int map_fd = bpf_map__fd(map);
    if (map_fd < 0)
        return;   /* map not present on this kernel — skip silently */

    /*
     * Iterate over all map entries, accumulating per-comm samples.
     * We build a temporary scratch array of (comm, sample) pairs.
     */

    /* Scratch: one current sample per comm seen in this sweep */
    typedef struct { char comm[16]; sc_sample_t smp; } sweep_entry_t;
    sweep_entry_t *sweep = calloc(SA_MAX_COMMS, sizeof(sweep_entry_t));
    if (!sweep)
        return;
    int nsweep = 0;

    struct syscall_key key, next_key;
    memset(&key, 0, sizeof(key));

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        uint64_t count = 0;
        if (bpf_map_lookup_elem(map_fd, &next_key, &count) != 0) {
            key = next_key;
            continue;
        }

        /* Find or create a sweep entry for this comm. */
        sweep_entry_t *se = NULL;
        for (int i = 0; i < nsweep; i++) {
            if (strncmp(sweep[i].comm, next_key.comm, 15) == 0) {
                se = &sweep[i];
                break;
            }
        }
        if (!se) {
            if (nsweep >= SA_MAX_COMMS) {
                key = next_key;
                continue;
            }
            se = &sweep[nsweep++];
            memset(se, 0, sizeof(*se));
            strncpy(se->comm, next_key.comm, sizeof(se->comm) - 1);
        }

        sample_add(&se->smp, next_key.nr, count);
        key = next_key;
    }

    /*
     * For each comm seen in this sweep, run anomaly detection then push
     * the current sample into the rolling history.
     */
    for (int i = 0; i < nsweep; i++) {
        sweep_entry_t *se = &sweep[i];
        if (se->smp.total == 0)
            continue;

        comm_state_t *cs = find_or_alloc_state(se->comm);
        if (!cs)
            continue;

        double chi2 = compute_chi2(cs, &se->smp);
        if (chi2 >= SA_CHI2_THRESHOLD) {
            const sc_entry_t *dom = sample_dominant(&se->smp);
            /* Best-effort syscall name for the most common x86-64 numbers. */
            static const struct { uint32_t nr; const char *name; } sc_names[] = {
                {  0, "read"      }, {  1, "write"     }, {  2, "open"      },
                {  3, "close"     }, {  4, "stat"      }, {  5, "fstat"     },
                {  8, "lseek"     }, {  9, "mmap"      }, { 10, "mprotect"  },
                { 11, "munmap"    }, { 17, "pread64"   }, { 18, "pwrite64"  },
                { 21, "access"    }, { 39, "getpid"    }, { 41, "socket"    },
                { 42, "connect"   }, { 43, "accept"    }, { 44, "sendto"    },
                { 45, "recvfrom"  }, { 56, "clone"     }, { 57, "fork"      },
                { 59, "execve"    }, { 60, "exit"       }, { 61, "wait4"    },
                { 62, "kill"      }, { 63, "uname"      }, { 72, "fcntl"    },
                { 78, "getdents"  }, { 89, "readlink"  }, { 96, "gettimeofday" },
                { 97, "getrlimit" }, { 102, "getuid"   }, { 105, "setuid"   },
            };
            const char *sc_name = NULL;
            uint32_t dom_nr = dom ? dom->nr : 0u;
            for (int _k = 0;
                 _k < (int)(sizeof(sc_names)/sizeof(sc_names[0])); _k++) {
                if (sc_names[_k].nr == dom_nr) {
                    sc_name = sc_names[_k].name;
                    break;
                }
            }
            char sc_label[32];
            if (sc_name)
                snprintf(sc_label, sizeof(sc_label), "%s(%u)", sc_name, dom_nr);
            else
                snprintf(sc_label, sizeof(sc_label), "syscall(%u)", dom_nr);

            fprintf(stderr,
                    "[SYSCALL_ANOM] comm=%s dominant_syscall=%s"
                    " count=%llu deviation=%.1f\n",
                    cs->comm,
                    sc_label,
                    (unsigned long long)(dom ? dom->count : 0ULL),
                    chi2);
        }

        /* Push current sample into history ring buffer. */
        cs->history[cs->history_next] = se->smp;
        cs->history_next = (cs->history_next + 1) % SA_HISTORY_LEN;
        if (cs->history_count < SA_HISTORY_LEN)
            cs->history_count++;
    }

    free(sweep);
}

void syscallanom_purge(const char *comm)
{
    if (!comm)
        return;
    for (int i = 0; i < g_nstates; i++) {
        if (strncmp(g_states[i].comm, comm, 15) == 0) {
            /* Remove by swapping with the last entry. */
            g_states[i] = g_states[g_nstates - 1];
            memset(&g_states[g_nstates - 1], 0, sizeof(comm_state_t));
            g_nstates--;
            return;
        }
    }
}
