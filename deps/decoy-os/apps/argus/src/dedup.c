#include <stdint.h>
#include <string.h>
#include <time.h>
#include "dedup.h"

#define DEDUP_SLOTS 512

typedef struct {
    char     key[128];
    time_t   first_seen;
    uint32_t count;
} dedup_entry_t;

static dedup_entry_t g_table[DEDUP_SLOTS];
static int           g_window   = 0;    /* seconds; 0 = disabled */
static long          g_suppressed = 0;

void dedup_init(int window_secs)
{
    g_window = window_secs;
    g_suppressed = 0;
    memset(g_table, 0, sizeof(g_table));
}

/* djb2 hash, slot in [0, DEDUP_SLOTS) */
static unsigned int hash_key(const char *key)
{
    unsigned long h = 5381;
    int c;
    while ((c = (unsigned char)*key++))
        h = ((h << 5) + h) + (unsigned long)c;
    return (unsigned int)(h % DEDUP_SLOTS);
}

int dedup_check(const char *key)
{
    if (!key || !key[0] || g_window <= 0)
        return 0;

    time_t now = time(NULL);
    unsigned int slot = hash_key(key);

    /* Linear probe to handle collisions */
    for (int i = 0; i < DEDUP_SLOTS; i++) {
        unsigned int idx = (slot + (unsigned int)i) % DEDUP_SLOTS;
        dedup_entry_t *e = &g_table[idx];

        if (!e->key[0]) {
            /* Empty slot — record and allow */
            strncpy(e->key, key, sizeof(e->key) - 1);
            e->first_seen = now;
            e->count      = 1;
            return 0;
        }

        if (strncmp(e->key, key, sizeof(e->key) - 1) == 0) {
            if (now - e->first_seen <= (time_t)g_window) {
                /* Within window — suppress */
                e->count++;
                g_suppressed++;
                return 1;
            }
            /* Window expired — reset and allow */
            e->first_seen = now;
            e->count      = 1;
            return 0;
        }
    }

    /* Table full — allow through (fail open) */
    return 0;
}

long dedup_suppressed(void) { return g_suppressed; }
