#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include "container.h"

#define DOCKER_SOCK       "/var/run/docker.sock"
#define CACHE_SIZE        128
#define CACHE_TTL_SECS    60
/* A container ID is exactly 64 hex characters */
#define CONTAINER_ID_LEN  64

/* --------------------------------------------------------------------------
 * LRU cache
 * -------------------------------------------------------------------------- */

typedef struct {
    char              key[65];   /* container ID (lookup key) */
    container_info_t  info;
    time_t            expires;
    int               valid;
    unsigned long     lru_clock; /* monotonically increasing; highest = MRU */
} cache_entry_t;

static cache_entry_t  g_cache[CACHE_SIZE];
static unsigned long  g_lru_counter = 0;
static int            g_docker_available = 0;

/* --------------------------------------------------------------------------
 * Utility: extract a container ID from a cgroup leaf name.
 *
 * Recognised patterns (examples):
 *   docker-<64hex>.scope
 *   cri-containerd-<64hex>.scope
 *   <64hex>                        (plain ID)
 *   <64hex>.scope
 * -------------------------------------------------------------------------- */

static int extract_container_id(const char *cgroup_leaf, char *id_out)
{
    if (!cgroup_leaf || !cgroup_leaf[0])
        return 0;

    /* Try to find a 64-char hex run anywhere in the string */
    const char *p = cgroup_leaf;
    while (*p) {
        /* Find start of a hex run */
        if ((*p >= '0' && *p <= '9') ||
            (*p >= 'a' && *p <= 'f') ||
            (*p >= 'A' && *p <= 'F')) {
            const char *start = p;
            size_t len = 0;
            while ((*p >= '0' && *p <= '9') ||
                   (*p >= 'a' && *p <= 'f') ||
                   (*p >= 'A' && *p <= 'F')) {
                p++;
                len++;
            }
            if (len == CONTAINER_ID_LEN) {
                strncpy(id_out, start, CONTAINER_ID_LEN);
                id_out[CONTAINER_ID_LEN] = '\0';
                return 1;
            }
        } else {
            p++;
        }
    }
    return 0;
}

/* --------------------------------------------------------------------------
 * Minimal JSON value extraction via strstr.
 *
 * Extracts the value of a JSON string field named key from json_buf.
 * Writes up to out_size-1 bytes into out.  Returns 1 on success, 0 if
 * the field was not found.
 *
 * Handles only simple string values (no embedded escapes that span quotes).
 * -------------------------------------------------------------------------- */

static int json_extract_string(const char *json_buf,
                               const char *key,
                               char *out,
                               size_t out_size)
{
    /* Build search pattern: "key": " */
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);

    const char *pos = strstr(json_buf, pattern);
    if (!pos)
        return 0;

    pos += strlen(pattern);

    /* Skip whitespace and ':' */
    while (*pos == ' ' || *pos == '\t' || *pos == ':' || *pos == ' ')
        pos++;

    if (*pos != '"')
        return 0;
    pos++; /* skip opening quote */

    size_t i = 0;
    while (*pos && *pos != '"' && i < out_size - 1) {
        if (*pos == '\\') {
            pos++; /* skip escape char */
            if (*pos == '\0')
                break;
        }
        out[i++] = *pos++;
    }
    out[i] = '\0';
    return (i > 0) ? 1 : 0;
}

/*
 * Navigate into a JSON object field.  Given a buffer and an object key
 * whose value is itself an object, returns a pointer to the opening '{'
 * of the nested object, or NULL if not found.
 */
static const char *json_find_object(const char *json_buf, const char *key)
{
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);

    const char *pos = strstr(json_buf, pattern);
    if (!pos)
        return NULL;
    pos += strlen(pattern);

    while (*pos == ' ' || *pos == '\t' || *pos == ':' || *pos == ' ')
        pos++;

    if (*pos != '{')
        return NULL;
    return pos;
}

/* --------------------------------------------------------------------------
 * Docker Unix-socket HTTP query
 * -------------------------------------------------------------------------- */

/*
 * Open a Unix-domain socket connection to DOCKER_SOCK.
 * Returns a connected fd on success, -1 on failure.
 */
static int docker_connect(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, DOCKER_SOCK, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/*
 * Query GET /containers/{id}/json over the Docker Unix socket.
 * Writes the HTTP response body into buf (up to buf_size-1 bytes).
 * Returns the number of bytes written, or -1 on error.
 */
static ssize_t docker_get_container(const char *id, char *buf, size_t buf_size)
{
    int fd = docker_connect();
    if (fd < 0)
        return -1;

    /* Send HTTP/1.0 request */
    char req[256];
    int req_len = snprintf(req, sizeof(req),
        "GET /containers/%s/json HTTP/1.0\r\nHost: localhost\r\n\r\n", id);

    if (req_len <= 0 || (size_t)req_len >= sizeof(req)) {
        close(fd);
        return -1;
    }

    ssize_t sent = 0;
    while (sent < req_len) {
        ssize_t n = write(fd, req + sent, (size_t)(req_len - sent));
        if (n <= 0) {
            close(fd);
            return -1;
        }
        sent += n;
    }

    /* Read full response */
    size_t total = 0;
    while (total < buf_size - 1) {
        ssize_t n = read(fd, buf + total, buf_size - 1 - total);
        if (n <= 0)
            break;
        total += (size_t)n;
    }
    buf[total] = '\0';
    close(fd);

    /* Skip HTTP headers: find the blank line separating headers from body */
    const char *body = strstr(buf, "\r\n\r\n");
    if (!body)
        body = strstr(buf, "\n\n");
    if (!body)
        return (ssize_t)total;  /* return whatever we got */

    body += 4; /* skip \r\n\r\n (or advance 2 more for \n\n) */
    if (body > buf + total)
        return 0;

    /* Shift body to start of buf */
    size_t body_len = (size_t)((buf + total) - body);
    memmove(buf, body, body_len);
    buf[body_len] = '\0';
    return (ssize_t)body_len;
}

/* --------------------------------------------------------------------------
 * Cache helpers
 * -------------------------------------------------------------------------- */

static cache_entry_t *cache_lookup(const char *id)
{
    time_t now = time(NULL);
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (!g_cache[i].valid)
            continue;
        if (strcmp(g_cache[i].key, id) != 0)
            continue;
        if (now > g_cache[i].expires) {
            g_cache[i].valid = 0;
            return NULL;
        }
        g_cache[i].lru_clock = ++g_lru_counter;
        return &g_cache[i];
    }
    return NULL;
}

/* Find a slot to evict (either empty or the LRU expired/valid entry) */
static cache_entry_t *cache_evict_slot(void)
{
    /* Prefer an empty slot */
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (!g_cache[i].valid)
            return &g_cache[i];
    }

    /* Prefer an expired entry */
    time_t now = time(NULL);
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (now > g_cache[i].expires)
            return &g_cache[i];
    }

    /* Evict the LRU entry */
    cache_entry_t *lru = &g_cache[0];
    for (int i = 1; i < CACHE_SIZE; i++) {
        if (g_cache[i].lru_clock < lru->lru_clock)
            lru = &g_cache[i];
    }
    return lru;
}

static void cache_insert(const char *id, const container_info_t *info)
{
    cache_entry_t *slot = cache_evict_slot();
    strncpy(slot->key, id, 64);
    slot->key[64] = '\0';
    slot->info      = *info;
    slot->expires   = time(NULL) + CACHE_TTL_SECS;
    slot->lru_clock = ++g_lru_counter;
    slot->valid     = 1;
}

/* --------------------------------------------------------------------------
 * JSON → container_info_t
 * -------------------------------------------------------------------------- */

static void parse_container_json(const char *json, const char *id,
                                 container_info_t *out)
{
    memset(out, 0, sizeof(*out));
    strncpy(out->container_id, id, 64);
    out->container_id[64] = '\0';

    /* "Name": "/nginx-proxy"  → strip leading '/' */
    char tmp[256] = {0};
    if (json_extract_string(json, "Name", tmp, sizeof(tmp))) {
        const char *nm = (tmp[0] == '/') ? tmp + 1 : tmp;
        strncpy(out->container_name, nm, sizeof(out->container_name) - 1);
    }

    /* Config.Image */
    const char *config = json_find_object(json, "Config");
    if (config) {
        if (json_extract_string(config, "Image", tmp, sizeof(tmp)))
            strncpy(out->image_name, tmp, sizeof(out->image_name) - 1);

        /* Config.Labels → Kubernetes annotations */
        const char *labels = json_find_object(config, "Labels");
        if (labels) {
            if (json_extract_string(labels, "io.kubernetes.pod.name",
                                    tmp, sizeof(tmp)))
                strncpy(out->pod_name, tmp, sizeof(out->pod_name) - 1);

            if (json_extract_string(labels, "io.kubernetes.pod.namespace",
                                    tmp, sizeof(tmp)))
                strncpy(out->k8s_namespace, tmp,
                        sizeof(out->k8s_namespace) - 1);
        }
    }
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

void container_init(void)
{
    memset(g_cache, 0, sizeof(g_cache));
    g_lru_counter = 0;

    /* Probe the Docker socket */
    int fd = docker_connect();
    if (fd >= 0) {
        close(fd);
        g_docker_available = 1;
    } else {
        g_docker_available = 0;
    }
}

int container_available(void)
{
    return g_docker_available;
}

int container_lookup(const char *cgroup_leaf, container_info_t *out)
{
    if (!cgroup_leaf || !out)
        return 0;
    if (!g_docker_available)
        return 0;

    char id[65];
    if (!extract_container_id(cgroup_leaf, id))
        return 0;

    /* Check cache first */
    cache_entry_t *cached = cache_lookup(id);
    if (cached) {
        *out = cached->info;
        return 1;
    }

    /* Query Docker */
    char *resp = (char *)malloc(128 * 1024);
    if (!resp)
        return 0;

    ssize_t n = docker_get_container(id, resp, 128 * 1024);
    if (n <= 0) {
        free(resp);
        return 0;
    }

    /* A 404 means the container is not known to Docker */
    if (strstr(resp, "\"message\"") && strstr(resp, "No such container")) {
        free(resp);
        return 0;
    }

    container_info_t info;
    parse_container_json(resp, id, &info);
    free(resp);

    /* Only cache and return if we got a meaningful result */
    if (info.container_id[0] == '\0')
        return 0;

    cache_insert(id, &info);
    *out = info;
    return 1;
}
