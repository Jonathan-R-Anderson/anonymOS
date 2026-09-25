#ifndef __CONTAINER_H
#define __CONTAINER_H

/*
 * Docker / containerd / Kubernetes enrichment.
 *
 * Resolves a cgroup leaf name (as found in event_t.cgroup) to a full
 * container description by querying the Docker Unix socket.  Results are
 * cached in an LRU table with a 60-second TTL.
 */

typedef struct {
    char container_id[65];    /* full 64-char container ID, or empty string  */
    char container_name[128]; /* human-readable name, e.g. "nginx-proxy"     */
    char image_name[256];     /* image reference, e.g. "nginx:1.25-alpine"   */
    char pod_name[128];       /* Kubernetes pod name, or empty string        */
    char k8s_namespace[128];  /* Kubernetes namespace, or empty string       */
} container_info_t;

/*
 * Initialise the module.  Attempts to connect to /var/run/docker.sock.
 * Silently succeeds even when the socket is not present.
 */
void container_init(void);

/*
 * Resolve a cgroup leaf name to container metadata.
 * Fills *out on success.
 * Returns 1 if the container was found, 0 otherwise.
 * Results are cached for 60 seconds.
 */
int  container_lookup(const char *cgroup_leaf, container_info_t *out);

/* Returns 1 if the Docker socket is accessible, 0 otherwise. */
int  container_available(void);

#endif /* __CONTAINER_H */
