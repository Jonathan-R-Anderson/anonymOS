# =============================================================================
# registry.local/maniwani-updater — the 13th image. Build context: ./k8s/updater
# =============================================================================
#   docker build -t registry.local/maniwani-updater:latest ./k8s/updater
#   docker save   registry.local/maniwani-updater:latest | sudo k3s ctr images import -
#
# Built and imported exactly like the other twelve (bootstrap README §7). There
# is no registry; `imagePullPolicy: IfNotPresent` + a locally imported image is
# how every workload in this cluster gets its bits.
#
# >>> THE UPDATER NEVER REBUILDS THIS IMAGE. <<<
# update.sh has no rule that maps k8s/updater/** to a build, the Role has no
# verbs on cronjobs, and a commit touching this directory is logged as a NOTICE
# and skipped. An updater that ships a broken version of ITSELF is unrecoverable
# without the SSH login this whole feature exists to remove. Rebuilding it is a
# deliberate two-command human act, and that is the point.
#
# It is also the only image in the stack that legitimately keeps a floating
# :latest tag, because it is never part of a render (update.sh only renders
# k8s/{app,aggregators,media,data,bootstrap}).
# =============================================================================

# docker:28-cli gives the docker CLI ONLY — no daemon, no containerd, no
# ~700 MB of engine. The build itself happens in the HOST's daemon over the
# mounted socket; this image just needs something that can speak to it.
# Alpine 3.22 based, which is what makes postgresql17-client available.
FROM docker:28-cli

# bash              update.sh uses arrays, `local`, process substitution
# git + openssh     the clone. openssh-client provides ssh for GIT_SSH_COMMAND.
# curl              the two post-deploy smoke tests
# jq                status.json, applied.jsonl, the image keep-set
# yq                multi-document YAML splitting. update.sh applies ONE
#                   DOCUMENT AT A TIME so it can skip kinds the Role cannot
#                   write; `awk '/^---/'` splitting would break on any block
#                   scalar containing a --- line (nginx.conf lives in a
#                   ConfigMap, so this is not hypothetical).
# sqlite            `sqlite3 .backup` snapshots of the aggregator databases.
#                   A plain `cp` of a live SQLite file TEARS.
# coreutils         busybox's du has no -b, and stat/head/tac differ enough to
#                   matter. update.sh relies on `du -sb`, `stat -c %s`,
#                   `head -c`, `tac`.
# musl-utils        provides getent, used to resolve the nginx Service ClusterIP
#                   for the edge smoke test's --resolve
# postgresql17-client
#                   pg_dump + psql for the pre-migration restore point.
#                   >>> THE MAJOR MUST BE >= THE SERVER MAJOR. <<<
#                   data/10-postgres.yaml runs postgres:17. A 16 client refuses
#                   with "server version 17, pg_dump version 16", which surfaces
#                   as "refusing to migrate without a restore point" — correct
#                   behaviour, obscure root cause. Bump this when you bump the
#                   server.
# kubectl           FALLBACK ONLY; see the shim below.
RUN apk add --no-cache \
        bash \
        git \
        # update.sh shells out to python3 in six places (publish_status, the
        # migrate/rollback Job renderers) and preflight() lists it as REQUIRED —
        # it was simply never installed, so every run died in init at the first
        # publish_status() with "python3: command not found".
        python3 \
        # flock, likewise in preflight()'s required list; coreutils does not
        # provide it, util-linux does.
        util-linux \
        openssh-client \
        curl \
        jq \
        yq \
        sqlite \
        coreutils \
        musl-utils \
        tzdata \
        postgresql17-client \
        kubectl

# -----------------------------------------------------------------------------
# kubectl SHIM — prefer the HOST's own k3s binary.
# -----------------------------------------------------------------------------
# The k3s binary bundles kubectl, and the CronJob already bind-mounts it at
# /host/k3s (read-only) for the containerd image import. Using it for kubectl too
# means the client is BY CONSTRUCTION the exact same version as the API server —
# no skew to reason about when k3s is upgraded, and no apk package to keep in
# step with a cluster it knows nothing about.
#
# The apk kubectl above is the fallback for the case where the hostPath is
# missing or the k3s layout changes. /usr/local/bin precedes /usr/bin in PATH,
# so this shim wins whenever /host/k3s is present.
#
# CAVEAT (this comment used to claim the opposite, and it was wrong):
# `k3s kubectl` does NOT fall through to in-cluster discovery. With no
# kubeconfig it targets http://localhost:8080 and every call fails with
# "connection refused". Only the distro kubectl honours KUBERNETES_SERVICE_HOST
# + the projected ServiceAccount token. update.sh therefore switches KUBECTL to
# /usr/bin/kubectl explicitly on the in-cluster path (see preflight); this shim
# is for the kubeconfig case, where matching the server version is worth it.
# `k3s` ITSELF must also be on PATH, not just the kubectl shim: update.sh's
# preflight requires it ("missing k3s (needed for 'k3s ctr images import')")
# because importing a freshly built image into containerd is `k3s ctr images
# import`, and there is no registry in this cluster. Without this shim every run
# died in preflight even though the binary was mounted at /host/k3s all along.
RUN printf '%s\n' \
      '#!/bin/sh' \
      'if [ ! -x /host/k3s ]; then' \
      '  echo "k3s shim: /host/k3s is not mounted or not executable" >&2' \
      '  exit 127' \
      'fi' \
      'exec /host/k3s "$@"' \
    > /usr/local/bin/k3s \
 && chmod 0755 /usr/local/bin/k3s

RUN printf '%s\n' \
      '#!/bin/sh' \
      '# prefer the host k3s binary (exact server version); fall back to apk kubectl' \
      'if [ -x /host/k3s ]; then exec /host/k3s kubectl "$@"; fi' \
      'exec /usr/bin/kubectl "$@"' \
    > /usr/local/bin/kubectl \
 && chmod 0755 /usr/local/bin/kubectl

# The script itself is NOT baked in. It arrives from ConfigMap
# maniwani-updater-script at /etc/updater/update.sh, so a bug in the updater is
# fixed with `kubectl apply -f` from anywhere instead of a rebuild on the node.
# See the header of 30-configmap-updater.yaml.
WORKDIR /state
ENTRYPOINT ["/bin/bash"]
CMD ["/etc/updater/update.sh"]

# VERIFY THE BUILD BEFORE IMPORTING IT (the pg_dump major is the one that bites):
#   docker run --rm registry.local/maniwani-updater:latest -lc \
#     'pg_dump --version; yq --version; jq --version; git --version; sqlite3 --version; docker --version'
