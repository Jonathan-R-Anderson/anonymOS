# ── Stage 1: builder ─────────────────────────────────────────────────────────
FROM ubuntu:22.04 AS builder

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc clang llvm make \
    libbpf-dev libelf-dev zlib1g-dev \
    libssl-dev libsqlite3-dev pkg-config \
    linux-tools-common linux-tools-generic \
    && rm -rf /var/lib/apt/lists/*

# Locate bpftool (versioned under linux-tools) and symlink to stable path.
RUN set -e; \
    KVER=$(ls /usr/lib/linux-tools/ 2>/dev/null | sort -V | tail -1); \
    BPFTOOL=/usr/lib/linux-tools/${KVER}/bpftool; \
    if [ -x "$BPFTOOL" ]; then ln -sf "$BPFTOOL" /usr/local/bin/bpftool; fi

WORKDIR /build
COPY . .

# Generate vmlinux.h from the host kernel BTF (must be run with --privileged
# and /sys bind-mounted, or BTF blob injected via COPY).
# If BTF is not available fall back to a pre-generated header if present.
RUN if [ -f /sys/kernel/btf/vmlinux ]; then \
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h; \
    elif [ ! -f src/bpf/vmlinux.h ]; then \
        echo "WARNING: /sys/kernel/btf/vmlinux not available; BPF skeleton will not build."; \
        echo "Run: docker build --privileged -v /sys:/sys ."; \
        touch src/bpf/vmlinux.h; \
    fi

# Build everything. Optional features are detected automatically.
RUN make argus argus-server

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM ubuntu:22.04 AS runtime

ARG DEBIAN_FRONTEND=noninteractive

# Minimal runtime dependencies only.
# libbpf0    — BPF skeleton loader
# libsqlite3 — event store (optional feature, linked at build time)
# libssl3    — TLS forwarding + TLS inspection (optional)
# iptables   — response isolation (--response-isolate)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libbpf0 \
    libsqlite3-0 \
    libssl3 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/argus        /usr/local/bin/argus
COPY --from=builder /build/argus-server /usr/local/bin/argus-server

# Create runtime directories
RUN mkdir -p /etc/argus /var/log/argus /var/lib/argus /run/argus

# Copy example config (rename to config.json to activate)
COPY packaging/argus.conf.example /etc/argus/argus.conf.example

EXPOSE 9000/tcp

# BPF requires CAP_SYS_ADMIN (+ CAP_BPF on kernel >= 5.8).
# Run with:
#   docker run --privileged --pid=host -v /sys:/sys \
#              -v /var/log/argus:/var/log/argus \
#              argus:latest
ENTRYPOINT ["/usr/local/bin/argus"]
CMD ["--json", "--output", "/var/log/argus/events.jsonl"]
