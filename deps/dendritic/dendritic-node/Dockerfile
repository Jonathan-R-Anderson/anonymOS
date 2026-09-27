# =============================================================================
# registry.local/syndichan-node — the storage node, run ON THE SERVER.
# =============================================================================
#   docker build -t registry.local/syndichan-node:latest ./storage-client
#   docker save   registry.local/syndichan-node:latest | sudo k3s ctr -n k8s.io images import -
#
# The same binary volunteers run, deployed as a cluster workload. It does two
# jobs the network currently has nobody to do:
#
#   1. THE STABLE BOOTSTRAP PEER. The well-known document currently publishes
#      "peers": [], so no volunteer can discover another. This node has a
#      persistent I2P destination and is always up, so it is the anchor every
#      other node dials first.
#
#   2. THE S3 GATEWAY the backend offloads to (DHT_S3_ENDPOINT). Objects written
#      here are encrypted, erasure-coded and pushed out to volunteers.
#
# CGO_ENABLED=0 and a static build, so the runtime image needs no libc and the
# binary is the only moving part.
# =============================================================================
FROM golang:1.25-alpine AS build

WORKDIR /src
# Dependency layer first so source edits do not re-download the module graph.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# -trimpath keeps build paths out of the binary; the release script uses the
# same flags, so a cluster build and a volunteer build are byte-comparable.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
        -o /out/syndichan-node ./cmd/syndichan-node

# -----------------------------------------------------------------------------
FROM alpine:3.20

# ca-certificates: the presence heartbeat is a real HTTPS POST to syndichan.org
# and is the ONE deliberate exception to I2P-only networking. Without root certs
# it fails TLS verification while peer traffic looks perfectly healthy -- the
# exact split-brain the upstream troubleshooting section warns about.
RUN apk add --no-cache ca-certificates \
 && adduser -D -H -u 10001 syndichan

COPY --from=build /out/syndichan-node /usr/local/bin/syndichan-node

# Not root. The upstream README is explicit that the node must not run as root,
# and nothing here needs privilege: it binds loopback-ish ports above 1024 and
# writes only to its data directory.
USER 10001:10001

# Config and shards. Mounted as a PVC in k8s; -data-dir points at it.
ENV XDG_CONFIG_HOME=/data
VOLUME ["/data"]

EXPOSE 9000 9090

ENTRYPOINT ["/usr/local/bin/syndichan-node"]
