# Kubernetes object storage

`syndichan-node` is the primary S3-compatible object store and the stable DHT
bootstrap peer. Ceph is no longer part of the Kubernetes source of truth.

The node stores encrypted, erasure-coded shards in a local-path PVC and
distributes them to peers over I2P. A local-path claim is a normal directory,
not a preallocated disk image: filesystem usage grows when objects or remote
shards arrive and shrinks when unreferenced data is deleted. New stores start
with the 60 GiB logical ceiling from `-capacity-gib`; a later dashboard choice
is persisted and survives pod restarts.

## Prerequisites

Build and import the storage image:

```sh
docker build -t registry.local/syndichan-node:latest ./storage-client
docker save registry.local/syndichan-node:latest |
  sudo k3s ctr -n k8s.io images import -
```

Create a TLS certificate whose SAN list includes both service names:

```text
DNS:syndichan-node
DNS:syndichan-node.maniwani.svc.cluster.local
```

Store it as:

```sh
kubectl -n maniwani create secret tls syndichan-node-tls \
  --cert=syndichan-node.crt \
  --key=syndichan-node.key
```

`maniwani-env` must contain `S3_ACCESS_KEY` and an `S3_SECRET_KEY` of at least
32 characters. The backend and node consume the same keys; the node receives
them as projected files.

Apply the storage workload before the application tier:

```sh
kubectl apply -f k8s/storage/10-syndichan-node.yaml
kubectl -n maniwani rollout status statefulset/syndichan-node --timeout=10m
```

The pod uses `hostNetwork` for the I2P router, so the node process also binds
host port 9000. Before starting it, enforce a host firewall rule that permits
9000 only from the cluster pod CIDR, loopback, and the WireGuard management
network, and rejects it on the public interface. The Kubernetes NetworkPolicy is
defence in depth; host-network policy enforcement varies by CNI and must not be
the only boundary. SAM, the I2P HTTP proxy, and the dashboard remain loopback
only.

## Existing Ceph installation: lossless cutover

Do not delete the running Ceph StatefulSet or its PVCs yet.

1. Start `syndichan-node` alongside Ceph.
2. Apply and follow the one-shot copy-and-verify Job:

   ```sh
   kubectl apply -f k8s/storage/migration/ceph-to-syndichan-node.yaml
   kubectl -n maniwani logs -f job/ceph-to-syndichan-node
   kubectl -n maniwani wait --for=condition=complete \
     job/ceph-to-syndichan-node --timeout=24h
   ```

3. Restart the backend once. Its startup creates/verifies all four buckets,
   installs their public-read policies, and syncs static assets.
4. Apply the rewired ConfigMaps, backend, seedbox, nginx, and updater templates.
5. Test an upload, a public `/s3/` read, a seedbox fetch, and a storage-node
   restart followed by another `/s3/` read.
6. Stop Ceph without deleting it:

   ```sh
   kubectl -n maniwani scale statefulset/ceph --replicas=0
   ```

7. Run the same read/write tests again. Keep the retained Ceph PVCs through an
   agreed rollback window. Delete them only after backup and explicit approval.

The migration uses `copy`, never `sync` or `delete`, so source objects are not
removed. Re-running the Job is idempotent.

## Operations

Check logical and physical usage:

```sh
kubectl -n maniwani port-forward statefulset/syndichan-node 9090:9090
curl http://127.0.0.1:9090/api/status
kubectl -n maniwani exec syndichan-node-0 -c node -- du -sh /data/node
```

Change the working-set ceiling through the loopback dashboard using the port
forward. Reducing it below current use is refused; delete objects or rejected
shards first. Kubernetes cannot shrink a PVC request, but no resize is needed
for this directory-backed volume: deleting shard files immediately returns
space to the node filesystem.
