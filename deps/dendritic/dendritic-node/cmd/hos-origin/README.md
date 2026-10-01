# hos-origin

The anonymOS origin server (`roadmap/ORIGIN_SERVER_ROADMAP.md`): coordinator of the dendritic
network, release channel for OS and software updates, and crash-report intake -- one static Go
binary (standard library only) on a single VPS, reachable only through the dendritic network.

It holds **no release-signing key**: releases are signed by the owner's wallet on another machine
and verified by every client, so taking this server over can stop updates but not ship one.

```sh
go build -trimpath -o hos-origin .          # static (CGO_ENABLED=0) for the VPS
./hos-origin keygen -out coordinator.key    # once; prints the public key the OS image pins
./hos-origin serve -data /var/lib/hos-origin -key coordinator.key -listen 127.0.0.1:8470 \
                   -seed /garlic32/<origin-node>/p2p/<peer-id>
go test ./...
```

| Endpoint | |
|---|---|
| `GET /.well-known/syndichan/storage-node.json` | signed bootstrap document (live peers + seeds), byte-compatible with the node's verifier |
| `POST /api/v1/storage/nodes/heartbeat` | a node's signed beacon (peer-ID key, clock skew, replay checked), answered with live peers |
| `GET /api/v1/network/peers` | the active nodes |
| `GET /api/v1/releases/{channel}` | the current wallet-signed release manifest for a channel |
| `POST /api/v1/crash` | a scrubbed crash report; any field outside the schema is refused |
| `GET /api/v1/crash/groups` | operator view (refused when the request came through the network) |

Status: the coordinator speaks the node's current formats, which still carry I2P (`/garlic32`)
addresses; those become AXON service addresses as the node moves onto AXON (roadmap P1b).
