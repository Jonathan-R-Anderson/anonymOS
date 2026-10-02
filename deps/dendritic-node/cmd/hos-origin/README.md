# hos-origin

The anonymOS origin server (`roadmap/ORIGIN_SERVER_ROADMAP.md`): coordinator of the dendritic
network, release channel for OS and software updates, and crash-report intake -- one static Go
binary on a single VPS, built from the dendritic node's module so it shares AXON's code, reachable only through the dendritic network.

It holds **no release-signing key**: releases are signed by the owner's wallet on another machine
and verified by every client, so taking this server over can stop updates but not ship one.

```sh
go build -trimpath -o hos-origin .          # static (CGO_ENABLED=0) for the VPS
./hos-origin keygen -out coordinator.key    # once; prints the public key the OS image pins
./hos-origin serve -data /var/lib/hos-origin -key coordinator.key -listen 127.0.0.1:8470
go test ./...
```

| Endpoint | |
|---|---|
| `GET /.well-known/rabbiit/storage-node.json` | signed bootstrap document (live peers + seeds), byte-compatible with the node's verifier |
| `POST /api/v1/storage/nodes/heartbeat` | a node's signed beacon (peer-ID key, clock skew, replay checked), answered with live peers |
| `GET /api/v1/network/peers` | the active nodes |
| `GET /api/v1/releases/{channel}` | the current wallet-signed release manifest for a channel |
| `POST /api/v1/crash` | a scrubbed crash report; any field outside the schema is refused |
| `GET /api/v1/crash/groups` | operator view (refused when the request came through the network) |
| `GET /api/v1/swarm` | the files this origin seeds, as `axon-swarm:` locators |
| `POST /api/v1/swarm/{root}/announce` | a computer joins (or renews its place in) a file's swarm |
| `GET /api/v1/swarm/{root}/peers` | other computers in that swarm, the origin first when it seeds the file |

**The release swarm.** Put a release file in `<data>/artifacts/` and restart: the origin hashes it
into a Merkle tree, logs its `axon-swarm:` locator (the value the release manifest lists), and
super-seeds it. Computers fetching it find each other through the tracker endpoints above and trade
pieces among themselves, every piece checked against the root, so the origin's upload is the
smallest part of a release reaching everyone (`internal/axon/swarm`; numbers in the roadmap §4a).

Status: the coordinator speaks the node's current formats, which still carry I2P (`/garlic32`)
addresses; those become AXON service addresses as the node moves onto AXON (roadmap P1b).
