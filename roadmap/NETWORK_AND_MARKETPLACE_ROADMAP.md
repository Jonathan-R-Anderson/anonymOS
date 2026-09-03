# EpinAnonymOS Network Stack + I2P P2P Template Marketplace Roadmap

## Why these two are one roadmap

The Domain Manager's **DM12 marketplace** (`domain_manager.md` §8–17 — discover, download, and verify
Template Domains from peers over a decentralized I2P network) was deferred as out-of-scope because there is no
**functional** transport for an I2P SAM session, a Kademlia DHT, or a peer download.

⚠️ **Accurate starting state (verified, 2026-06-27):** EpinAnonymOS is *not* a clean slate — it already has
network-stack **modules** (`src/kernel/d/network/`: `tcp.d`, `ipv4.d`, `ipv6.d`, `udp.d`, `arp.d`,
`ethernet.d`, `icmp.d`, `dns.d`, `dhcp.d`, `https.d`, `stack.d`) and a **NIC driver** (`drivers/network/
network.d`: virtio-net `0x1AF4:0x1000` + an e1000 path, `sendEthFrame`/`receiveEthFrame`). **But they are not
wired up:** `networkStackInit` (`stack.d`) is *never called from `kernel_main`*; AF_INET sockets reject
(`sys_connect` returns `EAFNOSUPPORT` — only `AF_UNIX` is handled); and there is **no boot self-test** for the
stack (every other subsystem prints `[tag] selftest PASS`; the network stack does not). So the work is
**integration + driving the NIC + wiring AF_INET behind the existing socket syscalls + verifying end-to-end**,
NOT writing TCP from scratch — the modules' correctness is simply unproven until exercised. (The README's
"complete in-kernel network stack" line overstated this; it has been corrected to match reality.)

The marketplace is therefore not a separable feature — it is the *application* that rides on top of a network
stack that is **present but inert.** Building the two together keeps the layering honest: **Part A wires +
proves the stack, Part B is the payload.** Part A also independently unblocks the **DM8 network-policy runtime
gate** (`NetPolicy` in `identity.d` becomes enforceable at a real `connect()`), so the network stack pays for
itself before the marketplace exists.

## North star

A domain-isolated, capability-gated network stack — every socket is an Object, every outbound connection is
checked against the owning domain's `NetPolicy` (DM8) — carrying a censorship-resistant, server-less template
marketplace where signed Template Domains (DM12 `.hosdt` bundles, already exportable/verifiable offline) are
announced, discovered, and downloaded peer-to-peer over I2P, content-addressed and trust-policy-gated.

## What already exists to build on
- **Network-stack modules, present but inert** (`src/kernel/d/network/`): `ethernet.d`, `arp.d`, `ipv4.d`/
  `ipv6.d`, `icmp.d`, `udp.d`, `tcp.d`, `dns.d`, `dhcp.d`, `https.d`, `stack.d` (`networkStackInit`). They
  compile (in the `*.d` build glob) but are **un-initialized + unverified** — the integration work below is
  to *call* `networkStackInit`, feed it from the NIC, and prove each layer. Treat their internals as a
  starting draft to audit, not as known-good.
- **NIC driver** (`drivers/network/network.d`): virtio-net (`0x1AF4:0x1000`) + an e1000 path,
  `sendEthFrame`/`receiveEthFrame`, rx/tx descriptor rings. N0 below is "drive its rx in the poll loop +
  prove a frame round-trips," not "write a driver."
- **AF_UNIX socket layer** (`syscalls/posix.d`): `sys_socket`/`bind`/`listen`/`accept`/`connect`/`send`/
  `recv`, the `LocalSocket` table, fd integration, poll/epoll readiness — the BSD-socket *shape* is done;
  AF_INET just needs a protocol backend behind the same syscalls (today `sys_connect` returns `EAFNOSUPPORT`
  for it).
- **virtio transport** (from the GPU work, `core/*`): modern virtio PCI cap-walk + virtqueue driver
  (`virtio-gpu`). A **virtio-net** NIC reuses that virtqueue machinery (rx/tx rings instead of the gpu
  control queue) — the hardest part (modern virtio) is already solved.
- **DM12 template bundles** (`core/template_bundle.d`): export/import, **HMAC sign/verify** (`crypto.d`),
  the local registry, publisher trust, Generations + rollback — the marketplace's *local* half is DONE; this
  roadmap adds only the *transport + discovery*.
- **crypto.d**: HMAC-SHA256 (bundle + announcement signing), X25519/HKDF/ChaCha20-Poly1305 (secure IPC) —
  reusable for peer-session crypto and per-publisher keys.
- **Identity `NetPolicy`** (`identity.d`: None/NAT/VPN/Tor/LocalOnly/Disposable) + per-domain device/fs gates
  (DM8/DM10.7) — the policy vocabulary for gating network egress per domain already exists, unenforced.

---

## Dependency graph + first cut

```
N0 virtio-net → N1 eth/arp → N2 ip/icmp(ping!) → N3 udp → N4 tcp → N5 AF_INET
                                                                   ├→ N6 dns/dhcp
                                                                   └→ N7 DM8 net gate (payoff)
N4 tcp → M0 SAM bridge → M1 objects → M2 DHT → M3 announce → M4 download → M5 trust/quarantine → M6/M7/M8
```

**First cut:** **N0 → N2 (host `ping <guest>` works)** is the proof the box is on the network and the single
most motivating milestone. **N4 → N5 → N7** delivers real, domain-gated TCP for musl apps (and makes the DM8
net policy enforceable). Only then does **M0 → M4** become reachable — the marketplace is the long tail.

## Honest risks
- **TCP (N4) is the hard part** — a correct state machine + retransmit + windowing is a real subsystem; keep
  it minimal, lean on a reference (lwIP's design, not its code) and heavy in-VM testing under TCG + KVM.
- **I2P SAM (M0) needs an external I2P router** reachable from the guest — fine on QEMU user-net to the host's
  i2pd; the marketplace is genuinely a *networked, multi-node* feature, so testing needs ≥2 nodes.
- **Determinism:** the network introduces real async I/O + timers into a polled, cooperative kernel; this
  pairs naturally with **SMP** (`SMP_ROADMAP.md`) — a `net-lkl` / net stack on its own core (S4/S8) is the
  production shape. Until SMP lands, the polled rx path lives in the existing service loop.
- **Per-publisher PKI (M3)** is the real trust upgrade over DM12's single `crypto.d` key — design the key
  format + storage (`/objects/identities/publishers/`) before the DHT layer hardens.
