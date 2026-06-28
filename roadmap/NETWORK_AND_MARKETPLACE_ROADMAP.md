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

## Status (2026-06-27): N0 + N1 DONE + verified — the box is on the network (rx/tx + ARP)

- **N0 (NIC driver) ✅** — the **e1000** path (`drivers/network/network.d`) is brought up and proven. It was a
  half-finished draft: `e1000Receive`, `readE1000Mac`, and `enablePCIBusMastering` were all **commented out**,
  and MMIO used a hardcoded `KERNEL_BASE` with the raw BAR phys as a pointer. Fixed: map the BAR through the
  runtime **HHDM** (`+ hhdm_offset`, matching the AHCI MMIO path), enable bus-master + memory-space in the PCI
  command register (DMA), and restore the MAC read (RAL/RAH) + the rx descriptor poll. **Verified:** init clean,
  `MAC=52:54:00:12:34:56`, tx works (the ARP request is on the wire), rx works (1 frame delivered).
- **N1 (Ethernet + ARP) ✅** — frame demux by ethertype + the ARP request/reply path resolve the gateway MAC.
  ★ ROOT-CAUSE BUG: the wire structs were **not packed** — `IPv4Address` has alignment 4 (its `union { ubyte[4];
  uint addr; }`), so it took 2 bytes of padding inside `ARPPacket`, scrambling every field on the wire (the
  request went out as `who-has 0.0.0.0 tell 0.0.10.0`). Fix = `align(1):` on `ARPPacket` (the same fix the
  IPv4/ICMP/UDP/TCP headers will need). **Verified `NET=1`:** `who-has 10.0.2.2 tell 10.0.2.15` → slirp `Reply
  10.0.2.2 is-at 52:55:0a:00:02:02` → `gateway ARP RESOLVED`, 0 faults.
- **Harness:** `NET=1 bash qemu-run.sh` adds e1000 + QEMU user-net (guest 10.0.2.15) + a `net.pcap` dump; the
  default boot is `-nic none` so the in-kernel network init is skipped (the desktop is never at risk). ★ The
  locally-built **virgl QEMU lacks slirp** (`network backend 'user' is not compiled in`) — run the network test
  on the **system QEMU** (`QEMU_BIN=qemu-system-x86_64`, no GPU), which has user-net.
- **N2 (IPv4 + ICMP) + N3/N6 (UDP/DHCP) TX ◑ — every transmit path is proven correct on the wire; the inbound
  IP RX path can't be verified here because this sandbox's slirp answers ONLY ARP.** Packed IPv4/ICMP headers
  (`align(1)`, defensive) + an ICMP-echo-reply counter. **Verified on the wire (pcap), all well-formed:** `ICMP
  echo request 10.0.2.15 > 10.0.2.2`, `DNS A? example.com` (UDP), and a textbook **552-byte DHCP DISCOVER**
  `0.0.0.0.68 > 255.255.255.255.67`. So IPv4 + ICMP + UDP + DNS-query + DHCP-DISCOVER **TX** are all correct.
- ★★ **Decisive RX finding:** the full pcap shows slirp **replies only to ARP** (gateway + DNS-server MAC);
  **ICMP, DNS, and DHCP all get zero reply** in this environment — ICMP is host-disabled
  (`ping_group_range = 1 0`), DNS has no upstream internet, and even slirp's *internal* DHCP server stays
  silent here. ARP is the only slirp service that responds (it fabricates replies for its virtual IPs with no
  host interaction). So the IPv4 *receive* dispatch is exercised in code but **cannot be end-to-end proven on
  this host by any available means**; the **eth RX is** proven (N1 ARP replies received + parsed). Finishing
  N2/N3 RX needs a **real NIC / a tap device / a non-sandboxed host**.
- ★ **6 real stack bugs fixed along the way** (the DHCP client now emits a standards-compliant DISCOVER, and
  the IP send handles broadcast): (1) `ipv4Send` ARP-resolved the *broadcast* address instead of using the
  Ethernet broadcast MAC → broadcast/DHCP could never send; (2) DHCP packet buffer `548 < DHCPHeader(240)+312`
  → `buildDHCPPacket` returned 0; (3,4) DHCP **magic cookie** stored/compared as a host-endian uint (TX + the
  RX callback) → byte-swapped on the wire; (5) DHCP **flags** `0x8000` not `htons`'d → broadcast bit landed in
  the wrong byte; (6) DISCOVER not padded to the BOOTP minimum (250 B) → slirp drops it (now padded to 552).
  Also: the draft IP-send has **no ARP defer-and-retransmit** (first packet to an unresolved IP is dropped) →
  the self-test pre-resolves a dest MAC before sending. The DHCP *RX* path turned out to be **wired** after all
  (it uses a normal `udpBind(68)` + callback, and `udpHandlePacket` dispatches by port).
- **Next: N3 (UDP socket integration) / N4 (TCP)** + finishing N2/N3 RX on a real network per the above.

---

# Part A — TCP/IP network stack

A small, correct, polled IPv4 stack (matching the kernel's existing no-IRQ polling model), wired behind the
existing socket syscalls so AF_INET "just works" for musl binaries.

- **N0 — virtio-net driver.** Find the virtio-net PCI device (0x1AF4:0x1041 modern / 0x1000 legacy; class
  0x0200), walk the modern caps to the common-config (reuse the virtio-gpu cap-walk), set up the **rx + tx
  virtqueues**, negotiate features (VIRTIO_NET_F_MAC, MRG_RXBUF), read the MAC. Poll the rx ring in the
  kernel's existing service loop. *Verify:* the driver reports the MAC + sees inbound frames (a host `ping`
  to the guest lands in the rx ring; klog the ethertype histogram).
- **N1 — Ethernet + ARP.** Frame demux by ethertype; an ARP table + request/reply (resolve the gateway MAC).
  *Verify:* the guest answers an ARP `who-has` for its IP and resolves the gateway.
- **N2 — IPv4 + ICMP.** IPv4 header parse/build, per-protocol demux, checksum; ICMP echo reply.
  *Verify:* host `ping <guest-ip>` succeeds end-to-end (the headline milestone — the box is "on the network").
- **N3 — UDP.** UDP datagram in/out, a port-demux table, integration with the socket layer (SOCK_DGRAM /
  AF_INET). *Verify:* a guest `sendto`/`recvfrom` round-trips a datagram with a host `nc -u`.
- **N4 — TCP.** The hard milestone: connection state machine (SYN/SYN-ACK/ACK, FIN/RST), sequence/ack
  numbers, a retransmit timer, a receive window + reassembly buffer, congestion control (start simple:
  fixed window / slow-start). Keep it minimal but correct. *Verify:* a guest TCP `connect()` to a host
  listener completes the handshake and streams bytes both ways; `iperf`-style throughput sanity.
- **N5 — AF_INET sockets.** Route `AF_INET` through the **existing** `sys_socket`/`bind`/`connect`/`listen`/
  `accept`/`send`/`recv` (a protocol backend behind the AF_UNIX shape), with poll/epoll readiness from the
  rx path. *Verify:* an unmodified musl client (e.g. a tiny HTTP GET) works with no app changes.
- **N6 — DNS + DHCP.** A stub resolver (UDP/53) + a DHCP client (lease the guest IP/gateway/DNS from QEMU's
  built-in server) — or static config first. *Verify:* `getaddrinfo("example.com")` resolves.
- **N7 — DM8 network-policy gate (the payoff).** Wire `connect()` (and `bind` for listeners) through the
  calling task's domain `NetPolicy` (`deviceClassGate`-style): `NetPolicy.None` → `EACCES`; `LocalOnly` →
  only loopback/LAN; `Tor`/`VPN` → route through the corresponding proxy (later). *Verify:* a
  `networkPolicy:none` domain's `connect()` returns EACCES while a `NAT` domain's succeeds — the DM8 net gate
  the device gate already models, now real.
- **N8 — Hardening.** Per-domain socket Objects + cap rights (CAP_RIGHT_NET), SYN-flood/RST sanity limits, a
  loopback interface, IPv6 (optional). The stack stays small; correctness + the domain gate matter more than
  features.

**Honest scope:** a full Linux-grade stack (GRO, TSO, full congestion control, IPv6 everything) is the
goal — a *correct, minimal, domain-gated* IPv4 TCP/UDP stack that carries real musl traffic and enforces
`NetPolicy` is. QEMU user-net (`-netdev user`) + virtio-net is the dev path; bare-metal NICs reuse the LKL
bridge ([[bare-metal-lkl]], `BARE_METAL_ROADMAP.md`) — an `net-lkl` driving a real NIC over the L1–L5 bridge
is the alternative substrate (and pairs with SMP's `net-lkl` on its own core).

---

# Part B — I2P P2P template marketplace (on Part A)

Decentralized, server-less sharing of signed Template Domains. Reuses DM12's offline bundle core verbatim —
this part adds only **transport (I2P SAM), discovery (Kademlia DHT), and content-addressed download.**

- **M0 — I2P SAM bridge.** Speak the **I2P SAM v3 protocol** to an external I2P router over TCP (N4) — do NOT
  embed a router (the brief says "use SAM where possible"). `SESSION CREATE` → a local I2P destination;
  `STREAM CONNECT`/`STREAM ACCEPT` for peer streams; `DATAGRAM` for DHT RPCs. Config at
  `/objects/marketplace/config.json` (SAM host/port, local destination, bootstrap peers). *Verify:*
  `market peer start` creates a session and prints the local I2P destination; `market peer id` shows it.
- **M1 — Marketplace object model.** The brief's objects as first-class kernel objects under
  `/objects/marketplace/`: `MarketplaceNode`, `MarketplacePeer`, `TemplateAnnouncement`, `TemplateIndexRecord`,
  `TemplateDownloadSession`, `PublisherIdentityRecord`, `DHTRoutingTable`. `nodeId = SHA256(i2pDestination)`.
- **M2 — Kademlia DHT.** XOR-distance routing table (k-buckets) over I2P datagrams; RPCs PING / STORE /
  FIND_NODE / FIND_TEMPLATE / FIND_PUBLISHER / GET_MANIFEST / GET_PEERS. *Verify:* two guest nodes (two QEMU
  instances sharing a host I2P router) bootstrap and find each other via FIND_NODE.
- **M3 — Signed template announcements.** Publishing stores a small **signed** `TemplateAnnouncement`
  (templateId / version / policyEpoch / publisher / bundleHash / manifestHash / tags / i2pSources / signature)
  in the DHT — NOT the bundle. Sign with the publisher key (reuse `crypto.d`; per-publisher PKI is the
  upgrade over DM12's single system key). *Verify:* `market publish dev.hosdt` → the announcement is
  STORE'd + retrievable by another node; the signature verifies.
- **M4 — Content-addressed download.** `market download <templateId>`: find the announcement → verify its
  signature → find peers serving `bundleHash` → stream bundle **chunks** over I2P → verify each chunk hash →
  reassemble → verify the whole `bundleHash` → hand the bytes to DM12 `bundleImport` (verify HMAC + publisher
  trust + create a Generation). **Never trust filenames; content-address everything.** *Verify:* node B
  downloads + installs a template node A published; a corrupted chunk is rejected and retried from another
  peer (peer reputation decremented).
- **M5 — Trust policies + quarantine.** Marketplace trust policy (`allowUnknownPublishers`,
  `allowUnsignedTemplates`, `trustedPublishers`, `blockedPublishers`, `minimumPolicyEpoch`,
  `requireReproducibleManifest`) layered on DM12's publisher-trust table. Untrusted templates install only
  into a **quarantined** review domain (no startup services, no network, no identity inheritance, no global
  defaults, no auto-update) until `domain template promote`. *Verify:* an untrusted publisher's template is
  blocked / quarantined per policy; `market publisher trust <id>` then allows install.
- **M6 — Dependency resolution + rollback.** Reuse `compiler.d` resolution for template dependencies
  (TemplateDomain / package set / linux-compat / service / policy / identity-inheritance); fail import if a
  dependency can't be resolved locally or fetched from trusted sources. Rollback via DM12 Generations.
- **M7 — Auto-update (optional).** `market update check` / `market update install <domain>` — never bypassing
  signature / trust / policyEpoch / dependency / Generation-rollback checks.
- **M8 — CLI + GUI.** `market peer|publish|search|download|install|publisher|update` CLI; the Domain Manager
  **Marketplace toolbar button** (currently the explicit out-of-scope stub) becomes a real search/browse/
  install panel reading the DHT index, with per-result trust badges.

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
