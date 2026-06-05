# Secure IPC Roadmap

> Add authenticated, encrypted, replay-resistant IPC **between userspace processes**,
> with the **kernel kept minimal and key-free**. The kernel only routes
> capability-gated channels and isolates memory; a privileged userspace **broker**
> handles identity/authorization and issues **signed session descriptors**; each
> endpoint still performs its **own** Diffie-Hellman. Grounded in the existing
> transport primitives in `src/kernel/d/core/syscalls/posix.d`.

---

## What already exists (and why it's enough transport)

The kernel already has the primitives secure IPC needs as *transport*; we add crypto
**above** them and a tiny capability gate **inside** them:

- **Datagram/stream channel:** `socketpair`/`connect` over `LocalSocket`
  (`posix.d`), `sendmsg`/`recvmsg`.
- **Descriptor passing:** `SCM_RIGHTS` over `sendmsg` (`LocalSocket.passedFiles[]`,
  ~3471) — the mechanism to hand a channel/memfd to a peer or to the broker.
- **Shared memory:** `memfd_create` + `ftruncate` + shared `mmap` — the high-throughput
  ciphertext ring buffer.
- **Wakeups:** `eventfd`, `epoll`.
- **Entropy + time:** `getrandom` (CSPRNG) and `clock_gettime` — for ephemeral keys,
  nonces, and descriptor expiry.

**What is missing:** any crypto, any identity, any capability gate, any service
framework (everything runs as uid 0 today; see `SECURITY_ROADMAP.md`/`OBJECT_OS_ROADMAP.md`).
So secure IPC is **mostly a userspace build** on top of stable kernel transport, which
is exactly the design goal.

---

## 1. High-level architecture

```
        ┌─────────────────────────── userspace ───────────────────────────┐
        │                                                                  │
        │   ┌───────────────┐    register/authorize/get-descriptor          │
        │   │ Identity Svc  │◄───────────────┐        ┌──────────────────┐  │
        │   │ (CA: signs    │                │        │  Secure IPC      │  │
        │   │  proc certs)  │───cert────────▶│        │  Broker / KeySvc │  │
        │   └───────────────┘                │        │ (signs SESSION    │  │
        │                                    │        │  DESCRIPTORS;     │  │
        │   ┌───────────────┐  authorize?    │        │  holds NO session │  │
        │   │ Capability    │◄───────────────┘        │  keys)            │  │
        │   │ Manager       │   yes/no + chan cap      └─────────┬────────┘  │
        │   └───────────────┘                                   │ signed     │
        │                                                       │ descriptor │
        │   ┌──────────────┐    signed-DH handshake + AEAD      ▼            │
        │   │  Process A    │◄═════════ encrypted msgs ═════════►│ Process B │ │
        │   │ (does X25519, │   (each does its OWN DH; derives   │ (X25519,  │ │
        │   │  HKDF, AEAD)  │    keys; keys never leave proc)    │  HKDF,    │ │
        │   └──────┬───────┘                                    │  AEAD)    │ │
        └──────────┼──────────────────────────────────────────────┼─────────┘
                   │ kernel channel (socketpair / memfd ring),     │
                   ▼ capability-gated routing + memory isolation   ▼
        ┌──────────────────────── KERNEL (minimal, key-free) ──────────────────┐
        │  routes a message only if sender holds the channel capability;        │
        │  isolates the memfd ring; provides getrandom + clock; can REVOKE a    │
        │  channel cap on broker request. Stores NO plaintext keys, no DH.      │
        └───────────────────────────────────────────────────────────────────────┘
```

**Trust split:** the kernel is trusted for **isolation + routing** but *not* with key
secrecy (defense-in-depth — a kernel memory leak exposes no session keys). The broker
is trusted to **authorize pairs and bind identities**, but *not* with keys either — it
never sees a session key because **endpoints do their own DH**. A process trusts a peer
only after cryptographic proof, never because a message arrived.

---

## 2. Roles

- **Kernel IPC primitive.** Capability-gated channel: deliver a message from A to B
  **iff** A holds a channel capability to B; isolate the shared `memfd` ring; expose
  `getrandom`/`clock_gettime`; support **revoke(channelCap)** to tear a session's
  transport. *Holds no keys, performs no crypto, parses no ciphertext.* (Today: the
  `LocalSocket`/`SCM_RIGHTS`/`memfd` paths + a new cap check + a revoke op.)
- **Secure IPC Broker / Key Service.** A privileged userspace **object**. Authenticates
  processes (via Identity Svc), authorizes an IPC pair (via Capability Manager), issues
  a **broker-signed Session Descriptor** binding `{A_id, B_id, channelCap, suite,
  policy, epoch, notAfter}`. Maintains a **revocation epoch/list**. **Holds the broker
  signing key, NOT session keys.**
- **Process Identity Service.** A CA: binds each process **object** to a stable
  identity keypair and issues a **cert** (`identityPub` signed by the broker/identity
  CA) tied to the process's object-tree position + launch capability. Answers "is this
  identityPub really object X?" — the anchor for authenticating peers.
- **Capability Manager.** Decides who may open a channel to whom (an **IPC-pair
  capability**); narrows on spawn so a child inherits ≤ parent's IPC authority
  (`OBJECT_OS_ROADMAP.md` P6). Hands the kernel the channel cap the broker authorized.
- **User processes (endpoints).** Generate ephemeral X25519 keys per session, run the
  **signed-DH** handshake, derive keys with **HKDF**, **AEAD**-encrypt every message
  with strict per-direction counters, rotate keys, and verify peer identity + descriptor
  + revocation before trusting any payload.

---

## 3. Implementation TODO (phased)

### Phase 0 — Crypto + transport foundation  ✅ DONE
> **Status:** the `libsecipc` crypto library landed in `core/libsecipc.d` (module
> `core.libsecipc`), wired into the boot self-test loop. Every primitive is a **real,
> RFC-vector-proven** implementation (not a stub): `[libsecipc] selftest PASS` checks
> ChaCha20 against RFC 8439 §2.3.2, Poly1305 §2.5.2, ChaCha20-Poly1305 AEAD §2.8.2
> (tag + round-trip + tamper-rejects), HKDF-SHA-256 against RFC 5869 §A.1, and X25519
> against RFC 7748 §5.2 (plus a Diffie-Hellman agreement check). Built on the genuine
> SHA-256/HMAC of `core/crypto.d` (§8.1).
- **0.1** Userspace crypto lib (`libsecipc`): X25519, HKDF-SHA256, ChaCha20-Poly1305
  (+AES-GCM alt), Ed25519 verify/sign, constant-time compare, secure zeroization.
  *Deps:* `getrandom`. *Critical.* ✅ X25519, HKDF-SHA256, ChaCha20-Poly1305,
  `ctEqual`/`zeroize` implemented + vector-proven. *(AES-256-GCM alt and asymmetric
  **Ed25519** sign/verify remain — Ed25519 needs SHA-512 + Edwards arithmetic;
  identity/broker signatures use the HMAC-SHA-256 authenticator meanwhile.)*
- **0.2** Channel abstraction over `socketpair` + a `memfd` ciphertext ring; framing
  (length-prefixed records). *Deps:* existing posix transport. ✅ Length-prefixed
  `frameEncode`/`frameDecode` (truncation- and oversize-rejecting) implemented + tested;
  the live socketpair/memfd ciphertext-ring wiring is the remaining endpoint integration.
- **0.3** Broker/Identity/CapMgr **stubs** as services reachable at well-known object
  paths (e.g. unix sockets under `/run/secipc/{broker,identity}.sock`). *Deps:* service
  framework (`OBJECT_OS_ROADMAP.md` P10) — stub if absent. ✅ **Superseded by Phase 1:**
  `core/secipc.d` implements the broker/identity/cap-manager as real in-kernel object
  services (more than stubs); reaching them over well-known sockets is the M2 wiring.

### Phase 1 — Identity + descriptors (no crypto on the wire yet)  ✅ DONE
> **Status:** implemented in `core/secipc.d` (module `core.secipc`), wired into the
> boot self-test loop and built on the real §8.1 HMAC-SHA-256 (the Ed25519 stand-in
> for CA/broker signatures), the `core/cap.d` capability tables, and `core/ipc.d`
> endpoints. The broker/identity/capability-manager run **in-kernel as object
> services** for now (relocating them to userspace + wiring the live `LocalSocket`/
> `sendmsg` path through `secipcKernelRoute` is the remaining integration, §7/M2).
> `[secipc] selftest PASS` proves all three sub-tasks.
- **1.1** Process registration → Identity cert (`identityPub` signed by CA, bound to
  object id + launch cap). **Critical.** ✅ `identityRegister` refuses unless the
  process **proves it holds its launch capability** (`requireCapIn`), then issues a CA
  HMAC cert over (objId‖identityPub‖notAfter); `identityVerifyCert` is the peer-auth
  anchor (tampered cert rejected).
- **1.2** Broker `RequestSession(peerId, suitePrefs)` → consults Capability Manager →
  returns a **signed Session Descriptor** + a channel cap. **Critical.** ✅
  `brokerRequestSession` checks both certs valid+unexpired and the pair authorized
  (`brokerAuthorizePair`), picks the strongest offered suite, allocates a channel
  endpoint, installs the **channel cap** into A's table, and returns a broker-signed
  `SessionDescriptor{A,B,channelCap,suite,epoch,notAfter}`. Unauthorized pair refused;
  tampered/expired/revoked descriptors rejected by `brokerVerifyDescriptor`.
- **1.3** Kernel: **capability-gated routing** — deliver only if sender holds the
  channel cap (`dispatchSyscall`/socket path). **Critical, minimal kernel change.** ✅
  `secipcKernelRoute` admits iff the sender holds the channel cap (`CAP_RIGHT_CALL`)
  and performs **no crypto / no descriptor parsing** (invariant K1);
  `secipcChannelRevoke` (`channel_revoke`) revokes the cap so routing then fails.
  *(Live wiring is into a function today; routing the real socket path through it is
  the M2 integration.)*

### Phase 2 — Authenticated DH + AEAD  ✅ DONE
> **Status:** implemented in `core/secsession.d` (module `core.secsession`), wired
> into the boot self-test loop. The per-endpoint `Session` layer turns a Phase-1
> descriptor + channel into an authenticated, encrypted, replay-resistant stream
> using the real §0 libsecipc (X25519/HKDF/ChaCha20-Poly1305) — keys never leave the
> endpoint (K1/K2). `[secsession] selftest PASS` runs a full A↔B exchange and proves
> all four sub-tasks plus replay/tamper/wrong-direction rejection.
- **2.1** **Signed-DH (SIGMA-style) handshake** over the channel: each endpoint sends
  its ephemeral X25519 pub **signed by its identity key**; both verify the peer cert
  chains to the CA **and** matches the descriptor's `{A_id,B_id}`. **Critical.** ✅
  `sessionBuildHandshake`/`sessionProcessHandshake` verify the descriptor, the peer
  cert (`identityVerifyCert`), and the peer's signature over its ephemeral + offered
  suites; peer must be the descriptor's other party. *(Identity signatures are the
  HMAC-SHA-256 stand-in for Ed25519 via the Identity Service.)*
- **2.2** **HKDF** session-key derivation from the X25519 shared secret + a **transcript
  hash** (descriptor + both ephemerals + suite list) → distinct send/recv keys per
  direction. **Critical.** ✅ `ss = X25519(ePriv,peerEPub)` (all-zero/low-order
  rejected) → `transcript = SHA-256(descHash‖ePubA‖ePubB‖suite)` →
  `HKDF-Extract/Expand` to per-direction keys; both endpoints derive identical keys;
  `ss`/`ePriv`/`prk` zeroized (forward secrecy).
- **2.3** **AEAD** record layer: encrypt every message; AAD = `sessionId‖epoch‖
  direction‖counter`; **strict monotonic counter** per direction; receiver replay
  window. **Critical.** ✅ `sessionSend`/`sessionRecv` use ChaCha20-Poly1305 with
  nonce = `direction‖counter`, that AAD, a per-direction monotonic counter + 64-entry
  sliding replay window; replay/MAC-failure/wrong-direction dropped fail-closed.
- **2.4** **Downgrade resistance:** the signed transcript covers the offered suite list,
  so an attacker cannot strip strong suites without breaking a signature. **High.** ✅
  the offered `suiteList` is inside the signed handshake; the self-test proves a
  stripped-suite handshake fails the identity signature.

### Phase 3 — Lifecycle: rotation, revocation, recovery  ✅ DONE
> **Status:** implemented in `core/secsession.d` (extending Phase 2), wired into the
> boot self-test loop. Sessions gained a `keyGen` generation + `authFailCount`, and
> records carry `keyGen` so stale-generation records are dropped. `[seclife] selftest
> PASS` proves all three sub-tasks via two live A↔B pairs.
- **3.1** **Key rotation / rekey:** new ephemeral DH within a live session before the
  counter nears exhaustion or on a timer; old keys zeroized. **High.** ✅
  `sessionNeedsRekey` (fires at `REKEY_THRESHOLD`), `sessionRekeyBuild`/
  `sessionRekeyProcess` run a fresh signed X25519 within the live session, derive
  next-generation keys (bound to the new `keyGen` in the transcript+HKDF), reset
  counters, and overwrite/zeroize the old keys; the stream continues, and a record
  stamped with the previous `keyGen` is rejected.
- **3.2** **Revocation:** broker bumps a **revocation epoch** / publishes a revoked
  sessionId; endpoints re-check epoch periodically and on each descriptor use; broker
  asks the **kernel to revoke the channel cap** (transport dies). **Critical.** ✅
  `sessionRevocationTick` re-runs `brokerVerifyDescriptor` (Phase-1 revoked-set +
  expiry); on revoke it closes the session and zeroizes keys, refusing further I/O.
  The kernel-cap teardown is the Phase-1 `secipcChannelRevoke`.
- **3.3** Failure handling: handshake timeout, MAC failure, counter exhaustion, peer
  death (eventfd/EPOLLHUP) → fail-closed, zeroize, optionally re-establish. **High.** ✅
  `sessionHandshakeTimeout` (stuck in HANDSHAKE past a deadline), an AEAD-auth-flood
  tear after `AUTH_FAIL_MAX` consecutive MAC failures, counter-exhaustion refusal in
  `sessionSend` (forces rekey), and `sessionPeerDied` — all close + zeroize
  (fail-closed; never downgrade to plaintext).

### Phase 4 — Object-tree + Linux-compat integration  ✅ DONE
> **Status:** implemented in `core/secobj.d` (module `core.secobj`), wired into the
> boot self-test loop. Adds four object types (`ObjType.SecChannel/SecSession/SecCert/
> SecDescriptor`) and a transparent AEAD shim over a wire. `[secobj] selftest PASS`
> proves both sub-tasks.
- **4.1** Model channel, session, identity cert, descriptor as **objects** in the tree;
  IPC-pair authority is a **capability** delegated downward (parent ⊇ child).
  *Deps:* `OBJECT_OS_ROADMAP.md`. **High.** ✅ `secChannelObject`/`secSessionObject`/
  `secCertObject`/`secDescriptorObject` allocate correctly-typed tree objects (a
  `SecSession` holds **no keys**); the authority to use a channel is a capability to its
  `SecChannel` object, and `ipcPairDerive` (`capDeriveObjectToIn`) narrows it
  parent→child — a child holds ⊆ the parent's IPC reach and **widening is refused**.
- **4.2** **Linux-compat shim:** `libsecipc` wraps a normal unix-socket fd; a Linux app
  uses `send`/`recv` and the library does the AEAD transparently; broker reachable via a
  well-known socket. No new Linux syscalls. **Medium.** ✅ `secShimSend`/`secShimRecv`
  seal/frame and deframe/open a record over a `SecWire` (the socketpair/memfd ring
  stand-in); the self-test confirms the **wire carries ciphertext, not the plaintext**,
  and a Linux-style `send`/`recv` round-trips both directions with the AEAD applied
  transparently. *(Wiring `SecWire` onto the live posix socketpair/memfd fd is the
  remaining endpoint integration; the broker is the Phase-1 service object, reachable
  by name.)*

### Phase 5 — Production hardening
- **5.1** Constant-time everything; nonce-reuse impossibility proofs; memory zeroization;
  side-channel review. **High.**
- **5.2** Fuzz the record/handshake parsers; formal-ish review of the state machine.
  **High.**

---

## 4. Required data structures

```c
// Identity Service (CA)
struct ProcIdentity { ObjId obj; u8 identityPub[32]; /*Ed25519*/
                      u8 certSig[64]; /*CA over (obj‖identityPub‖notAfter)*/
                      CapId launchCap; u64 notAfter; }

// Broker → endpoints (signed)
struct SessionDescriptor { u64 sessionId; ObjId aId, bId; CapId channelCap;
                           u16 suite; u32 policy; u64 epoch; u64 notAfter;
                           u8 brokerSig[64]; }  // Ed25519 over all prior fields

// On-wire handshake (per endpoint)
struct HandshakeMsg { u64 sessionId; u8 ephemeralPub[32]; /*X25519*/
                      u16 suiteList; u8 idSig[64]; }  // identity-key sig over
                      // (sessionId‖ephemeralPub‖suiteList‖transcriptSoFar)

// Per-endpoint session state (NEVER leaves the process; not in kernel)
struct Session { u64 sessionId; u16 suite; u64 epoch;
                 u8 sendKey[32], recvKey[32];          // from HKDF
                 u64 sendCtr; u64 recvCtr; u64 recvWindowBits; // replay window
                 ObjId peerId; u8 peerIdentityPub[32];
                 enum {HANDSHAKE, OPEN, REKEY, CLOSED} st; u64 notAfter; }

// AEAD record on the channel
struct SecRecord { u64 sessionId; u64 counter; u8 ct[]; u8 tag[16]; }
// AAD = sessionId ‖ epoch ‖ direction(1) ‖ counter ; nonce = direction ‖ counter(LE96)

// Broker tables
struct BrokerState { Map<ObjId,ProcIdentity> registry;
                     PairPolicy authz;            // who may talk to whom
                     u64 revocationEpoch; Set<u64> revokedSessions;
                     Ed25519Key brokerSigningKey; } // signing key only — no session keys
```

---

## 5. Message-flow diagrams (text)

**Process registration**
```
Proc A ──register(obj, identityPub, proof-of-launch-cap)──▶ Identity Svc
Identity Svc: verify launch cap ties A to obj ; sign cert(obj‖identityPub‖notAfter)
Identity Svc ──cert──▶ Proc A         // A can now prove "identityPub == obj A"
```

**Capability authorization**
```
Proc A ──RequestSession(peerId=B, suitePrefs)──▶ Broker
Broker ──may A↔B?──▶ Capability Manager
CapMgr: check A holds an IPC-pair cap to B (inherited/delegated) ──yes+channelCap──▶ Broker
Broker: mint sessionId, epoch ; sign SessionDescriptor{A,B,channelCap,suite,epoch,notAfter}
Broker ──descriptor + channelCap──▶ Proc A   (and a matching descriptor to B on its ask)
// authority to talk is proven here; NO keys exchanged with broker
```

**Diffie-Hellman handshake (signed-DH / SIGMA-like)**
```
A: eA = X25519_keygen() ; tA = H(descriptor)
A ──Handshake{sessionId, ePubA, suiteList, sig_A(sessionId‖ePubA‖suiteList‖tA)}──▶ B
B: verify A's cert (chains to CA) ∧ A==descriptor.aId ∧ verify sig_A
B: eB = X25519_keygen()
B ──Handshake{sessionId, ePubB, suiteList, sig_B(...‖transcript)}──▶ A
A: verify B's cert ∧ B==descriptor.bId ∧ verify sig_B ∧ suiteList matches (no downgrade)
both: ss = X25519(ePriv, peerEPub) ; transcript = H(descriptor‖ePubA‖ePubB‖suiteList)
```

**Secure session establishment (key derivation)**
```
both: prk = HKDF-Extract(salt=transcript, ikm=ss)
      keyA→B = HKDF-Expand(prk, "secipc A->B" ‖ sessionId, 32)
      keyB→A = HKDF-Expand(prk, "secipc B->A" ‖ sessionId, 32)
A.sendKey=keyA→B, A.recvKey=keyB→A ; B mirrored ; ctr=0 ; state=OPEN
ss, prk, ephemeral privs ──zeroized──   // forward secrecy
```

**Encrypted message send / receive**
```
SEND (A→B):   n = direction(A→B) ‖ A.sendCtr(LE) ; aad = sessionId‖epoch‖dir‖A.sendCtr
              ct,tag = AEAD_Enc(A.sendKey, n, aad, plaintext) ; A.sendCtr++
              write SecRecord{sessionId, A.sendCtr-1, ct, tag} to channel
RECV (B):     read record ; if record.epoch≠current → reject (revoked)
              if counter ≤ last ∨ outside window → DROP (replay)   // monotone+window
              pt = AEAD_Dec(B.recvKey, n, aad, ct,tag) ; if FAIL → DROP+alarm
              advance recv window ; deliver pt
```

**Session revocation**
```
Policy change / compromise ──▶ Broker: revocationEpoch++ ; revokedSessions += sessionId
Broker ──revoke(channelCap)──▶ Kernel        // transport torn down (cap invalid)
Endpoints (on next epoch check or EPOLLHUP): state=CLOSED ; zeroize keys ; refuse I/O
// a peer holding stale keys can no longer route (kernel cap gone) and is epoch-stale
```

---

## 6. Cryptography choices

- **DH:** **X25519** (ephemeral per session ⇒ forward secrecy). Reject low-order /
  all-zero shared secret.
- **KDF:** **HKDF-SHA-256**; Extract salt = the **transcript hash** (binds identities +
  ephemerals + suite ⇒ channel binding + downgrade resistance), Expand with distinct
  per-direction labels.
- **AEAD:** **ChaCha20-Poly1305** (default; fast without AES-NI — matters for swrast/QEMU)
  with **AES-256-GCM** as a negotiated alternative.
- **Identity / descriptor signatures:** **Ed25519**.
- **Nonce/counter:** 96-bit nonce = `direction(1 bit/byte) ‖ 64-bit little-endian
  counter`. **Counter is strictly monotonic per direction**, **never reused**; sender
  refuses to send at counter max (forces rekey, §3.1); receiver enforces
  **monotonic + sliding replay window**. Per-direction keys ⇒ A→B and B→A never share a
  (key,nonce). AAD always includes `sessionId‖epoch‖direction‖counter`.
- **Suite/version:** offered suite list is **inside the signed transcript** ⇒ no
  cleartext downgrade.

---

## 7. Kernel changes (kept minimal)

Only three small, key-free additions — everything else is the existing transport:

1. **Capability gate on routing.** In the socket/`sendmsg` path (`posix.d`) +
   `dispatchSyscall` (`kernel_main.d`), deliver/connect only if the sender holds the
   channel **capability** (`OBJECT_OS_ROADMAP.md` P6 cap table). *Complexity: Medium.*
2. **`channel_revoke(cap)` op.** Lets the broker tear a session's transport; invalidates
   the cap so a revoked session can't route. *Complexity: Low.*
3. **Expose entropy + monotonic time to endpoints** — already present (`getrandom`,
   `clock_gettime`); just ensure they're cap-reachable. *Complexity: Trivial.*

**Explicitly NOT in the kernel:** X25519/HKDF/AEAD, long-term keys, session keys,
identity certs, descriptor signing, ciphertext parsing. The kernel never holds
plaintext keys (hard constraint satisfied). Memory isolation of the `memfd` ring is the
existing per-mapping mechanism.

---

## 8. Userspace service APIs

```
// Identity Service
cert        Register(ObjId self, PubKey identityPub, LaunchCapProof p)
ProcIdentity Lookup(ObjId peer)          // get peer's cert to verify in handshake

// Secure IPC Broker / Key Service
SessionDescriptor, ChannelCap  RequestSession(ObjId peer, SuiteList prefs)
void        AcceptOffer(u64 sessionId)   // peer side fetches its descriptor
u64         CurrentRevocationEpoch()
void        RevokeSession(u64 sessionId) // requires admin/owner cap

// libsecipc (in-process, links into each endpoint and the Linux shim)
Session*    secipc_connect(ObjId peer, SuiteList prefs)   // RequestSession+handshake
ssize_t     secipc_send(Session*, const void* buf, size_t)
ssize_t     secipc_recv(Session*, void* buf, size_t)
int         secipc_rekey(Session*)
void        secipc_close(Session*)        // zeroize + close channel
// Capability Manager: AuthorizePair / DeriveChannelCap (see OBJECT_OS_ROADMAP.md)
```

---

## 9. Security invariants & threat model

**Invariants**
- **K1** Kernel holds **no** long-term or session keys and performs **no** crypto.
- **K2** Broker holds **no** session keys; it only authorizes + signs descriptors.
- **K3** A process accepts payload from a peer **only after** verifying: peer
  identity cert (chains to CA) **and** signed-DH **and** descriptor `{aId,bId}` match
  **and** session not revoked. *Receiving a message ⇒ nothing.*
- **K4** Forward secrecy: compromising long-term identity keys does **not** decrypt past
  sessions (ephemeral DH).
- **K5** No (key,nonce) reuse, ever (per-direction key + monotonic counter + rekey
  before exhaustion).
- **K6** Authority to open a channel is a capability inherited/narrowed down the object
  tree; **send ≠ trust**.

**Threat model (in scope):** a malicious or compromised **peer process**; a process
that can *send* but isn't authorized; a local **MITM/relay** process; **replay/reorder**
on the channel; **downgrade** attempts; **revoked** peers; a **kernel memory disclosure**
(must not leak session keys — they're never there). **Out of scope (stated):** a fully
compromised kernel that breaks isolation/routing arbitrarily (but even then K1/K4 limit
key exposure); physical/side-channel beyond §5; the broker's signing-key compromise
(detected via revocation + key rotation, but is a trust-root break).

---

## 10. Failure cases & recovery

| Failure | Detection | Recovery |
|---|---|---|
| Handshake timeout / bad sig | timer / verify fail | fail-closed, zeroize, no session; retry with backoff |
| AEAD/MAC failure on recv | `AEAD_Dec` fail | **drop** record, raise audit event; repeated ⇒ tear session |
| Replay / out-of-window counter | window check | drop silently (+counter), no state change |
| Counter near exhaustion | sender check | force **rekey** (§3.1) before send |
| Peer death | EPOLLHUP / eventfd | mark CLOSED, zeroize, notify owner |
| Revocation (epoch bump / cap revoke) | epoch re-check / routing fails | CLOSED + zeroize; re-`RequestSession` if still authorized |
| Broker unreachable | RPC timeout | cannot establish **new** sessions; existing OPEN sessions keep working until expiry |
| Descriptor expired (`notAfter`) | clock check | refuse handshake; request fresh descriptor |
| Identity CA compromise suspected | out-of-band | rotate CA key; bump revocation epoch; force re-register |

General rule: **fail-closed + zeroize**; never downgrade to plaintext; never accept on
verify failure.

---

## 11. Unit / integration tests

- **Crypto vectors:** X25519/HKDF/ChaCha20-Poly1305/Ed25519 KATs; reject low-order
  X25519, tampered tags, truncated records.
- **Handshake:** happy path; wrong identity (cert mismatch) rejected; descriptor
  `{aId,bId}` mismatch rejected; **downgrade** (strip suite) rejected; expired
  descriptor rejected.
- **Record layer:** **replay** (resend record) dropped; **reorder** within/out-of window;
  **counter-exhaustion** forces rekey; per-direction key separation (A→B record fails as
  B→A).
- **Revocation:** epoch bump + cap revoke ⇒ both ends fail-closed; revoked peer cannot
  route (kernel cap gone).
- **Rotation:** rekey preserves stream; old keys zeroized (assert no plaintext key in a
  post-rekey memory dump).
- **Capability/object-tree:** child with narrowed IPC cap **cannot** open a channel the
  parent could; unauthorized pair refused by Capability Manager.
- **Kernel:** routing denied without channel cap; `channel_revoke` tears transport;
  assert kernel memory holds **no** session key (scan).
- **Linux-compat:** a BusyBox/Linux client using the `libsecipc` shim over a normal fd
  interoperates with a native endpoint.
- **Fuzz:** record + handshake parsers; broker RPC.

---

## 12. Milestones (simplest → production)

- **M0 — Echo over transport.** `libsecipc` channel over `socketpair`+`memfd`,
  framing, broker/identity **stubs** issuing unsigned descriptors. *Proves transport +
  service plumbing.* (Phase 0)
- **M1 — Unauthenticated encrypted channel.** Raw X25519 + HKDF + ChaCha20-Poly1305 +
  counters/replay window — **no identity yet**. *Proves the record layer.* (Phase 2.2–2.3)
- **M2 — Authenticated sessions.** Identity certs + broker-signed descriptors +
  **signed-DH** + downgrade-bound transcript + capability-gated routing in the kernel.
  *This is the first honestly "secure" milestone.* (Phases 1–2)
- **M3 — Lifecycle hardened.** Key rotation, revocation (epoch + kernel cap revoke),
  full failure/recovery matrix, replay hardening. (Phase 3)
- **M4 — Object-tree native.** Channels/sessions/certs/descriptors are objects; IPC
  authority is a delegated, narrowable capability; integrates with
  `OBJECT_OS_ROADMAP.md`/`OBJECT_REFERENCE_GRAPH_ROADMAP.md`. (Phase 4.1)
- **M5 — Linux-compatible + production.** `libsecipc` shim for Linux apps over normal
  fds; constant-time/zeroization/side-channel review; parser fuzzing; state-machine
  review. (Phases 4.2, 5)

---

## Object-tree & Linux-compat integration (summary)

- **Object tree:** the **channel**, **session**, **identity cert**, and **session
  descriptor** are objects; the **right to open a channel to peer Y** is a capability a
  process holds, delegated **down** the tree and **narrowed** on spawn (a child can only
  reach peers its parent could). The broker/identity/capability services are themselves
  service objects. This makes "send ≠ trust" structural: authority is the cap, identity
  is the cert, secrecy is the endpoints' DH — three independent checks.
- **Linux compatibility:** to a Linux process the kernel channel is just a **unix-socket
  fd** (from `socketpair`/`SCM_RIGHTS`) or a shared **memfd**; `libsecipc` wraps
  `send`/`recv` with the AEAD and talks to the broker over a well-known socket. **No new
  Linux syscalls, no kernel crypto** — the same `posix.d` transport already used by
  BusyBox/Hyprland, with a capability gate added underneath.

*Companion roadmaps in this folder:* `OBJECT_OS_ROADMAP.md` (capability/object substrate
— provides the channel cap + service model this builds on), `SECURITY_ROADMAP.md`
(crypto primitives, audit log, rootless identity — shares `core/crypto/` and
`core/audit.d`), and `OBJECT_REFERENCE_GRAPH_ROADMAP.md` (sessions/channels as graph
objects with correct ownership + revocation edges).
