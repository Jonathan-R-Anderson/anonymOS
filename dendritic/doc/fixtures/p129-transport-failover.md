# P12-9 — execution-RPC transport failover

**Transport failover, not trust failover.** The secondary is an alternate way to
obtain bytes, never an alternate source of truth. Every response from either
endpoint continues through the identical existing verification path.

Verified live between two real, independent Alchemy accounts.

## Where it went, and why there

Execution bytes enter through exactly two types in the acquisition layer, both
with the same shape (`Endpoint string` + `*http.Client`):

| type | carries |
|---|---|
| `ethproof.Client` | headers, `eth_getProof` |
| `ethproof.RPCSource` | receipts, batched headers |

`channel.RPCChainReader` has no real call sites and is superseded in production
by `EvidenceChainReader`, which reaches no RPC at all; `chainprobe` is a
read-only measurement probe. **One new file, plus a few lines in each of those
two. Nothing else.**

## The separation is structural, not a rule

```text
TRANSPORT   Endpoints.Post  ->  "which configured transport supplied bytes?"
                                     │  raw bytes
                                     ▼
VERIFY      AuthenticateReceipts / AuthenticateHeader / VerifyProof
                                ->  "do these bytes prove what Ethereum says?"
```

The forbidden shape — *provider A rejected → provider B accepted → therefore
valid* — cannot occur, and not because anyone remembers not to write it:

> Verification runs **above** the transport, on bytes the transport has already
> returned. A verification failure is not visible to the transport, and there is
> no path back into it. There is no code that could retry on it.

`transport.go` contains zero Ethereum logic. It knows HTTP status codes and
JSON-RPC framing — the same way it knows a response is HTTP — and never inspects
`result`.

## Failure classification

| condition | transport failure? |
|---|---|
| connection refused / DNS / TLS / timeout | yes — fail over |
| HTTP 5xx | yes |
| HTTP 429, or a capacity refusal on a 200 | yes |
| unusable JSON-RPC framing | yes |
| **a well-formed JSON-RPC error** | **no** — that is an answer |
| **a cryptographically invalid response** | **no** — never reaches this layer |
| **a malformed endpoint URL** | **no** — our config fault, not a provider's |

A well-formed `"block not found"` is the endpoint answering correctly. Asking a
second provider for a nicer reply is the oracle this design forbids.

Bounded: **each endpoint is tried once, in order.** No loop, no rotation, no
background health machinery. On total failure, `ErrChainUnreachable` — never
stale data, never `WatchQuiet`. Inability to observe is not a conclusion that
nothing happened.

## Tests — 16, all passing

| | |
|---|---|
| primary succeeds → secondary never called | pass |
| primary times out → secondary succeeds | pass |
| primary 500 / 429 / capacity-on-200 → secondary succeeds | pass |
| primary malformed JSON → secondary succeeds | pass |
| both fail → `ErrChainUnreachable`, no bytes, **no URL in the error** | pass |
| **verification failure → NO failover** (the regression test) | pass |
| secondary's response equally untrusted | pass |
| secondary cannot smuggle an unverified header | pass |
| well-formed RPC error is not a transport failure | pass |
| config fault does not fail over | pass |
| single endpoint / unset secondary behave as before | pass |
| failover is bounded to one attempt each | pass |

### Mutation-tested

Six deliberate breaks. Three caught immediately; three survived and were
informative:

- **429 / 5xx not classified** survived because the "any non-200" catch-all still
  failed over — correct behaviour, insufficiently specific tests. Added
  `TestRateLimitClassificationIsPinned`, since `RPCSource`'s capacity accounting
  keys off the rate-limited flag. 429 now caught.
- **5xx via catch-all** remains an **equivalent mutation**: 500 falls through to
  the same branch with the same reason string, so nothing observable changes.
  Recorded as equivalent rather than presented as a hole.
- **non-transport error retried on the next endpoint** survived because nothing
  exercised that path. Added `TestConfigurationFaultDoesNotFailOver`. Now caught.

## Live verification — two real accounts

Alchemy cannot be taken down, so a local reverse proxy fronts the **real**
primary and is switched between forwarding and refusing. Both endpoints remain
real independent accounts; only reachability of the first is controlled.

```text
AUTHENTICATED reference: block 25747812, receiptsRoot 1e9f9e51…
                         (from the BEACON chain — neither execution provider)

PHASE A  primary healthy       2026-08-13T18:28:24Z
         endpoint 0, 269 receipts, VERIFIED, 194 ms
PHASE B  primary unavailable   injected HTTP 503
         endpoint 1, 269 receipts, VERIFIED,  93 ms
PHASE C  primary restored
         endpoint 0, 269 receipts, VERIFIED,  62 ms

primary forwards   2        failovers observed  1
primary refusals   1        failure type        http 503
outage duration    176 ms   recovery latency    73 ms
```

Every phase re-verified through the production path against the
beacon-authenticated receiptsRoot. And separately: the secondary's real receipts
verify against the authenticated root, and are **refused** against a root they do
not rebuild to — carrying the request confers no privilege.

## Scope and constraints

Changed: `transport.go` (new), and a few lines each in `client.go` and
`rpcsource.go`. Verified unchanged: `challengebudget.go`, `validation.go`,
`watchtower.go`, `bls.go`, `execution.go`, `proof.go`, `receipts.go`,
`triebuild.go`, `evidence.go`, `anchor.go`, `lightclient.go`,
`evidencereader.go`. No `challengePeriod`, no budget term, no trust anchor, no
deployment gate.

Configuration is `ETH_RPC_URL_PRIMARY` / `ETH_RPC_URL_SECONDARY` in `.env`. No
URL or key appears in source, tests, fixtures, documentation, logs or error
messages — the failover hook receives **indices and a reason, never URLs**, and a
test asserts the total-failure error leaks neither endpoint.

## What this does NOT do

**It does not validate the `rpc failure` budget term.** That term is closed as
NOT MEASURED / NOT VALIDATED by architectural choice, and this does not reopen
it: what was built is transport availability, not the measured recovery-time
evidence the gate asks for. The 30-minute budget is untouched.
