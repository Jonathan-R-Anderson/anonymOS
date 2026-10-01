# Syndichan Storage Node

`syndichan-node` is a single program that lets you donate spare disk space, or
spare bandwidth, to Syndichan. It runs on Windows, macOS, and Linux.

It does two jobs, and you choose one or both:

- **Storage node.** It stores encrypted pieces of other people's files and
  keeps a copy of your own. Everything is encrypted and split up before it
  leaves your machine, and all peer traffic goes over I2P, so other volunteers
  never see your IP address or what any file is. It also gives you a local S3
  endpoint your own applications can use.
- **HTTPS gateway.** Your machine acts as one of the public front doors for
  `syndichan.org`. This one needs a public port and is off by default.

Donated storage **earns credits** you can spend in the store on
`syndichan.org` — see [Getting paid](#getting-paid-proof-of-facilitation).

That's the whole idea. The rest of this page is how to build it, how to run it,
and what to open on your router if you want to run a gateway from home.

## Build it

Everything below runs **from the root of this repository** — the folder holding
`go.mod`, `cmd/` and `internal/`. There is no nested source directory to step
into first. If `ls go.mod` shows the file, you are in the right place.

You need [Go](https://go.dev/dl/). `go.mod` asks for **1.25.12**, but an older
toolchain from 1.21 onwards works too: Go reads that line and downloads the
required toolchain on its own, so `go version` reporting something older is not
a problem and needs no action. Nothing else is required — the build sets
`CGO_ENABLED=0`, so one machine can cross-compile every target and the result
has no C library to match at run time.

```sh
go mod download
go test ./...
```

Build for the computer you're on:

```sh
go build -trimpath -o syndichan-node ./cmd/syndichan-node
```

That leaves a `syndichan-node` binary in the current directory. Run it with
`./syndichan-node`. It reads (and on first run writes) its configuration at
`~/.config/Syndichan/storage-node/config.json` on Linux, and prints the path it
chose on the first line of its output.

**A freshly built node needs an I2P router already running**, because it dials a
SAM bridge at `127.0.0.1:7656` during startup and exits if nothing answers:

```
connect to local I2P SAM bridge at 127.0.0.1:7656: dial tcp ... connection refused
```

That message means the router is not up *yet*, not that the build is broken.
SAM often lags the router by up to two minutes — the console on `:7657` comes up
almost immediately while `:7656` stays closed — so check the port rather than
the service:

```sh
ss -lnt | grep 7656        # nothing yet? wait, then look again
```

See *Install it* for getting a router running in the first place.

If startup instead fails with a bare `timeout`, another `syndichan-node` is
already running against the same data directory and holding its database lock.
Only one instance may use a data directory at a time.

Or build every release binary into `dist/`:

```sh
./scripts/build-release.sh          # Linux / macOS
.\scripts\build-release.ps1         # Windows PowerShell
```

That produces:

| Target machine | Executable |
| --- | --- |
| Intel/AMD Linux | `syndichan-node-linux-amd64` |
| ARM Linux (incl. Raspberry Pi 4/5) | `syndichan-node-linux-arm64` |
| Intel Mac | `syndichan-node-darwin-amd64` |
| Apple Silicon Mac | `syndichan-node-darwin-arm64` |
| Intel/AMD Windows | `syndichan-node-windows-amd64.exe` |
| Windows on ARM | `syndichan-node-windows-arm64.exe` |

These are unsigned binaries. macOS Gatekeeper and Windows SmartScreen will warn
about a build you downloaded rather than compiled yourself.

### The other things you may need to build

The binary is not the whole node. Two of these matter only if you lend compute,
but they are easy to miss because nothing fails until a job is already running.

**A container image, to run the node under Kubernetes or Docker:**

```sh
docker build -t registry.local/syndichan-node:latest .
```

`registry.local` is **not a real registry** — nothing can pull from it. Under
k3s the image has to be handed to containerd directly, or the pod sits in
`ImagePullBackOff`:

```sh
docker save registry.local/syndichan-node:latest -o node.tar
sudo k3s ctr images import node.tar
```

**Catalogue images, if this node lends compute.** These live in the site
repository under `compute-images/`, and the same "no real registry" rule applies
— *every machine that runs compute jobs must build them locally*:

```sh
./compute-images/build.sh            # python, c, go and embed
./compute-images/build.sh embed      # just one
```

A node missing a catalogue image does not refuse the job. It accepts it, returns
a ticket, and then fails with `No such image` — which the network reads as a
failed *execution* rather than a missing prerequisite, so it keeps being chosen.
Build them before enabling compute.

**A microVM rootfs, if you are running arbitrary submitted code:**

```sh
./compute-images/rootfs/build-rootfs.sh <dockerfile-dir> rootfs.ext4
```

This prints the image's SHA-256, which is its address on the network. Needs
`mke2fs` (`e2fsprogs`).

## Install it

**One line, on Linux:**

```sh
curl -fsSL https://syndichan.org/install.sh | sh
```

That fetches a prebuilt binary for this machine's architecture, verifies its
published SHA-256 before running anything, installs an I2P router if SAM is not
already answering, and leaves the node running as a non-root systemd service
that comes back after a reboot. It prints the plan and asks before it changes
anything; `| sh -s -- --check` prints the plan and stops. The script is served
as plain text — open <https://syndichan.org/install.sh> and read it first.

Its source is `backend/static/install.sh` in the site repository, because the
file the site serves and the file that was reviewed have to be the same file.

**From source**, which is what the rest of this section covers:
`scripts/install.sh` does the whole Linux setup — it finds what is missing,
installs it, builds the binary here, and leaves the node running as a non-root
service that comes back after a reboot. Use it when you want the compute/DCS
role, an OpenRC machine, or a binary you compiled yourself; the one-liner does
none of those.

**Start with `--check`.** It runs every detection and changes nothing:

```sh
./scripts/install.sh --check
```

That prints a table of each dependency, which role needs it, whether it is
present, and what would be done about it — including the things that *cannot*
be installed (a CPU without `vmx`/`svm`, a VPS with no `/dev/kvm`, the microVM
guest kernel you have to supply yourself). It is also the fastest answer to
"why is my node half-working?", so keep using it after the install.

When the plan looks right:

```sh
sudo ./scripts/install.sh                      # asks before it changes anything
sudo ./scripts/install.sh --yes                # same plan, no questions
sudo ./scripts/install.sh --with-compute       # also prepare Docker for compute
sudo ./scripts/install.sh --no-service         # no boot service; you run it yourself
```

What it does, and does not do:

- **Installs an I2P router only if one is not already there.** It decides that
  by completing a real SAM handshake on `127.0.0.1:7656`, not by checking a
  console port — the console answers immediately while SAM can be two minutes
  behind it. If something already answers, it installs no router and edits no
  router config: two routers fighting over `7656` is worse than none.
- **Waits for SAM properly**, up to five minutes, and installs that same wait
  as the service's `ExecStartPre`. The node has no startup retry, so a service
  that starts before the bridge exists just dies.
- **Runs the node as a dedicated `syndichan` user**, never root, and the only
  path it takes ownership of is the node's own data directory.
- **Enables the router on boot too**, otherwise the node reboots into nothing.
- **Never downloads a guest kernel**, never installs a GPU driver, and never
  claims `/dev/kvm` can be installed. Those it reports.
- **Is safe to re-run.** If the unit file has been edited since the installer
  wrote it, it says so and refuses to overwrite your changes.

On macOS it installs a LaunchAgent instead and says plainly that this starts
the node at login rather than at boot. On a platform it does not recognise it
prints the exact commands to run rather than guessing.

Run `./scripts/install.sh --help` for the full option list.

## Run it as a storage node

**First install I2P**, because the storage node refuses to start without it —
it will never fall back to sending your traffic over the open Internet.

- **Windows / macOS:** the
  [I2P Easy Install Bundle](https://i2p.net/en/downloads/) includes everything.
- **Linux (Ubuntu):**
  ```sh
  sudo apt-add-repository ppa:i2p-maintainers/i2p
  sudo apt-get update && sudo apt-get install i2p
  ```

Then open the router console at `http://127.0.0.1:7657`, go to
**Configure I2P Internals > Clients**, start the **SAM application bridge**, and
tick **Run at Startup**. Java I2P does not turn SAM on by default. Give a fresh
router a few minutes to join the network before worrying about errors.

The node expects I2P's SAM bridge on `127.0.0.1:7656` and its HTTP proxy on
`127.0.0.1:4444`. Both stay on loopback — never expose them.

Now start the node as your normal user (not root):

```sh
chmod 755 syndichan-node-linux-amd64
./syndichan-node-linux-amd64
```

```powershell
.\syndichan-node-windows-amd64.exe
```

On first start it creates a mode-0600 config file, your S3 credentials, and
your encryption keys in your user config directory:

- Linux: `~/.config/Syndichan/storage-node`
- macOS: `~/Library/Application Support/Syndichan/storage-node`
- Windows: `%AppData%\Syndichan\storage-node`

Out of the box you get:

| | |
| --- | --- |
| Dashboard | `http://127.0.0.1:9090` |
| S3 endpoint | `http://127.0.0.1:9000` |
| Disk donated | 20 GiB |

Open the dashboard to see what you're storing, change how much disk you donate,
and reject anything you don't want to host. Both ports are loopback by default.
The S3 port should stay that way; the dashboard can be moved to your own LAN if
you want to reach it from another machine — see
[Reaching the dashboard from another machine on your network](#reaching-the-dashboard-from-another-machine-on-your-network).

**Everything is configured in the config file, and the management page is one
way to edit it.** Open `http://127.0.0.1:9090` and from there you can:

- donate more (or less) disk, and choose **where** the encrypted shards live;
- switch to **cache-only** (keep only your own content, host nothing for peers);
- read your **S3 credentials** (they stay in the mode-0600 config file and are
  shown on the page rather than printed to your shell history);
- turn the **volunteer gateway** and **Docker facilitation (DCS)** on or off;
- set the node's **run mode** — storage, gateway-only, or probe-only.

Changes are written to the config file and most take effect the next time the
node starts.

### Reaching the dashboard from another machine on your network

By default the page answers only on `127.0.0.1`, so it is limited to whoever is
sitting at the machine. To open it from your laptop while the node runs on the
box in the cupboard, point `ui_listen` at that machine's **LAN address** and set
a password:

```json
{
  "ui_listen": "192.168.1.50:9090",
  "ui_username": "admin",
  "ui_password": "a-long-password-you-use-nowhere-else"
}
```

Then browse to `http://192.168.1.50:9090/` and the browser will ask for that
username and password.

Three rules are enforced, and the node refuses to start rather than bend them:

- **A private address only.** `10.x`, `172.16–31.x`, `192.168.x`, `169.254.x`,
  or an IPv6 unique-local `fc00::/7` address. A publicly routable address is
  refused: this page can change your payout address.
- **`0.0.0.0` and `::` are refused**, even with a password. They bind *every*
  interface the machine has now or acquires later — the LAN one you meant, and
  also the public one on a rented server, and the café Wi-Fi a laptop joins next
  week. Name the address you actually mean.
- **A password of at least 12 characters** whenever the address is not loopback.
  There is no lockout, and anyone on the network can try. `ui_username` is
  optional and defaults to `admin`.

The password is stored as typed in the mode-0600 config file — the same file
that already holds your S3 secret key — so **use one you do not use anywhere
else**. It is hidden from `-show-config` output. It travels over plain HTTP on
your LAN, which is why this is limited to networks you control.

Leaving `ui_listen` on loopback needs no password and changes nothing.

**On a server with no browser, use the flags instead.** The management page
binds loopback by default, and can only be moved to a private address (never a
public one), so an operator with only SSH into a public host cannot reach it.
Every setting lives in the JSON and can be edited with any text editor; these
are the handful people change on first run:

| Flag | What it does |
| --- | --- |
| `-config <path>` | use a config file other than the default location above |
| `-payout 0x…` | where CREDIT earnings are sent; saved to the config |
| `-capacity-gib <n>` | how much disk to donate |
| `-ui-listen off` | turn the management page off entirely |
| `-show-config` | print the effective config (secret redacted) and exit |
| `-config-path` | print where the config file is and exit |

A flag is saved to the config and used from then on, so you pass it once rather
than baking it into a service unit:

```sh
./syndichan-node -payout 0xYourWalletAddress -capacity-gib 100 -ui-listen off
```

A bad payout address is refused rather than saved with a warning: a typo there
sends every reward the node ever earns to an address nobody controls.

Back up `master.key` and `metadata.db` from your data directory. Without them
your own uploaded files cannot be reassembled — no peer can do it for you,
which is the point.

## Getting paid: Proof of Facilitation

Donating disk earns **CREDIT**, the network's token on ZKsync Era. You spend it
in the store on `syndichan.org`, and other people buy it with a card — which is
where the money behind it comes from.

### Set a payout address

Nothing is earned without one, because there is nowhere to send it:

```sh
./syndichan-node -payout 0xYourWalletAddress
```

or set `"payout_address"` in the config file. On start the node publishes that
address **signed by its own identity key**, so nobody who learns your node's id
— which is public, it is the libp2p peer id — can redirect your earnings to
themselves. The declaration carries a sequence number, so the newest signed
statement wins and an old one cannot be replayed to point you somewhere else.

It is an ordinary wallet address. Nothing about it needs to match the machine
the node runs on, so several nodes can pay into one wallet.

### What actually earns

Time is cut into **epochs** of one hour. In each one your node:

1. **advertises what it holds** — the shards it can prove possession of;
2. **answers audits** — a peer drawn to test you asks for a Merkle proof over
   chunks it picks from the epoch randomness, so the answer cannot be prepared
   in advance and possession is the only way to produce it;
3. **performs audits** — you are drawn to test other people's shards on the
   same public rule, and doing that work is worth more than merely being
   auditable, because the network needs auditors more than it needs volunteers;
4. **uploads the receipts** it earned, each signed by the provider and attested
   by witnesses the protocol selected — not chosen by either party.

At the end of an epoch the receipts are settled: their roots go on-chain, a
challenge window opens in which anyone holding the same receipts can recompute
the roots and dispute a mismatch, and rewards are claimable against the reward
root once it finalizes.

Two consequences worth stating plainly:

- **A cache-only node earns nothing from storage.** It hosts no shards for
  peers, so there is nothing for anyone to audit. That is a legitimate way to
  run — you keep your own content and nothing else — it just is not paid work.
- **Being offline is not punished, it is simply unpaid.** A node nobody can
  reach earns nothing that epoch, and unreachable is never recorded as
  dishonest. A power cut is not fraud.

### Reputation

Every node carries a score derived from what it actually did — proofs accepted,
audits performed, proofs failed — published at
[syndichan.org/reputation](https://syndichan.org/reputation). It is recomputed
from the evidence on every view rather than stored, so there is no number anyone
can edit, and you can recompute it yourself from the same public receipts.

Gains are slow and penalties are not. Failing an audit costs a little; being
caught attesting with witnesses nobody drew costs enormously, because a
reputation that is cheap to rebuild is not worth protecting.

### Watching it work

```
proof-of-facilitation: earnings will be paid to 0x…
proof-of-facilitation: epoch anchor is epoch 0 at unix …, 3600s each
proof-of-facilitation: answering audits for 12 shard(s) as node 9587ac2d…
proof-of-facilitation: uploaded 3 receipt(s) for epoch 41
```

The node id in that log is the same one the reputation page lists. If you see
`NO PAYOUT ADDRESS SET`, the node is serving the network for free.

## Running from home: ports and forwarding

**As a plain storage node you do not need to open anything.** All peer traffic
goes out through I2P, which handles its own connections. If that's all you want
to do, you're finished — skip this section.

**A gateway is different.** It is a public web server, so the Internet has to be
able to reach your machine, and a home router blocks that by default. To run a
gateway from your house you need to do three things on your own network:

1. **Give the machine a fixed address on your LAN.** In your router's DHCP
   settings, reserve an address for it (something like `192.168.1.50`). If the
   address changes, your forwarding rules quietly stop working.

2. **Forward the ports on your router.** In the router admin page — usually
   under *Port Forwarding*, *Virtual Server*, or *NAT* — send incoming traffic
   to that machine:

   | Port | Protocol | Forward to | Needed for |
   | --- | --- | --- | --- |
   | 443 | TCP | your machine's LAN IP, port 443 | the gateway itself |
   | 80 | TCP | your machine's LAN IP, port 80 | only if the node gets its own certificate (`tls.mode: "acme"`) |

   The node deliberately does not use UPnP to punch holes for you. You open the
   ports yourself, knowingly.

3. **Allow the same ports in the machine's own firewall.** Forwarding on the
   router is not enough if the computer itself drops the connection.

   ```sh
   sudo ufw allow 443/tcp && sudo ufw allow 80/tcp    # Linux (ufw)
   ```

   ```powershell
   New-NetFirewallRule -DisplayName "Syndichan 443" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
   ```

Then check from **outside** your network — a phone on mobile data works well.
Testing from inside your own LAN often succeeds even when the Internet cannot
reach you, so it proves nothing:

```sh
curl --fail https://your-gateway-hostname/readyz
```

If it never works from outside, the usual causes are: your ISP puts you behind
CGNAT (a shared address you cannot forward through), you have two routers
chained together and only forwarded through one of them, port 443 is already
taken by something else on that machine, or IPv6 is being filtered separately
from IPv4. CGNAT in particular cannot be fixed from your end — you'd need a
static or public IP from your ISP.

Before a gateway is trusted with real traffic, independent probe nodes on other
networks connect back to your public address and verify it. A gateway that only
answers on your LAN is never admitted.

## Run a dedicated gateway (no storage)

For a VPS or spare box that should only forward HTTPS and store nothing, set the
run mode to **gateway-only** on the management page (or `"run_mode":
"gateway-only"` in the config file), then start the node:

```sh
./syndichan-node -config gateway.json
```

Gateway-only runs the gateway and nothing else: no shard store, no S3, no I2P.
The management page still comes up (on loopback) so you can edit the gateway
settings there. Copy [`gateway.example.json`](gateway.example.json) as a starting
point and set at minimum `run_mode: "gateway-only"`, `gateway.enabled`, your
public address, and how TLS is handled.

It does still send the five-minute presence heartbeat, reporting zero capacity.
That is how the operator's map knows your gateway exists and separates it from
a storage node.

### ⚠️ Put your real email in the config first

If `tls.mode` is `"acme"`, **you must replace the placeholder email**:

```json
"tls": {
  "mode": "acme",
  "acme_email": "you@your-real-domain.example",
  "acme_http_address": "0.0.0.0:80"
}
```

The example ships `operator@example.com`, and Let's Encrypt **refuses that
domain outright**. The failure is indirect and easy to misread — you get no
certificate, so the controller's connect-back to your port 443 fails TLS, and
the only thing you see is:

```text
gateway registration publish failed: gateway registry returned HTTP 422
```

The real error is one line earlier in the log:

```text
400 urn:ietf:params:acme:error:invalidContact: contact email has forbidden domain "example.com"
```

The address is used only for Let's Encrypt expiry warnings. It is not published
in DNS, not sent to the controller, and never appears in your certificate.

### Wait — how can several gateways have certificates for `syndichan.org`?

They don't, and this is the part worth understanding.

**Your gateway never holds a certificate for `syndichan.org`.** It gets one for
a hostname of its own, `gw-<your-node-id>.syndichan.org`, which the controller
assigns from your node's identity. No two gateways ever request the same name,
so there is nothing to collide.

**It doesn't need one either.** When the frontend forwards site traffic it does
*not* terminate TLS. It reads only the unencrypted SNI field from the opening
ClientHello, decides where the connection belongs, and then splices raw bytes
between the visitor and the origin. The TLS session is end-to-end between the
visitor's browser and the origin server, which holds the real `syndichan.org`
certificate. Your gateway carries ciphertext it cannot read. That is also why
the origin listener is declared `listen 9443 ssl proxy_protocol` — the origin,
not the gateway, does the SSL.

So your `gw-…` certificate exists for one purpose: proving to probes and to the
controller that the machine answering on that address really holds your node's
private key.

**And no, Let's Encrypt has no "one email per domain" rule.** The address is a
property of an ACME *account*, not of a domain. Every gateway creates its own
account with its own key and its own contact address, and any number of
accounts may hold certificates for names under the same parent domain.

The limit that *does* matter is different: Let's Encrypt allows roughly **50
certificates per registered domain per week**. Each brand-new gateway spends
one of those on its `gw-…` name (renewals are counted separately), so onboarding
more than ~50 new gateways in a single week would hit the ceiling.

### About `probe_urls`

Before a gateway is trusted, something has to prove it is genuinely reachable
from the outside rather than just claiming to be. Two independent things can do
that, and `gateway.external_verification` picks which you use:

- **`enabled: true` (the default)** — your node asks other volunteers running in
  **probe-only** run mode to connect back to your public address and confirm it. Those
  volunteers' URLs go in `probe_urls`, and you need at least as many as
  `minimum_successful_probes` (3 by default), spread across at least two
  different networks. This is the stronger check, but it needs a probe fleet to
  exist.
- **`enabled: false`** — skip the peer probes. Your node still registers with
  the controller, and the controller still connects back to your address and
  checks `/readyz` itself before putting you in DNS. You just don't get the
  independent multi-network opinion, so your node never reports itself as
  "verified".

If you are standing up the first gateway there are no probes to point at yet,
so use the second form:

```json
"external_verification": { "enabled": false }
```

There is also a **probe-only** run mode, which runs just the verification probe
service — that is what other people would point their `probe_urls` at. Set it on
the management page or with `"run_mode": "probe-only"`.

The gateway is turned on, off, and configured on the management page at
`http://127.0.0.1:9090` (the "Volunteer gateway" panel), which writes those
settings to the config file.

### Run it automatically on boot (Linux / systemd)

This is the set-and-forget setup: start it once, and it comes back on reboot and
after a crash without you touching it. Works on Ubuntu, Debian, Fedora, Arch,
RHEL — anything with systemd.

**1. Lay it out.** Keep the binary, the config and the data under one directory:

```sh
mkdir -p ~/syndichan-node/{bin,config,data}
cp syndichan-node ~/syndichan-node/bin/
cp gateway.json  ~/syndichan-node/config/config.json
chmod 600 ~/syndichan-node/config/config.json
```

**2. Create the service.** Save it as
`/etc/systemd/system/syndichan-node.service`.

**Replace `EXAMPLE` with your own username everywhere it appears** — six places
below. If your user is `alice`, every `/home/EXAMPLE/...` becomes
`/home/alice/...`.

```ini
[Unit]
Description=Syndichan Gateway Node
Wants=network-online.target
After=network-online.target
# These two belong in [Unit], not [Service] -- systemd moved them, and it
# silently ignores them if you put them under [Service].
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=EXAMPLE
Group=EXAMPLE
WorkingDirectory=/home/EXAMPLE/syndichan-node
# No posture flags: run mode (gateway-only here), the data directory and
# everything else come from the config file. Set "run_mode": "gateway-only" in
# it, or switch it on the management page.
ExecStart=/home/EXAMPLE/syndichan-node/bin/syndichan-node \
    -config /home/EXAMPLE/syndichan-node/config/config.json

# Ports 80 and 443 are privileged. This is what lets an ordinary user bind
# them; without it the service dies instantly with "permission denied".
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# on-failure, not always: a bad config should stop and tell you, not respawn
# forever. The burst limit in [Unit] above gives up after 5 tries in 60s.
Restart=on-failure
RestartSec=5s

# Let in-flight connections drain and the gateway publish its withdrawal.
TimeoutStopSec=75s
LimitNOFILE=65535

# Sandboxing. The node needs to write only its own directory.
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=read-only
# This must be the "data_dir" from the config file above, and the DATA DIRECTORY
# ITSELF -- not <data_dir>/storage. The node writes i2p.destination, p2p.key and
# content.key beside storage/, so a unit that lists only the subdirectory starts,
# opens the shard store, and then dies on the next file. If data_dir lives on
# another disk, list that path here (several paths are allowed, space separated,
# quoted if they contain spaces) or the node fails with
# "read-only file system" on a mount that is perfectly writable.
ReadWritePaths=/home/EXAMPLE/syndichan-node
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

**3. Enable and start it.** `--now` does both: starts it immediately *and*
enables it at boot.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now syndichan-node
```

**4. Confirm, then forget about it:**

```sh
systemctl status syndichan-node
journalctl -u syndichan-node -f          # live log; Ctrl-C to stop watching
```

You want to see `Active: active (running)` and a line like
`volunteer gateway candidate listening on 0.0.0.0:443`. That's it — it now
survives reboots and restarts itself if it ever exits.

Three things people get wrong here:

- **Keep the data directory stable.** It holds `p2p.key`, your node's permanent
  identity, which determines your `gw-….syndichan.org` hostname and your
  certificate. It defaults to the config file's own directory and can be moved on
  the management page (`data_dir` in the config). What matters is that it does not
  *change* between runs — running once by hand with `sudo` and once as a service
  against different data directories creates *two different identities*, two
  hostnames and two certificates.
- **Don't run a second copy by hand while the service is up.** Only one process
  can hold ports 80 and 443; the second exits with "address already in use".
  Use `sudo systemctl stop syndichan-node` first.
- **`ProtectHome=read-only` plus `ReadWritePaths`** is what keeps the node from
  writing anywhere in your home directory except its own folder. If you move
  the installation, update `ReadWritePaths` too or it will fail to write.

Everyday commands:

```sh
sudo systemctl restart syndichan-node     # after editing the config
sudo systemctl stop syndichan-node        # graceful, withdraws it from DNS
sudo systemctl disable --now syndichan-node   # stop and remove from boot
```

To upgrade, replace the binary and restart:

```sh
sudo systemctl stop syndichan-node
cp /path/to/new/syndichan-node ~/syndichan-node/bin/syndichan-node
sudo systemctl start syndichan-node
```

A ready-made copy of this unit ships as
[`packaging/systemd/syndichan-node-gateway-home.service`](packaging/systemd/syndichan-node-gateway-home.service),
and [`GATEWAY.md`](GATEWAY.md) covers a timer that pulls and rebuilds from git
automatically, with rollback if the new build fails to come up.

**Non-systemd systems:** on Alpine (OpenRC) or a BSD, run the same command under
your init's supervisor. The only requirements are that the process runs as a
consistent user, uses the same data directory every time, and can bind ports 80
and 443.

Full setup — TLS modes, probe quorum, serving `syndichan.org` through your box,
systemd units, and automatic updates — is in [`GATEWAY.md`](GATEWAY.md).

## Run a container worker (Distributed Container Service)

Optional, **off by default**, and a real donation of compute: a container
worker runs Docker containers for other people over I2P — a decentralized,
registry-free, coordinator-free container service. Only enable it if you mean to
lend your machine's CPU and memory to strangers.

A worker runs **alongside** a storage node — it reuses the same I2P bridge, the
same peer identity, the same DHT, and the same shard store — so you start it by
adding a `dcs` block to a normal storage node's `config.json`, not by running a
separate program.

### What you need

- A working storage node (the section above): I2P running, SAM enabled.
- **Docker**, reachable at the endpoint in the config (default
  `unix:///var/run/docker.sock`). Your user must be able to talk to it (be in the
  `docker` group). If Docker is not reachable the node logs it and keeps running
  as a plain storage node — the worker just does not start.

### Turn it on

Open the **Docker facilitation (DCS)** panel on the management page
(`http://127.0.0.1:9090`) and tick *Enable DCS* + *Run containers (worker)*, set
the limits, and save — or edit `config.json` directly, setting at least `enabled`
and `role.worker`:

```json
"dcs": {
  "enabled": true,
  "role": { "worker": true, "lab": false, "gpu": false, "volumes": false },
  "limits": {
    "max_containers": 4,
    "ram_bytes": 4294967296,
    "max_runtime_seconds": 0,
    "lab_max_runtime_seconds": 14400
  },
  "docker_endpoint": "unix:///var/run/docker.sock"
}
```

Then start the node the normal way:

```sh
./syndichan-node-linux-amd64
```

You should see, after the node comes up:

```text
dcs: container worker started (slots=4, lab=false, ttl=24h0m0s)
```

That is the whole thing. The worker now:

- **publishes a capability record** to the DHT so others can find it (expires
  and refreshes on its own, like the gateway record — a crashed worker vanishes);
- **accepts signed deployment requests** over I2P on `/syndichan/dcs/1.0.0`;
- **caps concurrent containers** at `max_containers`. Beyond that, further
  requests are **queued** and the requester is told their place in line and an
  estimated wait — nobody is bogged down past what you set;
- **allows one running instance per requester**, so a single user cannot fill
  your worker (different users running the *same* image as separate instances is
  fine);
- **auto-spins-down every instance after 24 hours** (`max_runtime_seconds`, or
  the default), so a forgotten container is always reclaimed;
- **gives each container its own I2P destination** and nothing else — no clearnet
  egress, no host network, dropped capabilities, read-only root filesystem.

### The limits are yours

Every knob under `limits` is a promise to yourself about how much this costs:

| Field | Meaning |
| --- | --- |
| `max_containers` | Hard cap on simultaneous containers. This is the "don't bog down my machine" dial. |
| `ram_bytes` | Advertised memory; also the per-container ceiling. |
| `max_runtime_seconds` | Auto spin-down for any instance. `0` uses the 24-hour default. |
| `lab_max_runtime_seconds` | Stricter ceiling for lab workloads (default 4h). |
| `image_cache_bytes` | Disk budget for cached build layers. |

Everything under `policy` defaults to a refusal: no interactive shell
(`allow_exec`), no clearnet egress for containers (`allow_clearnet_egress`), no
public gateway exposure (`allow_gateway_publish`). Turn one on only if you
understand what it lets a stranger's container do on your machine.

### Registry-free images: the Dockerfile lives on the DHT

There is no Docker Hub in this design. A deployer packs a **build context** —
the Dockerfile plus its supporting files — into one content-addressed blob that
is stored on the network as encrypted shards, exactly like any other object. A
worker fetches that blob by digest, verifies it, and runs `docker build`
locally. So the image is reproduced from source on your machine; nothing is
pulled from a registry, and a tampered build context fails its digest check.

### Vulnerable-host labs (Attack Range)

`role.lab` is a **separate** opt-in from `role.worker`. Set it only if you are
willing to host deliberately-vulnerable containers (e.g. Splunk Attack Range)
for security researchers. A lab container is reachable **only** at an I2P
destination that is never published anywhere — the researcher who deployed it is
the sole party told the address — and it is denied clearnet egress and gateway
exposure unconditionally, and destroyed after its (short) TTL no matter what. A
plain `worker` never receives lab workloads. Do not enable `lab` casually; see
[`DCS.md`](DCS.md) §19 for exactly what it means to host one.

### Turn it off

Set `"enabled": false` (or `"role": {"worker": false}`) and restart. Running
containers are reclaimed as they hit their TTL, or immediately with a normal
`docker stop`/`rm` — they are ordinary containers with DCS labels.

### Deploying to the network

Deploys happen through a **bridged website**, not a command-line flag. A person
picks a challenge on the site (its Lab page); the site's bridge node — a normal
node running the loopback deploy API described below — finds a worker over I2P,
hands it the build context (a Dockerfile, or a `docker-compose` project, stored
on the DHT), and returns the container's **private `.b32.i2p` address** to that
one user. The images themselves are pulled from a registry; only the small build
context rides on the DHT.

Everything the operator promised still holds:

- a container gets its own I2P destination and nothing else — one address carries
  every port, so the deployer can port-scan the box across all of them;
- a lab box's address is disclosed to its deployer alone;
- each user may run **one instance at a time**; different users may run the same
  image as separate instances;
- when the network is at capacity the user is **queued**, with a live place in
  line and a countdown, until a slot frees;
- every instance **auto-spins-down at its TTL** whether or not anyone stays online.

### Bridge a website to the container service

A **website** has thousands of users and cannot ask each of them to run a node.
The **bridge** is how a site deploys on its users' behalf through a single node:
it runs a normal storage node with a small loopback HTTP API, and the site's
backend calls that
API to publish challenge images, spin instances up, poll the queue, and spin
them down.

This is exactly how Syndichan's own Attack Range page works
(`backend/services/attack_range.py` → `NodeBridgeClient`).

Turn it on by adding `api_listen` to the `dcs` block. The bridge needs no
`role.worker` — a node can bridge without running containers itself — but it does
need the full storage substrate (I2P, DHT, shard store):

```json
"dcs": {
  "enabled": true,
  "api_listen": "127.0.0.1:8760"
}
```

You should see, after the node comes up:

```text
dcs-bridge: deploy API listening on 127.0.0.1:8760 (loopback/cluster-internal only)
```

Point the website at it with an environment variable:

```sh
export DCS_NODE_URL=http://127.0.0.1:8760   # or the cluster-internal address
```

The API is four endpoints, all JSON, all meant for a co-located caller only:

| Endpoint | Purpose |
| --- | --- |
| `PUT /dcs/blob` | Store a packed build context on the DHT; returns its `sha256:` digest. |
| `POST /dcs/deploy` | Deploy for a user (`on_behalf_of`); returns which worker took it, the container id, and the private `.b32.i2p` — or a queue position + ticket. |
| `POST /dcs/status` | Report a queued deploy's place in line. |
| `POST /dcs/destroy` | Spin a container down before its TTL. |

> ⚠️ **`api_listen` is unauthenticated by design** — the trust boundary is the
> network, not a credential. Bind it to loopback or a cluster-internal address
> the public cannot reach. Never expose it on a public interface.

**Per-user accounting without a node per user.** The bridge deploys every user
through one node identity but tags each request with an opaque `on_behalf_of`
id. So the worker's "one container per user" rule keys on the *real* end user,
not on the shared bridge — otherwise a whole site would be capped to a single
container per worker. A worker only honours that sub-accounting from a node it
trusts, so each **worker** that should accept a site's traffic lists the bridge
node's id under `policy.trusted_brokers`:

```json
"dcs": {
  "enabled": true,
  "role": { "worker": true, "lab": true },
  "policy": { "trusted_brokers": ["12D3KooW…the-bridge-node-id"] }
}
```

Without that entry the worker still runs the container, but accounts the whole
site as one owner — the safe default. `trusted_brokers` is the deliberate opt-in
that says "let this node name its sub-owners honestly," the same trust a company
places in one service account that deploys for its employees.

The full architecture — scheduling, the RPC protocol, image distribution,
failure recovery, the security model, and the roadmap — is in [`DCS.md`](DCS.md).

## When something goes wrong

- **`connect to local I2P SAM bridge ... connection refused`** — I2P isn't
  running, or the SAM bridge isn't enabled. See the run section above.
- **Bootstrap or coordinator requests fail** — I2P's HTTP proxy on port 4444
  needs a working outproxy. There is intentionally no direct fallback.
- **Port 9000 or 9090 already in use** — stop whatever else is using it, or
  change the address in `config.json`.
- **The dashboard won't let you lower your donated space** — you're storing
  more than the new limit. Remove some content first.
- **`ui_listen … makes the management dashboard reachable from your local
  network`** — you moved the dashboard off loopback, so it needs a password.
  Set `ui_password` (12+ characters) in the config file, or put `ui_listen`
  back to `127.0.0.1:9090`.
- **`ui_listen … binds every interface` / `is publicly routable`** — the
  dashboard may only be bound to loopback or a private LAN address. Use the
  machine's actual `192.168.x` / `10.x` address rather than `0.0.0.0`.
- **The gateway works locally but never gets verified** — it's a reachability
  problem, not a config problem. Work through the ports section above and test
  from another network.
- **Gateway-only mode won't start** — it needs `gateway.enabled` or
  `gateway.probe_enabled` set to true in the config file (the "Volunteer gateway"
  panel on the management page). The startup log prints the role and the exact
  config path it loaded.
- **`gateway.external_verification needs 3 probe_urls`** — you have no probe
  fleet to verify against. Set `external_verification.enabled` to false and let
  the controller do the reachability check; see the section above.
- **`gateway public_addresses is empty`** — list this host's literal public IP,
  e.g. `"public_addresses": ["203.0.113.10"]`. Run `curl ifconfig.me` on the
  box to find it.
- **`dcs: Docker is not reachable ... worker not started`** — the node is fine
  as a storage node, but the container worker needs Docker. Check the daemon is
  running and your user can reach `docker_endpoint` (`docker ps` should work).
- **`dcs: worker role requires full storage mode; not started`** — a container
  worker can't run in gateway-only/probe-only run mode; it needs the storage
  node's I2P, DHT and shard store. Set the run mode back to storage and enable the
  `dcs` panel.

## More detail

- [`GATEWAY.md`](GATEWAY.md) — gateway roles, verification protocol, and deployment
- [`DCS.md`](DCS.md) — the container service: architecture, RPC, scheduling, security
- [`SECURITY.md`](SECURITY.md) — what is and isn't protected, and from whom
- [`../gateway-controller/README.md`](../gateway-controller/README.md) — the
  server side that owns DNS

Two things worth knowing up front. The node sends a signed heartbeat directly
over HTTPS to `syndichan.org` every five minutes, so the site operator sees your
IP address — exactly as they would if you simply visited the site. The privacy
guarantee is between *volunteers*: other peers only ever see an I2P destination,
never your address. And the local S3 credentials are yours alone; they are never
sent anywhere and the server neither holds nor needs them.

Supported S3 operations cover ordinary AWS SDK use including multipart upload.
Versioning, server-side copy, and presigned-query auth return `NotImplemented`
rather than silently doing something different.
