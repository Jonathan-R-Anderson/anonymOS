"""The ways somebody actually runs the node, each with a config that fits it.

One config.json is only correct for one of these. The node talks to an I2P
router at `127.0.0.1:7656` and serves its dashboard on `127.0.0.1:9090` — both
true when the binary runs on the machine, both wrong inside a container, where
`127.0.0.1` is the container itself and the dashboard would be reachable by
nobody. Handing out a single config and a list of run methods means every
container user hits the same failure and has to work out the same fix.

So each run target gets its OWN preconfigured config, generated from the same
choices, with the addresses that target needs.

THREE THINGS THAT ARE EASY TO GET WRONG AND ARE GOT RIGHT HERE
--------------------------------------------------------------
* **Port 443 is privileged.** A systemd unit running as an unprivileged user
  cannot bind it. The fix is one ambient capability, not running the whole node
  as root, and it is only added when a role actually needs the port.

* **Windows services are not just "a program that keeps running".** A service
  must speak the service control protocol; this node is an ordinary console
  program, so `New-Service` installs it and then reports that it "did not
  respond in a timely fashion". A scheduled task at startup is the mechanism
  that works, with nothing extra to install.

* **A container needs a Linux binary.** Docker files ship only with the Linux
  downloads. Putting a docker-compose.yml next to a Windows .exe would describe
  an image that cannot be built from what is in the archive.
"""

import copy
import json


def _docker_config(config):
    """The same choices, addressed for inside a container.

    Every changed value here is a value that is correct on the host and wrong in
    a container, not a preference:

    * `i2p_sam` — the router is a sibling container, not localhost.
    * `s3_listen` / `ui_listen` — binding 127.0.0.1 inside a container publishes
      to nothing; the port mapping in compose is what keeps them host-only, and
      it is written as 127.0.0.1:PORT:PORT so the dashboard stays as local as
      the page promises rather than being exposed to the network.
    """
    docker = copy.deepcopy(config)
    docker["i2p_sam"] = "i2pd:7656"
    docker["i2p_http_proxy"] = "http://i2pd:4444"
    docker["s3_listen"] = "0.0.0.0:9000"
    docker["ui_listen"] = "0.0.0.0:9090"
    return docker


def _needs_privileged_port(config):
    gateway = config.get("gateway") or {}
    return bool(gateway.get("enabled") or gateway.get("probe_enabled"))


# -- systemd ---------------------------------------------------------------

def _systemd_unit(binary, config):
    capability = ""
    if _needs_privileged_port(config):
        capability = (
            "# 443 and 80 are privileged ports. This grants the single\n"
            "# capability needed to bind them instead of running the whole node\n"
            "# as root. Ambient capabilities survive NoNewPrivileges.\n"
            "AmbientCapabilities=CAP_NET_BIND_SERVICE\n"
            "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"
        )
    return """[Unit]
Description=Syndichan node
Documentation=https://syndichan.org/network
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=syndichan
Group=syndichan
# config.json is read from the working directory, so this is not cosmetic.
WorkingDirectory=/opt/syndichan-node
ExecStart=/opt/syndichan-node/%(binary)s
Restart=always
RestartSec=5
%(capability)sNoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/syndichan-node

[Install]
WantedBy=multi-user.target
""" % {"binary": binary, "capability": capability}


def _systemd_install(binary, config):
    port_note = ""
    if _needs_privileged_port(config):
        port_note = (
            'echo "This node binds port 443. Forward it on your router, or it"\n'
            'echo "will run and never be reached. Behind carrier-grade NAT that"\n'
            'echo "is not possible at all."\n'
        )
    return """#!/bin/sh
# Install the node as a systemd service. Run from the unpacked archive:
#
#     sh systemd/install.sh
#
set -eu

DEST=/opt/syndichan-node
BINARY=%(binary)s

if [ ! -f "$BINARY" ]; then
    echo "Run this from the unpacked archive — $BINARY is not here." >&2
    exit 1
fi

# A dedicated unprivileged account. The node needs no more than its own files.
if ! id syndichan >/dev/null 2>&1; then
    sudo useradd --system --home-dir "$DEST" --shell /usr/sbin/nologin syndichan
fi

sudo mkdir -p "$DEST"
sudo cp "$BINARY" config.json "$DEST"/
sudo chmod +x "$DEST/$BINARY"
sudo chown -R syndichan:syndichan "$DEST"

sudo cp systemd/syndichan-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now syndichan-node

echo
echo "Installed. Follow it with:  journalctl -u syndichan-node -f"
%(port_note)s""" % {"binary": binary, "port_note": port_note}


# -- launchd ---------------------------------------------------------------

def _launchd_plist(binary):
    return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>org.syndichan.node</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/syndichan-node/%(binary)s</string>
  </array>
  <!-- config.json is read from the working directory. -->
  <key>WorkingDirectory</key>
  <string>/usr/local/syndichan-node</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/usr/local/syndichan-node/node.log</string>
  <key>StandardErrorPath</key>
  <string>/usr/local/syndichan-node/node.err</string>
</dict>
</plist>
""" % {"binary": binary}


def _launchd_install(binary, config):
    note = ""
    if _needs_privileged_port(config):
        note = ('echo "This node binds port 443, which is why it is installed as a"\n'
                'echo "system daemon (running as root) rather than a user agent."\n')
    return """#!/bin/sh
# Install the node as a launchd daemon. Run from the unpacked archive:
#
#     sh launchd/install.sh
#
# Installed under /Library/LaunchDaemons rather than ~/Library/LaunchAgents so
# it runs without anybody being logged in — a node that only exists while you
# are at the keyboard is not much use to the network.
set -eu

DEST=/usr/local/syndichan-node
BINARY=%(binary)s

if [ ! -f "$BINARY" ]; then
    echo "Run this from the unpacked archive — $BINARY is not here." >&2
    exit 1
fi

sudo mkdir -p "$DEST"
sudo cp "$BINARY" config.json "$DEST"/
sudo chmod +x "$DEST/$BINARY"
# macOS refuses to load a daemon whose plist is group- or world-writable.
sudo cp launchd/org.syndichan.node.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/org.syndichan.node.plist
sudo chmod 644 /Library/LaunchDaemons/org.syndichan.node.plist

sudo launchctl bootstrap system /Library/LaunchDaemons/org.syndichan.node.plist \\
    || sudo launchctl load /Library/LaunchDaemons/org.syndichan.node.plist

echo
echo "Installed. Follow it with:  tail -f $DEST/node.log"
%(note)s""" % {"binary": binary, "note": note}


# -- windows ---------------------------------------------------------------

def _windows_install(binary, config):
    firewall = ""
    if _needs_privileged_port(config):
        firewall = """
# Inbound 443/80 for the gateway. This opens the Windows firewall; it does NOT
# forward the port on your router, which is a separate change you have to make
# there or nothing outside your house will reach this node.
New-NetFirewallRule -DisplayName "Syndichan Node (HTTPS)" -Direction Inbound `
    -Action Allow -Protocol TCP -LocalPort 443 -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "Syndichan Node (ACME)" -Direction Inbound `
    -Action Allow -Protocol TCP -LocalPort 80 -ErrorAction SilentlyContinue | Out-Null
"""
    return """# Install the node so it starts with Windows.
# Run in an ADMINISTRATOR PowerShell, from the unpacked archive:
#
#     powershell -ExecutionPolicy Bypass -File windows\\install.ps1
#
# WHY A SCHEDULED TASK AND NOT A SERVICE
# A Windows service has to speak the service control protocol. This node is an
# ordinary console program, so New-Service installs it and then reports that it
# "did not respond in a timely fashion" — a confusing failure with a healthy
# looking install. A scheduled task at startup runs a console program correctly
# and needs nothing extra installed.

$ErrorActionPreference = "Stop"

$Binary = "%(binary)s"
$Dest   = "$env:ProgramFiles\\Syndichan Node"

if (-not (Test-Path $Binary)) {
    Write-Error "Run this from the unpacked archive - $Binary is not here."
}

New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Copy-Item $Binary, "config.json" -Destination $Dest -Force
%(firewall)s
$action = New-ScheduledTaskAction -Execute "$Dest\\$Binary" -WorkingDirectory $Dest
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName "Syndichan Node" -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName "Syndichan Node"

Write-Host ""
Write-Host "Installed and started. Manage it in Task Scheduler under 'Syndichan Node'."
Write-Host "Stop it with:   Stop-ScheduledTask -TaskName 'Syndichan Node'"
Write-Host "Remove it with: Unregister-ScheduledTask -TaskName 'Syndichan Node'"
""" % {"binary": binary, "firewall": firewall}


# -- docker ----------------------------------------------------------------

def _dockerfile(binary):
    return """# Built from the archive root, so the binary and config sit alongside.
FROM alpine:3.20

# ACME and every outbound HTTPS call need a trust store. Without this the node
# starts and then fails every certificate check, which reads as a network fault.
RUN apk add --no-cache ca-certificates && adduser -S -u 10001 syndichan

WORKDIR /app
COPY %(binary)s /app/syndichan-node
RUN chmod +x /app/syndichan-node

USER syndichan
ENTRYPOINT ["/app/syndichan-node"]
""" % {"binary": binary}


def _compose(config):
    gateway_ports = ""
    if _needs_privileged_port(config):
        gateway_ports = """      # Gateway: reachable from the internet. Forwarding these on your
      # router is a separate change — publishing them here only gets them
      # out of the container.
      - "443:443"
      - "80:80"
"""
    return """# docker compose up -d --build
#
# Two containers: the node, and the I2P router it speaks to. They are separate
# because i2pd is a maintained image doing a job that has nothing to do with
# this project, and running it in the same container would mean rebuilding I2P
# every time the node changes.
services:
  i2pd:
    image: purplei2p/i2pd:latest
    restart: unless-stopped
    command: --sam.enabled=true --sam.address=0.0.0.0 --sam.port=7656
    volumes:
      - i2pd-data:/home/i2pd/data
    # SAM is deliberately NOT published to the host. Only the node needs it,
    # and an exposed SAM port is a way to use your I2P identity.
    expose:
      - "7656"

  node:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    restart: unless-stopped
    depends_on:
      - i2pd
    volumes:
      # docker/config.json — the same choices with container addresses.
      - ./config.json:/app/config.json:ro
      - node-data:/app/data
    ports:
      # Bound to 127.0.0.1 on purpose: the dashboard and the S3 endpoint stay
      # reachable from this machine only, which is what the node promises.
      - "127.0.0.1:9090:9090"
      - "127.0.0.1:9000:9000"
%(gateway_ports)s
volumes:
  i2pd-data:
  node-data:
""" % {"gateway_ports": gateway_ports}


# -- assembly --------------------------------------------------------------

def artifacts(platform, binary, config):
    """{path: text} for every way of running this platform's build."""
    files = {}
    system = platform["os"]

    if system == "linux":
        files["systemd/syndichan-node.service"] = _systemd_unit(binary, config)
        files["systemd/install.sh"] = _systemd_install(binary, config)
        # Docker only here: an image needs a Linux binary, so shipping these
        # beside a .exe would describe something the archive cannot build.
        files["docker/Dockerfile"] = _dockerfile(binary)
        files["docker/docker-compose.yml"] = _compose(config)
        files["docker/config.json"] = json.dumps(
            _docker_config(config), indent=2, sort_keys=True) + "\n"
    elif system == "darwin":
        files["launchd/org.syndichan.node.plist"] = _launchd_plist(binary)
        files["launchd/install.sh"] = _launchd_install(binary, config)
    elif system == "windows":
        files["windows/install.ps1"] = _windows_install(binary, config)

    files["README.txt"] = readme(platform, binary, config)
    return files


# Which files are shell scripts, and so need the executable bit in the archive.
def executable_paths(files):
    return {path for path in files if path.endswith(".sh")}


def readme(platform, binary, config):
    """How to run it, in the order somebody should try."""
    system = platform["os"]
    gateway = config.get("gateway") or {}
    # Read back out of the CONFIG rather than taking the page's word for it.
    # This line is how somebody checks the download matches what they asked
    # for, so it has to describe the file, not the request that produced it.
    roles = []
    if gateway.get("enabled"):
        roles.append("gateway")
    if gateway.get("probe_enabled"):
        roles.append("probe")
    if (gateway.get("validator") or {}).get("enabled"):
        roles.append("validator")
    if not config.get("cache_only"):
        roles.append("storage (%.0f GB)" % (config.get("capacity_bytes", 0) / 1024 ** 3))

    if system == "linux":
        ways = """1. Try it first, in this directory
   ------------------------------
       ./%(binary)s

   Reads config.json from the working directory. Ctrl-C stops it. Nothing is
   installed, so this is the cheapest way to find out whether it works here.

2. Keep it running — systemd
   -------------------------
       sh systemd/install.sh

   Installs to /opt/syndichan-node under a dedicated unprivileged account and
   starts at boot. Follow it with `journalctl -u syndichan-node -f`.

3. Keep it running — Docker
   ------------------------
       cd docker && docker compose up -d --build

   Brings up the node AND an I2P router it can talk to. Uses docker/config.json,
   which is this same configuration with the addresses a container needs —
   `127.0.0.1:7656` means the container itself in there, not your I2P router.
   The dashboard is published to 127.0.0.1 only.
""" % {"binary": binary}
    elif system == "darwin":
        ways = """1. Try it first, in this directory
   ------------------------------
       ./%(binary)s

   Reads config.json from the working directory. Ctrl-C stops it.

   macOS Gatekeeper will refuse an unsigned binary downloaded from the web. To
   allow it: right-click the file, choose Open, then confirm — or run
   `xattr -d com.apple.quarantine %(binary)s`. Verify the hash first (VERIFY.txt);
   that is what the hash is for.

2. Keep it running — launchd
   -------------------------
       sh launchd/install.sh

   Installs to /usr/local/syndichan-node as a system daemon, so it runs whether
   or not you are logged in. Follow it with
   `tail -f /usr/local/syndichan-node/node.log`.

3. Docker
   ------
   Not included here: a container image needs a LINUX binary. Download the
   Linux build from https://syndichan.org/network if you want the Docker setup.
""" % {"binary": binary}
    else:
        ways = """1. Try it first, in this directory
   ------------------------------
       .\\%(binary)s

   Reads config.json from the working directory. Ctrl-C stops it.

   SmartScreen will warn about an unsigned program from the internet. Choose
   "More info" then "Run anyway" — after checking the hash in VERIFY.txt, which
   is the part that actually tells you the file is intact.

2. Keep it running — scheduled task
   --------------------------------
       powershell -ExecutionPolicy Bypass -File windows\\install.ps1

   Run it in an ADMINISTRATOR PowerShell. Installs to Program Files and starts
   at boot. Not a Windows service on purpose: a service must speak the service
   control protocol, and this node is a console program, so a service install
   would report that it "did not respond in a timely fashion".

3. Docker
   ------
   Not included here: a container image needs a LINUX binary. Download the
   Linux build from https://syndichan.org/network if you want the Docker setup.
""" % {"binary": binary}

    needs_i2p = not config.get("cache_only")
    i2p_note = ""
    if needs_i2p:
        i2p_note = """
YOU NEED AN I2P ROUTER
----------------------
Storage and validation reach the network over I2P. The node speaks SAM to a
router on 127.0.0.1:7656 — install i2pd (or the Java I2P router) and enable
SAM, or use the Docker option above, which brings one up for you. Without it
the node starts and reports that it cannot reach the network.
"""

    port_note = ""
    if _needs_privileged_port(config):
        port_note = """
YOU NEED AN OPEN PORT
---------------------
This configuration includes a role that must be reachable from the internet on
TCP 443. That means a port-forwarding rule on your router, pointed at this
machine. Opening the firewall on the machine itself is not enough, and behind
carrier-grade NAT — common on mobile and some fibre plans — inbound connections
are not possible at all and this role cannot work.
"""

    return """Syndichan node — %(label)s
%(underline)s

Configured for: %(roles)s

Everything below runs the SAME binary. The only difference is the configuration
and how it is kept running, so pick whichever suits the machine.

%(ways)s%(i2p)s%(port)s
CHANGING YOUR MIND
------------------
Every setting lives in config.json and can be edited afterwards; nothing chosen
on the website is permanent. The node serves its own dashboard on
http://127.0.0.1:9090 — local to this machine only, so running a node does not
expose one more thing to the internet.

Check the binary before you run it: see VERIFY.txt.
""" % {"label": platform["label"],
       "underline": "=" * (len("Syndichan node — ") + len(platform["label"])),
       "roles": ", ".join(roles) if roles else "no role selected",
       "ways": ways, "i2p": i2p_note, "port": port_note}
