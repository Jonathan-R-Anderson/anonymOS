# Project Spectre V2: Resource Tracking

We have successfully completed **V2 (Resource Tracking)**. V2 extends Spectre from a process execution flow monitor to a full process-resource graph tracker, capturing files (READ/WRITE) and sockets (CONNECT/LISTEN) in real time.

---

## 1. Core Mechanics

Spectre V2 monitors file and socket access using Python's `psutil`:
* **File Events (`READ` / `WRITE`)**: Obtained via `proc.open_files()`. The file access mode (e.g. `'r'`, `'w'`, `'a'`) determines if it is classified as a read or write event.
* **Network Events (`CONNECT` / `LISTEN`)**: Obtained via `proc.net_connections()`. A process establishing an outbound TCP/UDP connection to a remote IP yields a `CONNECT` event. A process setting up a local listener yields a `LISTEN` event.

---

## 2. Advanced Performance Filters & Optimization

To ensure Spectre remains extremely lightweight (CPU <5%, RAM <200MB) and console noise is minimized, we implemented three key filtering systems:

1. **Targeted Resource Polling**: Files and sockets are only queried for processes spawned **after** Spectre starts. Pre-existing system daemons are not queried for resources, keeping CPU usage extremely low.
2. **IDE/Agent Isolation**: Any process name, command line, or file path containing the agent/workspace identifiers (e.g., `antigravity`, `language_server`) is automatically excluded.
3. **Noisy Resource Exclusions**:
   - Shared libraries (`.so`, `.so.*`) and python bytecode archives (`.pyc`, `__pycache__`) are ignored.
   - Standard system paths like `/usr/lib/`, `/lib/`, and `/usr/share/locale/` are ignored.
   - Outbound loopback/localhost network connections (e.g. `127.0.0.1`, `::1`) are skipped.

---

## 3. Verification Logs

We ran two simulated resource tracking audits:

### Test 1: File READ Event
We ran a python execution to keep a file read open for 3 seconds:
`python3 -c "f = open('/etc/hosts'); import time; time.sleep(3)"`

The monitor successfully outputted the file read under the new process node:
```text
[EVENT DETECTED]
systemd (PID: 1) [Cmd: /usr/lib/systemd/systemd --switched-root --system --deserialize=57 rhgb splash]
    systemd (PID: 2571) [Cmd: /usr/lib/systemd/systemd --user]
        gnome-shell (PID: 2804) [Cmd: /usr/bin/gnome-shell --mode=user]
            antigravity (PID: 4516) [Cmd: /usr/share/antigravity/antigravity]
                language_server_linux_x64 (PID: 5185) [Cmd: /usr/share/antigravity/resources/app/extensions/antigravity/bin/language_serv...]
                    bash (PID: 11567) [Cmd: bash -c trap 'declare -p > "/home/legion/.gemini/antigravity/brain/41f8b7f1-e...]
                        python3 (PID: 11585) [Cmd: python3 -c f = open('/etc/hosts'); import time; time.sleep(3)]
                        ├── [READ] /etc/hosts
                        └── [READ] /proc/5185/smaps
```

### Test 2: Network CONNECT Event
We ran a python execution to connect to an external TCP socket on port 53 (Google DNS) for 3 seconds:
`python3 -c "import socket, time; s = socket.socket(); s.connect(('8.8.8.8', 53)); time.sleep(3)"`

The monitor successfully captured the outbound socket connection in real time:
```text
[EVENT DETECTED]
systemd (PID: 1) [Cmd: /usr/lib/systemd/systemd --switched-root --system --deserialize=57 rhgb splash]
    systemd (PID: 2571) [Cmd: /usr/lib/systemd/systemd --user]
        gnome-shell (PID: 2804) [Cmd: /usr/bin/gnome-shell --mode=user]
            antigravity (PID: 4516) [Cmd: /usr/share/antigravity/antigravity]
                language_server_linux_x64 (PID: 5185) [Cmd: /usr/share/antigravity/resources/app/extensions/antigravity/bin/language_serv...]
                    bash (PID: 11587) [Cmd: bash -c trap 'declare -p > "/home/legion/.gemini/antigravity/brain/41f8b7f1-e...]
                        python3 (PID: 11605) [Cmd: python3 -c import socket, time; s = socket.socket(); s.connect(('8.8.8.8', 53...]
                        ├── [READ] /proc/5185/smaps
                        └── [CONNECT] 8.8.8.8:53 (ESTABLISHED)
```
