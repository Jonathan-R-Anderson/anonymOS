#!/bin/sh
set -e

# dev mode - file storage backend, sqlite, no nginx, etc.
if [ "$1" = "devmode" ]; then
	python3 ensure_runtime.py
	# start up internal pubsub server
	python3 storestub.py &
	python3 - <<'PY'
import socket
import sys
import time

PORTS = (5577, 5578)
deadline = time.time() + 10.0
pending = set(PORTS)
last_errors = {}

while pending and time.time() < deadline:
    for port in tuple(pending):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(0.2)
            sock.connect(("127.0.0.1", port))
            pending.remove(port)
        except OSError as exc:
            last_errors[port] = exc
        finally:
            sock.close()
    if pending:
        time.sleep(0.1)

if pending:
    details = ", ".join("%d (%s)" % (port, last_errors.get(port)) for port in sorted(pending))
    raise SystemExit("storestub did not open required ports in time: %s" % details)
PY
	# start up react sidecar
	/maniwani-frontend/devmode-entrypoint.sh &
	uwsgi --ini ./deploy-configs/uwsgi-devmode.ini
# attempting to bootstrap?
elif [ "$1" = "bootstrap" ]; then
	python3 bootstrap.py
# version upgrade?
elif [ "$1" = "update" ]; then
	python3 update.py
# running normal production mode startup
else
	python3 ensure_runtime.py
	uwsgi --ini ./deploy-configs/uwsgi.ini
fi
