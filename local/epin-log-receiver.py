#!/usr/bin/env python3
"""Robust user-space HTTP receiver for EpinAnonymOS log uploads (no sudo, high port).

Threaded + per-connection timeout so a stalled/partial upload can't wedge it, and it saves whatever
bytes actually arrive (logging got-vs-expected) so a truncated body from the LKL shim is visible.
The FW13 POSTs /run/klog here (busybox-dyn wget --post-file); body is written to ~/epinanonymos-debug.log."""
import http.server, socketserver, os, sys, datetime

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8088
OUT  = os.path.expanduser("~/epinanonymos-debug.log")

class H(http.server.BaseHTTPRequestHandler):
    timeout = 25  # don't hang forever on a stalled body

    def _save(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        data = bytearray()
        try:
            remaining = n if n > 0 else (1 << 30)
            while remaining > 0:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                data += chunk
                remaining -= len(chunk)
        except Exception as e:
            print(f"[receiver] read stopped after {len(data)}B: {e}", flush=True)
        try:
            with open(OUT, "wb") as f:
                f.write(data)
        except Exception as e:
            print(f"[receiver] write error: {e}", flush=True)
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        exp = f"/{n}" if n else ""
        print(f"[receiver {ts}] <- {self.client_address[0]}  got {len(data)}{exp} bytes -> {OUT}", flush=True)
        try:
            self.send_response(200); self.send_header("Content-Length", "3"); self.end_headers()
            self.wfile.write(b"OK\n")
        except Exception:
            pass

    def do_POST(self): self._save()
    def do_PUT(self):  self._save()
    def do_GET(self):
        try:
            self.send_response(200); self.send_header("Content-Length", "24"); self.end_headers()
            self.wfile.write(b"epin log receiver is up\n")
        except Exception:
            pass
    def log_message(self, *a): pass

class Threaded(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

print(f"[receiver] listening on 0.0.0.0:{PORT}  ->  {OUT}", flush=True)
Threaded(("0.0.0.0", PORT), H).serve_forever()
