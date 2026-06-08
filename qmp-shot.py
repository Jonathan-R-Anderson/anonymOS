#!/usr/bin/env python3
import socket, json, sys
sock_path, out_path = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sock_path)
f = s.makefile("rw")
def recv():
    line = f.readline(); return json.loads(line) if line.strip() else None
def send(c): f.write(json.dumps(c)+"\n"); f.flush()
recv(); send({"execute":"qmp_capabilities"}); recv()
# optional: inject a relative mouse move so the cursor is somewhere visible
if len(sys.argv) > 3 and sys.argv[3] == "move":
    send({"execute":"input-send-event","arguments":{"events":[
        {"type":"rel","data":{"axis":"x","value":300}},
        {"type":"rel","data":{"axis":"y","value":200}}]}})
    recv()
send({"execute":"screendump","arguments":{"filename":out_path}})
for _ in range(20):
    r = recv()
    if r is not None and "return" in r: break
s.close()
