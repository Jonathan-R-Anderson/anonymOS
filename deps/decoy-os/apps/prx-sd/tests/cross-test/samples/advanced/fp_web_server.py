#!/usr/bin/env python3
import http.server, socket, os
server = http.server.HTTPServer(('0.0.0.0', 8080), http.server.SimpleHTTPRequestHandler)
print(f"Serving on port 8080")
server.serve_forever()
