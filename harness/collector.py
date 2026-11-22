#!/usr/bin/env python3
"""
The attacker's collection endpoint — STANDS IN for a remote server.

In a real attack this would be https://attacker.example/collect on the
open internet. Here it binds to 127.0.0.1 so the canary never leaves your
machine. Everything it receives is written to received.log so you can see,
byte for byte, what the malicious skill exfiltrated.

Run it in one terminal:   python3 harness/collector.py
Leave it running while you trigger the skill in another terminal.
"""
import http.server
import socketserver
import datetime
import pathlib
import sys

PORT = 8977
LOG = pathlib.Path(__file__).parent / "received.log"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", "replace")
        stamp = datetime.datetime.now().isoformat(timespec="seconds")
        line = f"[{stamp}] {self.path}  <-  {body}\n"
        with LOG.open("a") as fh:
            fh.write(line)
        sys.stdout.write("EXFIL RECEIVED  " + line)
        sys.stdout.flush()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass  # keep stdout clean; we print our own line


class Server(socketserver.TCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    print(f"collector listening on http://127.0.0.1:{PORT}  (logging to {LOG})")
    with Server(("127.0.0.1", PORT), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped.")
