#!/usr/bin/env python3
"""Local fixtures for the release smoke test.

Two SOCKS5 servers that answer every CONNECT with a banner naming themselves,
and one HTTP server serving a subscription document. Nothing here reaches the
internet: the whole smoke test runs against these, so it works on a laptop with
the network off and cannot depend on somebody else's proxy staying up.

    python3 scripts/smoke-fixtures.py WORKDIR      # run until killed
    python3 scripts/smoke-fixtures.py --probe PORT # ask through a local SOCKS5

It writes WORKDIR/fixtures.env with the ports it chose, so the shell script does
not have to guess or hard-code them.
"""

import base64
import socket
import socketserver
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Socks5Handler(socketserver.BaseRequestHandler):
    """Enough SOCKS5 to be connected to, and no more.

    It never actually connects anywhere: it completes the handshake and then
    writes a banner naming itself, so a test can tell which egress carried a
    connection by reading the answer. That is the whole point — a real onward
    connection would make the test depend on the internet.
    """

    banner = b"EGRESS unnamed"

    def handle(self) -> None:
        try:
            greeting = self.request.recv(262)
            if not greeting or greeting[0] != 0x05:
                return
            # No authentication: these are loopback fixtures, and offering
            # username/password would only add a way for the test to fail.
            self.request.sendall(b"\x05\x00")

            request = self.request.recv(4)
            if len(request) < 4 or request[1] != 0x01:
                return
            kind = request[3]
            if kind == 0x01:
                self.request.recv(4)
            elif kind == 0x03:
                length = self.request.recv(1)[0]
                self.request.recv(length)
            elif kind == 0x04:
                self.request.recv(16)
            self.request.recv(2)

            self.request.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            self.request.sendall(self.banner + b"\n")
        except OSError:
            pass


class ThreadedTcp(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_egress(name: str, port: int) -> ThreadedTcp:
    handler = type(f"Egress{name}", (Socks5Handler,), {"banner": f"EGRESS {name}".encode()})
    server = ThreadedTcp(("127.0.0.1", port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def start_subscription(port: int, links: list[str]) -> HTTPServer:
    document = base64.b64encode("\n".join(links).encode()).decode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = document.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("ETag", '"smoke-1"')
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args) -> None:
            pass

    server = HTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def probe(port: int) -> int:
    """Speak SOCKS5 to a local port and print whatever comes back."""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
        client.sendall(b"\x05\x01\x00")
        if client.recv(2)[:1] != b"\x05":
            print("not a SOCKS5 server", file=sys.stderr)
            return 1
        host = b"example.invalid"
        client.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + (80).to_bytes(2, "big"))
        reply = client.recv(10)
        if len(reply) < 2 or reply[1] != 0x00:
            print("connect refused", file=sys.stderr)
            return 1
        client.settimeout(5)
        print(client.recv(256).decode(errors="replace").strip())
        return 0


def main() -> int:
    if len(sys.argv) >= 3 and sys.argv[1] == "--probe":
        return probe(int(sys.argv[2]))
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2

    work = sys.argv[1]
    alpha, bravo, http = free_port(), free_port(), free_port()
    start_egress("alpha", alpha)
    start_egress("bravo", bravo)

    # The subscription serves credential-free SOCKS links pointing at the two
    # local egresses, so an "update" produces nodes that actually work.
    links = [
        f"socks://127.0.0.1:{alpha}#sub-node-one",
        f"socks://127.0.0.1:{bravo}#sub-node-two",
    ]
    start_subscription(http, links)

    with open(f"{work}/fixtures.env", "w", encoding="utf-8") as handle:
        handle.write(f"EGRESS_A_PORT={alpha}\n")
        handle.write(f"EGRESS_B_PORT={bravo}\n")
        handle.write(f"HTTP_PORT={http}\n")

    threading.Event().wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
