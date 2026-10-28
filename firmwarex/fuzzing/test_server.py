"""Lightweight loopback test server for deterministic protocol fuzzing verification.

Runs strictly on 127.0.0.1 with ephemeral port assignment. Simulates normal responses
and intentional defect boundary triggers (e.g., oversized headers triggering HTTP 500)
to verify fuzzer detection and diagnostic reporting end-to-end without external network access.
"""

import http.server
import socketserver
import threading
from typing import ClassVar


class SyntheticHandler(http.server.BaseHTTPRequestHandler):
    """Handles requests with defensive boundary detection."""

    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self._handle_request()

    def do_POST(self):
        # Read content if present
        content_len = self.headers.get("Content-Length")
        if content_len:
            try:
                _ = self.rfile.read(int(content_len))
            except Exception:
                pass
        self._handle_request()

    def _handle_request(self):
        # Check boundary condition 1: Oversized header trigger
        custom_header = self.headers.get("X-Custom-Fuzz", "")
        if len(custom_header) >= 1024:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Simulated buffer overflow trigger in header"}')
            return

        # Check boundary condition 2: Path traversal trigger
        if "shadow" in self.path or "etc" in self.path:
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Path traversal attempt blocked"}')
            return

        # Normal response
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "16")
        self.end_headers()
        self.wfile.write(b'{"status": "ok"}')

    def log_message(self, format, *args):
        # Suppress noisy HTTP request logging during automated tests
        pass


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address: ClassVar[bool] = True


class SyntheticLocalTestServer:
    """Manages lifecycle of loopback test server for fuzzing tests."""

    def __init__(self, host: str = "127.0.0.1"):
        self.host = host
        self.server: ThreadedTCPServer | None = None
        self.thread: threading.Thread | None = None
        self.port: int | None = None

    def start(self) -> int:
        """Start the test server on an ephemeral loopback port and return port number."""
        self.server = ThreadedTCPServer((self.host, 0), SyntheticHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self.port

    def stop(self):
        """Shut down the server and terminate background thread."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
