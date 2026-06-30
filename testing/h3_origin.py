#!/usr/bin/env python3
"""Minimal HTTP/3 origin for testing confiacdn's H3 backend leg.

Standalone for manual smoke checks; testing/all.py later imports this
module and starts/stops the server inside the harness process. Returns
deterministic bodies so the smoke driver can SHA-256 compare.

Routes:
  GET /size/<N>          -> N bytes of seeded random bytes (binary)
  GET /text/<N>          -> N bytes of compressible ASCII text
  GET /status/<code>     -> HTTP <code> with a short body
  GET /404               -> 404 with "not found"
  anything else          -> 200 with "hello\n"

usage:
  python3 testing/h3_origin.py <port> <cert> <key>
"""

from __future__ import annotations

import asyncio
import random
import struct
import sys
from typing import Dict, Optional

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived, H3Event
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent


def _body_for_path(path: str) -> tuple[int, bytes, str]:
    """Return (status, body, content_type) for a path. Deterministic."""
    if path.startswith("/size/"):
        try:
            n = int(path[len("/size/"):])
        except ValueError:
            return 400, b"bad size", "text/plain"
        rng = random.Random(n)
        # Predictable, the same seed gives identical bytes across runs.
        return 200, rng.randbytes(n), "application/octet-stream"
    if path.startswith("/text/"):
        try:
            n = int(path[len("/text/"):])
        except ValueError:
            return 400, b"bad size", "text/plain"
        # Highly compressible ASCII.
        return 200, (b"abcdefghij" * ((n // 10) + 1))[:n], "text/plain; charset=utf-8"
    if path.startswith("/status/"):
        try:
            code = int(path[len("/status/"):])
        except ValueError:
            return 400, b"bad code", "text/plain"
        return code, f"status {code}\n".encode(), "text/plain"
    if path == "/404":
        return 404, b"not found", "text/plain"
    return 200, b"hello\n", "text/plain"


class H3Protocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h3: Optional[H3Connection] = None
        # stream_id -> request headers
        self._requests: Dict[int, Dict[bytes, bytes]] = {}

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._h3 is None:
            self._h3 = H3Connection(self._quic)
        for h3_event in self._h3.handle_event(event):
            self._handle_h3(h3_event)

    def _handle_h3(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            headers = {k: v for k, v in event.headers}
            self._requests[event.stream_id] = headers
            if event.stream_ended:
                self._respond(event.stream_id, headers)
        elif isinstance(event, DataReceived):
            if event.stream_ended:
                headers = self._requests.get(event.stream_id, {})
                self._respond(event.stream_id, headers)

    def _respond(self, stream_id: int, headers: Dict[bytes, bytes]) -> None:
        path = headers.get(b":path", b"/").decode("latin1")
        status, body, ctype = _body_for_path(path)
        self._h3.send_headers(
            stream_id=stream_id,
            headers=[
                (b":status", str(status).encode()),
                (b"content-type", ctype.encode()),
                (b"content-length", str(len(body)).encode()),
                (b"server", b"h3-origin/0.1"),
            ],
        )
        self._h3.send_data(stream_id=stream_id, data=body, end_stream=True)


async def amain(port: int, cert: str, key: str) -> None:
    # session_ticket_handler must be non-None and passed to serve() (not
    # to QuicConfiguration!) for aioquic's server to emit NewSessionTicket
    # frames. We don't persist tickets server-side, so the callback is a
    # no-op — we just need the side effect of enabling ticket issuance.
    config = QuicConfiguration(
        is_client=False,
        alpn_protocols=H3_ALPN,
        max_datagram_frame_size=65536,
    )
    config.load_cert_chain(cert, key)
    await serve(
        host="::",
        port=port,
        configuration=config,
        create_protocol=H3Protocol,
        session_ticket_handler=lambda ticket: None,
    )
    # serve() returns once the listener is up; keep the loop alive.
    await asyncio.Future()


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        sys.stderr.write(f"usage: {argv[0]} <port> <cert> <key>\n")
        return 2
    port = int(argv[1])
    cert = argv[2]
    key = argv[3]
    asyncio.run(amain(port, cert, key))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
