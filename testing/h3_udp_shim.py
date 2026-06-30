#!/usr/bin/env python3
"""UDP datagram-perturbing relay for confiacdn's HTTP/3 (QUIC) transport tests.

Sits between an HTTP/3 client (testing/h3_smoke, or the daemon's Http3 leg)
and the aioquic origin (testing/h3_origin.py), forwarding UDP datagrams in
both directions while applying a configurable
drop / reorder / duplicate / corrupt / blackhole policy.

Why this exists: the TCP "misbehaving origin" profiles in all.py
(disconnect / rst_mid_body / freeze / slowheader ...) cannot reach the
QUIC-specific failure modes, because QUIC rides UDP and does its own loss
recovery, packet-number dedup, AEAD authentication and idle/PTO timers.
Those paths only get exercised if individual *datagrams* are dropped,
reordered, duplicated or corrupted at the worst possible moment (handshake,
mid-body, the FIN-bearing tail). This relay is the injection point.

The relay is deliberately dumb: it never parses QUIC. It only counts
datagrams and forwarded bytes per direction and applies index/byte-threshold
based policies. All randomness is seeded, so a given policy + seed produces
the same drop pattern every run.

Directions:
  c2o   client -> origin   (datagrams received on the listen socket)
  o2c   origin -> client   (datagrams received on the upstream socket)

It is a per-connection NAT-style relay: each distinct client source address
gets its own dedicated upstream socket to the origin, so the origin sees a
stable 4-tuple per QUIC connection. Runs until killed (SIGTERM/SIGKILL).

usage:
  python3 h3_udp_shim.py --listen-port P --origin-port Q [policy flags]

The origin host defaults to ::1 (the harness binds the aioquic origin on
[::]:Q and confiacdn resolves every name to ::1 under
FORCEALLDNSTOLOCALHOSTIPV6). The listen host defaults to ::1.
"""

from __future__ import annotations

import argparse
import random
import selectors
import socket
import sys
import time
from typing import Dict, List, Optional, Tuple


C2O = "c2o"  # client -> origin
O2C = "o2c"  # origin -> client


class Policy:
    """Per-direction perturbation policy. Pure bookkeeping; no QUIC parsing.

    Counters are kept per direction so thresholds ("first N", "after N bytes")
    are meaningful. The decide() method returns the list of datagrams to
    actually emit for one received datagram:
      []            -> drop
      [d]           -> forward unchanged
      [d, d]        -> duplicate
      [d']          -> forward corrupted copy
    Reordering is applied separately, at emit time, by emit()/flush_held():
    decide() determines *which* datagrams result (in arrival order) and emit()
    determines the *order* they hit the wire.
    """

    def __init__(self, args: argparse.Namespace):
        self.a = args
        # Per-direction datagram counts and forwarded-byte tallies.
        self.count: Dict[str, int] = {C2O: 0, O2C: 0}
        self.bytes_seen: Dict[str, int] = {C2O: 0, O2C: 0}
        self.total_bytes = 0
        # Independent RNG per direction so c2o/o2c fractional drops don't
        # correlate. Seeded for reproducibility.
        self.rng: Dict[str, random.Random] = {
            C2O: random.Random(args.seed ^ 0x1111),
            O2C: random.Random(args.seed ^ 0x2222),
        }
        # Emit-time sequence counter and single held datagram per direction,
        # used to implement adjacent-swap reordering (a held datagram is
        # released right after the next one is emitted).
        self._eseq: Dict[str, int] = {C2O: 0, O2C: 0}
        self._held: Dict[str, Optional[Tuple[bytes, object]]] = {
            C2O: None, O2C: None}
        # Stats for the final report.
        self.dropped: Dict[str, int] = {C2O: 0, O2C: 0}
        self.duped: Dict[str, int] = {C2O: 0, O2C: 0}
        self.corrupted: Dict[str, int] = {C2O: 0, O2C: 0}
        self.reordered: Dict[str, int] = {C2O: 0, O2C: 0}
        self.blackholed = False

    # --- helpers ---------------------------------------------------------

    def _frac(self, direction: str) -> float:
        return self.a.drop_c2o_frac if direction == C2O else self.a.drop_o2c_frac

    def _first(self, direction: str) -> int:
        return self.a.drop_c2o_first if direction == C2O else self.a.drop_o2c_first

    def _corrupt_every(self, direction: str) -> int:
        return self.a.corrupt_c2o if direction == C2O else self.a.corrupt_o2c

    @staticmethod
    def _corrupt(data: bytes) -> bytes:
        """Flip the final byte. For any 1-RTT short-header QUIC packet the
        last 16 bytes are the AEAD auth tag, so a flip there makes the packet
        fail authentication -> the peer MUST silently discard it (RFC 9000
        §10.2) and rely on retransmission. We never touch the first byte
        (header form / connection-id routing)."""
        if not data:
            return data
        b = bytearray(data)
        b[-1] ^= 0xFF
        return bytes(b)

    # --- the decision ----------------------------------------------------

    def is_blackholed(self, direction: str) -> bool:
        """True once a permanent blackhole threshold has been crossed.

        Once set it stays set (latching) so a transfer that recovers data
        flow can't un-blackhole."""
        if self.blackholed:
            return True
        # Full both-directions blackhole once total forwarded bytes pass the
        # threshold (used to kill a connection right after the handshake).
        if (self.a.blackhole_after_handshake_bytes >= 0 and
                self.total_bytes >= self.a.blackhole_after_handshake_bytes):
            self.blackholed = True
            return True
        # o2c-only permanent blackhole.
        if (direction == O2C and self.a.blackhole_o2c_after_bytes >= 0 and
                self.bytes_seen[O2C] >= self.a.blackhole_o2c_after_bytes):
            return True
        return False

    def emit(self, direction: str, data: bytes, sink) -> None:
        """Put one resulting datagram on the wire via `sink(data)`, applying
        adjacent-swap reordering. Every `reorder` datagrams, hold one back and
        release it immediately after the next is emitted — so packet k is
        delivered after packet k+1. Holds at most one at a time; a held
        datagram is also released by flush_held() on an idle tick so a held
        tail packet can't stall the transfer forever (QUIC retransmits it
        regardless, but flushing avoids a needless RTT of delay)."""
        every = self.a.reorder_o2c if direction == O2C else 0
        self._eseq[direction] += 1
        if (every > 0 and self._eseq[direction] % every == 0
                and self._held[direction] is None):
            self._held[direction] = (data, sink)
            self.reordered[direction] += 1
            return
        sink(data)
        if self._held[direction] is not None:
            hd, hsink = self._held[direction]
            self._held[direction] = None
            hsink(hd)

    def flush_held(self) -> None:
        """Release any datagrams held for reordering. Called on idle ticks."""
        for direction in (C2O, O2C):
            if self._held[direction] is not None:
                hd, hsink = self._held[direction]
                self._held[direction] = None
                hsink(hd)

    def decide(self, direction: str, data: bytes) -> List[bytes]:
        """Return the datagrams to emit (possibly empty) for one received
        datagram. Updates counters. Does NOT handle reorder (see
        want_reorder)."""
        self.count[direction] += 1
        self.bytes_seen[direction] += len(data)
        self.total_bytes += len(data)
        n = self.count[direction]

        # Permanent blackhole wins over everything.
        if self.is_blackholed(direction):
            self.dropped[direction] += 1
            return []

        # Drop the first N datagrams of this direction (handshake attack).
        if n <= self._first(direction):
            self.dropped[direction] += 1
            return []

        # Windowed mid-stream / tail drop on o2c: once `after_bytes` bytes
        # have flowed, drop the next `window` datagrams, then resume. The
        # window is counted in datagrams (not bytes) so even a tiny tail
        # drops a deterministic, known number of packets.
        if (direction == O2C and self.a.drop_o2c_after_bytes >= 0
                and self._o2c_window_remaining > 0
                and self.bytes_seen[O2C] - len(data) >= self.a.drop_o2c_after_bytes):
            self._o2c_window_remaining -= 1
            self.dropped[O2C] += 1
            return []

        # Uniform fractional drop.
        f = self._frac(direction)
        if f > 0.0 and self.rng[direction].random() < f:
            self.dropped[direction] += 1
            return []

        # Corruption: flip the tail byte of every Kth datagram, but only
        # after the handshake (skip the first few datagrams of the
        # direction) so we corrupt 1-RTT packets whose AEAD failure is
        # silently-discarded rather than handshake packets.
        every = self._corrupt_every(direction)
        if every > 0 and n > self.a.corrupt_skip_first and (n % every == 0):
            self.corrupted[direction] += 1
            return [self._corrupt(data)]

        # Duplication.
        if direction == O2C and self.a.dup_o2c > 0 and (n % self.a.dup_o2c == 0):
            self.duped[O2C] += 1
            return [data, data]

        return [data]

    # The windowed-drop budget (datagram count). Initialised by arm_windows()
    # before the relay loop starts.
    _o2c_window_remaining: int = -1

    def arm_windows(self) -> None:
        self._o2c_window_remaining = self.a.drop_o2c_window


def run(args: argparse.Namespace) -> int:
    listen_host = args.listen_host
    origin = (args.origin_host, args.origin_port)

    listen = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.setblocking(False)
    listen.bind((listen_host, args.listen_port))

    policy = Policy(args)
    policy.arm_windows()

    sel = selectors.DefaultSelector()
    sel.register(listen, selectors.EVENT_READ, data="listen")

    # client_addr -> upstream socket; and reverse upstream-fd -> client_addr.
    up_for_client: Dict[Tuple, socket.socket] = {}
    client_for_up: Dict[int, Tuple] = {}
    last_client_addr: Optional[Tuple] = None

    sys.stderr.write(
        f"[h3-shim] listening [{listen_host}]:{args.listen_port} -> "
        f"[{args.origin_host}]:{args.origin_port}  policy={_policy_repr(args)}\n")
    sys.stderr.flush()

    def emit_o2c(data: bytes, client_addr: Tuple) -> None:
        try:
            listen.sendto(data, client_addr)
        except OSError:
            pass

    def emit_c2o(data: bytes, up: socket.socket) -> None:
        try:
            up.sendto(data, origin)
        except OSError:
            pass

    try:
        while True:
            events = sel.select(timeout=0.2)
            if not events:
                # Idle tick: release any datagram held for reordering so a
                # held tail packet doesn't stall the transfer.
                policy.flush_held()
                continue
            for key, _mask in events:
                sock = key.fileobj
                tag = key.data
                if tag == "listen":
                    # client -> origin
                    while True:
                        try:
                            data, caddr = sock.recvfrom(65535)
                        except (BlockingIOError, InterruptedError):
                            break
                        except OSError:
                            break
                        if not data:
                            break
                        last_client_addr = caddr
                        up = up_for_client.get(caddr)
                        if up is None:
                            up = socket.socket(socket.AF_INET6,
                                               socket.SOCK_DGRAM)
                            up.setblocking(False)
                            up.bind(("::", 0))
                            sel.register(up, selectors.EVENT_READ, data="up")
                            up_for_client[caddr] = up
                            client_for_up[up.fileno()] = caddr
                        for out in policy.decide(C2O, data):
                            policy.emit(C2O, out,
                                        lambda d, u=up: emit_c2o(d, u))
                else:
                    # origin -> client
                    caddr = client_for_up.get(sock.fileno(), last_client_addr)
                    while True:
                        try:
                            data, _oaddr = sock.recvfrom(65535)
                        except (BlockingIOError, InterruptedError):
                            break
                        except OSError:
                            break
                        if not data:
                            break
                        if caddr is None:
                            continue
                        for out in policy.decide(O2C, data):
                            policy.emit(O2C, out,
                                        lambda d, c=caddr: emit_o2c(d, c))
    except KeyboardInterrupt:
        pass
    finally:
        _report(policy)
    return 0


def _policy_repr(a: argparse.Namespace) -> str:
    parts = []
    for k in ("drop_c2o_first", "drop_o2c_first", "drop_c2o_frac",
              "drop_o2c_frac", "drop_o2c_after_bytes", "drop_o2c_window",
              "blackhole_o2c_after_bytes", "blackhole_after_handshake_bytes",
              "reorder_o2c", "dup_o2c", "corrupt_o2c", "corrupt_c2o"):
        v = getattr(a, k)
        if v not in (0, -1, 0.0):
            parts.append(f"{k}={v}")
    return ",".join(parts) if parts else "passthrough"


def _report(p: Policy) -> None:
    sys.stderr.write(
        "[h3-shim] stats "
        f"c2o(n={p.count[C2O]} drop={p.dropped[C2O]} dup={p.duped[C2O]} "
        f"corrupt={p.corrupted[C2O]} reorder={p.reordered[C2O]}) "
        f"o2c(n={p.count[O2C]} drop={p.dropped[O2C]} dup={p.duped[O2C]} "
        f"corrupt={p.corrupted[O2C]} reorder={p.reordered[O2C]}) "
        f"blackholed={p.blackholed}\n")
    sys.stderr.flush()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--listen-host", default="::1")
    p.add_argument("--listen-port", type=int, required=True)
    p.add_argument("--origin-host", default="::1")
    p.add_argument("--origin-port", type=int, required=True)
    p.add_argument("--seed", type=int, default=1234)
    # Drop the first N datagrams of a direction (handshake-phase attack).
    p.add_argument("--drop-c2o-first", type=int, default=0)
    p.add_argument("--drop-o2c-first", type=int, default=0)
    # Uniform fractional drop across the whole transfer.
    p.add_argument("--drop-c2o-frac", type=float, default=0.0)
    p.add_argument("--drop-o2c-frac", type=float, default=0.0)
    # Windowed drop on o2c: once `after-bytes` origin->client bytes have
    # flowed, drop the next `window` datagrams, then resume.
    p.add_argument("--drop-o2c-after-bytes", type=int, default=-1)
    p.add_argument("--drop-o2c-window", type=int, default=0)
    # Permanent blackholes.
    p.add_argument("--blackhole-o2c-after-bytes", type=int, default=-1)
    p.add_argument("--blackhole-after-handshake-bytes", type=int, default=-1)
    # Reorder / duplicate / corrupt.
    p.add_argument("--reorder-o2c", type=int, default=0)
    p.add_argument("--dup-o2c", type=int, default=0)
    p.add_argument("--corrupt-o2c", type=int, default=0)
    p.add_argument("--corrupt-c2o", type=int, default=0)
    p.add_argument("--corrupt-skip-first", type=int, default=4,
                   help="don't corrupt the first N datagrams of a direction "
                        "(keeps the handshake intact so AEAD failures land on "
                        "silently-discarded 1-RTT packets)")
    return p


def main(argv: List[str]) -> int:
    args = build_parser().parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
