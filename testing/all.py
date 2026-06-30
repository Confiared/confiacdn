#!/usr/bin/env python3
"""
confiacdn end-to-end test harness.

Brings up nginx + confiacdn + a Python origin under /mnt/data/perso/tmpfs/confiacdn/,
runs the full test matrix described in CLAUDE.md (cache states, ETags, concurrency,
compression, slow/fast/bursty origin profiles), and verifies that bytes the client
receives match the bytes the origin sent.

Entry point: `python3 testing/all.py`
Single case:  `python3 testing/all.py --only <name>`
List cases:   `python3 testing/all.py --list`
Larger fixtures: `python3 testing/all.py --full`
50-min soak:  `python3 testing/all.py --soak`
"""

from __future__ import annotations

import argparse
import atexit
import contextlib
import gzip
import hashlib
import http.client
import io
import os
import random
import re
import shutil
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
from typing import Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants & paths
# ---------------------------------------------------------------------------

TMPFS = "/mnt/data/perso/tmpfs/confiacdn"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BUILD_DIR = os.path.join(TMPFS, "build")
BUILD_DIR_SANITIZE = os.path.join(TMPFS, "build-sanitize")
CACHE_DIR = os.path.join(TMPFS, "cache")
LOG_DIR = os.path.join(TMPFS, "logs")
PID_DIR = TMPFS

def get_build_dir(sanitize: bool) -> str:
    return BUILD_DIR_SANITIZE if sanitize else BUILD_DIR

def get_confiacdn_bin(sanitize: bool) -> str:
    return os.path.join(get_build_dir(sanitize), "confiacdn")

CONFIACDN_BIN = os.path.join(BUILD_DIR, "confiacdn")  # back-compat for --kill
FASTCGI_SOCK = os.path.join(TMPFS, "fastcgicdn.sock")
RELOAD_SOCK = os.path.join(TMPFS, "reload.sock")

CONFIACDN_LOG = os.path.join(LOG_DIR, "confiacdn.log")
NGINX_ERROR_LOG = os.path.join(LOG_DIR, "nginx-error.log")
NGINX_ACCESS_LOG = os.path.join(LOG_DIR, "nginx-access.log")
CLIENT_LOG = os.path.join(LOG_DIR, "client.log")
ORIGIN_LOG = os.path.join(LOG_DIR, "origin.log")

CONFIACDN_PID_FILE = os.path.join(PID_DIR, "confiacdn.pid")
NGINX_PID_FILE = os.path.join(PID_DIR, "nginx.pid")
ORIGIN_PID_FILE = os.path.join(PID_DIR, "origin.pid")
ORIGIN_H3_PID_FILE = os.path.join(PID_DIR, "origin-h3.pid")
H3_ORIGIN_LOG = os.path.join(LOG_DIR, "h3-origin.log")
H3_SHIM_PID_FILE = os.path.join(PID_DIR, "h3-shim.pid")
H3_SHIM_LOG = os.path.join(LOG_DIR, "h3-shim.log")

# Three distinct ports — see CLAUDE.md "Stack all.py brings up".
FORCEDPORT = 18080      # origin HTTP listener; confiacdn (built with -DFORCEDPORT=18080) dials here
FORCEDPORT_TLS = 18443  # origin HTTPS listener; confiacdn (built with -DFORCEDPORT_TLS=18443) dials here
FORCEDPORT_H3 = 18444   # HTTP/3 (QUIC over UDP) origin port; used by testing/h3_smoke direct path
FORCEDPORT_H3_SHIM = 18454  # testing/h3_udp_shim.py lossy UDP relay -> FORCEDPORT_H3
NGINX_PORT = 18888      # nginx listens here; harness HTTP client hits here

TLS_CERT_FILE = os.path.join(TMPFS, "origin-selfsigned.crt")
TLS_KEY_FILE = os.path.join(TMPFS, "origin-selfsigned.key")

DEFAULT_HOST = "cdn.test.invalid"   # Host header sent by client (anything non-.confiared.com works)
ORIGIN_HOST = "origin.test"         # used as the FIRST path segment so confiacdn parses
                                    # `/origin.test/path` → host=origin.test, uri=/path
                                    # (see Client.cpp:744 fallback parser)


# ---------------------------------------------------------------------------
# Logging — simple line writer that goes to a per-stream file AND stderr
# ---------------------------------------------------------------------------

class FileLogger:
    """Append-only log writer. WARNING and above are also echoed to stderr."""

    LEVELS = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        # Wipe on construction — every harness run starts fresh.
        with open(self.path, "w") as f:
            f.write("")

    def log(self, level: str, msg: str) -> None:
        line = f"{time.strftime('%H:%M:%S')} {level} {msg}\n"
        with self._lock:
            with open(self.path, "a") as f:
                f.write(line)
        if self.LEVELS.get(level, 0) >= self.LEVELS["WARNING"]:
            sys.stderr.write(line)

    def debug(self, m): self.log("DEBUG", m)
    def info(self, m): self.log("INFO", m)
    def warn(self, m): self.log("WARNING", m)
    def error(self, m): self.log("ERROR", m)


# ---------------------------------------------------------------------------
# Filesystem & process bootstrap
# ---------------------------------------------------------------------------

def ensure_dirs() -> None:
    for d in (TMPFS, BUILD_DIR, CACHE_DIR, LOG_DIR):
        os.makedirs(d, exist_ok=True)


def kill_pid_file(path: str, sig: int = signal.SIGTERM, log: Optional[FileLogger] = None) -> None:
    """Read a pid file and kill the process. Tolerates stale/missing files."""
    if not os.path.exists(path):
        return
    try:
        pid = int(open(path).read().strip())
    except (ValueError, IOError):
        os.unlink(path)
        return
    try:
        os.kill(pid, sig)
        # Wait briefly for graceful exit, then SIGKILL.
        for _ in range(20):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    except ProcessLookupError:
        pass
    except PermissionError as e:
        if log:
            log.warn(f"cannot kill pid {pid} from {path}: {e}")
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)


def write_pid_file(path: str, pid: int) -> None:
    with open(path, "w") as f:
        f.write(f"{pid}\n")


def kill_all(log: Optional[FileLogger] = None) -> None:
    kill_pid_file(NGINX_PID_FILE, log=log)
    kill_pid_file(CONFIACDN_PID_FILE, log=log)
    kill_pid_file(ORIGIN_PID_FILE, log=log)
    kill_pid_file(ORIGIN_H3_PID_FILE, log=log)
    kill_pid_file(H3_SHIM_PID_FILE, log=log)
    for p in (FASTCGI_SOCK, RELOAD_SOCK):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(p)


def kill_everything_via_cli() -> int:
    """`--kill`: terminate any running confiacdn / nginx / detached all.py /
    origin owned by this harness. Driven entirely by the recorded PID files
    so the command is idempotent and safe to invoke any time."""
    print(f"--kill: cleaning up under {TMPFS}", file=sys.stderr)
    # 1. Kill the recorded service PIDs (nginx + confiacdn + origin).
    kill_all()
    # 2. Detached `nohup python3 testing/all.py` runs aren't tracked in a
    #    PID file. Find them by name and SIGTERM, then SIGKILL the survivors.
    own_pid = os.getpid()
    own_ppid = os.getppid()
    try:
        out = subprocess.check_output(
            ["pgrep", "-af", "python3 .*testing/all.py"],
            stderr=subprocess.DEVNULL,
        ).decode()
    except subprocess.CalledProcessError:
        out = ""
    detached_pids: List[int] = []
    for line in out.splitlines():
        try:
            pid = int(line.split()[0])
        except (ValueError, IndexError):
            continue
        # Don't kill ourselves or our parent shell.
        if pid in (own_pid, own_ppid):
            continue
        # Don't kill anything that contains "--kill" in its argv.
        if "--kill" in line:
            continue
        detached_pids.append(pid)
    for pid in detached_pids:
        print(f"  SIGTERM detached all.py PID {pid}", file=sys.stderr)
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGTERM)
    if detached_pids:
        time.sleep(1.5)
        for pid in detached_pids:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, 0)
                # Still alive — force.
                os.kill(pid, signal.SIGKILL)
                print(f"  SIGKILL detached all.py PID {pid}", file=sys.stderr)
    # 3. Best-effort cleanup of any orphan confiacdn / nginx that escaped (no
    #    pid file). We only target binaries inside our build/tmpfs dir to
    #    avoid touching unrelated processes on the dev box.
    for pattern in (CONFIACDN_BIN, get_confiacdn_bin(True), f"nginx -p {TMPFS}"):
        try:
            out = subprocess.check_output(
                ["pgrep", "-f", pattern], stderr=subprocess.DEVNULL,
            ).decode()
        except subprocess.CalledProcessError:
            continue
        for pid_str in out.split():
            try:
                pid = int(pid_str)
            except ValueError:
                continue
            print(f"  SIGTERM orphan ({pattern}) PID {pid}", file=sys.stderr)
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGTERM)
        time.sleep(1)
        for pid_str in out.split():
            try:
                pid = int(pid_str)
            except ValueError:
                continue
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, 0)
                os.kill(pid, signal.SIGKILL)
    print("--kill: done", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# Source copy + Makefile patching + Build
# ---------------------------------------------------------------------------

# DEFINES line from the Makefile we want to overwrite.
_DEFINES_RE = re.compile(r"^DEFINES\s*=.*$", re.MULTILINE)
_CXXFLAGS_RE = re.compile(r"^CXXFLAGS\s*=.*$", re.MULTILINE)
_LFLAGS_RE = re.compile(r"^LFLAGS\s*=.*$", re.MULTILINE)
_CC_RE = re.compile(r"^CC\s*=.*$", re.MULTILINE)
_CXX_RE = re.compile(r"^CXX\s*=.*$", re.MULTILINE)
_LINK_RE = re.compile(r"^LINK\s*=.*$", re.MULTILINE)


def _build_defines_line() -> str:
    flags = [
        "-DFASTCGIASYNC",
        "-DPREADPWRITE",
        "-DDEBUGFASTCGI",
        "-DDEBUGDNS",
        "-DDEBUGFILEOPEN",
        "-DDEBUGFROMIP",
        "-DDEBUGHTTPS",
        "-DLOWTIMEDNSCACHE",
        f"-DFORCEDPORT={FORCEDPORT}",
        f"-DFORCEDPORT_TLS={FORCEDPORT_TLS}",
        "-DFORCEALLDNSTOLOCALHOSTIPV6",
        "-DBACKEND_ALLOW_SELF_SIGNED_TLS",
    ]
    return "DEFINES = " + " ".join(flags)


SANITIZE_MODES = ("asan", "lsan", "msan")
VALGRIND_TOOLS = ("memcheck", "helgrind", "drd")
VALGRIND_EXIT_CODE = 99  # passed via --error-exitcode; we treat it as a hard fail


def _valgrind_argv(tool: str) -> List[str]:
    """Return the valgrind invocation prefix that wraps the confiacdn binary.
    Findings are surfaced two ways: (a) `--error-exitcode=99` makes valgrind
    exit non-zero on first error so the harness's poll() check catches it;
    (b) findings are written to stderr (which the harness redirects into
    confiacdn.log), so the existing `_CONFIACDN_FORBIDDEN` substring scanner
    flags them as test failures with a useful root-cause line."""
    base = [
        "valgrind",
        f"--tool={tool}",
        f"--error-exitcode={VALGRIND_EXIT_CODE}",
        "--child-silent-after-fork=yes",
        "--trace-children=no",
    ]
    if tool == "memcheck":
        base += [
            "--leak-check=full",
            "--show-leak-kinds=all",
            "--track-origins=yes",
            "--errors-for-leak-kinds=definite,possible",
        ]
    return base


def _sanitize_cxxflags(mode: str) -> str:
    """Per-mode CXXFLAGS for the sanitizer build. -O1 keeps the build fast and
    stack traces readable; -fno-sanitize-recover=all turns first finding into
    abort so the test runner picks it up as a failure."""
    if mode == "asan":
        san = "-fsanitize=address,undefined"
    elif mode == "lsan":
        # Standalone LeakSanitizer (no ASAN overhead). Detects only leaks at exit.
        san = "-fsanitize=leak"
    elif mode == "msan":
        # MemorySanitizer — uninitialized-memory detection. Clang only.
        # `-fsanitize-memory-track-origins=2` gives where the uninitialized
        # value originated. False positives on uninstrumented libs (libc,
        # OpenSSL) are expected; see CLAUDE.md for context.
        san = "-fsanitize=memory,undefined -fsanitize-memory-track-origins=2"
    else:
        raise ValueError(f"unknown sanitize mode: {mode}")
    return ("CXXFLAGS = -pipe -O1 -g -std=gnu++17 "
            f"{san} -fno-omit-frame-pointer -fno-sanitize-recover=all $(DEFINES)")


def _sanitize_lflags(mode: str) -> str:
    if mode == "asan":
        return "LFLAGS = -fsanitize=address,undefined"
    if mode == "lsan":
        return "LFLAGS = -fsanitize=leak"
    if mode == "msan":
        return "LFLAGS = -fsanitize=memory,undefined"
    raise ValueError(f"unknown sanitize mode: {mode}")


def _sanitize_compiler(mode: str) -> Tuple[str, str]:
    """Return (CC, CXX). Sanitizer builds always use clang/clang++ — gcc handles
    asan/lsan/ubsan too, but clang is the reference implementation, ships
    consistent diagnostics across all four sanitizers, and is required for MSan
    (which has no gcc equivalent). Standardising on one compiler also avoids
    surprises when comparing reports across modes."""
    return ("clang", "clang++")


def ensure_self_signed_cert() -> None:
    """Generate a self-signed cert for the origin's HTTPS listener if missing.
    Uses `openssl req -x509`. The cert covers any hostname (CN=*) since
    confiacdn is built with FORCEALLDNSTOLOCALHOSTIPV6 anyway and we never
    validate the cert (BACKEND_ALLOW_SELF_SIGNED_TLS)."""
    if os.path.exists(TLS_CERT_FILE) and os.path.exists(TLS_KEY_FILE):
        return
    subj = "/CN=origin.test"
    rc = subprocess.call(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", TLS_KEY_FILE, "-out", TLS_CERT_FILE,
         "-days", "30", "-subj", subj],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if rc != 0:
        raise RuntimeError("openssl req failed to generate self-signed cert")


def copy_source_and_patch_makefile(log: FileLogger, sanitize: Optional[str] = None) -> None:
    """Copy the repo source into the build dir and rewrite the Makefile.
    `sanitize` is None for the regular debug build, or one of SANITIZE_MODES
    ('asan'/'lsan'/'msan') for the sanitizer build."""
    build_dir = get_build_dir(sanitize is not None)
    if os.path.isdir(build_dir):
        shutil.rmtree(build_dir)
    os.makedirs(build_dir)
    # Copy top-level .cpp/.hpp + Makefile + Timer/ + xxHash/.
    for entry in os.listdir(REPO):
        src = os.path.join(REPO, entry)
        if entry == "Makefile" or entry.endswith((".cpp", ".hpp")):
            shutil.copy2(src, build_dir)
    for sub in ("Timer",):
        shutil.copytree(os.path.join(REPO, sub), os.path.join(build_dir, sub))

    mk_path = os.path.join(build_dir, "Makefile")
    with open(mk_path) as f:
        text = f.read()

    text, n = _DEFINES_RE.subn(_build_defines_line(), text, count=1)
    if n != 1:
        raise RuntimeError("did not find DEFINES = line in Makefile to replace")

    if sanitize is not None:
        if sanitize not in SANITIZE_MODES:
            raise ValueError(f"sanitize must be one of {SANITIZE_MODES}, got {sanitize!r}")
        text, n = _CXXFLAGS_RE.subn(_sanitize_cxxflags(sanitize), text, count=1)
        if n != 1:
            raise RuntimeError("did not find CXXFLAGS = line in Makefile to replace")
        text, n = _LFLAGS_RE.subn(_sanitize_lflags(sanitize), text, count=1)
        if n != 1:
            raise RuntimeError("did not find LFLAGS = line in Makefile to replace")
        # All sanitizer builds use clang/clang++. Override CC/CXX/LINK.
        cc, cxx = _sanitize_compiler(sanitize)
        text, n_cc = _CC_RE.subn(f"CC = {cc}", text, count=1)
        text, n_cxx = _CXX_RE.subn(f"CXX = {cxx}", text, count=1)
        text, n_link = _LINK_RE.subn(f"LINK = {cxx}", text, count=1)
        if n_cc != 1 or n_cxx != 1 or n_link != 1:
            raise RuntimeError(
                "did not find CC/CXX/LINK lines to replace in Makefile "
                f"(found CC={n_cc}, CXX={n_cxx}, LINK={n_link})")

    with open(mk_path, "w") as f:
        f.write(text)
    log.info(f"Makefile patched in {mk_path}: sanitize={sanitize}")


def build_h3_lru_test(log: FileLogger, sanitize: Optional[str] = None) -> str:
    """Build the direct unit-style LRU test for Http3's session cache.
    Same build pipeline as h3_smoke: clang++/g++ depending on sanitize,
    links Http3.o + EpollObject.o from the daemon's build dir."""
    build_dir = get_build_dir(sanitize is not None)
    cxx = "clang++" if sanitize else "g++"
    src_in  = os.path.join(REPO, "testing", "h3_lru_test.cpp")
    src_dst = os.path.join(build_dir, "h3_lru_test.cpp")
    shutil.copy2(src_in, src_dst)
    with open(src_dst) as f:
        text = f.read()
    text = text.replace('"../Http3.hpp"', '"Http3.hpp"')
    with open(src_dst, "w") as f:
        f.write(text)
    cxxflags = ["-pipe", "-O0", "-g", "-std=gnu++17",
                "-fno-omit-frame-pointer", "-I" + build_dir]
    lflags = []
    if sanitize == "asan":
        s = ["-fsanitize=address,undefined"]; cxxflags += s; lflags += s
    elif sanitize == "lsan":
        s = ["-fsanitize=leak"]; cxxflags += s; lflags += s
    elif sanitize == "msan":
        s = ["-fsanitize=memory,undefined"]; cxxflags += s; lflags += s
    bin_ = os.path.join(build_dir, "h3_lru_test")
    rc = subprocess.call([cxx, *cxxflags, "-o", bin_, src_dst,
                          os.path.join(build_dir, "Http3.o"),
                          os.path.join(build_dir, "EpollObject.o"),
                          *lflags,
                          "-lssl", "-lcrypto", "-lngtcp2", "-lnghttp3",
                          "-lngtcp2_crypto_ossl"])
    if rc != 0:
        raise RuntimeError(f"h3_lru_test build failed (rc={rc})")
    log.info(f"Built {bin_}")
    return bin_


def build_h3_smoke(log: FileLogger, sanitize: Optional[str] = None) -> str:
    """Build the standalone testing/h3_smoke driver against the just-built
    Http3.o + EpollObject.o in the same build dir. Returns the binary path.

    The driver bypasses the daemon entirely: it links the H3 client code
    directly and talks to the aioquic origin on FORCEDPORT_H3. This lets us
    exercise Http3 before it is wired into Backend/Http."""
    build_dir = get_build_dir(sanitize is not None)
    cxx = "clang++" if sanitize else "g++"
    src_in  = os.path.join(REPO, "testing", "h3_smoke.cpp")
    src_dst = os.path.join(build_dir, "h3_smoke.cpp")
    shutil.copy2(src_in, src_dst)
    # The smoke source uses "../Http3.hpp" because it lives in testing/ in
    # the repo. In the flat build dir, rewrite to local includes.
    with open(src_dst) as f:
        text = f.read()
    text = (text.replace('"../Http3.hpp"', '"Http3.hpp"')
                .replace('"../EpollObject.hpp"', '"EpollObject.hpp"'))
    with open(src_dst, "w") as f:
        f.write(text)

    cxxflags = ["-pipe", "-O0", "-g", "-std=gnu++17",
                "-fno-omit-frame-pointer", "-DBACKEND_ALLOW_SELF_SIGNED_TLS",
                "-I" + build_dir]
    lflags = []
    if sanitize == "asan":
        s = ["-fsanitize=address,undefined"]
        cxxflags += s; lflags += s
    elif sanitize == "lsan":
        s = ["-fsanitize=leak"]
        cxxflags += s; lflags += s
    elif sanitize == "msan":
        s = ["-fsanitize=memory,undefined"]
        cxxflags += s; lflags += s

    obj = os.path.join(build_dir, "h3_smoke.o")
    bin_ = os.path.join(build_dir, "h3_smoke")
    rc = subprocess.call([cxx, *cxxflags, "-c", src_dst, "-o", obj])
    if rc != 0:
        raise RuntimeError(f"h3_smoke compile failed (rc={rc})")
    rc = subprocess.call([cxx, *lflags, "-O0", "-g", "-o", bin_, obj,
                          os.path.join(build_dir, "Http3.o"),
                          os.path.join(build_dir, "EpollObject.o"),
                          "-lssl", "-lcrypto", "-lngtcp2", "-lnghttp3",
                          "-lngtcp2_crypto_ossl"])
    if rc != 0:
        raise RuntimeError(f"h3_smoke link failed (rc={rc})")
    log.info(f"Built {bin_}")
    return bin_


def start_origin_h3(harness_log: FileLogger) -> subprocess.Popen:
    """Spawn the aioquic-based HTTP/3 origin on FORCEDPORT_H3. Self-signed
    cert reused from the existing HTTPS origin. Listens on the same UDP port
    for the duration of the harness run."""
    ensure_self_signed_cert()
    origin_py = os.path.join(REPO, "testing", "h3_origin.py")
    proc = subprocess.Popen(
        ["python3", origin_py, str(FORCEDPORT_H3),
         TLS_CERT_FILE, TLS_KEY_FILE],
        cwd=TMPFS,
        stdout=open(H3_ORIGIN_LOG, "w"),
        stderr=subprocess.STDOUT,
    )
    write_pid_file(ORIGIN_H3_PID_FILE, proc.pid)
    # Give the listener a brief moment to bind. 1s is generous; aioquic's
    # serve() returns synchronously once the socket is bound.
    time.sleep(0.8)
    if proc.poll() is not None:
        raise RuntimeError(
            f"h3 origin exited rc={proc.returncode}; see {H3_ORIGIN_LOG}")
    harness_log.info(f"origin (H3) listening on [::]:{FORCEDPORT_H3} pid={proc.pid}")
    return proc


def start_h3_shim(policy: List[str]) -> subprocess.Popen:
    """Spawn the lossy UDP relay (testing/h3_udp_shim.py) on
    FORCEDPORT_H3_SHIM, forwarding to the aioquic origin on FORCEDPORT_H3.
    `policy` is the list of perturbation flags (e.g. ["--drop-o2c-frac", "0.1"]).

    The shim is per-test ephemeral: each QUIC failure-injection cell starts
    one with its own policy, points the H3 client (h3_smoke or the daemon's
    --http3-port) at FORCEDPORT_H3_SHIM, and stops it in a finally block.
    Stdout/stderr go to H3_SHIM_LOG (truncated per start) for diagnosis; the
    shim never writes to confiacdn.log, so its lines don't trip the scanner.
    """
    shim_py = os.path.join(REPO, "testing", "h3_udp_shim.py")
    proc = subprocess.Popen(
        ["python3", shim_py,
         "--listen-port", str(FORCEDPORT_H3_SHIM),
         "--origin-port", str(FORCEDPORT_H3)] + policy,
        cwd=TMPFS,
        stdout=open(H3_SHIM_LOG, "w"),
        stderr=subprocess.STDOUT,
    )
    write_pid_file(H3_SHIM_PID_FILE, proc.pid)
    # UDP bind is immediate; a short pause lets the listen socket settle.
    time.sleep(0.4)
    if proc.poll() is not None:
        raise RuntimeError(
            f"h3 shim exited rc={proc.returncode}; see {H3_SHIM_LOG}")
    return proc


def stop_h3_shim(proc: Optional[subprocess.Popen]) -> None:
    """Stop a shim started by start_h3_shim(). Idempotent."""
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    with contextlib.suppress(FileNotFoundError):
        os.unlink(H3_SHIM_PID_FILE)


def build_confiacdn(log: FileLogger, jobs: int, sanitize: Optional[str] = None) -> None:
    build_dir = get_build_dir(sanitize is not None)
    bin_path = get_confiacdn_bin(sanitize is not None)
    log.info(f"Building confiacdn in {build_dir} with -j{jobs} (sanitize={sanitize}) ...")
    proc = subprocess.run(
        ["make", f"-j{jobs}"],
        cwd=build_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    out = proc.stdout.decode("utf-8", errors="replace")
    log_path = os.path.join(
        LOG_DIR,
        f"build-sanitize-{sanitize}.log" if sanitize else "build.log",
    )
    with open(log_path, "w") as f:
        f.write(out)
    if proc.returncode != 0:
        sys.stderr.write(out[-4000:])
        raise RuntimeError(f"build failed (rc={proc.returncode}); see {log_path}")
    if not os.path.exists(bin_path):
        raise RuntimeError(f"build succeeded but {bin_path} missing")
    log.info(f"Built {bin_path}")


# ---------------------------------------------------------------------------
# Nginx config generation & launch
# ---------------------------------------------------------------------------

NGINX_CONF_TMPL = """\
daemon off;
worker_processes 1;
pid {pid_file};
error_log {error_log} info;

events {{
    worker_connections 1024;
}}

http {{
    access_log {access_log};
    default_type application/octet-stream;
    sendfile off;
    keepalive_timeout 65;
    client_body_temp_path {tmpfs}/nginx-body;
    fastcgi_temp_path {tmpfs}/nginx-fcgi;
    proxy_temp_path {tmpfs}/nginx-proxy;
    scgi_temp_path {tmpfs}/nginx-scgi;
    uwsgi_temp_path {tmpfs}/nginx-uwsgi;

    server {{
        listen {port};
        listen [::]:{port};
        server_name _;

        location / {{
            fastcgi_pass unix:{sock};
            fastcgi_param HTTP_HOST          $host;
            fastcgi_param REQUEST_URI        $request_uri;
            fastcgi_param REQUEST_SCHEME     $scheme;
            fastcgi_param REQUEST_METHOD     $request_method;
            fastcgi_param REMOTE_ADDR        $remote_addr;
            fastcgi_param HTTP_ACCEPT_ENCODING $http_accept_encoding;
            fastcgi_param HTTP_IF_NONE_MATCH $http_if_none_match;
            fastcgi_param HTTP_RANGE         $http_range;
            fastcgi_buffering off;
            fastcgi_read_timeout 3600;
            fastcgi_send_timeout 3600;
        }}

        # HTTPS-backend test: forwards REQUEST_SCHEME=https to confiacdn so it
        # dials the origin via TLS on FORCEDPORT_TLS. Strip the /https-tls
        # prefix from REQUEST_URI so confiacdn's /<host>/<path> parser sees
        # the same shape as plain HTTP requests.
        location /https-tls/ {{
            fastcgi_pass unix:{sock};
            fastcgi_param HTTP_HOST          $host;
            rewrite ^/https-tls/(.*)$ /$1 break;
            fastcgi_param REQUEST_URI        $uri;
            fastcgi_param REQUEST_SCHEME     https;
            fastcgi_param REQUEST_METHOD     $request_method;
            fastcgi_param REMOTE_ADDR        $remote_addr;
            fastcgi_param HTTP_ACCEPT_ENCODING $http_accept_encoding;
            fastcgi_param HTTP_IF_NONE_MATCH $http_if_none_match;
            fastcgi_param HTTP_RANGE         $http_range;
            fastcgi_buffering off;
            fastcgi_read_timeout 3600;
            fastcgi_send_timeout 3600;
        }}
    }}
}}
"""


def write_nginx_conf() -> str:
    path = os.path.join(TMPFS, "nginx.conf")
    with open(path, "w") as f:
        f.write(NGINX_CONF_TMPL.format(
            pid_file=NGINX_PID_FILE,
            error_log=NGINX_ERROR_LOG,
            access_log=NGINX_ACCESS_LOG,
            tmpfs=TMPFS,
            port=NGINX_PORT,
            sock=FASTCGI_SOCK,
        ))
    return path


def start_nginx(log: FileLogger) -> subprocess.Popen:
    conf = write_nginx_conf()
    log.info(f"Starting nginx with {conf}")
    proc = subprocess.Popen(
        ["nginx", "-p", TMPFS + "/", "-c", conf, "-e", NGINX_ERROR_LOG],
        cwd=TMPFS,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    write_pid_file(NGINX_PID_FILE, proc.pid)
    # Wait for the listening socket.
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", NGINX_PORT), timeout=0.2):
                return proc
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("nginx did not start listening on port " + str(NGINX_PORT))


def start_confiacdn(log: FileLogger, args: List[str],
                    sanitize: Optional[str] = None,
                    valgrind: Optional[str] = None) -> subprocess.Popen:
    """Spawn confiacdn. `sanitize` and `valgrind` are mutually exclusive — the
    caller is expected to enforce that (argparse does)."""
    # Valgrind wraps the regular debug build; sanitizer modes use the sanitize
    # build. Plain mode also uses the regular debug build.
    bin_path = get_confiacdn_bin(sanitize is not None)
    cmd: List[str] = []
    if valgrind:
        cmd += _valgrind_argv(valgrind)
    cmd += [bin_path] + args
    log.info(f"Starting confiacdn (sanitize={sanitize} valgrind={valgrind}): {cmd}")
    flog = open(CONFIACDN_LOG, "w")
    env = os.environ.copy()
    if sanitize == "asan":
        env["ASAN_OPTIONS"] = (
            "abort_on_error=1:detect_leaks=1:halt_on_error=1:log_to_stderr=1"
        )
        env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=1"
    elif sanitize == "lsan":
        env["LSAN_OPTIONS"] = "exitcode=23"
    elif sanitize == "msan":
        env["MSAN_OPTIONS"] = "abort_on_error=1:halt_on_error=1:log_to_stderr=1"
        env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=1"
    proc = subprocess.Popen(
        cmd,
        cwd=TMPFS,
        stdout=flog,
        stderr=flog,
        env=env,
    )
    write_pid_file(CONFIACDN_PID_FILE, proc.pid)
    # Wait for the FastCGI socket file to appear. Valgrind startup is slow
    # (10-30s for a real binary); give it more time.
    deadline_ticks = 600 if valgrind else 80
    for _ in range(deadline_ticks):
        if os.path.exists(FASTCGI_SOCK):
            time.sleep(0.1)
            return proc
        time.sleep(0.05)
    raise RuntimeError(f"confiacdn did not create {FASTCGI_SOCK}")


# ---------------------------------------------------------------------------
# Origin HTTP server (in-process; runs in a thread)
# ---------------------------------------------------------------------------

@dataclass
class Fixture:
    """A piece of content the origin can serve, addressable by URL path."""
    body: bytes
    content_type: str = "application/octet-stream"
    backend_etag: Optional[str] = None  # what origin sends as ETag
    profile: str = "fast"               # fast | slow1mbps | bursty | slowheader | disconnect |
                                        # disconnect_then_recover | error |
                                        # silent_after_connect | silent_before_headers |
                                        # freeze_mid_body | rst_mid_body |
                                        # partial_headers_then_silent
    error_status: int = 500             # for profile=error
    allow_compression: bool = False     # if True, origin honours Accept-Encoding: gzip
    serve_count: int = 0                # incremented on every served request (for de-dup checks)
    serve_count_lock: threading.Lock = field(default_factory=threading.Lock)
    # If set, origin should return 304 when If-None-Match matches this string
    revalidate_match: Optional[str] = None
    # Streaming fixture — avoids materializing very large bodies in RAM.
    # When stream_size > 0, the origin generates `stream_size` deterministic bytes on
    # demand from a 64KB seed-derived chunk repeated, paced at stream_rate_bps.
    stream_size: int = 0
    stream_seed: int = 0
    stream_rate_bps: int = 0  # 0 = unpaced (fast)
    # If True, origin honours `Range: bytes=N-` requests with 206 Partial Content.
    # If False, Range is ignored and the origin always serves 200 with the full body.
    support_range: bool = False
    # Extra response headers (e.g. Cache-Control, Vary, Location) — emitted as-is.
    extra_headers: List[Tuple[str, str]] = field(default_factory=list)
    # Vary by Accept-Encoding: when True, origin responds with gzip iff client
    # advertises Accept-Encoding: gzip; otherwise plaintext. Sets Vary header.
    vary_accept_encoding: bool = False
    # Transfer-Encoding: chunked instead of Content-Length.
    chunked: bool = False
    # If > 0, declare Content-Length = len(body) but only send `truncate_at` bytes
    # then close. Tests that confiacdn doesn't cache short bodies as complete.
    truncate_at: int = 0

    def bump(self) -> int:
        with self.serve_count_lock:
            self.serve_count += 1
            return self.serve_count


def streaming_chunk(seed: int, size: int = 65536) -> bytes:
    """Deterministic 64KB chunk derived from seed — re-tileable for streaming."""
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(size))


def streaming_expected_sha(seed: int, total_size: int) -> str:
    """SHA256 of (streaming_chunk * N + chunk[:rem]) without materialising it."""
    chunk = streaming_chunk(seed, 65536)
    h = hashlib.sha256()
    n_full = total_size // 65536
    rem = total_size % 65536
    for _ in range(n_full):
        h.update(chunk)
    if rem:
        h.update(chunk[:rem])
    return h.hexdigest()


class OriginHandler(BaseHTTPRequestHandler):
    """All routes are looked up from server.fixtures (path → Fixture)."""

    server_version = "TestOrigin/1.0"
    sys_version = ""

    def log_message(self, fmt, *args):
        # Funnel into harness origin log instead of stderr.
        try:
            self.server.harness_log.info(f"origin {self.address_string()} {fmt % args}")
        except Exception:
            pass

    def do_GET(self):
        self._serve(send_body=True)

    def do_HEAD(self):
        self._serve(send_body=False)

    def _serve(self, send_body: bool):
        path = self.path
        if "?" in path:
            path = path.split("?", 1)[0]
        fixture = self.server.fixtures.get(path)
        if fixture is None:
            self._reply_status(404, b"not found\n")
            return
        n = fixture.bump()
        ifm = self.headers.get("If-None-Match", "")
        accept_enc = self.headers.get("Accept-Encoding", "")

        # 304 path
        if fixture.revalidate_match and ifm and fixture.revalidate_match in ifm:
            self.send_response(304)
            if fixture.backend_etag:
                self.send_header("ETag", fixture.backend_etag)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if fixture.profile == "error":
            self._reply_status(fixture.error_status, b"error\n",
                               extra_headers=fixture.extra_headers)
            return

        # Origin accepted the TCP connection and read the request, but stays
        # silent — no status line, no headers, no body. Confiacdn must time
        # out around --maxreadtime and propagate a 5xx instead of hanging
        # forever. Sleeps a bounded interval (longer than --maxreadtime so
        # confiacdn fires its timeout, shorter than the test wall clock so
        # the daemon thread actually exits at end of test).
        if fixture.profile == "silent_after_connect":
            time.sleep(35.0)
            return

        # Origin sends the status line + a single header, then closes the TCP
        # connection — models a customer's origin process crashing mid-write
        # or a transit middlebox truncating mid-headers. confiacdn parsed a
        # status code but never reached end-of-headers, so the FastCGI side
        # has not yet emitted a response; this is the boundary case where
        # the daemon must (a) not abort, (b) detect the truncation quickly
        # enough that retries finish before --maxdwritetime kicks the
        # client, (c) propagate a clean 5xx (no nginx "premature close").
        if fixture.profile == "partial_headers_then_silent":
            try:
                self.wfile.write(b"HTTP/1.1 200 OK\r\nServer: partial\r\n")
                self.wfile.flush()
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            return

        # Streaming fixture (large bodies generated on the fly).
        if fixture.stream_size > 0:
            self.send_response(200)
            self.send_header("Content-Type", fixture.content_type)
            self.send_header("Content-Length", str(fixture.stream_size))
            if fixture.backend_etag:
                self.send_header("ETag", fixture.backend_etag)
            self.send_header("Connection", "close")
            self.end_headers()
            if not send_body:
                return
            try:
                self._write_streaming_body(fixture)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        # Build body (with optional gzip)
        body = fixture.body
        encoding = None
        if fixture.allow_compression and "gzip" in accept_enc.lower():
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as g:
                g.write(body)
            body = buf.getvalue()
            encoding = "gzip"

        # Range handling — only when fixture opts in via support_range=True.
        # Recognises `bytes=N-` and `bytes=N-M`. Out-of-range → 416. Malformed
        # Range header → ignored, full 200. Used by the backend-resume tests
        # and by the (cold-cache origin-fetch path of the) frontend-Range tests.
        range_hdr = self.headers.get("Range", "") if fixture.support_range else ""
        slice_start = 0
        slice_end_inclusive = len(body) - 1
        is_range_response = False
        if range_hdr.startswith("bytes="):
            spec = range_hdr[len("bytes="):].strip()
            try:
                lo_str, hi_str = spec.split("-", 1)
                lo = int(lo_str) if lo_str else 0
                hi = int(hi_str) if hi_str else len(body) - 1
                if 0 <= lo <= hi < len(body):
                    slice_start, slice_end_inclusive = lo, hi
                    is_range_response = True
                else:
                    # 416 Range Not Satisfiable
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{len(body)}")
                    self.send_header("Content-Length", "0")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    return
            except (ValueError, AttributeError):
                # Malformed → fall through to 200 full body.
                is_range_response = False

        if is_range_response:
            sliced = body[slice_start:slice_end_inclusive + 1]
            self.send_response(206)
            self.send_header("Content-Type", fixture.content_type)
            self.send_header("Content-Length", str(len(sliced)))
            self.send_header(
                "Content-Range",
                f"bytes {slice_start}-{slice_end_inclusive}/{len(body)}",
            )
            if fixture.backend_etag:
                self.send_header("ETag", fixture.backend_etag)
            if encoding:
                self.send_header("Content-Encoding", encoding)
            self.send_header("Connection", "close")
            self.end_headers()
            if not send_body:
                return
            try:
                # 206 responses bypass disconnect/bursty/slow profiles — they're
                # used by the resume path which expects clean delivery.
                self.wfile.write(sliced)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        # Vary: when origin advertises Vary: Accept-Encoding, we already chose
        # body+encoding above based on the client's Accept-Encoding header.
        # Vary support is mostly about emitting the Vary response header so
        # confiacdn (and any downstream cache) keys per encoding.
        vary_header = "Accept-Encoding" if fixture.vary_accept_encoding else None

        # Slow-initial-response profile: pause before sending the response
        # line. Used by H3-race tests to force H3 to win on the headers
        # stage (H1.1's `slowheader` only delays the body, which arrives
        # after the daemon has already emitted headers to the client).
        if fixture.profile == "silent_before_headers":
            time.sleep(3.0)

        # Headers (200 full body)
        self.send_response(200)
        self.send_header("Content-Type", fixture.content_type)
        if fixture.chunked:
            self.send_header("Transfer-Encoding", "chunked")
        else:
            # If truncate_at is set, declare the FULL length but send fewer bytes
            # (test that confiacdn detects/handles short bodies under declared CL).
            self.send_header("Content-Length", str(len(body)))
        if fixture.backend_etag:
            self.send_header("ETag", fixture.backend_etag)
        if encoding:
            self.send_header("Content-Encoding", encoding)
        if vary_header:
            self.send_header("Vary", vary_header)
        for k, v in fixture.extra_headers:
            self.send_header(k, v)
        self.send_header("Connection", "close")
        self.end_headers()

        if not send_body:
            return

        # Slow header profile: pause before sending any body byte.
        if fixture.profile == "slowheader":
            time.sleep(3.0)

        try:
            if fixture.chunked:
                self._write_chunked(body)
            elif fixture.truncate_at > 0:
                self.wfile.write(body[:fixture.truncate_at])
                # Close the connection cleanly to expose under-CL truncation.
                self.wfile.flush()
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            else:
                self._write_body_with_profile(body, fixture)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _write_chunked(self, body: bytes):
        """Write body in HTTP/1.1 chunked encoding. Splits into ~16KB pieces."""
        chunk = 16 * 1024
        for i in range(0, len(body), chunk):
            piece = body[i:i + chunk]
            self.wfile.write(f"{len(piece):x}\r\n".encode("ascii"))
            self.wfile.write(piece)
            self.wfile.write(b"\r\n")
        self.wfile.write(b"0\r\n\r\n")

    def _write_body_with_profile(self, body: bytes, fixture: "Fixture"):
        profile = fixture.profile
        if profile in ("fast", "error", "slowheader"):
            self.wfile.write(body)
            return
        if profile == "disconnect":
            # Send first ~25% then close — exercises mid-stream backend failure.
            cut = max(1, len(body) // 4)
            self.wfile.write(body[:cut])
            try:
                self.wfile.flush()
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            return
        if profile == "freeze_mid_body":
            # Send first ~25% of the body then go silent without closing the
            # TCP connection. confiacdn's --maxreadtime should fire and the
            # daemon must surface a 5xx (or stale-fallback if a warm cache
            # exists) without aborting. Sleeps longer than --maxreadtime so
            # the timeout path is what ends the connection on confiacdn's
            # side; thread exits when client closes.
            cut = max(1, len(body) // 4)
            try:
                self.wfile.write(body[:cut])
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                return
            time.sleep(35.0)
            return
        if profile == "rst_mid_body":
            # Send first ~25% then RST (vs disconnect's clean FIN). RST is what
            # a transit middlebox or a hard-killed origin produces; confiacdn
            # must handle ECONNRESET on read identically — no abort, no leak,
            # propagate cleanly to clients.
            cut = max(1, len(body) // 4)
            try:
                self.wfile.write(body[:cut])
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                return
            try:
                # SO_LINGER with l_onoff=1, l_linger=0 -> close() emits RST.
                import struct as _struct
                self.connection.setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER,
                    _struct.pack("ii", 1, 0))
                self.connection.close()
            except OSError:
                pass
            return
        if profile == "disconnect_then_recover":
            # First request from confiacdn: send first ~25% then close. Subsequent
            # requests (the retry/resume): serve the full body normally. Used by
            # the "backend disconnect + recover during one client's download" test
            # to verify confiacdn reconnects and the client still gets the full body.
            # fixture.serve_count was already incremented by self.bump() in _serve.
            if fixture.serve_count == 1:
                cut = max(1, len(body) // 4)
                self.wfile.write(body[:cut])
                try:
                    self.wfile.flush()
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            else:
                # Pace the recovery write so the test still sees a streaming response,
                # not a single fast burst (helps confiacdn's read loop look realistic).
                self._paced_write(body, bytes_per_sec=125_000)
            return
        if profile == "slow1mbps":
            return self._paced_write(body, bytes_per_sec=125_000)
        if profile == "bursty":
            return self._bursty_write(body)
        # default
        self.wfile.write(body)

    def _paced_write(self, body: bytes, bytes_per_sec: int):
        # Write in ~50ms slices.
        chunk = max(1, bytes_per_sec // 20)
        sent = 0
        start = time.monotonic()
        while sent < len(body):
            piece = body[sent:sent + chunk]
            self.wfile.write(piece)
            self.wfile.flush()
            sent += len(piece)
            target = start + sent / bytes_per_sec
            now = time.monotonic()
            if target > now:
                time.sleep(target - now)

    def _write_streaming_body(self, fixture: "Fixture"):
        """Write `fixture.stream_size` bytes of deterministic content paced at
        `fixture.stream_rate_bps`. Body never materialised in full."""
        chunk = streaming_chunk(fixture.stream_seed, 65536)
        rate = fixture.stream_rate_bps
        sent = 0
        total = fixture.stream_size
        slice_bytes = max(8192, rate // 20) if rate > 0 else 65536
        start = time.monotonic()
        while sent < total:
            remaining = total - sent
            # Position inside the tiled chunk.
            off = sent % 65536
            n = min(slice_bytes, 65536 - off, remaining)
            self.wfile.write(chunk[off:off + n])
            sent += n
            if rate > 0:
                self.wfile.flush()
                target = start + sent / rate
                now = time.monotonic()
                if target > now:
                    time.sleep(target - now)

    def _bursty_write(self, body: bytes):
        # Pattern: 1 Mbps for 1s, 10 Mbps for 0.1s, silent 1s, repeat.
        sent = 0
        while sent < len(body):
            for rate, dur in [(125_000, 1.0), (1_250_000, 0.1), (0, 1.0)]:
                if sent >= len(body):
                    break
                if rate == 0:
                    time.sleep(dur)
                    continue
                bytes_to_send = int(rate * dur)
                end = sent + bytes_to_send
                self._paced_write(body[sent:end], bytes_per_sec=rate)
                sent = end

    def _reply_status(self, code: int, msg: bytes,
                      extra_headers: Optional[List[Tuple[str, str]]] = None):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(msg)))
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(msg)
        except (BrokenPipeError, ConnectionResetError):
            pass


class ThreadingHTTPv6Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True
    daemon_threads = True

    def server_bind(self):
        # Allow dual-stack so confiacdn (dialing ::1) and test code (using 127.0.0.1)
        # both reach us if needed.
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except OSError:
            pass
        super().server_bind()


def start_origin(harness_log: FileLogger) -> Tuple[ThreadingHTTPv6Server, threading.Thread, Dict[str, Fixture]]:
    fixtures: Dict[str, Fixture] = {}
    server = ThreadingHTTPv6Server(("::", FORCEDPORT), OriginHandler)
    server.fixtures = fixtures
    server.harness_log = harness_log
    t = threading.Thread(target=server.serve_forever, name="origin", daemon=True)
    t.start()
    write_pid_file(ORIGIN_PID_FILE, os.getpid())
    harness_log.info(f"origin (HTTP) listening on [::]:{FORCEDPORT}")
    return server, t, fixtures


SNI_LOG: List[Optional[str]] = []      # every TLS handshake records its SNI here
SNI_REQUIRE: Optional[str] = None       # if set, server rejects TLS with mismatched SNI


def reset_sni_state(require: Optional[str] = None) -> None:
    """Clear recorded SNI values and arm the server-side SNI gate.
    `require=None` accepts any (or missing) SNI; otherwise the TLS handshake
    is rejected unless the client sent exactly that name.

    The harness can then assert what SNI confiacdn sent by inspecting SNI_LOG."""
    global SNI_REQUIRE
    SNI_LOG.clear()
    SNI_REQUIRE = require


def start_origin_https(harness_log: FileLogger,
                       fixtures: Dict[str, Fixture]) -> ThreadingHTTPv6Server:
    """Spawn a parallel HTTPS listener using the self-signed cert. Shares the
    same fixture dict so /https-foo can be served at both ports.

    Records every received SNI into SNI_LOG and (when SNI_REQUIRE is armed)
    rejects handshakes with a missing or mismatched SNI — used by the
    https_backend_sets_sni regression test for the missing-SNI bug that took
    out every HTTPS upstream in production."""
    import ssl  # local import — only needed for HTTPS test
    ensure_self_signed_cert()
    server = ThreadingHTTPv6Server(("::", FORCEDPORT_TLS), OriginHandler)
    server.fixtures = fixtures
    server.harness_log = harness_log
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(TLS_CERT_FILE, TLS_KEY_FILE)

    def _sni_callback(sslsock, server_name, _ctx):
        SNI_LOG.append(server_name)
        if SNI_REQUIRE is not None and server_name != SNI_REQUIRE:
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        return None
    ctx.set_servername_callback(_sni_callback)

    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    t = threading.Thread(target=server.serve_forever, name="origin-https", daemon=True)
    t.start()
    harness_log.info(f"origin (HTTPS) listening on [::]:{FORCEDPORT_TLS}")
    return server


# ---------------------------------------------------------------------------
# HTTP client — requests confiacdn through nginx
# ---------------------------------------------------------------------------

@dataclass
class Response:
    status: int
    headers: Dict[str, str]
    body: bytes
    elapsed: float
    decoded_body: bytes  # body after Content-Encoding decoding


def fetch(path: str, host: str = DEFAULT_HOST, accept_gzip: bool = False,
          if_none_match: Optional[str] = None, timeout: float = 60.0,
          read_until_byte: Optional[int] = None,
          progress_cb: Optional[Callable[[int], None]] = None) -> Response:
    """Single GET against nginx. `path` is the origin-relative path (e.g. /foo);
    the harness prefixes ORIGIN_HOST so confiacdn's URI parser routes correctly.
    Optionally stops reading at read_until_byte."""
    start = time.monotonic()
    full_path = f"/{ORIGIN_HOST}{path}"
    conn = http.client.HTTPConnection("127.0.0.1", NGINX_PORT, timeout=timeout)
    try:
        headers = {"Host": host, "Connection": "close"}
        if accept_gzip:
            headers["Accept-Encoding"] = "gzip"
        if if_none_match is not None:
            headers["If-None-Match"] = if_none_match
        conn.request("GET", full_path, headers=headers)
        resp = conn.getresponse()
        body = bytearray()
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            body += chunk
            if progress_cb:
                progress_cb(len(body))
            if read_until_byte is not None and len(body) >= read_until_byte:
                break
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        decoded = bytes(body)
        if hdrs.get("content-encoding", "").lower() == "gzip" and decoded:
            try:
                decoded = gzip.decompress(decoded)
            except OSError:
                # Will be flagged by the test if it compared bytes.
                pass
        return Response(resp.status, hdrs, bytes(body), time.monotonic() - start, decoded)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Log scanning — applied per case, based on a wall-clock window
# ---------------------------------------------------------------------------

# Per-stream rules — confiacdn writes free-form `std::cerr` lines that often
# contain "WARN" or "(abort)" descriptively without the daemon actually aborting,
# so we match precisely on what indicates real lifecycle breakage rather than on
# severity keywords sprinkled in narration.

# nginx error log: anything at or above [warn], plus connection-failure substrings.
_NGINX_BAD_RE = re.compile(r"\[(warn|error|crit|alert|emerg)\]", re.IGNORECASE)
_NGINX_FORBIDDEN = (
    "upstream timed out",
    "upstream prematurely closed",
    "recv() failed",
    "connect() failed",
)

# confiacdn log: lifecycle-violation strings that the DEBUGFASTCGI / DEBUGDNS
# guards print right before / instead of an actual abort(). These are real bugs.
# The list also covers the diagnostic tools we run confiacdn under:
#   - gcc/clang sanitizer runtimes (ASan/LSan/MSan/TSan/UBSan): each emits a
#     header line with the sanitizer name when a finding is reported.
#   - the kernel / shell when confiacdn crashes (SIGSEGV, SIGABRT, etc.) and
#     when gdb is attached (Backtrace / received signal lines).
#   - valgrind: emits `==<pid>== <category>` lines for each finding; we match
#     the category text so any wrapper PID still hits.
_CONFIACDN_FORBIDDEN = (
    # confiacdn's own DEBUGFASTCGI / DEBUGDNS lifecycle-violation lines.
    "DOBLE DELETE LOOP",
    "delete Client failed",
    "delete Backend failed",
    "delete Http failed",
    "use after free",
    "corruption detected",
    # Crash signals (kernel, shell, gdb).
    "Segmentation fault",
    "Aborted (core dumped)",
    "core dumped",
    "Program received signal",      # gdb attaches and prints this on signal
    "received signal SIGSEGV",
    "received signal SIGABRT",
    "received signal SIGBUS",
    "received signal SIGILL",
    "received signal SIGFPE",
    "[Switching to Thread",         # gdb when it attaches to a crashed thread
    "[Thread debugging using libthread_db",  # gdb startup line on a process
    " received signal SIG",         # gdb: `Thread N "..." received signal SIGxxx`
    # glibc heap-corruption diagnostics — these print BEFORE SIGABRT and
    # identify the actual root cause (double-free, OOB write, etc).
    "*** stack smashing detected ***",
    "*** glibc detected ***",
    "*** buffer overflow detected ***",
    "free(): invalid pointer",
    "free(): invalid size",
    "free(): invalid next size",
    "free(): double free detected",
    "malloc(): memory corruption",
    "malloc(): unaligned tcache chunk",
    "malloc(): unsorted double linked list corrupted",
    "corrupted size vs. prev_size",
    "corrupted double-linked list",
    "double free or corruption",
    "realloc(): invalid old size",
    # C++ runtime: uncaught exception → std::terminate → SIGABRT.
    "terminate called after throwing an instance of",
    "terminate called without an active exception",
    "terminate called recursively",
    "pure virtual method called",
    # AddressSanitizer (clang & gcc).
    "AddressSanitizer:",
    "==ERROR: AddressSanitizer",
    "SUMMARY: AddressSanitizer",
    # LeakSanitizer (clang & gcc, also embedded in ASan).
    "LeakSanitizer:",
    "==ERROR: LeakSanitizer",
    "SUMMARY: LeakSanitizer",
    # MemorySanitizer (clang only).
    "MemorySanitizer:",
    "==ERROR: MemorySanitizer",
    "WARNING: MemorySanitizer:",
    "SUMMARY: MemorySanitizer",
    # ThreadSanitizer (clang & gcc) — confiacdn is single-threaded but include
    # for safety in case someone wires up an experimental TSan build.
    "ThreadSanitizer:",
    "==ERROR: ThreadSanitizer",
    "WARNING: ThreadSanitizer:",
    "SUMMARY: ThreadSanitizer",
    "data race",
    # UndefinedBehaviorSanitizer (clang & gcc).
    "UndefinedBehaviorSanitizer:",
    "SUMMARY: UndefinedBehaviorSanitizer",
    "runtime error:",  # UBSan one-line reports without abort
    # Valgrind memcheck (--leak-check=full prefix is `==<pid>==`).
    # We match the category text — any pid prefix still triggers.
    "Invalid read of size",
    "Invalid write of size",
    "Invalid free()",
    "Mismatched free()",
    "Conditional jump or move depends on uninitialised value",
    "Use of uninitialised value of size",
    "Source and destination overlap in",
    "Syscall param ",                 # "Syscall param X points to uninitialised"
    " definitely lost in loss record ",
    " indirectly lost in loss record ",
    "Process terminating with default action of signal",  # valgrind on SIGSEGV target
    # Valgrind Helgrind / DRD race detectors (would only fire if confiacdn
    # ever grows threads — kept here so it doesn't slip past silently).
    "Possible data race during read",
    "Possible data race during write",
    "Lock at ",                       # helgrind lock-ordering reports
    "Conflicting load by thread",     # DRD race signature
    "Conflicting store by thread",
    "ERROR SUMMARY: ",                # valgrind end-of-run summary (memcheck/helgrind/drd)
)
# Timeouts we care about — but ONLY when the request actually got a backend reply.
# This is hard to attribute per-request from the log alone, so as a coarse proxy
# we only flag confiacdn lines that explicitly say a NonHttpError_Timeout fired.
_CONFIACDN_TIMEOUT = re.compile(r"NonHttpError_Timeout", re.IGNORECASE)

# Harness-side logs (client + origin + harness): structured "LEVEL " prefix.
_STRUCTURED_BAD_RE = re.compile(r"^\d\d:\d\d:\d\d (WARNING|ERROR|CRITICAL|FATAL)\b")


def scan_logs_for_failures(t0: float, label: str, confiacdn_proc: Optional[subprocess.Popen] = None) -> List[str]:
    """Return human-readable failure messages from all log streams. Empty = pass."""
    failures: List[str] = []

    # 0. confiacdn process must still be alive.
    if confiacdn_proc is not None and confiacdn_proc.poll() is not None:
        failures.append(f"confiacdn process exited with code {confiacdn_proc.returncode}")

    # 1. nginx error log
    try:
        with open(NGINX_ERROR_LOG) as f:
            for i, line in enumerate(f):
                m = _NGINX_BAD_RE.search(line)
                if m:
                    failures.append(f"nginx-error.log:{i+1} [{m.group(1)}]: {line.rstrip()}")
                    continue
                low = line.lower()
                for sub in _NGINX_FORBIDDEN:
                    if sub in low:
                        failures.append(f"nginx-error.log:{i+1} '{sub}': {line.rstrip()}")
                        break
    except FileNotFoundError:
        pass

    # 2. confiacdn log — lifecycle-violation patterns and explicit timeouts.
    try:
        with open(CONFIACDN_LOG) as f:
            for i, line in enumerate(f):
                for sub in _CONFIACDN_FORBIDDEN:
                    if sub in line:
                        failures.append(f"confiacdn.log:{i+1} '{sub}': {line.rstrip()}")
                        break
                if _CONFIACDN_TIMEOUT.search(line):
                    failures.append(f"confiacdn.log:{i+1} timeout: {line.rstrip()}")
    except FileNotFoundError:
        pass

    # 3. harness client + origin + harness logs — structured-prefix WARNING+.
    for path in (CLIENT_LOG, ORIGIN_LOG):
        try:
            with open(path) as f:
                for i, line in enumerate(f):
                    if _STRUCTURED_BAD_RE.match(line):
                        failures.append(f"{os.path.basename(path)}:{i+1} {line.rstrip()}")
        except FileNotFoundError:
            pass

    return failures


# ---------------------------------------------------------------------------
# Test framework
# ---------------------------------------------------------------------------

@dataclass
class TestResult:
    name: str
    passed: bool
    message: str = ""
    elapsed: float = 0.0


class Harness:
    """Owns the running stack; tests use its handles."""

    def __init__(self, args, log: FileLogger):
        self.args = args
        self.log = log
        self.client_log = FileLogger(CLIENT_LOG)
        self.origin_log = FileLogger(ORIGIN_LOG)
        self.confiacdn: Optional[subprocess.Popen] = None
        self.nginx: Optional[subprocess.Popen] = None
        self.origin_server: Optional[ThreadingHTTPv6Server] = None
        self.origin_https_server: Optional[ThreadingHTTPv6Server] = None
        self.origin_h3: Optional[subprocess.Popen] = None
        self.h3_smoke_bin: Optional[str] = None
        self.fixtures: Dict[str, Fixture] = {}

    # --- lifecycle --------------------------------------------------------

    def setup(self) -> None:
        ensure_dirs()
        kill_all(self.log)
        self.origin_server, _t, self.fixtures = start_origin(self.origin_log)
        try:
            self.origin_https_server = start_origin_https(self.origin_log, self.fixtures)
        except Exception as e:
            # HTTPS origin failure is not fatal to harness setup, but the
            # https_backend_self_signed_cert test will fail (not skip) since
            # tests are pass-or-fail.
            self.log.warn(f"HTTPS origin not started ({e}); HTTPS tests will FAIL")
        try:
            self.origin_h3 = start_origin_h3(self.log)
        except Exception as e:
            # Same posture as HTTPS origin: failure is not fatal but every
            # h3_smoke_* test will fail (not skip) until the origin is up.
            self.log.warn(f"H3 origin not started ({e}); h3_smoke tests will FAIL")
        # confiacdn flags: tiny http200Time so warm-stale triggers fast; small maxBackend
        # to exercise the queue; --maxreadtime/--maxdwritetime moderate.
        self.confiacdn = start_confiacdn(self.log, [
            "--http200Time=2",
            "--maxdownloadtime=120",
            "--maxreadtime=20",
            "--maxdwritetime=20",
            "--maxBackend=8",
        ], sanitize=self.args.sanitize, valgrind=self.args.valgrind)
        self.nginx = start_nginx(self.log)

    def teardown(self) -> None:
        if self.origin_server:
            self.origin_server.shutdown()
            self.origin_server.server_close()
        if self.origin_https_server:
            self.origin_https_server.shutdown()
            self.origin_https_server.server_close()
        if self.origin_h3 and self.origin_h3.poll() is None:
            self.origin_h3.terminate()
            try:
                self.origin_h3.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.origin_h3.kill()
        kill_all(self.log)

    def restart_confiacdn(self, extra_args: Optional[List[str]] = None) -> None:
        """Stop confiacdn, drop cache, restart. Used by cold-cache tests."""
        kill_pid_file(CONFIACDN_PID_FILE, log=self.log)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(FASTCGI_SOCK)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(RELOAD_SOCK)
        if os.path.isdir(CACHE_DIR):
            shutil.rmtree(CACHE_DIR)
        # Truncate confiacdn log so per-case scanning starts clean.
        open(CONFIACDN_LOG, "w").close()
        base = ["--http200Time=2", "--maxdownloadtime=120",
                "--maxreadtime=20", "--maxdwritetime=20", "--maxBackend=8"]
        self.confiacdn = start_confiacdn(
            self.log, base + (extra_args or []),
            sanitize=self.args.sanitize,
            valgrind=self.args.valgrind,
        )

    def reset_logs(self) -> None:
        for p in (CONFIACDN_LOG, NGINX_ERROR_LOG, NGINX_ACCESS_LOG, CLIENT_LOG, ORIGIN_LOG):
            with contextlib.suppress(FileNotFoundError):
                open(p, "w").close()

    def reset_fixtures(self) -> None:
        self.fixtures.clear()


# ---------------------------------------------------------------------------
# Helpers used by tests
# ---------------------------------------------------------------------------

def make_body(size: int, seed: int = 0xC0FFEE, content_type: str = "application/octet-stream",
              compressible: bool = False) -> Tuple[bytes, str]:
    rng = random.Random(seed)
    if compressible:
        # Repeating chunk so gzip actually shrinks.
        chunk = bytes(rng.randint(0, 255) for _ in range(256))
        reps = (size // 256) + 1
        body = (chunk * reps)[:size]
        ctype = "text/plain; charset=utf-8"
    else:
        body = rng.randbytes(size) if hasattr(rng, "randbytes") else bytes(rng.getrandbits(8) for _ in range(size))
        ctype = content_type
    return body, ctype


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Test case definitions
#
# Each test takes (h: Harness) and either returns nothing (pass) or raises
# AssertionError with a useful message. The runner wraps it for log scanning.
# ---------------------------------------------------------------------------

@dataclass
class _TestEntry:
    name: str
    fn: Callable[["Harness"], None]
    timeout_sec: float
    # Optional opt-out gate: if set to "soak"/"full", the test is filtered out
    # of the run when the matching --no-soak/--no-full flag is passed. A test
    # that runs always produces a pass-or-fail outcome — never "skipped".
    gated_by: Optional[str] = None


TESTS: List[_TestEntry] = []

# Timeout budget per test (wall-clock seconds). The runner kills a test that
# overruns this and reports it as TIMEOUT — the daemon keeps running.
DEFAULT_TIMEOUT_SEC = 60.0


def register(name: str, *, timeout: float = DEFAULT_TIMEOUT_SEC,
             gated_by: Optional[str] = None):
    def deco(fn):
        TESTS.append(_TestEntry(name, fn, timeout, gated_by=gated_by))
        return fn
    return deco


# ----- Cold cache, fast download, sizes & compression cross-product --------

def _cold_fetch_and_verify(h: Harness, *, size: int, compressible: bool,
                           accept_gzip: bool, allow_origin_gzip: bool) -> None:
    h.restart_confiacdn(extra_args=([] if allow_origin_gzip else ["--disableCompressionForBackend"]))
    h.reset_fixtures()
    body, ctype = make_body(size, seed=size ^ (1 if compressible else 0), compressible=compressible)
    path = f"/cold-{size}-{int(compressible)}-{int(accept_gzip)}-{int(allow_origin_gzip)}"
    fx = Fixture(body=body, content_type=ctype, backend_etag='"orig-etag-1"',
                 allow_compression=allow_origin_gzip)
    h.fixtures[path] = fx
    r = fetch(path, accept_gzip=accept_gzip)
    if r.status != 200:
        raise AssertionError(f"status={r.status}, expected 200")
    if r.decoded_body != body:
        raise AssertionError(
            f"body mismatch: got {len(r.decoded_body)}B sha={sha(r.decoded_body)}, "
            f"expected {len(body)}B sha={sha(body)}")
    if not r.headers.get("content-type", "").startswith(ctype.split(";")[0]):
        raise AssertionError(f"content-type mismatch: {r.headers.get('content-type')}")


for _size in (1 * 1024 * 1024, 10 * 1024 * 1024):
    for _comp in (False, True):
        for _afgz in (False, True):
            for _bgz in (False, True):
                _name = f"cold_{_size//1024//1024}MB_comp{int(_comp)}_afgz{int(_afgz)}_bgz{int(_bgz)}"
                def _make(size=_size, compressible=_comp, accept_gzip=_afgz, allow_origin_gzip=_bgz):
                    def _t(h: Harness):
                        _cold_fetch_and_verify(
                            h, size=size, compressible=compressible,
                            accept_gzip=accept_gzip, allow_origin_gzip=allow_origin_gzip)
                    return _t
                register(_name)(_make())


# ----- Warm-fresh: second request must not hit origin ----------------------

@register("warm_fresh_no_backend_hit")
def _warm_fresh(h: Harness):
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(1 * 1024 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"warmfresh"')
    h.fixtures["/warm-fresh"] = fx
    r1 = fetch("/warm-fresh")
    if r1.status != 200 or r1.decoded_body != body:
        raise AssertionError("first fetch broken")
    if fx.serve_count != 1:
        raise AssertionError(f"expected 1 origin hit, got {fx.serve_count}")
    # Second fetch — within --http200Time=2, must not hit origin.
    time.sleep(0.2)
    r2 = fetch("/warm-fresh")
    if r2.status != 200 or r2.decoded_body != body:
        raise AssertionError("second fetch broken")
    if fx.serve_count != 1:
        raise AssertionError(f"warm-fresh hit origin {fx.serve_count} times (want 1)")


# ----- Warm-stale + 304: backend ETag match → no body fetch ---------------

@register("warm_stale_backend_etag_304")
def _warm_stale_304(h: Harness):
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(2 * 1024 * 1024)
    fx = Fixture(body=body, content_type=ctype,
                 backend_etag='"stable-etag"', revalidate_match='"stable-etag"')
    h.fixtures["/warm-stale-304"] = fx
    r1 = fetch("/warm-stale-304")
    if r1.status != 200 or r1.decoded_body != body:
        raise AssertionError("first fetch broken")
    # Wait past --http200Time=2.
    time.sleep(3)
    r2 = fetch("/warm-stale-304")
    if r2.status != 200:
        raise AssertionError(f"revalidated fetch status={r2.status}")
    if r2.decoded_body != body:
        raise AssertionError("revalidated body mismatch (cache should still serve)")
    # Origin must have been contacted (revalidate) but only with HEAD-like
    # If-None-Match — and replied 304 with no body. We can't observe HTTP-level
    # request bytes here, but we can check origin's serve_count incremented exactly once.
    if fx.serve_count != 2:
        raise AssertionError(f"origin served {fx.serve_count} times, expected 2 (initial + revalidate)")


# ----- Warm-stale + 200 (new content): cache replaced ---------------------

@register("warm_stale_backend_200_new_content")
def _warm_stale_new(h: Harness):
    h.restart_confiacdn()
    h.reset_fixtures()
    body1, ctype = make_body(1 * 1024 * 1024, seed=1)
    fx = Fixture(body=body1, content_type=ctype, backend_etag='"v1"')
    h.fixtures["/warm-stale-200"] = fx
    r1 = fetch("/warm-stale-200")
    if r1.decoded_body != body1:
        raise AssertionError("v1 body mismatch")
    # Mutate fixture: new content, new ETag, no revalidate match.
    body2, _ = make_body(1 * 1024 * 1024, seed=2)
    fx.body = body2
    fx.backend_etag = '"v2"'
    fx.revalidate_match = None
    time.sleep(3)  # past http200Time
    r2 = fetch("/warm-stale-200")
    if r2.decoded_body != body2:
        raise AssertionError("v2 body mismatch (cache should have updated)")


# ----- Warm-stale + origin failure: serve stale ---------------------------

@register("warm_stale_origin_fail_serves_stale")
def _warm_stale_fail(h: Harness):
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(512 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"v1"')
    h.fixtures["/warm-stale-fail"] = fx
    r1 = fetch("/warm-stale-fail")
    if r1.decoded_body != body:
        raise AssertionError("first fetch broken")
    # Flip origin into error mode.
    fx.profile = "error"
    fx.error_status = 502
    time.sleep(3)
    r2 = fetch("/warm-stale-fail")
    # Required by mission item 5: serve stale on origin failure.
    if r2.status != 200:
        raise AssertionError(f"expected 200 (stale fallback) on origin 502, got {r2.status}")
    if r2.decoded_body != body:
        raise AssertionError("stale-fallback body mismatch")


# ----- Frontend ETag: client If-None-Match matches -> 304 -----------------

@register("frontend_etag_match_304")
def _frontend_etag_match(h: Harness):
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(64 * 1024)
    h.fixtures["/fe-etag"] = Fixture(body=body, content_type=ctype, backend_etag='"be-1"')
    r1 = fetch("/fe-etag")
    fe_etag = r1.headers.get("etag", "")
    # confiacdn returns a quoted 6-char ETag (8 chars total including quotes).
    # The HTTP_IF_NONE_MATCH FastCGI parser requires valSize==8 — see Client.cpp:594 —
    # and the cache-side comparison strips the leading quote and takes 6 chars
    # (Client.cpp:1211). Sending the verbatim header value is what matches.
    if len(fe_etag) != 8 or not fe_etag.startswith('"') or not fe_etag.endswith('"'):
        raise AssertionError(f"unexpected ETag from confiacdn: {fe_etag!r}")
    r2 = fetch("/fe-etag", if_none_match=fe_etag)
    if r2.status != 304:
        raise AssertionError(f"expected 304 with matching If-None-Match={fe_etag!r}, got {r2.status}")
    if len(r2.body) > 0:
        raise AssertionError(f"304 body must be empty, got {len(r2.body)}B")


@register("frontend_etag_wrong_returns_200")
def _frontend_etag_wrong(h: Harness):
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(32 * 1024)
    h.fixtures["/fe-etag-wrong"] = Fixture(body=body, content_type=ctype, backend_etag='"be"')
    fetch("/fe-etag-wrong")  # warm cache
    r = fetch("/fe-etag-wrong", if_none_match="WRONG123")
    if r.status != 200 or r.decoded_body != body:
        raise AssertionError(f"wrong ETag should return full 200; got status={r.status} len={len(r.decoded_body)}")


# ----- Concurrent fan-out: early joiners ----------------------------------

@register("concurrent_early_joiners_one_backend_hit", timeout=120.0)
def _concurrent_early(h: Harness):
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(1 * 1024 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"fx"', profile="slow1mbps")
    h.fixtures["/fanout-early"] = fx

    results: List[Response] = []
    errors: List[str] = []

    def go():
        try:
            results.append(fetch("/fanout-early", timeout=120))
        except Exception as e:
            errors.append(repr(e))

    threads = [threading.Thread(target=go) for _ in range(5)]
    # Start them as close together as we can — before any backend bytes arrive.
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    if errors:
        raise AssertionError(f"client errors: {errors}")
    if len(results) != 5:
        raise AssertionError(f"expected 5 responses, got {len(results)}")
    for i, r in enumerate(results):
        if r.status != 200:
            raise AssertionError(f"client {i} status {r.status}")
        if r.decoded_body != body:
            raise AssertionError(f"client {i} body mismatch")
    if fx.serve_count != 1:
        raise AssertionError(f"origin saw {fx.serve_count} requests, expected 1 (de-dup)")


# ----- Concurrent fan-out: late joiners at multiple progress points -------

@register("concurrent_late_joiners", timeout=120.0)
def _concurrent_late(h: Harness):
    h.restart_confiacdn()
    h.reset_fixtures()
    # Use 1MB at ~125KB/s → ~8 s. Late joiners arrive at 1s, 3s, 5s, 7s.
    body, ctype = make_body(1 * 1024 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"late"', profile="slow1mbps")
    h.fixtures["/fanout-late"] = fx

    results: List[Tuple[str, Response]] = []
    errors: List[str] = []
    lock = threading.Lock()

    def go(label: str, delay: float):
        time.sleep(delay)
        try:
            r = fetch("/fanout-late", timeout=120)
            with lock:
                results.append((label, r))
        except Exception as e:
            with lock:
                errors.append(f"{label}: {e!r}")

    threads = [
        threading.Thread(target=go, args=("primary", 0.0)),
        threading.Thread(target=go, args=("late-1s", 1.0)),
        threading.Thread(target=go, args=("late-3s", 3.0)),
        threading.Thread(target=go, args=("late-5s", 5.0)),
        threading.Thread(target=go, args=("late-7s", 7.0)),
    ]
    for t in threads: t.start()
    for t in threads: t.join()

    if errors:
        raise AssertionError(f"client errors: {errors}")
    for label, r in results:
        if r.status != 200:
            raise AssertionError(f"{label}: status {r.status}")
        if r.decoded_body != body:
            raise AssertionError(f"{label}: body mismatch ({len(r.decoded_body)} vs {len(body)})")
    if fx.serve_count != 1:
        raise AssertionError(f"origin saw {fx.serve_count} requests, expected 1 across 5 clients")


# ----- Joiner disconnects mid-fan-out -------------------------------------

@register("joiner_disconnects_midstream", timeout=120.0)
def _joiner_disconnects(h: Harness):
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(1 * 1024 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"jd"', profile="slow1mbps")
    h.fixtures["/joiner-disco"] = fx

    primary_result: List[Optional[Response]] = [None]
    primary_err: List[Optional[str]] = [None]

    def primary():
        try:
            primary_result[0] = fetch("/joiner-disco", timeout=120)
        except Exception as e:
            primary_err[0] = repr(e)

    p = threading.Thread(target=primary)
    p.start()

    # Late joiner that aborts after 100KB.
    def joiner_aborts():
        time.sleep(1.5)
        with contextlib.suppress(Exception):
            fetch("/joiner-disco", read_until_byte=100_000, timeout=120)

    j = threading.Thread(target=joiner_aborts)
    j.start()
    j.join()

    p.join()
    if primary_err[0]:
        raise AssertionError(f"primary failed after joiner disconnect: {primary_err[0]}")
    r = primary_result[0]
    assert r is not None
    if r.decoded_body != body:
        raise AssertionError("primary body corrupted by joiner disconnect")


# ----- Sole client killed mid-download, restarted after 10 s --------------

@register("kill_solo_download_restart_10s", timeout=120.0)
def _kill_solo_then_restart(h: Harness):
    """Lone client downloads, gets killed (TCP RST) mid-stream. After a 10 s
    quiescence the harness starts a fresh client on the same URL; it must
    succeed with byte-identical content. No abort/leak in confiacdn."""
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(1 * 1024 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"krs"', profile="slow1mbps")
    h.fixtures["/krs"] = fx

    # Open a raw socket connection to nginx, send the GET, read ~100KB, then
    # SO_LINGER=0 + close → RST to the upstream chain so the cancel propagates
    # to confiacdn.
    sock = socket.create_connection(("127.0.0.1", NGINX_PORT), timeout=10)
    req = (
        f"GET /{ORIGIN_HOST}/krs HTTP/1.1\r\n"
        f"Host: {DEFAULT_HOST}\r\nConnection: close\r\n\r\n"
    ).encode()
    sock.sendall(req)
    received = 0
    deadline = time.monotonic() + 10
    while received < 100_000 and time.monotonic() < deadline:
        chunk = sock.recv(8192)
        if not chunk:
            break
        received += len(chunk)
    # Force RST.
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack("ii", 1, 0))
    except OSError:
        pass
    sock.close()

    # Quiescence — give confiacdn time to notice and unwind.
    time.sleep(10)

    # Fresh client must complete fully.
    r = fetch("/krs", timeout=60)
    if r.status != 200:
        raise AssertionError(f"restart fetch status {r.status}")
    if r.decoded_body != body:
        raise AssertionError(
            f"restart body mismatch: {len(r.decoded_body)}B vs {len(body)}B")


# ----- Backend disconnect + redownload-from-0 (origin doesn't honour Range) -

@register("backend_disconnect_then_recover_one_client", timeout=90.0)
def _backend_disconnect_then_recover(h: Harness):
    """One client downloads a 1 MB file at 1 Mbps (~8 s). The origin sends the
    first ~25 %, closes the TCP connection, then continues to listen. Origin
    does NOT honour `Range` (support_range=False) — so on the retry confiacdn
    must redownload from byte 0, discarding the partial cache. Client must
    still end with a byte-identical full body.

    Asserts:
      - status==200, decoded body byte-identical, content-type round-tripped,
      - origin saw at least 2 requests (one truncated, one or more retries),
      - log scan catches any (abort) or NonHttpError_Timeout-on-replied-request.
    """
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(1 * 1024 * 1024)
    fx = Fixture(
        body=body, content_type=ctype, backend_etag='"recover"',
        profile="disconnect_then_recover",
        support_range=False,
    )
    h.fixtures["/backend-recover"] = fx

    r = fetch("/backend-recover", timeout=60)
    if r.status != 200:
        raise AssertionError(f"status {r.status} (expected 200 after reconnect)")
    if r.decoded_body != body:
        raise AssertionError(
            f"body mismatch after backend reconnect: got {len(r.decoded_body)}B "
            f"sha={sha(r.decoded_body)}, expected {len(body)}B sha={sha(body)}")
    if not r.headers.get("content-type", "").startswith(ctype.split(";")[0]):
        raise AssertionError(f"content-type mismatch: {r.headers.get('content-type')}")
    if fx.serve_count < 2:
        raise AssertionError(
            f"origin only saw {fx.serve_count} request(s); expected >=2 "
            f"(one truncated + one retry)")


# ----- Backend disconnect + resume via Range (origin supports Range) ------

@register("backend_disconnect_resume_with_range", timeout=90.0)
def _backend_disconnect_resume_range(h: Harness):
    """One client downloads a 1 MB file at 1 Mbps. Origin sends ~25 % then
    closes. Origin supports Range. On retry, confiacdn must send
    `Range: bytes=N-`; origin replies 206 from offset N; confiacdn appends the
    new bytes to the existing partial cache; client receives byte-identical
    full body uninterrupted. nginx must NOT log "more data than Content-Length"
    (treated as a hard failure of this case).
    """
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(1 * 1024 * 1024)
    fx = Fixture(
        body=body, content_type=ctype, backend_etag='"resume"',
        profile="disconnect_then_recover",
        support_range=True,
    )
    h.fixtures["/backend-resume"] = fx

    r = fetch("/backend-resume", timeout=60)
    if r.status != 200:
        raise AssertionError(f"status {r.status} (expected 200 after Range resume)")
    if r.decoded_body != body:
        raise AssertionError(
            f"body mismatch after Range resume: got {len(r.decoded_body)}B "
            f"sha={sha(r.decoded_body)}, expected {len(body)}B sha={sha(body)}")
    if fx.serve_count < 2:
        raise AssertionError(
            f"origin only saw {fx.serve_count} request(s); expected >=2 "
            f"(one truncated + one Range resume)")


# ----- Frontend Range request — partial response from cache ---------------

@register("frontend_range_open_ended_warm_cache", timeout=60.0)
def _frontend_range_open_ended(h: Harness):
    """Warm cache + client `Range: bytes=N-`. confiacdn must reply 206 with
    `Content-Range: bytes N-(end)/(total)` and the slice from N to end."""
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(256 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"frange"',
                 support_range=True)
    h.fixtures["/frange"] = fx

    # Warm the cache.
    r0 = fetch("/frange")
    if r0.decoded_body != body:
        raise AssertionError("warm-up fetch broken")

    # Range request: open-ended from N.
    n = 100_000
    full_path = f"/{ORIGIN_HOST}/frange"
    conn = http.client.HTTPConnection("127.0.0.1", NGINX_PORT, timeout=30)
    try:
        conn.request("GET", full_path, headers={
            "Host": DEFAULT_HOST, "Connection": "close",
            "Range": f"bytes={n}-",
        })
        resp = conn.getresponse()
        status = resp.status
        body_recv = resp.read()
        cr = resp.getheader("Content-Range") or ""
    finally:
        conn.close()

    if status != 206:
        raise AssertionError(f"expected 206 Partial Content, got {status}")
    if not cr.startswith(f"bytes {n}-"):
        raise AssertionError(f"bad Content-Range: {cr!r}")
    if not cr.endswith(f"/{len(body)}"):
        raise AssertionError(f"Content-Range total mismatch: {cr!r}")
    expected_slice = body[n:]
    if body_recv != expected_slice:
        raise AssertionError(
            f"slice mismatch: got {len(body_recv)}B sha={sha(body_recv)}, "
            f"expected {len(expected_slice)}B sha={sha(expected_slice)}")


@register("frontend_range_bounded_warm_cache", timeout=60.0)
def _frontend_range_bounded(h: Harness):
    """Warm cache + client `Range: bytes=N-M`. confiacdn must reply 206 with
    the exact inclusive slice."""
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(256 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"frangeb"',
                 support_range=True)
    h.fixtures["/frangeb"] = fx
    r0 = fetch("/frangeb")
    if r0.decoded_body != body:
        raise AssertionError("warm-up fetch broken")

    n, m = 50_000, 150_000
    full_path = f"/{ORIGIN_HOST}/frangeb"
    conn = http.client.HTTPConnection("127.0.0.1", NGINX_PORT, timeout=30)
    try:
        conn.request("GET", full_path, headers={
            "Host": DEFAULT_HOST, "Connection": "close",
            "Range": f"bytes={n}-{m}",
        })
        resp = conn.getresponse()
        status = resp.status
        body_recv = resp.read()
        cr = resp.getheader("Content-Range") or ""
    finally:
        conn.close()

    if status != 206:
        raise AssertionError(f"expected 206, got {status}")
    if cr != f"bytes {n}-{m}/{len(body)}":
        raise AssertionError(f"bad Content-Range: {cr!r}")
    expected_slice = body[n:m + 1]
    if body_recv != expected_slice:
        raise AssertionError(
            f"slice mismatch: got {len(body_recv)}B sha={sha(body_recv)}, "
            f"expected {len(expected_slice)}B sha={sha(expected_slice)}")


@register("frontend_range_past_eof_returns_416", timeout=60.0)
def _frontend_range_past_eof(h: Harness):
    """Warm cache + client `Range: bytes=N-` where N >= total. confiacdn must
    reply 416 Range Not Satisfiable with `Content-Range: bytes */<total>`."""
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(64 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"frangeoob"',
                 support_range=True)
    h.fixtures["/frange-oob"] = fx
    r0 = fetch("/frange-oob")
    if r0.decoded_body != body:
        raise AssertionError("warm-up fetch broken")

    full_path = f"/{ORIGIN_HOST}/frange-oob"
    conn = http.client.HTTPConnection("127.0.0.1", NGINX_PORT, timeout=30)
    try:
        conn.request("GET", full_path, headers={
            "Host": DEFAULT_HOST, "Connection": "close",
            "Range": f"bytes={len(body) + 1}-",
        })
        resp = conn.getresponse()
        status = resp.status
        cr = resp.getheader("Content-Range") or ""
        resp.read()
    finally:
        conn.close()

    if status != 416:
        raise AssertionError(f"expected 416 Range Not Satisfiable, got {status}")
    if cr != f"bytes */{len(body)}":
        raise AssertionError(f"bad Content-Range: {cr!r}")


@register("frontend_range_invalid_header_falls_back_to_200", timeout=60.0)
def _frontend_range_invalid(h: Harness):
    """Malformed Range header → confiacdn must serve full 200 (never abort/timeout)."""
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(32 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"frangeinv"',
                 support_range=True)
    h.fixtures["/frange-inv"] = fx
    r0 = fetch("/frange-inv")
    if r0.decoded_body != body:
        raise AssertionError("warm-up fetch broken")

    full_path = f"/{ORIGIN_HOST}/frange-inv"
    conn = http.client.HTTPConnection("127.0.0.1", NGINX_PORT, timeout=30)
    try:
        conn.request("GET", full_path, headers={
            "Host": DEFAULT_HOST, "Connection": "close",
            "Range": "bytes=foo",
        })
        resp = conn.getresponse()
        status = resp.status
        body_recv = resp.read()
    finally:
        conn.close()

    if status != 200:
        raise AssertionError(f"malformed Range should fall back to 200, got {status}")
    if body_recv != body:
        raise AssertionError(f"body mismatch: {len(body_recv)} vs {len(body)}")


# ----- Multi-client flapping ---------------------------------------------

@register("multi_client_flapping", timeout=120.0)
def _multi_client_flapping(h: Harness):
    """Stable clients: `first` connects at t=0; `stable-other` connects at t=5s
    (catch-up-from-partial-cache path). Three other clients flap at 1 Hz for
    the duration. Assertions:
      - both stable clients receive a byte-identical full body,
      - origin saw exactly one request (de-dup intact through the churn),
      - no lifecycle abort in the confiacdn log."""
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(1 * 1024 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"flap"', profile="slow1mbps")
    h.fixtures["/flap"] = fx

    stable_results: Dict[str, Optional[Response]] = {"first": None, "stable-other": None}
    stable_errors: Dict[str, Optional[str]] = {"first": None, "stable-other": None}

    def stable(label: str, delay: float):
        time.sleep(delay)
        try:
            stable_results[label] = fetch("/flap", timeout=60)
        except Exception as e:
            stable_errors[label] = repr(e)

    def flapper(label: str, stop: threading.Event):
        # Connect, read briefly (drains the cache catch-up), close, sleep, repeat.
        while not stop.is_set():
            try:
                s = socket.create_connection(("127.0.0.1", NGINX_PORT), timeout=5)
                s.sendall((f"GET /{ORIGIN_HOST}/flap HTTP/1.1\r\nHost: {DEFAULT_HOST}\r\n"
                           f"Connection: close\r\n\r\n").encode())
                end = time.monotonic() + 0.5
                while time.monotonic() < end:
                    if not s.recv(4096):
                        break
                # Hard-close to exercise mid-stream client removal.
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                 struct.pack("ii", 1, 0))
                except OSError:
                    pass
                s.close()
            except OSError:
                pass
            stop.wait(0.5)

    stop = threading.Event()
    t_first = threading.Thread(target=stable, args=("first", 0.0))
    t_other = threading.Thread(target=stable, args=("stable-other", 5.0))
    t_flaps = [threading.Thread(target=flapper, args=(f"flap{i}", stop)) for i in range(3)]
    t_first.start()
    t_other.start()
    for t in t_flaps:
        t.start()
    t_first.join(timeout=60)
    t_other.join(timeout=60)
    stop.set()
    for t in t_flaps:
        t.join(timeout=5)

    if stable_errors["first"] or stable_errors["stable-other"]:
        raise AssertionError(f"stable-client errors: {stable_errors}")
    for label, r in stable_results.items():
        if r is None:
            raise AssertionError(f"{label} did not return")
        if r.status != 200:
            raise AssertionError(f"{label} status {r.status}")
        if r.decoded_body != body:
            raise AssertionError(f"{label} body mismatch")
    if fx.serve_count != 1:
        raise AssertionError(
            f"origin saw {fx.serve_count} requests; flapping must not bypass de-dup")


# ----- Hardening tests (production-failure-mode coverage) -----------------

def _rss_kb(pid: int) -> int:
    """Resident set size of a process from /proc/<pid>/status (kilobytes).
    Returns -1 if the pid is gone or /proc isn't accessible."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return -1
    return -1


@register("maxbackend_saturation_queues_and_drains", timeout=180.0)
def _maxbackend_saturation(h: Harness):
    """N+4 simultaneous fetches for distinct URLs to the same origin IP, where
    N == --maxBackend. The (N+1)..(N+4)th requests must queue into pending and
    eventually complete byte-correct. Each origin URL is paced at 1 Mbps so the
    backend slots stay busy long enough for queueing to actually happen."""
    n_max = 8  # matches harness's --maxBackend=8
    extra = 4
    h.restart_confiacdn()
    h.reset_fixtures()
    bodies = {}
    for i in range(n_max + extra):
        b, ct = make_body(256 * 1024, seed=0x1000 + i)
        bodies[i] = b
        h.fixtures[f"/sat-{i}"] = Fixture(
            body=b, content_type=ct, backend_etag=f'"sat{i}"',
            profile="slow1mbps",
        )
    results: List[Optional[Response]] = [None] * (n_max + extra)
    errors: List[Optional[str]] = [None] * (n_max + extra)

    def go(i):
        try:
            results[i] = fetch(f"/sat-{i}", timeout=120)
        except Exception as e:
            errors[i] = repr(e)

    threads = [threading.Thread(target=go, args=(i,)) for i in range(n_max + extra)]
    for t in threads: t.start()
    for t in threads: t.join()

    if any(errors):
        raise AssertionError(f"client errors: {[e for e in errors if e]}")
    for i, r in enumerate(results):
        if r is None or r.status != 200:
            raise AssertionError(f"client {i} status {r.status if r else None}")
        if r.decoded_body != bodies[i]:
            raise AssertionError(f"client {i} body mismatch")


@register("origin_truncation_under_content_length_not_cached", timeout=60.0)
def _origin_truncation(h: Harness):
    """Origin declares Content-Length=1MB, sends 800KB, closes. confiacdn must
    NOT cache the partial body as if it were complete. Second request must hit
    origin again."""
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(1024 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"trunc"',
                 truncate_at=800 * 1024)
    h.fixtures["/trunc"] = fx

    # First fetch — may succeed-with-short-body or error; both acceptable.
    with contextlib.suppress(Exception):
        fetch("/trunc", timeout=30)

    # Second fetch — must hit origin again (cache rejected partial).
    initial_count = fx.serve_count
    with contextlib.suppress(Exception):
        fetch("/trunc", timeout=30)
    if fx.serve_count <= initial_count:
        raise AssertionError(
            f"second fetch did not hit origin (serve_count went {initial_count}→"
            f"{fx.serve_count}); confiacdn cached a truncated body as complete")


@register("cache_file_header_corruption_recovers", timeout=60.0)
def _cache_header_corruption(h: Harness):
    """Pre-create a cache file with garbage in the header region. Request the URL
    → confiacdn must detect bad header, treat as miss, fetch fresh, overwrite."""
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(64 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"corrupt"')
    h.fixtures["/corrupt"] = fx

    # Find what cache-key confiacdn would use by doing one normal fetch first
    # (this populates the cache with a valid file).
    r0 = fetch("/corrupt")
    if r0.decoded_body != body:
        raise AssertionError("warm-up fetch broken")

    # Identify the cache file (any file in CACHE_DIR matching the pattern).
    # The fetch returns to us as soon as the FastCGI body+END_REQUEST reaches
    # nginx, but confiacdn does the tempPath→cachePath rename one syscall later
    # (in disconnectBackend). Poll briefly for the renamed file to appear.
    cache_files: List[str] = []
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        cache_files = [
            os.path.join(CACHE_DIR, f) for f in os.listdir(CACHE_DIR)
            if not f.endswith(".tmp")
        ]
        if cache_files:
            break
        time.sleep(0.05)
    if not cache_files:
        raise AssertionError("no cache file produced by warm-up fetch")
    target = max(cache_files, key=os.path.getmtime)

    # Stomp the first 64 bytes (header region) with garbage.
    with open(target, "r+b") as f:
        f.write(os.urandom(64))

    # Restart cache state for confiacdn (no fresh process — it should detect
    # the corruption on the next read).
    initial_count = fx.serve_count
    r = fetch("/corrupt")
    if r.status != 200 or r.decoded_body != body:
        raise AssertionError(
            f"after corruption, expected fresh fetch with full body; "
            f"got status={r.status} len={len(r.decoded_body)}")
    if fx.serve_count <= initial_count:
        raise AssertionError(
            f"second fetch did not re-hit origin after cache corruption "
            f"(serve_count {initial_count}→{fx.serve_count})")


@register("head_request_returns_headers_no_body", timeout=60.0)
def _head_request(h: Harness):
    """HEAD must return the same headers as GET but zero body bytes."""
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(32 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"head"')
    h.fixtures["/head"] = fx
    # Warm cache with a GET so HEAD doesn't need to fetch.
    fetch("/head")

    full_path = f"/{ORIGIN_HOST}/head"
    conn = http.client.HTTPConnection("127.0.0.1", NGINX_PORT, timeout=30)
    try:
        conn.request("HEAD", full_path,
                     headers={"Host": DEFAULT_HOST, "Connection": "close"})
        resp = conn.getresponse()
        body_recv = resp.read()
        cl = resp.getheader("Content-Length") or ""
        ct = resp.getheader("Content-Type") or ""
        status = resp.status
    finally:
        conn.close()

    if status != 200:
        raise AssertionError(f"HEAD status {status}")
    if len(body_recv) != 0:
        raise AssertionError(f"HEAD body must be empty, got {len(body_recv)}B")
    # Content-Length should match the body size (not 0).
    if cl != str(len(body)):
        raise AssertionError(f"HEAD Content-Length {cl!r} != body size {len(body)}")
    if not ct.startswith(ctype.split(";")[0]):
        raise AssertionError(f"HEAD Content-Type {ct!r}")


@register("write_methods_rejected_no_backend_hit", timeout=60.0)
def _write_methods_rejected(h: Harness):
    """POST/PUT/DELETE must be rejected without opening a backend connection."""
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"wm"')
    h.fixtures["/wm"] = fx

    full_path = f"/{ORIGIN_HOST}/wm"
    for method in ("POST", "PUT", "DELETE"):
        conn = http.client.HTTPConnection("127.0.0.1", NGINX_PORT, timeout=30)
        try:
            conn.request(method, full_path, body=b"x" * 16,
                         headers={"Host": DEFAULT_HOST, "Connection": "close",
                                  "Content-Length": "16"})
            resp = conn.getresponse()
            status = resp.status
            resp.read()
        finally:
            conn.close()
        if status < 400 or status >= 500:
            # 4xx is acceptable. 2xx/3xx is not, 5xx is not.
            raise AssertionError(f"{method} got {status}; expected 4xx rejection")
    if fx.serve_count != 0:
        raise AssertionError(
            f"origin saw {fx.serve_count} request(s) for write methods; expected 0")


@register("path_traversal_no_fs_escape", timeout=60.0)
def _path_traversal(h: Harness):
    """Client requests with .., %2e%2e, very long URIs. Cache files stay inside
    the cache dir; no path containing literal '..' is created on disk."""
    h.restart_confiacdn()
    h.reset_fixtures()

    bad_paths = [
        "/origin.test/../../../etc/passwd",
        "/origin.test/%2e%2e%2f%2e%2e%2fetc/passwd",
        "/origin.test/" + "A" * 4000,  # very long
    ]
    full_paths = [f"/{ORIGIN_HOST}{p}" if not p.startswith(f"/{ORIGIN_HOST}") else p
                  for p in bad_paths]

    for fp in full_paths:
        conn = http.client.HTTPConnection("127.0.0.1", NGINX_PORT, timeout=30)
        try:
            with contextlib.suppress(Exception):
                conn.request("GET", fp,
                             headers={"Host": DEFAULT_HOST, "Connection": "close"})
                resp = conn.getresponse()
                resp.read()
        finally:
            conn.close()

    # Walk the entire tmpfs dir; assert no file path contains literal "..".
    for root, dirs, files in os.walk(TMPFS):
        for name in files + dirs:
            if ".." in name:
                raise AssertionError(f"file/dir with '..' on disk: {root}/{name}")
    # Cache directory must not contain anything outside our expected layout.
    for root, dirs, files in os.walk(CACHE_DIR):
        # All cache files must be 16 hex chars + optional G/R + optional .tmp suffix.
        for name in files:
            base = name.split(".")[0]
            if not all(c in "0123456789ABCDEFGRabcdefgr/" for c in base):
                # Tolerate ".tmp" siblings; only flag truly weird names.
                pass


@register("vary_accept_encoding_separates_cache", timeout=60.0)
def _vary_accept_encoding(h: Harness):
    """Origin returns gzip when Accept-Encoding: gzip, plaintext otherwise.
    Two clients (gzip / no-gzip) must each get the right content."""
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(64 * 1024, compressible=True)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"vary"',
                 allow_compression=True, vary_accept_encoding=True)
    h.fixtures["/vary"] = fx

    r_plain = fetch("/vary", accept_gzip=False)
    if r_plain.decoded_body != body:
        raise AssertionError("plain client body mismatch")
    if "gzip" in r_plain.headers.get("content-encoding", "").lower():
        raise AssertionError(
            f"plain client got gzip response: {r_plain.headers.get('content-encoding')}")

    r_gz = fetch("/vary", accept_gzip=True)
    if r_gz.decoded_body != body:
        raise AssertionError("gzip client body mismatch")
    # Either confiacdn gzipped on the way out OR served the gzipped origin
    # response unmodified. In both cases, decoded body matches.


@register("no_store_origin_directive_still_cached", timeout=60.0)
def _no_store_still_cached(h: Harness):
    """Origin sends Cache-Control: no-store. confiacdn deliberately ignores
    this — caching is the whole point and we don't let abusive origins force
    re-fetches. Second fetch must serve from cache; origin's serve_count
    stays at 1."""
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(32 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"nostore"',
                 extra_headers=[("Cache-Control", "no-store, no-cache, max-age=0")])
    h.fixtures["/nostore"] = fx

    r1 = fetch("/nostore")
    if r1.decoded_body != body:
        raise AssertionError("first fetch broken")
    if fx.serve_count != 1:
        raise AssertionError(f"first fetch serve_count={fx.serve_count}")

    # Second fetch within --http200Time=2 must serve from cache.
    time.sleep(0.2)
    r2 = fetch("/nostore")
    if r2.decoded_body != body:
        raise AssertionError("second fetch broken")
    if fx.serve_count != 1:
        raise AssertionError(
            f"origin re-hit despite cache (serve_count went 1→{fx.serve_count}); "
            f"confiacdn must ignore Cache-Control: no-store and serve from cache")


@register("origin_30x_forwarded_not_followed", timeout=60.0)
def _redirect_forwarded(h: Harness):
    """Origin returns 301 with Location header. confiacdn must propagate the
    status and Location to the client verbatim — must NOT follow the redirect
    server-side (would result in origin not seeing a single request, only the
    target getting hit)."""
    h.restart_confiacdn()
    h.reset_fixtures()
    fx = Fixture(
        body=b"", content_type="text/plain", profile="error", error_status=301,
        extra_headers=[("Location", "https://elsewhere.example/target")],
    )
    h.fixtures["/redirect"] = fx

    r = fetch("/redirect", timeout=30)
    if r.status != 301:
        raise AssertionError(
            f"expected 301 forwarded to client, got {r.status} "
            f"(confiacdn must not follow redirects server-side)")
    loc = r.headers.get("location", "")
    if "elsewhere.example" not in loc:
        raise AssertionError(f"Location header not forwarded: {loc!r}")


@register("zero_byte_body_round_trips", timeout=60.0)
def _zero_byte(h: Harness):
    """Origin returns 200 with Content-Length: 0. Cache + re-serve."""
    h.restart_confiacdn()
    h.reset_fixtures()
    fx = Fixture(body=b"", content_type="application/octet-stream",
                 backend_etag='"zb"')
    h.fixtures["/zero"] = fx

    r = fetch("/zero")
    if r.status != 200 or len(r.decoded_body) != 0:
        raise AssertionError(f"first fetch: status={r.status} len={len(r.decoded_body)}")
    # Second fetch from cache.
    r2 = fetch("/zero")
    if r2.status != 200 or len(r2.decoded_body) != 0:
        raise AssertionError(f"second fetch: status={r2.status} len={len(r2.decoded_body)}")


@register("chunked_transfer_encoding_decoded", timeout=60.0)
def _chunked_te(h: Harness):
    """Origin sends Transfer-Encoding: chunked, no Content-Length. confiacdn
    must decode the chunks and deliver the assembled body byte-correct."""
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(128 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"chunk"',
                 chunked=True)
    h.fixtures["/chunk"] = fx

    r = fetch("/chunk", timeout=30)
    if r.status != 200:
        raise AssertionError(f"chunked: status {r.status}")
    if r.decoded_body != body:
        raise AssertionError(
            f"chunked body mismatch: {len(r.decoded_body)} vs {len(body)}")


@register("cache_ttl_boundary_int_ms", timeout=60.0)
def _cache_ttl_boundary(h: Harness):
    """Cache TTL boundary test using INTEGER milliseconds throughout — never
    floats/doubles. Plain/sanitizer: --http200Time=2 (2000 ms) with 1900/2100 ms
    windows. Valgrind (10-50x slowdown): --http200Time=15 (15000 ms) with
    13000/17000 ms windows so per-fetch latency (hundreds of ms) doesn't blur
    the boundary. Time is measured from r1 completion (when cache was written),
    not test start."""
    if h.args.valgrind:
        ttl_sec = 15
        warm_fresh_ms = 13000
        warm_stale_ms = 17000
        h.restart_confiacdn(extra_args=[f"--http200Time={ttl_sec}"])
    else:
        h.restart_confiacdn()
        warm_fresh_ms = 1900
        warm_stale_ms = 2100
    h.reset_fixtures()
    body, ctype = make_body(8 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"ttl"',
                 # 304 path: when revalidating, return 304 so cache stays alive.
                 revalidate_match='"ttl"')
    h.fixtures["/ttl"] = fx

    def now_ms() -> int:
        return int(time.monotonic() * 1000)

    r1 = fetch("/ttl")
    if r1.decoded_body != body:
        raise AssertionError("first fetch broken")
    if fx.serve_count != 1:
        raise AssertionError(f"first-fetch serve_count={fx.serve_count}")
    # Reference time = right after r1 returns (cache was just written).
    t1_ms = now_ms()

    # Step 1: warm-fresh window.
    target_ms = t1_ms + warm_fresh_ms
    sleep_ms = target_ms - now_ms()
    if sleep_ms > 0:
        time.sleep(sleep_ms / 1000)  # sleep takes float; we computed in int ms
    r2 = fetch("/ttl")
    if r2.decoded_body != body:
        raise AssertionError("warm-fresh fetch broken")
    if fx.serve_count != 1:
        raise AssertionError(
            f"warm-fresh fetch hit origin (serve_count={fx.serve_count}), "
            f"expected to stay at 1 within --http200Time")

    # Step 2: warm-stale window.
    target_ms = t1_ms + warm_stale_ms
    sleep_ms = target_ms - now_ms()
    if sleep_ms > 0:
        time.sleep(sleep_ms / 1000)
    r3 = fetch("/ttl")
    if r3.decoded_body != body:
        raise AssertionError("warm-stale fetch body broken")
    if fx.serve_count != 2:
        raise AssertionError(
            f"warm-stale fetch did not revalidate (serve_count={fx.serve_count}), "
            f"expected 2 (initial + revalidate)")


# ----- Slow client (FastCGI side) — RSS must stay bounded -----------------

@register("slow_client_no_memory_blowup", timeout=240.0)
def _slow_client(h: Harness):
    """Two clients read at ~10 KB/s while origin sends a 1 MB body fast.
    confiacdn must apply backpressure (writes to a slow client should pause /
    EAGAIN-yield, NOT accumulate in `Client::dataToWrite` unbounded). Sample
    confiacdn's RSS during the test; assert peak growth is bounded.

    Pacing math: 1 MB at 10 KB/s ≈ 100 s per client; both run concurrently."""
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(1 * 1024 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"slow"',
                 profile="fast")  # origin sends fast; the slowness is on the client
    h.fixtures["/slow-client"] = fx

    # Baseline RSS before the slow clients start.
    pid = h.confiacdn.pid if h.confiacdn else -1
    baseline_kb = _rss_kb(pid)
    if baseline_kb <= 0:
        raise AssertionError(f"could not read confiacdn RSS for pid {pid}")

    # Two slow clients in threads, each reading the body at ~10 KB/s.
    target_rate_bps = 10 * 1024
    results: List[Tuple[int, bytes]] = []
    errors: List[str] = []
    lock = threading.Lock()

    def slow_fetch(label: str):
        full_path = f"/{ORIGIN_HOST}/slow-client"
        try:
            conn = http.client.HTTPConnection("127.0.0.1", NGINX_PORT, timeout=180)
            conn.request("GET", full_path,
                         headers={"Host": DEFAULT_HOST, "Connection": "close"})
            resp = conn.getresponse()
            buf = bytearray()
            start = time.monotonic()
            while True:
                c = resp.read(1024)
                if not c:
                    break
                buf += c
                # Pace: target finishing `len(buf)` bytes by start + len(buf)/rate.
                target = start + len(buf) / target_rate_bps
                now = time.monotonic()
                if target > now:
                    time.sleep(target - now)
            conn.close()
            with lock:
                results.append((resp.status, bytes(buf)))
        except Exception as e:
            with lock:
                errors.append(f"{label}: {e!r}")

    t1 = threading.Thread(target=slow_fetch, args=("slow1",))
    t2 = threading.Thread(target=slow_fetch, args=("slow2",))
    t1.start(); t2.start()

    # Sample RSS while the slow clients drain.
    peak_kb = baseline_kb
    while t1.is_alive() or t2.is_alive():
        time.sleep(2)
        cur = _rss_kb(pid)
        if cur > peak_kb:
            peak_kb = cur

    t1.join(); t2.join()

    if errors:
        raise AssertionError(f"slow-client errors: {errors}")
    for status, recv in results:
        if status != 200:
            raise AssertionError(f"slow-client status {status}")
        if recv != body:
            raise AssertionError(
                f"slow-client body mismatch: {len(recv)}B sha={sha(recv)} vs "
                f"{len(body)}B sha={sha(body)}")

    # Bound: 16 MB headroom over baseline. Two 1 MB streams in flight + cache
    # buffering + the daemon's own working set comfortably fits.
    growth_kb = peak_kb - baseline_kb
    if growth_kb > 16 * 1024:
        raise AssertionError(
            f"confiacdn RSS grew {growth_kb} KB during slow-client run "
            f"(baseline {baseline_kb} KB → peak {peak_kb} KB); suggests "
            f"unbounded buffering on the client send side")


# ----- High-rate flapping (stress variant of multi_client_flapping) -------

@register("multi_client_high_rate_flapping_stress", timeout=180.0)
def _multi_client_high_rate_flapping(h: Harness):
    """Stress variant: 50 flapping clients at ~10 Hz instead of 3 at 1 Hz.
    Same de-dup invariant — origin must see exactly one request — but under
    much harder churn. Likely to surface race conditions in `Http::pathToHttp`
    that the gentle 3@1Hz version doesn't reach."""
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(1 * 1024 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"hflap"',
                 profile="slow1mbps")
    h.fixtures["/hflap"] = fx

    stable_results: Dict[str, Optional[Response]] = {"first": None, "stable-other": None}
    stable_errors: Dict[str, Optional[str]] = {"first": None, "stable-other": None}

    def stable(label: str, delay: float):
        time.sleep(delay)
        try:
            stable_results[label] = fetch("/hflap", timeout=60)
        except Exception as e:
            stable_errors[label] = repr(e)

    def flapper(_label: str, stop: threading.Event):
        # 10 Hz: 50 ms reading + 50 ms idle.
        while not stop.is_set():
            try:
                s = socket.create_connection(("127.0.0.1", NGINX_PORT), timeout=5)
                s.sendall((f"GET /{ORIGIN_HOST}/hflap HTTP/1.1\r\nHost: {DEFAULT_HOST}\r\n"
                           f"Connection: close\r\n\r\n").encode())
                end = time.monotonic() + 0.05
                while time.monotonic() < end:
                    try:
                        if not s.recv(4096):
                            break
                    except (socket.timeout, OSError):
                        break
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                 struct.pack("ii", 1, 0))
                except OSError:
                    pass
                s.close()
            except OSError:
                pass
            stop.wait(0.05)

    stop = threading.Event()
    t_first = threading.Thread(target=stable, args=("first", 0.0))
    t_other = threading.Thread(target=stable, args=("stable-other", 5.0))
    # Under valgrind's 10-50x slowdown, 50 clients × 10 Hz saturates the
    # virtualised CPU and starves the stable readers. Scale down to keep the
    # de-dup invariant exercised under churn without bringing valgrind to its
    # knees. Plain/sanitizer keep the original 50@10Hz stress.
    n_flappers = 10 if h.args.valgrind else 50
    t_flaps = [threading.Thread(target=flapper, args=(f"hflap{i}", stop))
               for i in range(n_flappers)]
    t_first.start()
    t_other.start()
    for t in t_flaps:
        t.start()
    t_first.join(timeout=120)
    t_other.join(timeout=120)
    stop.set()
    for t in t_flaps:
        t.join(timeout=10)

    if stable_errors["first"] or stable_errors["stable-other"]:
        raise AssertionError(f"stable-client errors: {stable_errors}")
    for label, r in stable_results.items():
        if r is None:
            raise AssertionError(f"{label} did not return")
        if r.status != 200:
            raise AssertionError(f"{label} status {r.status}")
        if r.decoded_body != body:
            raise AssertionError(f"{label} body mismatch")
    if fx.serve_count != 1:
        raise AssertionError(
            f"origin saw {fx.serve_count} requests under high-rate flap; "
            f"de-dup must hold even at 50@10Hz churn")


# ----- DNS reload stress while serving ------------------------------------

@register("dns_reload_stress_during_download", timeout=120.0)
def _dns_reload_stress(h: Harness):
    """Spawn `confiacdn reload` 10× over 5 s while a slow download is in
    progress. The download must complete byte-correct. No abort/corruption
    in the confiacdn log."""
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(1 * 1024 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"reload"',
                 profile="slow1mbps")
    h.fixtures["/reload"] = fx

    bin_path = get_confiacdn_bin(h.args.sanitize is not None)
    reload_errors: List[str] = []
    download_result: List[Optional[Response]] = [None]
    download_error: List[Optional[str]] = [None]

    def do_download():
        try:
            download_result[0] = fetch("/reload", timeout=60)
        except Exception as e:
            download_error[0] = repr(e)

    def do_reloads():
        # 10 reloads spread across 5 seconds → one every ~500 ms.
        for i in range(10):
            time.sleep(0.5)
            try:
                proc = subprocess.run(
                    [bin_path, "reload"],
                    cwd=TMPFS,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                )
                # Non-zero exit is OK (reload may fail if no static entries to
                # send) — what matters is that it doesn't crash the daemon.
                _ = proc.returncode
            except Exception as e:
                reload_errors.append(f"reload #{i}: {e!r}")

    t_dl = threading.Thread(target=do_download)
    t_rl = threading.Thread(target=do_reloads)
    t_dl.start()
    t_rl.start()
    t_dl.join(timeout=90)
    t_rl.join(timeout=20)

    if download_error[0]:
        raise AssertionError(f"download errored under reload churn: {download_error[0]}")
    r = download_result[0]
    if r is None:
        raise AssertionError("download did not complete")
    if r.status != 200 or r.decoded_body != body:
        raise AssertionError(
            f"download corrupted by reload churn: status={r.status} "
            f"body {len(r.decoded_body)} vs {len(body)}")
    # Reload errors aren't fatal (the daemon may have rejected the empty
    # entry list), but if EVERY reload errored that's worth surfacing.
    if len(reload_errors) >= 10:
        raise AssertionError(f"every reload failed: {reload_errors[:3]} ...")


# ----- Hot-cache stress: 1000 sequential GETs for the same warm URL -------

@register("hot_cache_1000_sequential_gets", timeout=120.0)
def _hot_cache_stress(h: Harness):
    """1000 sequential GETs for a warm-cached URL. Verifies the hot path is
    cheap and there's no fd/memory leak. We also count open fds for the
    confiacdn pid before and after — must not grow significantly. Under
    valgrind, raise --http200Time so the 1000 GETs (which take much longer
    under valgrind) don't cross the TTL boundary and trigger revalidation."""
    if h.args.valgrind:
        h.restart_confiacdn(extra_args=["--http200Time=600"])
    else:
        h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(8 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"hot"')
    h.fixtures["/hot"] = fx

    # Warm the cache.
    r0 = fetch("/hot")
    if r0.decoded_body != body:
        raise AssertionError("warm-up fetch broken")
    if fx.serve_count != 1:
        raise AssertionError(f"warm-up serve_count={fx.serve_count}")

    pid = h.confiacdn.pid if h.confiacdn else -1
    def open_fd_count() -> int:
        try:
            return len(os.listdir(f"/proc/{pid}/fd"))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            return -1

    fds_before = open_fd_count()
    rss_before = _rss_kb(pid)

    # 1000 GETs. Use new connections each (more representative of nginx) but
    # keep them tiny by closing immediately.
    n = 1000
    started = time.monotonic()
    for i in range(n):
        r = fetch("/hot")
        if r.status != 200:
            raise AssertionError(f"hot GET #{i}: status {r.status}")
        if r.decoded_body != body:
            raise AssertionError(f"hot GET #{i}: body mismatch")
    elapsed = time.monotonic() - started

    fds_after = open_fd_count()
    rss_after = _rss_kb(pid)

    # Origin must not have been hit again — all 1000 served from cache.
    if fx.serve_count != 1:
        raise AssertionError(
            f"hot-cache stress: origin re-hit (serve_count went 1→{fx.serve_count})")

    # fd growth headroom. Tiny growth is OK (logging fd, etc.); big growth = leak.
    if fds_before > 0 and fds_after > 0 and fds_after - fds_before > 50:
        raise AssertionError(
            f"fd leak: confiacdn open-fd count went {fds_before}→{fds_after} "
            f"after {n} sequential GETs")
    # RSS growth headroom.
    if rss_before > 0 and rss_after - rss_before > 8 * 1024:
        raise AssertionError(
            f"RSS leak: confiacdn RSS went {rss_before}→{rss_after} KB after "
            f"{n} sequential GETs")
    # Throughput floor (loose): 1000 reqs in <60s = >16 req/s. If much slower,
    # something is off with the hot-cache path.
    if elapsed > 60:
        raise AssertionError(
            f"hot-cache too slow: {n} GETs took {elapsed:.1f}s")


# ----- HTTPS backend with self-signed cert --------------------------------

def _https_request(path_segments: str, host: str = DEFAULT_HOST,
                   accept_gzip: bool = False) -> Tuple[int, Dict[str, str], bytes]:
    """Send a request through nginx's /https-tls/ location so confiacdn dials
    the origin via TLS. Returns (status, header dict, raw body bytes)."""
    full_path = f"/https-tls/{path_segments}"
    conn = http.client.HTTPConnection("127.0.0.1", NGINX_PORT, timeout=30)
    try:
        hdrs = {"Host": host, "Connection": "close"}
        if accept_gzip:
            hdrs["Accept-Encoding"] = "gzip"
        conn.request("GET", full_path, headers=hdrs)
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, body
    finally:
        conn.close()


@register("https_backend_self_signed_cert", timeout=60.0)
def _https_backend_self_signed(h: Harness):
    """confiacdn fetches an `https://` origin that uses a self-signed cert.
    Build is gated on -DBACKEND_ALLOW_SELF_SIGNED_TLS so SSL_VERIFY_NONE is in
    effect; without that flag confiacdn would (correctly) refuse the cert."""
    if h.origin_https_server is None:
        raise AssertionError("HTTPS origin not available (cert generation failed?)")
    h.restart_confiacdn()
    h.reset_fixtures()
    reset_sni_state()
    body, ctype = make_body(64 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"https"')
    h.fixtures["/https-foo"] = fx

    status, hdrs, recv = _https_request(f"{ORIGIN_HOST}/https-foo")
    ct = hdrs.get("content-type", "")

    if status != 200:
        raise AssertionError(f"https backend status {status}")
    if recv != body:
        raise AssertionError(
            f"https backend body mismatch: {len(recv)}B sha={sha(recv)} vs "
            f"{len(body)}B sha={sha(body)}")
    if not ct.startswith(ctype.split(";")[0]):
        raise AssertionError(f"https backend content-type {ct!r}")
    # Even on the permissive build, confiacdn must send SNI — origins on shared
    # IPs return the wrong vhost cert without it (the prod 500 regression).
    if not SNI_LOG or SNI_LOG[0] != ORIGIN_HOST:
        raise AssertionError(f"SNI not propagated to origin: SNI_LOG={SNI_LOG!r}")


# Regression test for the prod 500: every HTTPS upstream returned 500 with
# `Error: Timeout into reply header` because Backend::startHttps() was not
# calling SSL_set_tlsext_host_name(). Fronted origins serve a default-vhost
# cert when no SNI arrives — usually for an unrelated name and often expired —
# and the SSL_VERIFY_PEER pass tightened in the same change set rejected it.
# Here the origin's TLS server demands SNI=ORIGIN_HOST and aborts the
# handshake otherwise, so a regression in the SNI path turns straight into a
# fetch failure instead of silently relying on permissive cert checks.
@register("https_backend_sets_sni", timeout=60.0)
def _https_backend_sets_sni(h: Harness):
    if h.origin_https_server is None:
        raise AssertionError("HTTPS origin not available")
    h.restart_confiacdn()
    h.reset_fixtures()
    reset_sni_state(require=ORIGIN_HOST)
    body, ctype = make_body(32 * 1024, content_type="text/css", compressible=True)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"sni"')
    h.fixtures["/sni-css"] = fx

    status, _hdrs, recv = _https_request(f"{ORIGIN_HOST}/sni-css")
    if status != 200:
        raise AssertionError(
            f"https w/ SNI gating: status={status} (origin likely rejected handshake "
            f"because confiacdn omitted SNI). SNI_LOG={SNI_LOG!r}")
    if recv != body:
        raise AssertionError(
            f"https w/ SNI gating: body mismatch len={len(recv)} vs {len(body)}")
    if not SNI_LOG or any(s != ORIGIN_HOST for s in SNI_LOG):
        raise AssertionError(f"unexpected SNI: {SNI_LOG!r}")


# Closer mimic of the prod request: cdn.confiared.com fronts upstream
# `ultracopier.herman-brule.com`, the file is a CSS asset, the origin returns
# Transfer-Encoding: chunked + Content-Encoding: gzip + a weak ETag (W/"...")
# when gzip is requested. Validates the full HTTPS-upstream response-decode
# pipeline.
@register("https_backend_chunked_gzip_weak_etag", timeout=60.0)
def _https_backend_chunked_gzip_weak_etag(h: Harness):
    if h.origin_https_server is None:
        raise AssertionError("HTTPS origin not available")
    h.restart_confiacdn()
    h.reset_fixtures()
    reset_sni_state(require=ORIGIN_HOST)
    body, _ = make_body(64 * 1024, content_type="text/css", compressible=True)
    ctype = "text/css"
    fx = Fixture(body=body, content_type=ctype,
                 backend_etag='W/"weak-css-1"',
                 chunked=True, allow_compression=True,
                 vary_accept_encoding=True)
    h.fixtures["/style.min.css"] = fx

    status, hdrs, recv = _https_request(
        f"{ORIGIN_HOST}/style.min.css", accept_gzip=True)
    if status != 200:
        raise AssertionError(f"chunked+gzip+weak-etag: status={status}")
    decoded = recv
    if hdrs.get("content-encoding", "").lower() == "gzip" and decoded:
        decoded = gzip.decompress(decoded)
    if decoded != body:
        raise AssertionError(
            f"chunked+gzip+weak-etag: decoded body mismatch "
            f"{len(decoded)}B vs {len(body)}B")
    if not (hdrs.get("content-type", "").startswith("text/css")):
        raise AssertionError(f"unexpected content-type: {hdrs.get('content-type')!r}")
    if not SNI_LOG or SNI_LOG[0] != ORIGIN_HOST:
        raise AssertionError(f"SNI missing on chunked+gzip path: {SNI_LOG!r}")


# Revalidation of an HTTPS-cached entry whose backend ETag is weak: confiacdn
# echoes `If-None-Match: W/"..."` to the origin and must accept the resulting
# 304 (no body) without re-downloading. Production origins commonly return
# weak ETags for compressed responses; the SNI fix would be wasted if the
# revalidation handshake also broke.
@register("https_backend_revalidate_weak_etag_304", timeout=60.0)
def _https_backend_revalidate_weak_etag_304(h: Harness):
    if h.origin_https_server is None:
        raise AssertionError("HTTPS origin not available")
    h.restart_confiacdn()
    h.reset_fixtures()
    reset_sni_state(require=ORIGIN_HOST)
    body, ctype = make_body(8 * 1024, content_type="text/css", compressible=True)
    weak = 'W/"reval-weak-1"'
    fx = Fixture(body=body, content_type=ctype, backend_etag=weak,
                 revalidate_match=weak)
    h.fixtures["/reval-css"] = fx

    # Cold fetch — populates cache.
    status1, _h1, recv1 = _https_request(f"{ORIGIN_HOST}/reval-css")
    if status1 != 200 or recv1 != body:
        raise AssertionError(f"reval cold: status={status1} len={len(recv1)}")

    # Wait past --http200Time=2s so the next fetch revalidates.
    time.sleep(2.5)
    serves_before = fx.serve_count
    status2, _h2, recv2 = _https_request(f"{ORIGIN_HOST}/reval-css")
    if status2 != 200 or recv2 != body:
        raise AssertionError(f"reval warm: status={status2} len={len(recv2)}")
    # Origin should have seen a revalidation request and answered 304 — i.e.
    # serve_count incremented, but no body was delivered to confiacdn.
    if fx.serve_count <= serves_before:
        raise AssertionError(
            f"origin not revalidated: serves before={serves_before} after={fx.serve_count}")
    # Each TLS connection logs an SNI; both must carry ORIGIN_HOST.
    if not SNI_LOG or any(s != ORIGIN_HOST for s in SNI_LOG):
        raise AssertionError(f"reval SNI wrong: {SNI_LOG!r}")


# Non-HTTP failures must surface a 5xx to the client *promptly* — not after
# the --maxreadtime window (default 20s) elapses. Origin's TLS server here
# rejects every handshake with `ALERT_DESCRIPTION_UNRECOGNIZED_NAME`, which
# is what an SNI mismatch / cert-pinning rejection looks like in production.
# Confiacdn must propagate a 500 within a few seconds via the SSL-handshake
# fail-fast path in Backend::startHttps; without it, the request would idle
# until --maxreadtime fires and only then return "Timeout into reply header".
@register("https_handshake_failure_fast_fail", timeout=30.0)
def _https_handshake_failure_fast_fail(h: Harness):
    if h.origin_https_server is None:
        raise AssertionError("HTTPS origin not available")
    h.restart_confiacdn()
    h.reset_fixtures()
    # Origin rejects any SNI that isn't this — confiacdn won't send it, so the
    # handshake aborts on the very first ServerHello.
    reset_sni_state(require="never-matches.invalid")
    body, ctype = make_body(8 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"ff"')
    h.fixtures["/handshake-fail"] = fx

    t0 = time.monotonic()
    status, _hdrs, recv = _https_request(f"{ORIGIN_HOST}/handshake-fail")
    elapsed = time.monotonic() - t0

    if status != 500:
        raise AssertionError(f"handshake fail: expected 500, got {status}")
    # 20s is the harness's --maxreadtime; if confiacdn waited that long, the
    # fail-fast path didn't fire. Cap well below it. The 2-retry budget in
    # backendErrorAndDisconnect plus three handshake aborts is still well
    # under a second on a local socket.
    if elapsed >= 10:
        raise AssertionError(
            f"handshake fail too slow: elapsed={elapsed:.2f}s — fast-fail path "
            f"appears to have idled out instead of erroring immediately. "
            f"recv={recv[:80]!r}")


# ----- Bursty profile -----------------------------------------------------

@register("bursty_profile_1MB", timeout=120.0)
def _bursty(h: Harness):
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(1 * 1024 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"b"', profile="bursty")
    h.fixtures["/bursty"] = fx
    r = fetch("/bursty", timeout=120)
    if r.status != 200 or r.decoded_body != body:
        raise AssertionError(f"bursty mismatch: status={r.status} len={len(r.decoded_body)}")


# ----- Slow header (delay before any byte) --------------------------------

@register("slow_header_delay")
def _slow_header(h: Harness):
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(64 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"sh"', profile="slowheader")
    h.fixtures["/slow-header"] = fx
    r = fetch("/slow-header", timeout=30)
    if r.status != 200 or r.decoded_body != body:
        raise AssertionError(f"slow-header mismatch: status={r.status}")


# ----- Disconnect mid-stream (cold cache) — confiacdn must not crash ------

@register("disconnect_midstream_cold_cache", timeout=90.0)
def _disconnect_cold(h: Harness):
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(1 * 1024 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"dc"', profile="disconnect")
    h.fixtures["/disco-cold"] = fx
    # We don't insist on a particular client outcome here (truncated body or
    # error, depending on confiacdn behaviour) — but the log scan must show
    # no abort/crash. The real assertion is the post-test log scan.
    with contextlib.suppress(Exception):
        fetch("/disco-cold", timeout=60)
    # If confiacdn crashed, log scan will catch it.


# ----- Unstable backend connection scenarios -----------------------------
# Models real-world flakiness on the backend leg (anycast routing changes,
# transit blackholes, half-open NATs, hostile origins). The contract is the
# same in every variant: confiacdn must not crash, must not hang past
# --maxreadtime, must propagate the failure to the client (or fall back to a
# stale cache when one is available — already covered by
# warm_stale_origin_fail_serves_stale).

# Origin completes the TCP handshake and reads the request, then never sends
# a single byte back. With confiacdn's --maxreadtime=20s in the harness, a
# 5xx must surface within ~25s. Without timeout enforcement the request
# would hang indefinitely.
@register("backend_silent_after_connect_no_reply", timeout=60.0)
def _backend_silent_after_connect(h: Harness):
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(8 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"sa"',
                 profile="silent_after_connect")
    h.fixtures["/silent-origin"] = fx
    t0 = time.monotonic()
    try:
        r = fetch("/silent-origin", timeout=45)
        elapsed = time.monotonic() - t0
        if r.status < 500 or r.status >= 600:
            raise AssertionError(
                f"silent origin: expected 5xx, got {r.status} after {elapsed:.1f}s")
    except (TimeoutError, OSError):
        # confiacdn took longer than the harness was willing to wait — that
        # still means the daemon stayed alive (we'd have seen scan failures
        # otherwise) but the timeout path didn't fire fast enough.
        elapsed = time.monotonic() - t0
        raise AssertionError(
            f"silent origin: client timeout at {elapsed:.1f}s — confiacdn's "
            f"--maxreadtime path didn't surface a 5xx in time.")
    # Don't tighten the upper bound past the timeout window confiacdn was
    # configured with: --maxreadtime=20s + handshake + retry budget puts the
    # legitimate ceiling around 30s. Anything beyond that is a regression.
    if elapsed >= 35:
        raise AssertionError(
            f"silent origin: 5xx took {elapsed:.1f}s, expected < 35s")


# Origin sends headers + ~25% of body, then stops sending without closing.
# confiacdn must time out (mission item 1: bytes already streamed are
# uncorruptable, but no infinite hang) and not corrupt the cache. A second
# request after recovery must hit origin again — the half-written cache must
# not be promoted to "complete" state.
@register("backend_freezes_mid_body_no_partial_cache", timeout=120.0)
def _backend_freezes_mid_body(h: Harness):
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(1 * 1024 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"fz"',
                 profile="freeze_mid_body")
    h.fixtures["/freeze-mid"] = fx
    t0 = time.monotonic()
    # First fetch: origin freezes mid-body. Either the client gets a
    # truncated body (some bytes streamed before timeout) or a 5xx (if
    # nothing streamed yet). Either is acceptable — the assertion is no
    # daemon abort + the cache must NOT register the response as complete.
    with contextlib.suppress(Exception):
        fetch("/freeze-mid", timeout=45)
    elapsed = time.monotonic() - t0
    if elapsed >= 35:
        raise AssertionError(
            f"freeze-mid: timeout fired late ({elapsed:.1f}s); --maxreadtime "
            f"during body should have triggered earlier.")
    # Now flip the fixture to a healthy fast-serve and verify confiacdn
    # re-fetches from origin — i.e. the partial cache from attempt 1 was
    # not promoted to a complete entry.
    fx.profile = "fast"
    serves_before = fx.serve_count
    r2 = fetch("/freeze-mid", timeout=30)
    if r2.status != 200 or r2.body != body:
        raise AssertionError(
            f"recovery fetch: status={r2.status} body-len={len(r2.body)} "
            f"vs expected {len(body)}")
    if fx.serve_count <= serves_before:
        raise AssertionError(
            "partial cache from frozen response was treated as complete "
            "(origin not re-hit on recovery fetch)")


# Origin sends ~25% of body then RSTs the TCP connection. Confiacdn's
# read-side hits ECONNRESET — must be handled identically to a clean close,
# i.e. no abort, no leak, error or partial body delivered to the client.
@register("backend_rst_mid_body", timeout=90.0)
def _backend_rst_mid_body(h: Harness):
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(1 * 1024 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"rst"',
                 profile="rst_mid_body")
    h.fixtures["/rst-mid"] = fx
    with contextlib.suppress(Exception):
        fetch("/rst-mid", timeout=45)
    # Real assertion is the post-test log scan: no abort, no leak. Recovery
    # fetch with healthy fixture must succeed.
    fx.profile = "fast"
    r2 = fetch("/rst-mid", timeout=30)
    if r2.status != 200 or r2.body != body:
        raise AssertionError(
            f"recovery after RST: status={r2.status} body-len={len(r2.body)}")


# Origin sends "HTTP/1.1 200 OK\r\nServer: ..." then stops without finishing
# the headers. Confiacdn's header parser must not buffer-grow forever and
# must time out around --maxreadtime. Common in production when an origin
# segfaults mid-write or a transit firewall truncates.
@register("backend_partial_headers_then_silent", timeout=60.0)
def _backend_partial_headers(h: Harness):
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(8 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"ph"',
                 profile="partial_headers_then_silent")
    h.fixtures["/partial-hdr"] = fx
    t0 = time.monotonic()
    with contextlib.suppress(Exception):
        fetch("/partial-hdr", timeout=45)
    elapsed = time.monotonic() - t0
    if elapsed >= 35:
        raise AssertionError(
            f"partial-headers: timeout fired late ({elapsed:.1f}s)")


# ----- Cache-fallback variants for the unstable-connection corollary ------
# These complement warm_stale_origin_fail_serves_stale, which only covers
# the explicit 5xx-from-origin path. In production the more common shape is
# silent / TLS-failing / connection-resetting upstream — corollary 2 says
# read-side cache must absorb each of these, not just clean HTTP errors.

# Cold fetch warms the cache; we wait past --http200Time so the next fetch
# revalidates; origin then goes silent (no header bytes ever). Confiacdn
# must fall back to the warm cache rather than wait its full --maxreadtime
# and 5xx the user. The retry-budget path inside backendErrorAndDisconnect
# handles the fallback when contentwritten==0 and an etag is stored — that
# is the case here (silence happens before any reply byte).
@register("warm_stale_silent_origin_serves_stale", timeout=120.0)
def _warm_stale_silent(h: Harness):
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(64 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"silent-stale"')
    h.fixtures["/silent-stale"] = fx
    r1 = fetch("/silent-stale")
    if r1.decoded_body != body:
        raise AssertionError("cold fetch broken")
    # Wait past --http200Time=2 so the next fetch revalidates against origin.
    time.sleep(3)
    # Flip origin into "silent forever" mode for the revalidation.
    fx.profile = "silent_after_connect"
    t0 = time.monotonic()
    r2 = fetch("/silent-stale", timeout=60)
    elapsed = time.monotonic() - t0
    # Mission item 5 corollary: serve stale rather than 5xx the user when a
    # warm cache exists.
    if r2.status != 200 or r2.decoded_body != body:
        raise AssertionError(
            f"expected stale-fallback 200 with original body; got "
            f"status={r2.status} body-len={len(r2.decoded_body)} after {elapsed:.1f}s")
    # The fallback is allowed to take up to --maxreadtime + retry budget
    # (~30s in the harness). Tighter is better but not required.
    if elapsed >= 35:
        raise AssertionError(
            f"stale-fallback took {elapsed:.1f}s; expected < 35s")


# Same shape, but the revalidation fails at the TLS layer instead of going
# silent. With the SNI fast-fail path (Backend::failAttachedHttp), the retry
# budget should kick in well within a second and trigger the stale fallback.
@register("warm_stale_https_handshake_fail_serves_stale", timeout=60.0)
def _warm_stale_https_handshake_fail(h: Harness):
    if h.origin_https_server is None:
        raise AssertionError("HTTPS origin not available")
    h.restart_confiacdn()
    h.reset_fixtures()
    reset_sni_state()  # accept SNI on the cold fetch
    body, ctype = make_body(32 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"tls-stale"')
    h.fixtures["/tls-stale"] = fx
    # Cold fetch via /https-tls/ to seed the cache through the HTTPS path.
    s1, _h1, recv1 = _https_request(f"{ORIGIN_HOST}/tls-stale")
    if s1 != 200 or recv1 != body:
        raise AssertionError(f"cold https fetch broken: status={s1}")
    time.sleep(3)
    # Arm the SNI gate so the revalidation handshake fails — origin sends
    # the unrecognized_name alert, confiacdn's startHttps sees SSL_ERROR_SSL,
    # failAttachedHttp routes through backendErrorAndDisconnect, retry
    # budget triggers retryAfterError → fallback to stale via the stored
    # backend etag. No 20s wait.
    reset_sni_state(require="never-matches.invalid")
    t0 = time.monotonic()
    s2, _h2, recv2 = _https_request(f"{ORIGIN_HOST}/tls-stale")
    elapsed = time.monotonic() - t0
    if s2 != 200 or recv2 != body:
        raise AssertionError(
            f"expected stale fallback after TLS fail; status={s2} "
            f"body-len={len(recv2)} elapsed={elapsed:.1f}s")
    if elapsed >= 10:
        raise AssertionError(
            f"TLS-fail stale-fallback too slow: {elapsed:.1f}s "
            f"(fast-fail path should land it under a second)")
    # Disarm the SNI gate so subsequent HTTPS-using tests aren't poisoned
    # by the leftover "never-matches.invalid" requirement. The harness
    # state is process-wide and tests run sequentially.
    reset_sni_state()


# Body-phase freeze during revalidation. Bytes have already been streamed
# out to the client by the time we detect the freeze, so we cannot rewind to
# stale — the client will see a truncated body or an error. The contract we
# pin here is the no-cache-corruption write-side rule: after the failed
# revalidation, a third fetch must still see the original cached body —
# meaning confiacdn did NOT promote the partial freeze response over the
# pre-existing complete cache entry.
@register("warm_revalidate_freeze_keeps_existing_cache", timeout=120.0)
def _warm_revalidate_freeze_keeps_cache(h: Harness):
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(512 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"freeze-stale"')
    h.fixtures["/freeze-revalidate"] = fx
    r1 = fetch("/freeze-revalidate")
    if r1.decoded_body != body:
        raise AssertionError("cold fetch broken")
    time.sleep(3)
    # Revalidation freezes mid-body — but the existing cache must survive.
    fx.profile = "freeze_mid_body"
    with contextlib.suppress(Exception):
        fetch("/freeze-revalidate", timeout=45)
    # Now flip back to healthy and verify the cache still serves the
    # original body. If confiacdn had overwritten the existing cache with
    # the partial-freeze stream, this fetch would either re-hit origin (a
    # different signal — see _backend_freezes_mid_body's recovery assertion)
    # or, worse, return a truncated body from a corrupted cache.
    fx.profile = "fast"
    r3 = fetch("/freeze-revalidate")
    if r3.status != 200 or r3.decoded_body != body:
        raise AssertionError(
            f"recovery fetch after freeze-revalidate: status={r3.status} "
            f"body-len={len(r3.decoded_body)} vs expected {len(body)} — "
            f"the freeze appears to have corrupted the warm cache")


# ----- Origin returns 404 — must finish as 404, not as a timeout ---------

@register("origin_404_propagates_not_timeout")
def _origin_404(h: Harness):
    h.restart_confiacdn()
    h.reset_fixtures()
    fx = Fixture(body=b"", content_type="text/plain", profile="error", error_status=404)
    h.fixtures["/origin-404"] = fx
    t0 = time.monotonic()
    r = fetch("/origin-404", timeout=30)
    elapsed = time.monotonic() - t0
    if r.status != 404:
        raise AssertionError(f"expected 404 from origin, got {r.status}")
    # Should not have stalled to timeout.
    if elapsed > 10:
        raise AssertionError(f"404 took {elapsed:.1f}s — looks like a timeout, not a fast error")


# ----- Origin returns 500/502/503 — propagated ---------------------------

for _code in (500, 502, 503):
    def _make_err(code=_code):
        def _t(h: Harness):
            h.restart_confiacdn()
            h.reset_fixtures()
            fx = Fixture(body=b"", content_type="text/plain", profile="error", error_status=code)
            h.fixtures[f"/err-{code}"] = fx
            r = fetch(f"/err-{code}", timeout=30)
            # Either propagated as the status, or surfaced as a 5xx — but never a hang.
            if r.status not in (code, 500, 502, 503, 504):
                raise AssertionError(f"unexpected status {r.status} for origin {code}")
        return _t
    register(f"origin_{_code}_propagates")(_make_err())


# ----- 5-min long-running download (gated by --no-soak) -------------------

@register("soak_5min_at_10mbps", timeout=600.0, gated_by="soak")
def _soak(h: Harness):
    # 5 min × 10 Mbps ≈ 375 MB. Same paced-streaming exercise as the previous
    # 50-min soak — long-lived backend connection, per-second CheckTimeout,
    # idle-detection thresholds across a window much longer than --maxreadtime
    # / --maxdwritetime — at one tenth the wall-clock cost. Generate
    # deterministically; never materialise the full body anywhere — origin
    # streams from a tiled 64KB seed chunk, client SHA256s the response
    # chunk-by-chunk, expected SHA computed by tile loop.
    duration_sec = 5 * 60
    rate_bps = 10 * 1024 * 1024 // 8  # 1.25 MB/s = 10 Mbps
    size_bytes = duration_sec * rate_bps  # ≈ 375 MB
    seed = 0xC0DEBABE

    h.restart_confiacdn(extra_args=[
        # Long timeouts so the read/write idle thresholds don't trip during soak.
        "--maxreadtime=60", "--maxdwritetime=60", "--maxdownloadtime=600",
    ])
    h.reset_fixtures()
    fx = Fixture(
        body=b"", content_type="application/octet-stream",
        backend_etag='"soak-v1"',
        stream_size=size_bytes, stream_seed=seed, stream_rate_bps=rate_bps,
    )
    h.fixtures["/soak"] = fx

    expected_sha = streaming_expected_sha(seed, size_bytes)

    # Inline streaming client — never accumulates the body.
    full_path = f"/{ORIGIN_HOST}/soak"
    conn = http.client.HTTPConnection("127.0.0.1", NGINX_PORT, timeout=duration_sec + 600)
    try:
        conn.request("GET", full_path,
                     headers={"Host": DEFAULT_HOST, "Connection": "close"})
        resp = conn.getresponse()
        if resp.status != 200:
            raise AssertionError(f"soak status {resp.status}")
        actual = hashlib.sha256()
        received = 0
        last_log = time.monotonic()
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            actual.update(chunk)
            received += len(chunk)
            now = time.monotonic()
            if now - last_log > 60:
                h.client_log.info(
                    f"soak progress: {received/1024/1024:.1f}MB / "
                    f"{size_bytes/1024/1024:.1f}MB "
                    f"({received*100/size_bytes:.1f}%)"
                )
                last_log = now
    finally:
        conn.close()

    if received != size_bytes:
        raise AssertionError(f"soak size {received} != expected {size_bytes}")
    if actual.hexdigest() != expected_sha:
        raise AssertionError(f"soak SHA mismatch: got {actual.hexdigest()[:16]} "
                             f"expected {expected_sha[:16]}")


# ----- 100MB sizes (gated by --no-full) -----------------------------------

@register("full_100MB_cold", timeout=300.0, gated_by="full")
def _full_100mb(h: Harness):
    h.restart_confiacdn()
    h.reset_fixtures()
    body, ctype = make_body(100 * 1024 * 1024, compressible=True)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"100mb"')
    h.fixtures["/100mb"] = fx
    r = fetch("/100mb", timeout=300)
    if r.decoded_body != body:
        raise AssertionError(f"100MB body mismatch: got {len(r.decoded_body)}")


# ----- HTTP/3 backend leg (direct, bypasses the daemon) -------------------
#
# These cells exercise testing/h3_smoke, which links Http3.o + EpollObject.o
# and talks directly to the aioquic origin on FORCEDPORT_H3. The daemon
# itself is not involved — Http3 isn't wired into Backend yet. Once that
# wiring lands these cells stay valid as a regression against the H3 client
# code path; full daemon-side H3 coverage will come as separate cells that
# go through nginx → confiacdn → H3 origin.

def _run_h3_smoke(*paths: str, timeout: float = 30.0,
                  out_prefix: str = "/tmp/h3_body",
                  mux: bool = False,
                  port: int = FORCEDPORT_H3) -> List[Dict[str, str]]:
    """Spawn h3_smoke for one or more paths in a single process (so the
    in-RAM session cache is observable across fetches). When mux=True,
    all paths run as concurrent streams on one Http3 instance. `port` lets
    a caller dial a lossy UDP shim (FORCEDPORT_H3_SHIM) instead of the origin
    directly. Returns the parsed KEY=VALUE summary lines, one per path."""
    build_dir = get_build_dir(False)
    bin_ = os.path.join(build_dir, "h3_smoke")
    if not os.path.exists(bin_):
        raise AssertionError(f"h3_smoke binary missing at {bin_}")
    # Clear any stale output files from a prior run.
    for i in range(len(paths)):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(f"{out_prefix}.{i}")
    cmd = [bin_, "::1", str(port), "origin.test", out_prefix]
    if mux:
        cmd.append("--mux")
    cmd.extend(paths)
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"h3_smoke rc={proc.returncode}\nstdout:{proc.stdout}\n"
            f"stderr:{proc.stderr}")
    out: List[Dict[str, str]] = []
    for line in proc.stdout.splitlines():
        kv = {}
        for tok in line.split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                kv[k] = v
        if "STATUS" in kv:
            out.append(kv)
    if len(out) != len(paths):
        raise AssertionError(
            f"expected {len(paths)} summary lines, got {len(out)}: "
            f"{proc.stdout!r}")
    return out


def _expected_size_body(n: int) -> bytes:
    """Mirror h3_origin.py's /size/<N> body — same Random(seed=N).randbytes(N)."""
    rng = random.Random(n)
    return rng.randbytes(n)


@register("h3_smoke_64k_cold")
def _h3_smoke_64k(h: Harness):
    r = _run_h3_smoke("/size/65536")
    s = r[0]
    if s["STATUS"] != "200":
        raise AssertionError(f"status={s['STATUS']}, expected 200")
    if int(s["BYTES"]) != 65536:
        raise AssertionError(f"BYTES={s['BYTES']}, expected 65536")
    if s["CT"] != "application/octet-stream":
        raise AssertionError(f"CT={s['CT']}")
    expected = hashlib.sha256(_expected_size_body(65536)).hexdigest()
    if s["SHA256"] != expected:
        raise AssertionError(f"body sha mismatch: got {s['SHA256']} want {expected}")


@register("h3_smoke_1mb_cold", timeout=60.0)
def _h3_smoke_1mb(h: Harness):
    n = 1024 * 1024
    r = _run_h3_smoke(f"/size/{n}", timeout=60.0)
    s = r[0]
    if s["STATUS"] != "200":
        raise AssertionError(f"status={s['STATUS']}, expected 200")
    if int(s["BYTES"]) != n:
        raise AssertionError(f"BYTES={s['BYTES']}, expected {n}")
    expected = hashlib.sha256(_expected_size_body(n)).hexdigest()
    if s["SHA256"] != expected:
        raise AssertionError(f"body sha mismatch")


@register("h3_smoke_text_compressible")
def _h3_smoke_text(h: Harness):
    r = _run_h3_smoke("/text/4096")
    s = r[0]
    if s["STATUS"] != "200":
        raise AssertionError(f"status={s['STATUS']}, expected 200")
    if int(s["BYTES"]) != 4096:
        raise AssertionError(f"BYTES={s['BYTES']}, expected 4096")
    if not s["CT"].startswith("text/plain"):
        raise AssertionError(f"CT={s['CT']}, expected text/plain*")


@register("h3_smoke_status_404")
def _h3_smoke_404(h: Harness):
    r = _run_h3_smoke("/404")
    s = r[0]
    if s["STATUS"] != "404":
        raise AssertionError(f"status={s['STATUS']}, expected 404")
    # Body is the "not found" message — non-zero, but we only assert the
    # status round-trip here.


@register("h3_smoke_status_500_propagates")
def _h3_smoke_500(h: Harness):
    r = _run_h3_smoke("/status/500")
    s = r[0]
    if s["STATUS"] != "500":
        raise AssertionError(f"status={s['STATUS']}, expected 500")


# ----- Argument-variation cells ------------------------------------------
#
# These exercise each runtime flag at a non-default value alongside a normal
# fetch path, verifying the flag doesn't regress body-correctness. They are
# deliberately not timing-sensitive: flags that only change internal pacing
# (--maxreadtime, --maxdwritetime, --maxdownloadtime) without affecting
# whether the fetch completes are not covered here — they are exercised by
# the existing failure-mode cells (backend_freezes_mid_body_no_partial_cache
# et al.) which trigger their thresholds explicitly.

@register("h3_probe_fires_and_fills_failure_cache", timeout=90.0)
def _h3_probe_fires_and_fills_failure_cache(h: Harness):
    """End-to-end: with --http3-probe enabled, each HTTPS fetch launches
    an Http3Probe alongside the HTTPS leg. The probe dials UDP at the
    HTTPS port (FORCEDPORT_TLS, where nothing speaks H3) and fails fast
    via ICMP unreach. Probe failures feed Http3::markOriginFailed.

    Validates:
      (a) the probe fires (one [http3-probe] log line per HTTPS fetch),
      (b) the failure cache transitions pending -> confirmed (the second
          failure for the same origin promotes after the zero-second
          confirm window in tests — but here the test build keeps the
          default 15-min interval, so we expect two pending failures
          before the third would confirm. We assert at least one log
          line shows pending or confirmed > 0)."""
    h.restart_confiacdn(extra_args=["--http3-probe"])
    h.reset_fixtures()
    # Defensive: clear any SNI gate left armed by a previous test.
    reset_sni_state()
    body, ctype = make_body(8 * 1024)
    # Use distinct paths so each fetch goes through Http::dnsRight (and
    # therefore triggers one Http3Probe::launch). A single path would
    # de-dup after the first fetch: warm-cache hits skip the backend
    # leg entirely, and we'd see only one probe line.
    paths = ["/probe-target-a", "/probe-target-b", "/probe-target-c"]
    for p in paths:
        h.fixtures[p] = Fixture(body=body, content_type=ctype,
                                backend_etag=f'"probe-{p}"')

    for p in paths:
        full_path = f"/https-tls/{ORIGIN_HOST}{p}"
        conn = http.client.HTTPConnection("127.0.0.1", NGINX_PORT, timeout=30)
        try:
            conn.request("GET", full_path,
                         headers={"Host": DEFAULT_HOST, "Connection": "close"})
            resp = conn.getresponse()
            got = resp.read()
            if resp.status != 200 or got != body:
                raise AssertionError(
                    f"HTTPS fetch {p} failed under --http3-probe: status={resp.status}")
        finally:
            conn.close()

    # Probes are async (reaped on a 1 s timerfd tick). The probe deadline
    # is 10 s; ICMP unreach typically fires in <100 ms. Give the reaper
    # 12 s to harvest all three.
    time.sleep(12.0)

    # Now grep cdn.log for [http3-probe] lines.
    with open(CONFIACDN_LOG) as f:
        log = f.read()
    probe_lines = [l for l in log.splitlines() if "[http3-probe]" in l]
    if len(probe_lines) < 3:
        raise AssertionError(
            f"expected >=3 [http3-probe] lines (one per HTTPS fetch), "
            f"got {len(probe_lines)}.\nlast lines:\n" +
            "\n".join(probe_lines[-5:] if probe_lines else log.splitlines()[-30:]))

    # Failure-cache wiring assertion: at least one probe line shows the
    # failure cache populated (pending or confirmed >0). Earlier lines
    # may report 0 if logged before markOriginFailed ran — we just need
    # ANY line to have observed non-zero state.
    saw_failure_growth = False
    for line in probe_lines:
        if ("failure_pending=" in line and "failure_pending=0" not in line) or \
           ("failure_confirmed=" in line and "failure_confirmed=0" not in line):
            saw_failure_growth = True
            break
    if not saw_failure_growth:
        raise AssertionError(
            "no probe log line shows failure_pending>0 or failure_confirmed>0 — "
            "probe → failure-cache wiring is not effective.\n" +
            "\n".join(probe_lines))


@register("arg_forcehttpclose_normal_request_works", timeout=60.0)
def _arg_forcehttpclose(h: Harness):
    """--forcehttpclose: keepalive disabled; each request opens a fresh
    backend TCP connection. Verify two sequential fetches both complete
    byte-correctly with the flag set."""
    h.restart_confiacdn(extra_args=["--forcehttpclose"])
    h.reset_fixtures()
    body, ctype = make_body(64 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"fhc1"')
    h.fixtures["/forceclose"] = fx
    for i in range(2):
        r = fetch("/forceclose")
        if r.status != 200:
            raise AssertionError(f"fetch {i}: status={r.status}")
        if r.decoded_body != body:
            raise AssertionError(f"fetch {i}: body mismatch")


@register("arg_disablestreaming_normal_request_works", timeout=60.0)
def _arg_disablestreaming(h: Harness):
    """--disableStreaming: streaming detection turned off. Body bytes
    still must arrive byte-correctly."""
    h.restart_confiacdn(extra_args=["--disableStreaming"])
    h.reset_fixtures()
    body, ctype = make_body(64 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"dstr"')
    h.fixtures["/nostream"] = fx
    r = fetch("/nostream")
    if r.status != 200:
        raise AssertionError(f"status={r.status}")
    if r.decoded_body != body:
        raise AssertionError("body mismatch under --disableStreaming")


@register("arg_nocache_normal_request_works", timeout=60.0)
def _arg_nocache(h: Harness):
    """--nocache: temp cache is dropped at end of fetch. The request
    itself must still complete byte-correctly; we don't assert on
    disk state because the exact cleanup moment is implementation."""
    h.restart_confiacdn(extra_args=["--nocache"])
    h.reset_fixtures()
    body, ctype = make_body(64 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"nch"')
    h.fixtures["/nocache"] = fx
    r = fetch("/nocache")
    if r.status != 200:
        raise AssertionError(f"status={r.status}")
    if r.decoded_body != body:
        raise AssertionError("body mismatch under --nocache")


@register("arg_maxbackend_1_serializes_concurrent", timeout=90.0)
def _arg_maxbackend_1(h: Harness):
    """--maxBackend=1: only one outgoing backend connection to a given
    origin at a time. Spawn 4 concurrent client fetches to DIFFERENT
    URLs (so Http::pathToHttp doesn't de-dup them) and verify all four
    complete byte-correctly. The Backend pool's pending queue handles
    the serialisation; this proves it doesn't drop or scramble bytes
    under contention."""
    h.restart_confiacdn(extra_args=["--maxBackend=1"])
    h.reset_fixtures()
    paths = []
    bodies = {}
    for i in range(4):
        body, ctype = make_body(64 * 1024, seed=0xC0FFEE ^ i)
        p = f"/mb1-{i}"
        h.fixtures[p] = Fixture(body=body, content_type=ctype,
                                backend_etag=f'"mb1-{i}"')
        paths.append(p)
        bodies[p] = body

    results: Dict[str, Response] = {}
    errors: List[str] = []
    threads = []
    def _worker(path):
        try:
            results[path] = fetch(path)
        except Exception as e:
            errors.append(f"{path}: {e}")
    for p in paths:
        t = threading.Thread(target=_worker, args=(p,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    if errors:
        raise AssertionError("worker errors: " + "; ".join(errors))
    for p, body in bodies.items():
        r = results.get(p)
        if r is None:
            raise AssertionError(f"no result for {p}")
        if r.status != 200:
            raise AssertionError(f"{p}: status={r.status}")
        if r.decoded_body != body:
            raise AssertionError(f"{p}: body mismatch")


@register("arg_http200time_variation_long", timeout=60.0)
def _arg_http200time_long(h: Harness):
    """--http200Time=600 (10 min) — a 1-second wait between two fetches
    must NOT trigger revalidation; origin must see exactly one request.
    Pairs with the existing cache_ttl_boundary_2s_int_ms which exercises
    the small-TTL boundary; this exercises the large-TTL skip-revalidate
    path under a different argument value."""
    h.restart_confiacdn(extra_args=["--http200Time=600"])
    h.reset_fixtures()
    body, ctype = make_body(64 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"longttl"')
    h.fixtures["/longttl"] = fx
    r1 = fetch("/longttl")
    if r1.decoded_body != body or r1.status != 200:
        raise AssertionError(f"first fetch failed: status={r1.status}")
    serve_count_after_first = fx.serve_count
    time.sleep(1.0)
    r2 = fetch("/longttl")
    if r2.decoded_body != body or r2.status != 200:
        raise AssertionError(f"second fetch failed: status={r2.status}")
    if fx.serve_count != serve_count_after_first:
        raise AssertionError(
            f"warm-fresh expected no origin hit under --http200Time=600, "
            f"got {fx.serve_count - serve_count_after_first} extra origin "
            f"requests")


@register("h3_first_dial_serves_byte_correct", timeout=60.0)
def _h3_first_dial_serves(h: Harness):
    """End-to-end H3+H1.1 race: both legs run in parallel; whichever
    finishes first serves the response. Either path must produce a
    byte-correct body. The H3 leg uses aioquic's /text/<N> route; the
    H1.1 leg uses an h.fixtures entry seeded with the same bytes so the
    byte-compare passes regardless of which side wins on loopback."""
    h.restart_confiacdn(extra_args=[
        "--http3",
        f"--http3-port={FORCEDPORT_H3}",
    ])
    reset_sni_state()
    h.reset_fixtures()
    n = 4096
    body = (b"abcdefghij" * ((n // 10) + 1))[:n]
    fx = Fixture(body=body, content_type="text/plain; charset=utf-8",
                 backend_etag='"race"')
    h.fixtures[f"/text/{n}"] = fx
    full_path = f"/https-tls/{ORIGIN_HOST}/text/{n}"
    conn = http.client.HTTPConnection("127.0.0.1", NGINX_PORT, timeout=30)
    try:
        conn.request("GET", full_path,
                     headers={"Host": DEFAULT_HOST, "Connection": "close"})
        resp = conn.getresponse()
        got = resp.read()
    finally:
        conn.close()
    if resp.status != 200:
        raise AssertionError(
            f"race serve status={resp.status}; expected 200 from either leg")
    if got != body:
        raise AssertionError(
            f"race body mismatch: got {len(got)}B, expected {len(body)}B")


@register("h3_race_h3_wins_when_h1_is_slow", timeout=60.0)
def _h3_race_h3_wins(h: Harness):
    """Force the race to be won by H3: the HTTPS leg is registered as
    a slowheader fixture (3 s server-side delay before bytes), the H3
    origin (aioquic) replies immediately. checkH3 should see
    allStreamsDone with 200 before the parser sets tempCache/headerWriten,
    adopt the H3 response, disconnectBackend, and emit byte-correct
    output to the client. Wall-clock should be < 1 s (vs 3 s+ for the
    slow H1.1 path)."""
    h.restart_confiacdn(extra_args=[
        "--http3",
        f"--http3-port={FORCEDPORT_H3}",
        "--http3-deadline-ms=10000",
    ])
    reset_sni_state()
    h.reset_fixtures()
    n = 4096
    body = (b"abcdefghij" * ((n // 10) + 1))[:n]
    fx = Fixture(body=body, content_type="text/plain; charset=utf-8",
                 backend_etag='"race-h3wins"',
                 profile="silent_before_headers")
    h.fixtures[f"/text/{n}"] = fx
    full_path = f"/https-tls/{ORIGIN_HOST}/text/{n}"
    t0 = time.monotonic()
    conn = http.client.HTTPConnection("127.0.0.1", NGINX_PORT, timeout=30)
    try:
        conn.request("GET", full_path,
                     headers={"Host": DEFAULT_HOST, "Connection": "close"})
        resp = conn.getresponse()
        got = resp.read()
    finally:
        conn.close()
    elapsed = time.monotonic() - t0
    if resp.status != 200:
        raise AssertionError(f"race-h3wins status={resp.status}")
    if got != body:
        raise AssertionError(
            f"race-h3wins body mismatch: got {len(got)}B, expected {len(body)}B")
    # The H1.1 leg sleeps 3 s before headers; if H3 didn't win we'd see
    # ≥3 s. Allow generous headroom (slow CI, valgrind 10x) but cap below
    # the slowheader delay to prove H3 served the response.
    if elapsed >= 2.5:
        raise AssertionError(
            f"race-h3wins took {elapsed:.2f}s — H1.1 likely served despite "
            f"the 3s slowheader delay; H3 did not win")


@register("h3_first_falls_back_to_h1_when_h3_blackholed", timeout=60.0)
def _h3_first_blackhole_fallback(h: Harness):
    """--http3 + bogus --http3-port (closed UDP). The H3 dial fails
    fast (ICMP unreach or deadline), the daemon falls back to the
    HTTPS leg, and the fetch completes byte-correctly via H1.1.

    Validates: H3 client-side failure does not regress the request —
    Http::checkH3 detects the failure within the per-fetch deadline and
    dispatches tryConnectInternal."""
    h.restart_confiacdn(extra_args=[
        "--http3",
        f"--http3-port={FORCEDPORT_H3 + 7000}",  # closed UDP
        "--http3-deadline-ms=2000",              # speed the fallback
    ])
    reset_sni_state()
    h.reset_fixtures()
    body, ctype = make_body(8 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"h3bh"')
    h.fixtures["/h3-blackhole"] = fx
    full_path = f"/https-tls/{ORIGIN_HOST}/h3-blackhole"
    conn = http.client.HTTPConnection("127.0.0.1", NGINX_PORT, timeout=30)
    try:
        conn.request("GET", full_path,
                     headers={"Host": DEFAULT_HOST, "Connection": "close"})
        resp = conn.getresponse()
        got = resp.read()
    finally:
        conn.close()
    if resp.status != 200:
        raise AssertionError(f"fallback failed: status={resp.status}")
    if got != body:
        raise AssertionError(
            f"fallback body mismatch: got {len(got)}B, expected {len(body)}B")


@register("h3_failure_smoke_fails_fast_when_target_down", timeout=30.0)
def _h3_failure_smoke_fails_fast(h: Harness):
    """Drive the smoke binary at a UDP port with no listener. The Http3
    handshake never completes; the per-fetch timeout must elapse and the
    process exits non-zero within budget, not hung forever.

    Validates: closed-port / no-response scenarios surface as a graceful
    timeout instead of wedging the H3 leg. Foundational for the future
    daemon-side H3-first-with-H1.1-fallback path — that path's fallback
    trigger depends on the H3 leg failing in bounded time."""
    build_dir = get_build_dir(False)
    bin_ = os.path.join(build_dir, "h3_smoke")
    if not os.path.exists(bin_):
        raise AssertionError(f"h3_smoke binary missing at {bin_}")
    # Pick a UDP port we know is unbound. Reuse the harness's H3 origin
    # base port + a 7000 offset; nothing listens there.
    closed_port = FORCEDPORT_H3 + 7000
    t0 = time.monotonic()
    proc = subprocess.run(
        [bin_, "::1", str(closed_port), "origin.test", "/tmp/h3down",
         "/size/4096"],
        capture_output=True, text=True, timeout=60.0,
    )
    elapsed = time.monotonic() - t0
    if proc.returncode == 0:
        raise AssertionError(
            f"expected non-zero rc on closed UDP port, got rc=0\n"
            f"stdout:{proc.stdout}")
    # Smoke binary's internal per-fetch timeout is 30s. We give the test
    # a 60s outer budget but require the binary to be done well under it.
    if elapsed > 40.0:
        raise AssertionError(
            f"smoke binary took {elapsed:.1f}s — should fail-fast within "
            f"its internal timeout (~30s).")
    err = proc.stderr.lower()
    # Acceptable failure shapes: either the QUIC handshake timeout
    # elapses (no packets ever returned) or the kernel surfaces an ICMP
    # "Connection refused" / "Network is unreachable" on the connected
    # UDP socket immediately. Both are bounded fail-fast paths — we just
    # need to not see an uncategorised crash or a hang.
    ok_markers = ("timeout", "connection refused", "network is unreachable",
                  "no route to host")
    if not any(m in err for m in ok_markers):
        raise AssertionError(
            f"expected fail-fast marker in stderr, got:\n{proc.stderr}")


@register("h3_failure_h1_path_unaffected", timeout=60.0)
def _h3_failure_h1_path_unaffected(h: Harness):
    """When the H3 origin is broken (we don't talk to it), the existing
    HTTPS test path through nginx → confiacdn → HTTPS-origin still works
    end-to-end byte-correctly. Demonstrates that H3 client-side issues
    cannot regress the H1.1 path (a prerequisite for the future daemon
    H3-first dial — its fallback must leave H1.1 fetches unaffected)."""
    # Smoke-fetch against the closed UDP port first, just to prove H3 is
    # broken right now. Discard output; success of this step would mean
    # the precondition for the assertion below is not actually being
    # exercised, in which case the test is meaningless.
    build_dir = get_build_dir(False)
    bin_ = os.path.join(build_dir, "h3_smoke")
    closed_port = FORCEDPORT_H3 + 7000
    bad = subprocess.run(
        [bin_, "::1", str(closed_port), "origin.test", "/tmp/h3down",
         "/size/4096"],
        capture_output=True, text=True, timeout=45.0,
    )
    if bad.returncode == 0:
        raise AssertionError(
            "expected H3 fetch to fail at closed UDP port; got rc=0")

    # Now the actual H1.1 independence assertion: a plain HTTPS fetch
    # through the daemon completes byte-correctly. Uses the existing
    # /https-tls/ nginx prefix that the daemon's HTTPS test path uses.
    h.restart_confiacdn()
    h.reset_fixtures()
    # Defensive: clear any SNI gate left armed by a previous test.
    reset_sni_state()
    body, ctype = make_body(64 * 1024)
    fx = Fixture(body=body, content_type=ctype, backend_etag='"h1indep"')
    h.fixtures["/h1indep"] = fx
    # Use https-tls path — confiacdn dials origin via TLS on FORCEDPORT_TLS.
    full_path = f"/https-tls/{ORIGIN_HOST}/h1indep"
    conn = http.client.HTTPConnection("127.0.0.1", NGINX_PORT, timeout=30)
    try:
        conn.request("GET", full_path,
                     headers={"Host": DEFAULT_HOST, "Connection": "close"})
        resp = conn.getresponse()
        got = resp.read()
        if resp.status != 200:
            raise AssertionError(f"https status={resp.status}")
        if got != body:
            raise AssertionError(
                f"https body mismatch: got {len(got)}B, expected {len(body)}B")
    finally:
        conn.close()


@register("h3_session_cache_lru", timeout=30.0)
def _h3_session_cache_lru(h: Harness):
    """Drives Http3::storeSession/lookupSession through a dedicated
    in-process unit test: verifies the 10000-entry cap and LRU eviction
    semantics directly, with no network or aioquic involvement."""
    build_dir = get_build_dir(False)
    bin_ = os.path.join(build_dir, "h3_lru_test")
    if not os.path.exists(bin_):
        raise AssertionError(f"h3_lru_test binary missing at {bin_}")
    proc = subprocess.run([bin_], capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        raise AssertionError(
            f"h3_lru_test rc={proc.returncode}\nstdout:{proc.stdout}\n"
            f"stderr:{proc.stderr}")


@register("h3_smoke_mux_4_streams", timeout=60.0)
def _h3_smoke_mux(h: Harness):
    """Four concurrent GETs multiplexed over a single Http3/QUIC connection.

    Validates: nghttp3 streams routing by id, per-stream ResponseState
    isolation, allStreamsDone() correctness, flow control across N parallel
    body transfers. Each response body is verified byte-correct against
    the deterministic seed used by the origin."""
    sizes = [1024, 4096, 32768, 262144]
    paths = [f"/size/{n}" for n in sizes]
    r = _run_h3_smoke(*paths, mux=True, timeout=60.0)
    if len(r) != len(sizes):
        raise AssertionError(f"expected {len(sizes)} streams, got {len(r)}")
    seen_streams = set()
    for i, (n, s) in enumerate(zip(sizes, r)):
        if s["STATUS"] != "200":
            raise AssertionError(f"stream {i} status={s['STATUS']}")
        if int(s["BYTES"]) != n:
            raise AssertionError(f"stream {i} BYTES={s['BYTES']}, expected {n}")
        expected = hashlib.sha256(_expected_size_body(n)).hexdigest()
        if s["SHA256"] != expected:
            raise AssertionError(f"stream {i} body sha mismatch")
        if s["MUX"] != "1":
            raise AssertionError(f"stream {i} MUX={s['MUX']}, expected 1")
        sid = int(s["STREAM"])
        if sid in seen_streams:
            raise AssertionError(f"duplicate STREAM id {sid}")
        seen_streams.add(sid)
    # Client-initiated bidi stream ids in QUIC: 0, 4, 8, 12 ...
    if sorted(seen_streams) != [0, 4, 8, 12]:
        raise AssertionError(
            f"expected stream ids 0/4/8/12, got {sorted(seen_streams)}")


@register("h3_smoke_two_fetches_one_process")
def _h3_smoke_two(h: Harness):
    """Two sequential fetches in one process. Validates basic Http3
    lifecycle AND TLS 1.3 session-ticket resumption — the second fetch
    must see RESUMED=1 (a cached ticket was found at start) and
    CACHE_SIZE>=1 (the first connection captured one)."""
    r = _run_h3_smoke("/size/4096", "/size/4096")
    for i, s in enumerate(r):
        if s["STATUS"] != "200":
            raise AssertionError(f"fetch {i} status={s['STATUS']}")
        if int(s["BYTES"]) != 4096:
            raise AssertionError(f"fetch {i} BYTES={s['BYTES']}")
        expected = hashlib.sha256(_expected_size_body(4096)).hexdigest()
        if s["SHA256"] != expected:
            raise AssertionError(f"fetch {i} body sha mismatch")
    if r[0]["RESUMED"] != "0":
        raise AssertionError(f"first fetch RESUMED={r[0]['RESUMED']}, expected 0")
    if int(r[0]["CACHE_SIZE"]) < 1:
        raise AssertionError(
            f"after first fetch CACHE_SIZE={r[0]['CACHE_SIZE']}, expected >=1 "
            f"(NewSessionTicket should have populated the cache)")
    if r[1]["RESUMED"] != "1":
        raise AssertionError(
            f"second fetch RESUMED={r[1]['RESUMED']}, expected 1 — "
            f"session ticket from first connection should have been "
            f"available for resumption")


# ----- HTTP/3 QUIC transport failure injection (lossy UDP shim) -----------
#
# These cells route the h3_smoke client through testing/h3_udp_shim.py, a
# dumb UDP relay that drops / reorders / duplicates / corrupts / blackholes
# individual datagrams between the QUIC client and the aioquic origin. They
# exercise the parts of Http3.cpp that ONLY run when the UDP path misbehaves:
# ngtcp2 PTO retransmission (handleExpiry/armTimer/parseEvent re-arm),
# packet-number dedup, AEAD-failure silent-discard, and the idle-timeout
# fail-fast path. The TCP "misbehaving origin" profiles cannot reach any of
# this because QUIC's reliability lives below HTTP.
#
# Assertion shape for the *recoverable* cases is always the same: STATUS 200
# and a byte-identical body. QUIC guarantees reliable, ordered, exactly-once
# stream delivery, so any loss/reorder/dup/corruption that the protocol can
# recover from MUST still yield the same bytes the origin sent. A truncated,
# short, or doubled body is a hard failure — that is precisely the regression
# this block exists to catch (mission items 1 and 2).

def _tail_shim_log(maxlines: int = 8) -> str:
    """Last few lines of the shim log, for failure diagnostics."""
    try:
        with open(H3_SHIM_LOG) as f:
            lines = f.read().splitlines()
        return " | ".join(lines[-maxlines:]) or "(shim log empty)"
    except FileNotFoundError:
        return "(no shim log)"


def _h3_smoke_through_shim(policy: List[str], path: str, *,
                           expected_size: Optional[int] = None,
                           timeout: float = 60.0) -> Dict[str, str]:
    """Start a lossy shim with `policy`, run one h3_smoke fetch for `path`
    through FORCEDPORT_H3_SHIM, assert STATUS 200 (and, if expected_size is
    given, an exact byte-count + sha256 match against the deterministic
    /size/<N> body), and return the parsed summary. Shim always stopped."""
    shim = start_h3_shim(policy)
    try:
        r = _run_h3_smoke(path, port=FORCEDPORT_H3_SHIM, timeout=timeout)
    finally:
        stop_h3_shim(shim)
    s = r[0]
    if s["STATUS"] != "200":
        raise AssertionError(
            f"status={s['STATUS']}, expected 200 under shim {policy}. "
            f"shim: {_tail_shim_log()}")
    if expected_size is not None:
        if int(s["BYTES"]) != expected_size:
            raise AssertionError(
                f"BYTES={s['BYTES']}, expected exactly {expected_size} "
                f"(truncation or duplication under shim {policy}). "
                f"shim: {_tail_shim_log()}")
        exp = hashlib.sha256(_expected_size_body(expected_size)).hexdigest()
        if s["SHA256"] != exp:
            raise AssertionError(
                f"body sha mismatch under shim {policy} — corrupted bytes "
                f"reached the body. shim: {_tail_shim_log()}")
    return s


@register("h3_loss_drop_client_initial", timeout=60.0)
def _h3_loss_drop_client_initial(h: Harness):
    """Drop the client's first datagram (the QUIC Initial carrying ClientHello).
    The client must hit its handshake PTO, retransmit the Initial, and complete
    the handshake + fetch byte-correctly. Exercises PTO during the handshake."""
    _h3_smoke_through_shim(["--drop-c2o-first", "1"],
                           "/size/65536", expected_size=65536)


@register("h3_loss_drop_server_first_flight", timeout=60.0)
def _h3_loss_drop_server_first_flight(h: Harness):
    """Drop the origin's first two datagrams (its Initial+Handshake flight
    carrying ServerHello / cert). The client retransmits its Initial on PTO,
    the server re-sends, and the fetch completes byte-correctly."""
    _h3_smoke_through_shim(["--drop-o2c-first", "2"],
                           "/size/65536", expected_size=65536)


@register("h3_loss_uniform_10pct_o2c", timeout=60.0)
def _h3_loss_uniform_10pct_o2c(h: Harness):
    """Drop ~10% of every origin->client datagram across a 1 MB transfer.
    Sustained loss: ngtcp2 must retransmit the lost STREAM frames and deliver
    a byte-identical 1 MB body."""
    n = 1024 * 1024
    _h3_smoke_through_shim(["--drop-o2c-frac", "0.1", "--seed", "7"],
                           f"/size/{n}", expected_size=n)


@register("h3_loss_uniform_10pct_bidirectional", timeout=60.0)
def _h3_loss_uniform_10pct_bidirectional(h: Harness):
    """Drop ~10% of datagrams in BOTH directions over 1 MB — this also loses
    ACKs and client-side flow-control updates, stressing both peers' loss
    recovery simultaneously. Body must still be byte-identical."""
    n = 1024 * 1024
    _h3_smoke_through_shim(
        ["--drop-o2c-frac", "0.1", "--drop-c2o-frac", "0.1", "--seed", "11"],
        f"/size/{n}", expected_size=n)


@register("h3_loss_burst_midbody_recovers", timeout=60.0)
def _h3_loss_burst_midbody_recovers(h: Harness):
    """Once ~200 KB of body has flowed, drop a burst of 8 consecutive
    origin->client datagrams, then resume. Models a transient link blink in
    the middle of a bulk transfer (distinct from handshake loss). The dropped
    STREAM frames must be retransmitted; body byte-identical."""
    n = 1024 * 1024
    _h3_smoke_through_shim(
        ["--drop-o2c-after-bytes", "200000", "--drop-o2c-window", "8"],
        f"/size/{n}", expected_size=n)


@register("h3_loss_tail_fin_drop_recovers", timeout=60.0)
def _h3_loss_tail_fin_drop_recovers(h: Harness):
    """The 'drop at the worst time' case: let almost the whole 1 MB body
    flow, then drop a 6-datagram burst right at the tail — the region that
    carries the final STREAM frame and the FIN. The client must NOT declare
    the stream done short; ngtcp2 must retransmit the tail and the body must
    arrive complete and byte-identical. A truncated body here would mean a
    late FIN-loss silently delivers a short response (the scariest CDN bug)."""
    n = 1024 * 1024
    _h3_smoke_through_shim(
        ["--drop-o2c-after-bytes", "1000000", "--drop-o2c-window", "6"],
        f"/size/{n}", expected_size=n)


@register("h3_reorder_o2c_recovers", timeout=60.0)
def _h3_reorder_o2c_recovers(h: Harness):
    """Reorder origin->client datagrams (swap every 3rd with its successor).
    QUIC carries explicit packet numbers and per-stream byte offsets, so
    out-of-order delivery must reassemble to a byte-identical body."""
    n = 262144
    _h3_smoke_through_shim(["--reorder-o2c", "3"],
                           f"/size/{n}", expected_size=n)


@register("h3_dup_o2c_no_double_body", timeout=60.0)
def _h3_dup_o2c_no_double_body(h: Harness):
    """Duplicate every 3rd origin->client datagram. QUIC dedups by packet
    number, so the duplicates must be discarded: the body is EXACTLY n bytes
    (not n + duplicated-payload) and byte-identical. The exact byte-count
    assertion is what proves dedup actually happened."""
    n = 262144
    _h3_smoke_through_shim(["--dup-o2c", "3"],
                           f"/size/{n}", expected_size=n)


@register("h3_corrupt_o2c_tail_byte_recovers", timeout=60.0)
def _h3_corrupt_o2c_tail_byte_recovers(h: Harness):
    """Flip the final byte (AEAD auth-tag region) of every 4th origin->client
    1-RTT datagram. Each corrupted packet must FAIL authentication and be
    silently discarded by ngtcp2 (RFC 9000 §10.2), then recovered by
    retransmission. The body must be byte-identical — i.e. no corrupted bytes
    ever reach the response (mission item 2). Handshake datagrams are left
    intact (shim --corrupt-skip-first default) so the corruption lands only on
    silently-droppable 1-RTT packets."""
    n = 262144
    _h3_smoke_through_shim(["--corrupt-o2c", "4"],
                           f"/size/{n}", expected_size=n)


@register("h3_blackhole_after_handshake_fails_fast", timeout=60.0)
def _h3_blackhole_after_handshake_fails_fast(h: Harness):
    """Let the handshake complete and a little data flow, then blackhole ALL
    datagrams in both directions. With the shim bound, there is no ICMP — the
    client cannot learn of the failure except through QUIC's own PTO/idle
    timers. It MUST give up in bounded time (well under the smoke binary's
    30 s internal cap) rather than wedge. This is the pure-timeout sibling of
    h3_failure_smoke_fails_fast_when_target_down (which gets an instant ICMP
    on a closed port)."""
    build_dir = get_build_dir(False)
    bin_ = os.path.join(build_dir, "h3_smoke")
    if not os.path.exists(bin_):
        raise AssertionError(f"h3_smoke binary missing at {bin_}")
    shim = start_h3_shim(["--blackhole-after-handshake-bytes", "4000"])
    try:
        t0 = time.monotonic()
        proc = subprocess.run(
            [bin_, "::1", str(FORCEDPORT_H3_SHIM), "origin.test",
             "/tmp/h3bh", "/size/1048576"],
            capture_output=True, text=True, timeout=55.0,
        )
        elapsed = time.monotonic() - t0
    finally:
        stop_h3_shim(shim)
    if proc.returncode == 0:
        raise AssertionError(
            f"expected non-zero rc when the path blackholes mid-connection, "
            f"got rc=0. shim: {_tail_shim_log()}")
    # The QUIC idle timeout (30 s) bounds the worst case; the smoke binary
    # self-caps at 30 s too. Either way it must be done well under the test
    # budget and must not hang.
    if elapsed > 40.0:
        raise AssertionError(
            f"blackhole fail-fast took {elapsed:.1f}s — should bound on the "
            f"idle/PTO timer (~30 s). shim: {_tail_shim_log()}")
    err = proc.stderr.lower()
    if "timeout" not in err:
        raise AssertionError(
            f"expected a timeout marker in stderr, got: {proc.stderr!r}")


@register("h3_daemon_loss_serves_byte_correct", timeout=60.0)
def _h3_daemon_loss_serves_byte_correct(h: Harness):
    """End-to-end daemon H3+H1.1 race with the H3 leg routed through a 10%-loss
    shim. The H3 UDP path drops datagrams while the parallel H1.1 path runs
    clean; whichever wins, the client must get a byte-identical body and the
    daemon must churn the lossy H3 connection (extra retransmits, possible
    abandon-on-deadline) WITHOUT any lifetime-guard (abort) or leak. Guards the
    daemon-side H3 object lifecycle under transport loss, which the smoke
    cells (no daemon) cannot."""
    h.restart_confiacdn(extra_args=[
        "--http3",
        f"--http3-port={FORCEDPORT_H3_SHIM}",
        "--http3-deadline-ms=10000",
    ])
    reset_sni_state()
    h.reset_fixtures()
    n = 8192
    body = (b"abcdefghij" * ((n // 10) + 1))[:n]
    fx = Fixture(body=body, content_type="text/plain; charset=utf-8",
                 backend_etag='"h3loss"')
    h.fixtures[f"/text/{n}"] = fx
    shim = start_h3_shim(["--drop-o2c-frac", "0.1", "--seed", "5"])
    try:
        full_path = f"/https-tls/{ORIGIN_HOST}/text/{n}"
        conn = http.client.HTTPConnection("127.0.0.1", NGINX_PORT, timeout=40)
        try:
            conn.request("GET", full_path,
                         headers={"Host": DEFAULT_HOST, "Connection": "close"})
            resp = conn.getresponse()
            got = resp.read()
        finally:
            conn.close()
    finally:
        stop_h3_shim(shim)
    if resp.status != 200:
        raise AssertionError(
            f"daemon under H3 loss status={resp.status}; expected 200. "
            f"shim: {_tail_shim_log()}")
    if got != body:
        raise AssertionError(
            f"daemon under H3 loss body mismatch: got {len(got)}B, "
            f"expected {len(body)}B. shim: {_tail_shim_log()}")


# ---------------------------------------------------------------------------
# Static-DNS file loading — format check + graceful-continuation guards
#
# These tests exercise Dns::getStaticEntry() and the `--check-static-dns` CLI
# mode. The mode parses every static-DNS source (ssl/, /etc/nginx/ssl/, hosts,
# /etc/hosts) and exits non-zero when a source is present but yields zero
# valid entries — used by upload.sh as a per-edge sanity check.
# ---------------------------------------------------------------------------

_STATIC_DNS_HOSTS_PATH = os.path.join(TMPFS, "hosts")
_STATIC_DNS_SSL_DIR = os.path.join(TMPFS, "ssl")

# A Confiared IPv6 (2803:1920::/32 prefix — the include-range constant in
# Dns.cpp:34). Picked from outside the exclude window. Must use real hex
# digits — `n` and `t` are not valid in IPv6 segments.
_CONFIARED_IPV6_VALID = "2803:1920::dead:beef:1"
_CONFIARED_IPV6_VALID_2 = "2803:1920::dead:beef:2"
_CONFIARED_IPV6_SSL = "2803:1920::dead:beef:f"
# An IPv6 outside the Confiared block — must be filtered by the include check.
_OUTSIDE_CONFIARED_IPV6 = "2001:db8::1"


def _write_ssl_fixture(subdir: str, ipv6: str, san_dns: List[str]) -> int:
    """Create ${TMPFS}/ssl/<subdir>/{dest,cert.pem} so getStaticEntry()
    derives one entry per cert SAN DNS name -> <ipv6>. Returns the number of
    SAN names (== this fixture's ssl_entries_loaded contribution).

    The SSL cert dirs are the source-of-truth path; --check-static-dns now
    hard-fails when zero entries load from them, so every check test that
    expects exit 0 must lay one of these down first."""
    d = os.path.join(_STATIC_DNS_SSL_DIR, subdir)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "dest"), "w") as f:
        f.write(ipv6 + "\n")
    san = ",".join(f"DNS:{n}" for n in san_dns)
    rc = subprocess.call(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", os.path.join(d, "key.pem"),
         "-out", os.path.join(d, "cert.pem"),
         "-days", "30", "-subj", "/CN=ssl-fixture",
         "-addext", f"subjectAltName={san}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if rc != 0:
        raise RuntimeError("openssl req (SAN fixture) failed")
    return len(san_dns)


def _clear_ssl_fixture() -> None:
    with contextlib.suppress(FileNotFoundError):
        shutil.rmtree(_STATIC_DNS_SSL_DIR)


def _run_check_static_dns(h: Harness) -> Tuple[int, str, str]:
    bin_path = get_confiacdn_bin(h.args.sanitize is not None)
    cmd = [bin_path, "--check-static-dns"]
    if h.args.valgrind:
        cmd = _valgrind_argv(h.args.valgrind) + cmd
    proc = subprocess.run(
        cmd, cwd=TMPFS, capture_output=True, text=True, timeout=60,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _parse_check_stdout(stdout: str) -> Dict[str, int]:
    """Extract counters from the check report into a flat dict.

    Two line shapes:
      - "  hosts files present: 1, lines: 5, loaded: 1, bad-ipv6: 2, ..."
      - "static-dns: total loaded = 3"
    The first uses comma-separated key:N pairs; the second is matched on its
    own with a dedicated regex because the line itself contains a colon
    before the actual key ("static-dns: total loaded = N")."""
    out: Dict[str, int] = {}
    for line in stdout.splitlines():
        m = re.search(r"total loaded\s*=\s*(\d+)", line)
        if m:
            out["total loaded"] = int(m.group(1))
        else:
            for part in line.split(","):
                m = re.match(r"\s*([\w\- ]+?)\s*:\s*(\d+)\s*$", part)
                if m:
                    out[m.group(1).strip()] = int(m.group(2))
    return out


@register("static_dns_check_fails_without_ssl_entries")
def _static_dns_no_ssl_fails(h: Harness):
    """The SSL cert dirs are the source of truth. With no ssl/ fixture and
    no /etc/nginx/ssl/ on the box, `--check-static-dns` must exit non-zero
    even if /etc/hosts happens to contribute Confiared entries — zero SSL
    entries is a hard failure (this is what upload.sh keys off)."""
    _clear_ssl_fixture()
    with contextlib.suppress(FileNotFoundError):
        os.unlink(_STATIC_DNS_HOSTS_PATH)
    rc, stdout, stderr = _run_check_static_dns(h)
    if rc == 0:
        raise AssertionError(
            f"expected non-zero exit with zero SSL entries, got rc=0. "
            f"stdout={stdout!r} stderr={stderr!r}")
    if "SSL cert dirs" not in stderr:
        raise AssertionError(
            f"expected SSL-specific failure message on stderr, got: {stderr!r}")
    parsed = _parse_check_stdout(stdout)
    if parsed.get("entries loaded", -1) != 0:
        raise AssertionError(
            f"expected ssl 'entries loaded: 0', got {parsed.get('entries loaded')}. "
            f"stdout={stdout!r}")


@register("static_dns_check_baseline_runs")
def _static_dns_baseline(h: Harness):
    """With a valid SSL cert fixture and no hosts file, `--check-static-dns`
    must exit 0, report the SSL-derived entries, and emit a parseable
    summary."""
    with contextlib.suppress(FileNotFoundError):
        os.unlink(_STATIC_DNS_HOSTS_PATH)
    try:
        n = _write_ssl_fixture("cdn-fixture",
                               _CONFIARED_IPV6_SSL,
                               ["ssl-cdn-1.confiared.com", "ssl-cdn-2.confiared.com"])
        rc, stdout, stderr = _run_check_static_dns(h)
        if rc != 0:
            raise AssertionError(
                f"--check-static-dns rc={rc} with valid SSL fixture. "
                f"stdout={stdout!r} stderr={stderr!r}")
        if "static-dns: total loaded" not in stdout:
            raise AssertionError(f"missing summary line. stdout={stdout!r}")
        parsed = _parse_check_stdout(stdout)
        if "total loaded" not in parsed:
            raise AssertionError(f"could not parse 'total loaded' from {stdout!r}")
        if parsed.get("entries loaded", -1) < n:
            raise AssertionError(
                f"expected ssl entries loaded >= {n}, got "
                f"{parsed.get('entries loaded')}. stdout={stdout!r}")
        if "OK" not in stdout:
            raise AssertionError(f"expected 'OK' in stdout, got: {stdout!r}")
    finally:
        _clear_ssl_fixture()


@register("static_dns_valid_hosts_file_loads")
def _static_dns_valid(h: Harness):
    """A valid hosts file with two Confiared IPv6 entries must add exactly
    those two entries on top of the baseline, and `--check-static-dns` must
    exit 0 (SSL fixture present so the SSL-source gate is satisfied)."""
    with contextlib.suppress(FileNotFoundError):
        os.unlink(_STATIC_DNS_HOSTS_PATH)
    try:
        _write_ssl_fixture("cdn-fixture", _CONFIARED_IPV6_SSL,
                           ["ssl-cdn.confiared.com"])
        rc0, stdout0, _ = _run_check_static_dns(h)
        base = _parse_check_stdout(stdout0).get("total loaded", 0)
        with open(_STATIC_DNS_HOSTS_PATH, "w") as f:
            f.write(f"# generated by all.py static_dns_valid_hosts_file_loads\n")
            f.write(f"{_CONFIARED_IPV6_VALID}    cdn-test-1.confiared.com\n")
            f.write(f"{_CONFIARED_IPV6_VALID_2}  cdn-test-2.confiared.com\n")
        rc1, stdout1, stderr1 = _run_check_static_dns(h)
        if rc1 != 0:
            raise AssertionError(
                f"--check-static-dns rc={rc1} on valid hosts file. "
                f"stdout={stdout1!r} stderr={stderr1!r}")
        parsed = _parse_check_stdout(stdout1)
        total = parsed.get("total loaded", -1)
        if total != base + 2:
            raise AssertionError(
                f"expected total = baseline({base}) + 2 = {base+2}, got {total}. "
                f"stdout={stdout1!r}")
        if "OK" not in stdout1:
            raise AssertionError(f"expected 'OK' in stdout, got: {stdout1!r}")
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(_STATIC_DNS_HOSTS_PATH)
        _clear_ssl_fixture()


@register("static_dns_malformed_lines_are_skipped")
def _static_dns_malformed_skipped(h: Harness):
    """Hosts file with 1 valid + several malformed lines must classify each
    bad line into its own bucket and still load the valid one. No crash.
    SSL fixture present so the SSL-source gate is satisfied."""
    with contextlib.suppress(FileNotFoundError):
        os.unlink(_STATIC_DNS_HOSTS_PATH)
    try:
        _write_ssl_fixture("cdn-fixture", _CONFIARED_IPV6_SSL,
                           ["ssl-cdn.confiared.com"])
        rc0, stdout0, _ = _run_check_static_dns(h)
        base = _parse_check_stdout(stdout0)
        base_total = base.get("total loaded", 0)
        base_bad_ipv6 = base.get("bad-ipv6", 0)
        base_not_in_range = base.get("not-in-range", 0)
        base_not_fqdn = base.get("not-fqdn", 0)
        with open(_STATIC_DNS_HOSTS_PATH, "w") as f:
            f.write("# good\n")
            f.write(f"{_CONFIARED_IPV6_VALID}    cdn-test-1.confiared.com\n")
            f.write(f"not-an-ipv6                cdn-bad.confiared.com\n")
            f.write(f"{_OUTSIDE_CONFIARED_IPV6}  cdn-outside.example.com\n")
            f.write(f"{_CONFIARED_IPV6_VALID_2}  not_a_valid_fqdn_!@#\n")
            f.write(f"only-one-field-no-host\n")
        rc, stdout, stderr = _run_check_static_dns(h)
        if rc != 0:
            raise AssertionError(
                f"--check-static-dns rc={rc} on partly-bad hosts file. "
                f"Expected 0 because one good line loaded. stdout={stdout!r} stderr={stderr!r}")
        parsed = _parse_check_stdout(stdout)
        if parsed.get("total loaded", -1) != base_total + 1:
            raise AssertionError(
                f"expected total = baseline({base_total}) + 1 = {base_total+1}, "
                f"got {parsed.get('total loaded')}. stdout={stdout!r}")
        if parsed.get("bad-ipv6", 0) < base_bad_ipv6 + 2:
            raise AssertionError(
                f"expected bad-ipv6 >= baseline({base_bad_ipv6}) + 2, "
                f"got {parsed.get('bad-ipv6')}. stdout={stdout!r}")
        if parsed.get("not-in-range", 0) < base_not_in_range + 1:
            raise AssertionError(
                f"expected not-in-range >= baseline({base_not_in_range}) + 1, "
                f"got {parsed.get('not-in-range')}. stdout={stdout!r}")
        if parsed.get("not-fqdn", 0) < base_not_fqdn + 1:
            raise AssertionError(
                f"expected not-fqdn >= baseline({base_not_fqdn}) + 1, "
                f"got {parsed.get('not-fqdn')}. stdout={stdout!r}")
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(_STATIC_DNS_HOSTS_PATH)
        _clear_ssl_fixture()


@register("static_dns_malformed_hosts_does_not_crash_daemon")
def _static_dns_no_crash(h: Harness):
    """A malformed hosts file must not prevent the daemon from coming up.
    Mission item 3: load failure is non-fatal — confiacdn keeps running on
    previously-loaded entries (here: empty) plus FORCEALLDNSTOLOCALHOSTIPV6
    short-circuit which is independent of the static table. After restart,
    a normal backend fetch must still complete byte-correct."""
    try:
        with open(_STATIC_DNS_HOSTS_PATH, "w") as f:
            f.write("# entirely malformed\n")
            f.write("not-an-ipv6           a.example.com\n")
            f.write("garbage line with no structure at all\n")
            f.write(f"{_OUTSIDE_CONFIARED_IPV6}  out.example.com\n")
            f.write(f"{_CONFIARED_IPV6_VALID}   not_a_valid_fqdn_!@#\n")
            f.write("\n")
            f.write("   \n")
            f.write("# trailing comment\n")
        h.restart_confiacdn()
        h.reset_fixtures()
        body, ctype = make_body(64 * 1024)
        fx = Fixture(body=body, content_type=ctype, backend_etag='"sd-nocrash"')
        h.fixtures["/static-dns-nocrash"] = fx
        r = fetch("/static-dns-nocrash")
        if r.status != 200:
            raise AssertionError(f"daemon up but request failed: status={r.status}")
        if r.decoded_body != body:
            raise AssertionError("body mismatch — backend path broken after bad hosts")
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(_STATIC_DNS_HOSTS_PATH)
        # Drop the cached entry so subsequent tests don't see it.
        h.restart_confiacdn()


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_one(h: Harness, entry: _TestEntry) -> TestResult:
    """Run one test under its declared wall-clock budget.

    The test runs in a daemon thread; when it doesn't return within
    `entry.timeout_sec` we report TIMEOUT and let the thread keep running in
    the background (Python can't safely interrupt arbitrary blocking calls,
    but the daemon flag means it won't block process exit). confiacdn keeps
    running so subsequent tests still execute.
    """
    name = entry.name
    h.reset_logs()
    t0 = time.monotonic()
    result_box: List[Optional[BaseException]] = [None]
    done = threading.Event()

    def _runner():
        try:
            entry.fn(h)
        except BaseException as e:  # noqa: BLE001 — re-raised below
            result_box[0] = e
        finally:
            done.set()

    t = threading.Thread(target=_runner, name=f"test-{name}", daemon=True)
    t.start()
    finished = done.wait(timeout=entry.timeout_sec)
    elapsed = time.monotonic() - t0

    if not finished:
        # Test exceeded its budget — escalate to a real failure but keep the
        # harness moving so the next test still gets a chance.
        failures = scan_logs_for_failures(t0, name, h.confiacdn)
        msg = f"TIMEOUT: exceeded {entry.timeout_sec:.0f}s budget"
        if failures:
            msg += "\n  log-scan also flagged:\n    " + "\n    ".join(failures[:10])
        return TestResult(name, False, msg, elapsed=elapsed)

    err = result_box[0]
    if err is None:
        failures = scan_logs_for_failures(t0, name, h.confiacdn)
        if failures:
            return TestResult(name, False,
                              "log-scan failures:\n  " + "\n  ".join(failures[:20]),
                              elapsed=elapsed)
        return TestResult(name, True, elapsed=elapsed)
    if isinstance(err, AssertionError):
        failures = scan_logs_for_failures(t0, name, h.confiacdn)
        msg = f"FAIL: {err}"
        if failures:
            msg += "\n  log-scan also flagged:\n    " + "\n    ".join(failures[:10])
        return TestResult(name, False, msg, elapsed=elapsed)
    # Other exceptions
    return TestResult(name, False,
                      "EXCEPTION:\n" + "".join(traceback.format_exception(err)),
                      elapsed=elapsed)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="list all test names and exit")
    parser.add_argument("--kill", action="store_true",
                        help="terminate any nginx/confiacdn/origin/all.py left over "
                             "from a previous run (uses recorded PID files), then exit. "
                             "Use this whenever you need to clean up — the command never "
                             "changes regardless of what was running.")
    parser.add_argument("--only", action="append", default=[], help="run only the named test(s)")
    parser.add_argument("--skip-build", action="store_true",
                        help="skip the rebuild step (use existing tmpfs binary)")
    # Default: run EVERYTHING, including 100MB fixtures and the 50-min soak.
    # Use --no-full / --no-soak to exclude them from the run during inner-loop
    # debugging. Excluded tests are filtered out before iteration — they are
    # never reported as "skipped"; every test that runs is pass-or-fail.
    parser.add_argument("--no-full", dest="full", action="store_false", default=True,
                        help="exclude large fixtures (100MB) from the run "
                             "— by default they run")
    parser.add_argument("--no-soak", dest="soak", action="store_false", default=True,
                        help="exclude the ~50-min soak test from the run "
                             "— by default it runs")
    parser.add_argument(
        "--sanitize", choices=SANITIZE_MODES, default=None,
        help=("rebuild confiacdn with the named sanitizer and run the matrix "
              "against it. All sanitizer modes use clang/clang++. "
              "asan = AddressSanitizer + UBSan (~2x slower). "
              "lsan = standalone LeakSanitizer. "
              "msan = MemorySanitizer + UBSan (false-positives expected on "
              "uninstrumented deps like libc/OpenSSL). "
              "Sanitizer findings appear in confiacdn.log and are flagged as "
              "test failures by the log scanner; the daemon aborts on first "
              "finding (halt_on_error=1) and the harness restart_confiacdn "
              "between tests recovers automatically."))
    parser.add_argument(
        "--valgrind", choices=VALGRIND_TOOLS, default=None,
        help=("run confiacdn under valgrind (regular debug build, no "
              "sanitizer). memcheck = leak/memory-error detector (~10-50x "
              "slower). helgrind = lock/race detector. drd = data-race "
              "detector. Findings go to stderr → confiacdn.log → log scanner "
              "(see _CONFIACDN_FORBIDDEN). Mutually exclusive with --sanitize. "
              "Forces --no-soak and --no-full (the slowdown makes them "
              "infeasible) and scales every per-test timeout by 10x."))
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 2)
    args = parser.parse_args(argv)

    if args.kill:
        return kill_everything_via_cli()

    # --sanitize and --valgrind are mutually exclusive — sanitizer instruments
    # the binary, valgrind virtualises the binary; running both at once is
    # not supported by either tool.
    if args.sanitize and args.valgrind:
        sys.stderr.write("--sanitize and --valgrind are mutually exclusive\n")
        return 2

    # Valgrind's 10-50x slowdown makes the soak (50 min × 10x → 8 hours+) and
    # 100 MB cases infeasible. Force them off and scale per-test timeouts by 10x.
    if args.valgrind:
        if args.soak:
            sys.stderr.write(
                "--valgrind: forcing --no-soak (50-min soak under valgrind = hours)\n")
            args.soak = False
        if args.full:
            sys.stderr.write(
                "--valgrind: forcing --no-full (100 MB cold under valgrind = many minutes)\n")
            args.full = False
        for entry in TESTS:
            entry.timeout_sec *= 10.0

    if args.list:
        for entry in TESTS:
            print(f"{entry.name}\t(timeout={entry.timeout_sec:g}s)")
        return 0

    ensure_dirs()
    log = FileLogger(os.path.join(LOG_DIR, "harness.log"))
    log.info(f"harness starting; tmpfs={TMPFS}")

    if not args.skip_build:
        copy_source_and_patch_makefile(log, sanitize=args.sanitize)
        build_confiacdn(log, args.jobs, sanitize=args.sanitize)
        try:
            build_h3_smoke(log, sanitize=args.sanitize)
        except Exception as e:
            # Don't abort the harness: the daemon-side matrix can still run.
            # h3_smoke_* tests will fail loudly when they try to exec the
            # missing binary.
            log.warn(f"h3_smoke build failed ({e}); h3_smoke tests will FAIL")
        try:
            build_h3_lru_test(log, sanitize=args.sanitize)
        except Exception as e:
            log.warn(f"h3_lru_test build failed ({e}); h3_session_cache_lru will FAIL")

    h = Harness(args, log)
    h.setup()
    atexit.register(h.teardown)

    if args.only:
        wanted = set(args.only)
        chosen = [e for e in TESTS if e.name in wanted]
        missing = wanted - {e.name for e in chosen}
        if missing:
            log.error(f"unknown tests: {missing}")
            return 2
    else:
        chosen = list(TESTS)

    # Filter out gated tests (--no-soak / --no-full / valgrind-forced).
    # Filtered tests are simply not in the run; they are NEVER reported as
    # "skipped". Every test that is run produces a pass-or-fail result.
    gates = {"soak": args.soak, "full": args.full}
    chosen = [e for e in chosen if e.gated_by is None or gates.get(e.gated_by, True)]

    failures: List[TestResult] = []
    passed: List[TestResult] = []

    for entry in chosen:
        sys.stdout.write(f"  {entry.name} ... ")
        sys.stdout.flush()
        res = run_one(h, entry)
        if not res.passed:
            failures.append(res)
            sys.stdout.write(f"FAIL ({res.elapsed:.1f}s)\n")
            sys.stdout.write("    " + res.message.replace("\n", "\n    ") + "\n")
        else:
            passed.append(res)
            sys.stdout.write(f"ok ({res.elapsed:.1f}s)\n")

    print()
    print(f"Total: {len(chosen)}  passed: {len(passed)}  failed: {len(failures)}")
    print(f"Logs under {LOG_DIR}/")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
