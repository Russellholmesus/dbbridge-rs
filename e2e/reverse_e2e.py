#!/usr/bin/env python3
"""Black-box reverse-mode end-to-end test.

Usage: python3 scripts/reverse_e2e.py [rs]

The database-side process has no listener: it dials the public-side HTTP
endpoint and keeps two reverse tunnels.  All addresses are allocated on
loopback for this invocation, and only the Popen children started here are
terminated during cleanup.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from common import BIN_RS, LOG_DIR, child_env  # noqa: E402

TOKEN = "reverse-e2e-token-0123456789abcdef"
GREETING = b"\x4a\x00\x00\x00\x0a8.4.0-dbbridge-test\x00"
CHILDREN: list[subprocess.Popen] = []
BACKEND: socket.socket | None = None
LOG_PATHS: dict[str, Path] = {}


def free_addr() -> str:
    """Return a currently free loopback address, without touching other PIDs."""
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", 0))
            return f"127.0.0.1:{s.getsockname()[1]}"
        finally:
            s.close()


def backend_server() -> tuple[str, bytes]:
    global BACKEND
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(128)
    BACKEND = s

    def accept_loop() -> None:
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            threading.Thread(target=backend_client, args=(c,), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    return f"127.0.0.1:{s.getsockname()[1]}", GREETING


def backend_client(c: socket.socket) -> None:
    try:
        c.sendall(GREETING)
        while True:
            data = c.recv(128 * 1024)
            if not data:
                return
            c.sendall(data)
    except OSError:
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass


def pattern(size: int, seed: int) -> bytes:
    # A deterministic byte pattern makes failures reproducible without relying
    # on the system random source.
    r = random.Random(seed)
    return bytes(r.randrange(256) for _ in range(size))


def exchange(addr: tuple[str, int], payload: bytes, greeting: bytes, check_greeting: bool = False) -> None:
    c = socket.create_connection(addr, timeout=10)
    c.settimeout(90)
    try:
        got = b""
        if check_greeting:
            while len(got) < len(greeting):
                part = c.recv(len(greeting) - len(got))
                if not part:
                    raise RuntimeError("backend closed before greeting")
                got += part
            if got != greeting:
                raise RuntimeError(f"greeting mismatch: {got!r}")

        received = bytearray()
        error: list[BaseException] = []

        def writer() -> None:
            try:
                c.sendall(payload)
                c.shutdown(socket.SHUT_WR)
            except BaseException as exc:  # propagate write failures
                error.append(exc)

        t = threading.Thread(target=writer)
        t.start()
        while len(received) < len(payload):
            part = c.recv(min(128 * 1024, len(payload) - len(received)))
            if not part:
                raise RuntimeError(f"short echo: {len(received)}/{len(payload)}")
            received.extend(part)
        t.join(30)
        if error:
            raise error[0]
        if bytes(received) != payload:
            raise RuntimeError("echo differs from request")
    finally:
        c.close()


def start(kind: str, cfg: Path, tag: str) -> subprocess.Popen:
    binary = {"rs": BIN_RS}[kind]
    if not (os.path.isfile(binary) and os.access(binary, os.X_OK)):
        raise RuntimeError(f"binary for {kind!r} not found or not executable: {binary}")
    log_path = Path(LOG_DIR) / f"reverse-e2e-{os.getpid()}-{tag}.log"
    print(f"log_{tag}={log_path}", flush=True)
    LOG_PATHS[tag] = log_path
    log = open(log_path, "w", encoding="utf-8")
    p = subprocess.Popen([binary, "run", "-c", str(cfg)], cwd=str(cfg.parent),
                         stdout=log, stderr=subprocess.STDOUT, env=child_env())
    # The file descriptor is inherited by the child; close this process's copy.
    log.close()
    CHILDREN.append(p)
    return p


def stop_children() -> None:
    for p in CHILDREN:
        if p.poll() is None:
            p.terminate()
    for p in CHILDREN:
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
    if BACKEND is not None:
        try:
            BACKEND.close()
        except OSError:
            pass


def fetch_metrics(admin: str) -> str:
    host, port = admin.rsplit(":", 1)
    conn = http.client.HTTPConnection(host, int(port), timeout=2)
    try:
        conn.request("GET", "/metrics")
        response = conn.getresponse()
        body = response.read()
        if response.status != 200:
            raise RuntimeError(f"admin metrics returned HTTP {response.status}")
        return body.decode("utf-8", errors="replace")
    finally:
        conn.close()


def wait_ready(pub: subprocess.Popen, db: subprocess.Popen, admin: str) -> None:
    deadline = time.monotonic() + 20
    last = ""
    while time.monotonic() < deadline:
        if pub.poll() is not None or db.poll() is not None:
            raise RuntimeError(f"dbbridge exited early (public={pub.returncode}, database={db.returncode})")
        metric_live = False
        try:
            metrics = fetch_metrics(admin)
            metric_live = any(
                line.startswith("dbb_reverse_hub_tunnels{")
                and 'transport="ws"' in line
                and line.rstrip().endswith(" 2")
                for line in metrics.splitlines()
            )
        except (OSError, RuntimeError) as exc:
            last = f"admin={exc!r}"
        public_log = LOG_PATHS.get("public")
        log_live = False
        if public_log is not None:
            try:
                log_live = "; 2 live" in public_log.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
        last = f"admin_two={metric_live} public_log_two={log_live}"
        if metric_live or log_live:
            return
        time.sleep(0.1)
    raise RuntimeError(f"timed out waiting for two registered reverse tunnels ({last})")


def make_configs(work: Path, http: str, admin: str, listen: str, backend: str) -> tuple[Path, Path]:
    pub = work / "pub.yaml"
    db = work / "db.yaml"
    pub_text = (work / "pub.yaml").read_text() if pub.exists() else ""
    # The copied templates use stable markers; replace only those values.
    pub_text = (pub_text.replace('127.0.0.1:28080', http)
                .replace('127.0.0.1:28083', admin)
                .replace('127.0.0.1:23306', listen))
    db_text = db.read_text()
    db_text = db_text.replace('127.0.0.1:28080', http).replace('127.0.0.1:3307', backend)
    pub.write_text(pub_text)
    db.write_text(db_text)
    return pub, db


def run(kind: str, concurrency: int, bulk_bytes: int, session_bytes: int) -> None:
    global CHILDREN, LOG_PATHS
    CHILDREN = []
    LOG_PATHS = {}
    work = Path(tempfile.mkdtemp(prefix="dbb-reverse-e2e-"))
    passed = False
    phase = "startup"
    try:
        shutil.copytree(ROOT / "e2e" / "configs" / "rev", work, dirs_exist_ok=True)
        http, admin, listen = free_addr(), free_addr(), free_addr()
        backend, greeting = backend_server()
        pub_cfg, db_cfg = make_configs(work, http, admin, listen, backend)
        # Use the same token semantics as the checked-in reverse pair while
        # making the temp copy self-contained.
        (work / "shared.token").write_text(TOKEN + "\n")
        print(f"implementation={kind} workdir={work} http={http} admin={admin} listener={listen} backend={backend}", flush=True)
        pub = start(kind, pub_cfg, "public")
        db = start(kind, db_cfg, "database")
        listen_host, listen_port = listen.rsplit(":", 1)
        addr = (listen_host, int(listen_port))
        wait_ready(pub, db, admin)
        print("PASS two reverse tunnels established; database side has no configured listener", flush=True)

        phase = "single-session greeting/transaction/bulk echo"
        c = socket.create_connection(addr, timeout=10)
        c.settimeout(90)
        got = read_full(c, len(greeting))
        if got != greeting:
            c.close()
            raise RuntimeError(f"greeting mismatch: {got!r}")
        for i, q in enumerate((b"BEGIN", b"INSERT INTO t VALUES (1)", b"SELECT * FROM t FOR UPDATE", b"COMMIT")):
            exchange_on_socket(c, bytes((len(q), 0, 0, i)) + q)
        exchange_on_socket(c, pattern(bulk_bytes, 7))
        print(f"PASS greeting, transactional request/response, and {bulk_bytes}-byte bidirectional echo", flush=True)

        phase = f"concurrent sessions ({concurrency} x {session_bytes} bytes)"
        failures: list[str] = []
        lock = threading.Lock()

        def session(i: int) -> None:
            try:
                exchange(addr, pattern(session_bytes, i), greeting, check_greeting=True)
            except Exception as exc:  # noqa: BLE001
                with lock:
                    failures.append(f"session {i}: {exc}")

        threads = [threading.Thread(target=session, args=(i,)) for i in range(concurrency)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(120)
        if failures:
            c.close()
            raise RuntimeError("; ".join(failures[:3]))
        c.close()
        print(f"PASS {concurrency} concurrent sessions with byte-for-byte echo", flush=True)
        passed = True
    except Exception as exc:
        raise RuntimeError(f"phase={phase}: {exc}") from exc
    finally:
        stop_children()
        if passed:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"kept_workdir={work}", flush=True)


def exchange_on_socket(c: socket.socket, payload: bytes) -> None:
    received = bytearray()
    error: list[BaseException] = []

    def writer() -> None:
        try:
            c.sendall(payload)
        except BaseException as exc:
            error.append(exc)

    t = threading.Thread(target=writer)
    t.start()
    while len(received) < len(payload):
        part = c.recv(min(128 * 1024, len(payload) - len(received)))
        if not part:
            raise RuntimeError(f"short echo: {len(received)}/{len(payload)}")
        received.extend(part)
    t.join(30)
    if error:
        raise error[0]
    if hashlib.sha256(received).digest() != hashlib.sha256(payload).digest():
        raise RuntimeError("echo differs from request")


def read_full(c: socket.socket, size: int) -> bytes:
    got = bytearray()
    while len(got) < size:
        part = c.recv(size - len(got))
        if not part:
            raise RuntimeError(f"short read: {len(got)}/{size}")
        got.extend(part)
    return bytes(got)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("implementation", nargs="?", choices=("rs",), default="rs")
    parser.add_argument("--concurrency", type=int, default=24)
    parser.add_argument("--bulk-bytes", type=int, default=8 << 20)
    parser.add_argument("--session-bytes", type=int, default=256 << 10)
    args = parser.parse_args()
    if args.concurrency < 1 or args.bulk_bytes < 1 or args.session_bytes < 1:
        parser.error("concurrency, bulk-bytes and session-bytes must all be positive")
    try:
        run(args.implementation, args.concurrency, args.bulk_bytes, args.session_bytes)
        print("RESULT PASS", flush=True)
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"RESULT FAIL: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
