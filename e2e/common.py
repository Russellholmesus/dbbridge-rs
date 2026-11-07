"""Shared helpers for the DBBridge e2e scripts.

Everything is configured through environment variables so the scripts run from
any checkout:

  BIN_RS     Rust binary   (default: <repo>/target/release/dbbridge,
                            then the x86_64 / aarch64 musl release paths)
  CFG_DIR    config root   (default: <repo>/configs)
  LOG_DIR    process logs  (default: /tmp/dbbridge-repo-logs)

The sandbox usually exports an HTTP proxy. Every connection here goes to
127.0.0.1, so proxy variables are removed from this process and from every
child process (a proxied localhost request hangs or returns 502).

Processes are tracked by PID and stopped with terminate()/kill() on exactly
those PIDs. Never use `pkill -f dbbridge`: other agents and sessions share the
machine and may run their own dbbridge processes.
"""
import os
import socket
import subprocess
import threading
import time

_PROXY_VARS = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy")
for _k in _PROXY_VARS:
    os.environ.pop(_k, None)
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost,::1"

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _first_existing(paths):
    for p in paths:
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return paths[0]


BIN_RS = os.environ.get("BIN_RS") or _first_existing([
    os.path.join(ROOT, "target", "release", "dbbridge"),
    os.path.join(ROOT, "target", "x86_64-unknown-linux-musl", "release", "dbbridge"),
    os.path.join(ROOT, "target", "aarch64-unknown-linux-musl", "release", "dbbridge"),
])
CFG_DIR = os.environ.get("CFG_DIR") or os.path.join(ROOT, "e2e", "configs")
LOG_DIR = os.environ.get("LOG_DIR") or "/tmp/dbbridge-repo-logs"
os.makedirs(LOG_DIR, exist_ok=True)

BINS = {"rs": BIN_RS}


def binary(kind):
    path = BINS[kind]
    if not os.path.isfile(path):
        raise SystemExit(f"binary for {kind!r} not found: {path} (set BIN_RS)")
    return path


def child_env():
    env = dict(os.environ)
    for k in _PROXY_VARS:
        env.pop(k, None)
    return env


# ---------------------------------------------------------------- echo backend
_echo_started = set()


def start_echo(port):
    """Loopback echo 'database' on 127.0.0.1:port (idempotent). Echoes until
    the client half-closes, then half-closes back (SHUT_WR) like a DB EOF."""
    if port in _echo_started:
        return
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
    except OSError:
        # Another script on this machine already serves the shared loopback
        # echo backend on this port; every instance has identical semantics.
        s.close()
        if wait_port(port, 1.0):
            print(f"note: reusing existing echo backend on 127.0.0.1:{port}", flush=True)
            _echo_started.add(port)
            return
        raise
    s.listen(512)

    def handle(c):
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                c.sendall(d)
            c.shutdown(socket.SHUT_WR)
        except Exception:
            pass
        finally:
            c.close()

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    _echo_started.add(port)


def roundtrip(payload, chunk=None, port=13306, timeout=60):
    """Send payload through the listener on port, half-close, read until EOF.
    Returns (ok, bytes_received)."""
    c = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    got = bytearray()

    def rd():
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                got.extend(d)
        except Exception:
            pass

    t = threading.Thread(target=rd)
    t.start()
    if chunk:
        for i in range(0, len(payload), chunk):
            c.sendall(payload[i:i + chunk])
    else:
        c.sendall(payload)
    c.shutdown(socket.SHUT_WR)
    t.join(timeout)
    c.close()
    return bytes(got) == payload, len(got)


def concurrent(n, size, port, timeout=60):
    """n parallel roundtrips of size random bytes. Returns (ok_count, first_errors)."""
    res = []

    def w():
        try:
            res.append(roundtrip(os.urandom(size), port=port, timeout=timeout)[0])
        except Exception as e:  # noqa: BLE001
            res.append(repr(e)[:80])

    th = [threading.Thread(target=w) for _ in range(n)]
    for x in th:
        x.start()
    for x in th:
        x.join(timeout + 5)
    return res.count(True), [x for x in res if x is not True][:3]


# ------------------------------------------------------------------- processes
def start(kind, cfg_path, tag, cwd=None):
    log = open(os.path.join(LOG_DIR, f"{tag}.log"), "w")
    extra = ["--log-level", os.environ["DBB_LOG_LEVEL"]] if os.environ.get("DBB_LOG_LEVEL") else []
    return subprocess.Popen([binary(kind), "run", "-c", cfg_path, *extra], stdout=log, stderr=subprocess.STDOUT,
                            cwd=cwd or os.path.dirname(cfg_path), env=child_env())


def stop(*procs):
    """Stop exactly these child processes (by PID). Never pkill."""
    for p in procs:
        if p and p.poll() is None:
            p.terminate()
    for p in procs:
        if not p:
            continue
        try:
            p.wait(timeout=50)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()


def wait_port(port, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


class Results:
    """Collects PASS/FAIL lines; exit_code() is 0 only when all passed.

    run(tag, name, fn, expect): with expect=None a check passes when fn()
    returns True or a tuple whose first item is True (roundtrip's (ok, n));
    otherwise it passes when fn() == expect."""

    def __init__(self):
        self.rows = []

    def run(self, tag, name, fn, expect=None):
        t = time.time()
        try:
            r = fn()
        except Exception as e:  # noqa: BLE001
            r = "ERR " + repr(e)[:100]
        if expect is not None:
            ok = r == expect
        else:
            ok = r is True or (isinstance(r, tuple) and len(r) > 0 and r[0] is True)
        dt = round(time.time() - t, 2)
        self.rows.append((tag, name, ok, r, dt))
        print(f"{'PASS' if ok else 'FAIL'} {tag} {name} {r} {dt}s", flush=True)
        return ok

    def exit_code(self):
        bad = [r for r in self.rows if not r[2]]
        print(f"\n{len(self.rows) - len(bad)}/{len(self.rows)} passed", flush=True)
        return 1 if bad else 0
