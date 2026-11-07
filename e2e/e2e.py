#!/usr/bin/env python3
"""Forward-mode end-to-end test with ONE implementation on both nodes.

usage: python3 e2e.py [auto,ws,http-sse]      (default: all three)
env:   IMPL=rs (default), BIN_RS, CFG_DIR, LOG_DIR

Topology (configs/pair): echo DB on 127.0.0.1:3306 <- egress peer-b
(http 127.0.0.1:18080, admin 18090) <- ingress peer-a (listener 13306,
admin 18083). Checks byte-exact delivery of 1 B, 3 MiB, 20 000 x 1 B writes,
20 concurrent 250 kB sessions, 30 MiB, and that /metrics answers.
Exit status 0 only when every check passed.
"""
import os
import shutil
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import CFG_DIR, Results, concurrent, roundtrip, start, start_echo, stop, wait_port  # noqa: E402

IMPL = os.environ.get("IMPL", "rs")
protos = (sys.argv[1] if len(sys.argv) > 1 else "auto,ws,http-sse").split(",")
work = tempfile.mkdtemp(prefix="dbb-e2e-")
shutil.copytree(os.path.join(CFG_DIR, "pair"), work, dirs_exist_ok=True)
start_echo(3306)
R = Results()
for proto in protos:
    a = os.path.join(work, f"a-{proto}.yaml")
    with open(os.path.join(work, "peer-a.yaml")) as f:
        text = f.read().replace("protocol: auto", f"protocol: {proto}")
    with open(a, "w") as f:
        f.write(text)
    tag = f"{IMPL}->{IMPL} {proto}"
    pb = start(IMPL, os.path.join(work, "peer-b.yaml"), f"e2e-b-{proto}")
    wait_port(18080)
    pa = start(IMPL, a, f"e2e-a-{proto}")
    wait_port(13306)
    time.sleep(0.5)
    try:
        R.run(tag, "1B", lambda: roundtrip(b"x"))
        R.run(tag, "3MiB", lambda: roundtrip(os.urandom(3 << 20)))
        R.run(tag, "20k-x-1B", lambda: roundtrip(os.urandom(20000), chunk=1))
        R.run(tag, "20conc", lambda: concurrent(20, 250000, 13306), expect=(20, []))
        R.run(tag, "30MiB", lambda: roundtrip(os.urandom(30 << 20), timeout=120))
        R.run(tag, "metrics", lambda: b"dbb_" in urllib.request.urlopen("http://127.0.0.1:18083/metrics", timeout=3).read())
    finally:
        stop(pa, pb)
sys.exit(R.exit_code())
