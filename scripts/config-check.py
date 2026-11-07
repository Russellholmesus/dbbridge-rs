#!/usr/bin/env python3
"""Run `dbbridge check-config` over testdata/config-corpus.json and compare
exit status, error codes and warnings with the recorded results."""
import argparse, json, os, re, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "testdata" / "config-corpus.json"


def run(binary, case, tmp):
    if "file" in case:
        config = ROOT / case["file"]
    else:
        config = Path(tmp) / (case["name"] + ".yaml")
        config.write_text(case["content"], encoding="utf-8")
    cmd = [binary, "check-config"] + (["--offline"] if case["offline"] else []) + ["--config", str(config)]
    env = os.environ.copy()
    env.setdefault("DBB_TOKEN_TO_HQ", "configuration-check-current")
    env.setdefault("DBB_TOKEN_FROM_PLANT_CURRENT", "configuration-check-current")
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                       encoding="utf-8", errors="replace", env=env, cwd=ROOT)
    out = p.stdout.replace("\r\n", "\n")
    return {
        "exit_code": p.returncode,
        "error_codes": re.findall(r"DBB(?:[-_][A-Z0-9]+)+", out),
        "warnings": sorted(l.strip() for l in out.splitlines() if l.strip().lower().startswith("warning:")),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bin", default=os.environ.get("BIN_RS", str(ROOT / "target" / "release" / "dbbridge")))
    ap.add_argument("--update", action="store_true", help="record the current results as expected")
    args = ap.parse_args()
    doc = json.loads(CORPUS.read_text(encoding="utf-8"))
    bad = []
    with tempfile.TemporaryDirectory(prefix="dbbridge-config-check-") as tmp:
        for case in doc["cases"]:
            got = run(args.bin, case, tmp)
            if args.update:
                case.update(got)
            elif got != {k: case[k] for k in got}:
                bad.append(f"{case['name']}: want {[case[k] for k in got]} got {list(got.values())}")
    if args.update:
        CORPUS.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Config corpus: {len(doc['cases'])} cases, {len(doc['cases']) - len(bad)} matched")
    for b in bad:
        print("  " + b)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
