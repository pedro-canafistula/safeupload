#!/usr/bin/env python3
"""T8 native-parity verdict: per-case result, deltas and the driver refusals (deny ring) inside each case's protected window.

Usage: parity-verdict.py <evidence dir with parity/*.json and deny-ring.txt> [--allow allow.json] [--json out.json]

The control folder never reaches the driver, so every deny-ring entry inside a protected window is a refusal the control did not
get. It is accepted only if the allow list names it with a reason (the allow list is reviewed text, not a threshold).
Exit 0 only when every case is PASS and no unexplained refusal remains.
"""
import argparse
import datetime as dt
import json
import pathlib
import re
import sys


def parse_time(text):
    text = re.sub(r"(\.\d{6})\d+", r"\1", text.rstrip("Z"))
    return dt.datetime.fromisoformat(text)


def load_ring(path):
    rows = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip().lstrip("OUT ").strip() if line.startswith("OUT") else line.strip()
        if line.startswith("{"):
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows


def allowed(entry, allow):
    name = entry.get("name") or ""
    for rule in allow:
        if rule.get("major") not in (None, entry.get("major")):
            continue
        if rule.get("status") not in (None, entry.get("statusName")):
            continue
        if rule.get("code") not in (None, entry.get("access")):
            continue
        if rule.get("reason") not in (None, entry.get("reason")):
            continue
        if rule.get("nameRegex") and not re.search(rule["nameRegex"], name, re.IGNORECASE):
            continue
        return rule
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("evidence")
    ap.add_argument("--allow")
    ap.add_argument("--json")
    ap.add_argument("--slack", type=float, default=3.0, help="seconds added after a protected window for asynchronous publication")
    args = ap.parse_args()
    ev = pathlib.Path(args.evidence)
    allow = json.loads(pathlib.Path(args.allow).read_text()) if args.allow else []
    ring = load_ring(ev / "deny-ring.txt")
    cases = []
    for path in sorted((ev / "parity").glob("*.json")):
        if path.name.startswith("summary"):
            continue
        cases.append(json.loads(path.read_text(encoding="utf-8-sig")))
    summary = {}
    for sp in sorted((ev / "parity").glob("summary*.json")):
        raw = json.loads(sp.read_text(encoding="utf-8-sig"))
        for row in (raw if isinstance(raw, list) else [raw]):
            summary[row["case"]] = row
    out = []
    bad = 0
    for c in cases:
        p = c["protected"]
        start = parse_time(p["startUtc"])
        end = parse_time(p["endUtc"]) + dt.timedelta(seconds=p["settle"]["seconds"] + args.slack)
        per_case = ev / f"ring-{c['case']}.ndjson"
        if per_case.is_file():
            inside = load_ring(per_case)          # the launcher read the ring right after this case
        else:
            inside = [e for e in ring if start <= parse_time(e["timeUtc"]) <= end]
        unexplained = [e for e in inside if allowed(e, allow) is None]
        verdict = c["verdict"]
        if verdict != "PASS" or unexplained:
            bad += 1
        out.append({"case": c["case"], "verdict": verdict, "deltas": c["deltas"], "refusals": len(inside), "unexplained": unexplained,
                    "settleControl": c["control"]["settle"]["seconds"], "settleProtected": p["settle"]["seconds"]})
    for name, row in summary.items():
        if name not in {o["case"] for o in out}:
            out.append({"case": name, "verdict": row["verdict"], "deltas": row.get("deltas", []), "refusals": 0, "unexplained": [],
                        "settleControl": None, "settleProtected": None})
            bad += 1
    for o in sorted(out, key=lambda x: x["case"]):
        print(f"{o['verdict']:8} {o['case']:22} deltas={len(o['deltas']):2} refusals={o['refusals']:3} unexplained={len(o['unexplained']):3}"
              f" settle c/p={o['settleControl']}/{o['settleProtected']}")
        for d in o["deltas"][:8]:
            print("           -", d[:230])
        groups = {}
        for e in o["unexplained"]:
            key = (e["major"], e["statusName"], e.get("access"), e.get("reason"), re.sub(r"[A-Za-z0-9_.~$ -]+$", "*", e.get("name") or ""))
            groups[key] = groups.get(key, 0) + 1
        for key, n in sorted(groups.items(), key=lambda kv: -kv[1])[:6]:
            print(f"           ! {n}x {key[0]} {key[1]} code/access={key[2]} reason={key[3]} {key[4]}")
    print(f"PARITY cases={len(out)} not-clean={bad}")
    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(out, indent=1))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
