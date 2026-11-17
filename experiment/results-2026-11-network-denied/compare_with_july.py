#!/usr/bin/env python3
"""Compare a repeated LAJC 503 evaluation with the archived July 2026 run.

usage: python3 -I compare_with_july.py JULY/evaluation.json REPEAT/evaluation.json

Compares, case by case and verifier by verifier, the verdict and the list of
reason codes of the multi-root verifier under policy A and policy B, of B3, of
B1 and of B2, then every other field of the two files. The per-case timing
(metrics.eatf_verify_ms) is the one field expected to differ and is reported,
not compared. Exit code 0 = no difference outside that field.
"""
from __future__ import annotations

import hashlib
import json
import statistics
import sys

COLS = [
    ("vmr_rp_a", "reason_codes", "Multi-root, policy A"),
    ("vmr_rp_b", "reason_codes", "Multi-root, policy B"),
    ("b3_single_root_policy_bound", "reason_codes", "B3"),
    ("b1_one_registry", "reasons", "B1"),
    ("b2_signature_only", "reasons", "B2"),
]


def without_timing(ev: dict) -> dict:
    ev = json.loads(json.dumps(ev))
    for c in ev["per_case"]:
        c["metrics"].pop("eatf_verify_ms", None)
    return ev


def canon(ev: dict) -> bytes:
    return json.dumps(ev, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def cell(verdict: str, codes: list[str]) -> str:
    return verdict + (" (" + ", ".join(codes) + ")" if codes else "")


def main() -> int:
    july = json.load(open(sys.argv[1], encoding="utf-8"))
    rep = json.load(open(sys.argv[2], encoding="utf-8"))
    cj = {c["case_id"]: c for c in july["per_case"]}
    cr = {c["case_id"]: c for c in rep["per_case"]}
    ok = list(cj) == list(cr)
    same = total = 0
    print("| Case | " + " | ".join(name for _, _, name in COLS) + " | Same |")
    print("|---|" + "---|" * (len(COLS) + 1))
    for cid, a in cj.items():
        b = cr.get(cid)
        cells, row_ok = [], b is not None
        for key, rk, _ in COLS:
            total += 1
            va, ra = a[key]["verdict"], a[key][rk]
            if b is not None and (b[key]["verdict"], b[key][rk]) == (va, ra):
                same += 1
                cells.append(cell(va, ra))
            else:
                row_ok = False
                got = cell(b[key]["verdict"], b[key][rk]) if b is not None else "missing"
                cells.append(f"{cell(va, ra)} → {got}")
        row_ok = row_ok and a["vmr_pass"] == b["vmr_pass"]
        ok = ok and row_ok
        print(f"| {cid} | " + " | ".join(cells) + f" | {'yes' if row_ok else 'NO'} |")
    print()
    print(f"Verdict and reason-code pairs identical: {same} of {total} "
          f"({len(cj)} cases x {len(COLS)} verifier configurations).")
    print(f"Pass contract (vmr_pass) identical on {sum(1 for c in cj if cr.get(c, {}).get('vmr_pass') == cj[c]['vmr_pass'])} of {len(cj)} cases.")
    hj, hr = (hashlib.sha256(canon(without_timing(e))).hexdigest() for e in (july, rep))
    rest_ok = hj == hr
    ok = ok and rest_ok
    print("Every other field, per-case timing left out: "
          + ("identical" if rest_ok else "DIFFERENT")
          + f" (SHA-256 of the canonical JSON: July {hj[:16]}…, repeat {hr[:16]}…).")
    if not rest_ok:
        a, b = without_timing(july), without_timing(rep)
        for k in a:
            if a.get(k) != b.get(k):
                print(f"  differs: {k}")
    tj = [c["metrics"]["eatf_verify_ms"] for c in july["per_case"]]
    tr = [c["metrics"]["eatf_verify_ms"] for c in rep["per_case"]]
    print(f"Timing, reported only (the repeat ran under strace): median per case "
          f"July {statistics.median(tj):.1f} ms, repeat {statistics.median(tr):.1f} ms.")
    print("Result: " + ("NO DIFFERENCE" if ok else "DIFFERENCE FOUND"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
