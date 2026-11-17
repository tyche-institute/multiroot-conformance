#!/usr/bin/env python3
"""Run the LAJC brokered-evidence evaluation (manuscript Sections 8.3-8.4).

Four verifiers over the same corpus, all run with the offline-only flag:

  V-MR  multi-root verifier  = EATF cryptographic verification + policy overlay,
        run under TWO relying-party policies (rp-a federated, rp-b narrow) for
        the R8 policy-portability check;
  B1    "one-registry" baseline: accepts only receipts whose every issuer is
        resolvable in its single central registry (issuer pair a). Receipts
        from any other issuer are unresolvable and rejected. No policy layer.
  B2    "signature-only" baseline: accepts iff every package passes
        cryptographic verification. No trust-policy binding at all.
  B3    "single-root, POLICY-BOUND" baseline: the SAME policy overlay as V-MR
        (every check family) but committed to one issuer pair. Added so that the
        comparison isolates root count from policy-engine depth: any V-MR vs B3
        difference is attributable to federation alone. Without B3, the B1/B2
        gap conflates "is multi-root" with "has any policy layer at all".

Metrics (Section 8.3): discrimination incl. false-accept rate on negative
controls; offline verifiability; federation coverage; broker transparency
(P4 vs P5 receipt diff). A case PASSES for V-MR only when the verdict AND the
expected reason codes match (right-answer-wrong-reason counts as failure).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import zipfile
import sys
import time
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
EXPERIMENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXPERIMENT_ROOT / "src"))

from policy_overlay import PackageRecord, evaluate_case, load_policy  # noqa: E402

GENERATED = EXPERIMENT_ROOT / "corpus/generated"
RESULTS = EXPERIMENT_ROOT / "results"
B1_REGISTRY = {"identity-root-a", "action-root-a"}


def resolve_verifier() -> Path:
    """Resolve the runtime from $EATF_ROOT or a local vendor/ dir.

    Deliberately NOT read from corpus-index.json: the index must not record an
    absolute filesystem path (it would leak the author's home directory into a
    blind-review artifact).
    """
    import os
    candidates = []
    if os.environ.get("EATF_ROOT"):
        candidates.append(Path(os.environ["EATF_ROOT"]))
    candidates.append(EXPERIMENT_ROOT / "vendor/eatf")
    for root in candidates:
        verifier = root / "cli/eatf-verify/bin/eatf-verify.js"
        if verifier.exists():
            return verifier
    raise SystemExit(
        "Evidence-package verifier not found. Set EATF_ROOT to the runtime root, "
        f"or place it at {EXPERIMENT_ROOT / 'vendor/eatf'}."
    )


def verify_package(verifier: Path, package: dict[str, Any]) -> PackageRecord:
    aep_path = EXPERIMENT_ROOT / package["path"]
    start = time.perf_counter()
    proc = subprocess.run(
        ["node", str(verifier), "--json", "--offline-only", str(aep_path)],
        check=False, capture_output=True, text=True,
    )
    elapsed_ms = (time.perf_counter() - start) * 1000
    if proc.stdout.strip():
        result = json.loads(proc.stdout.splitlines()[-1])
    else:
        result = {"valid": False, "failureReason": proc.stderr.strip() or f"exit {proc.returncode}", "metadata": {}}
    return PackageRecord(
        path=str(aep_path),
        valid=bool(result.get("valid")),
        metadata=result.get("metadata") or {},
        failure_reason=result.get("failureReason"),
        size_bytes=aep_path.stat().st_size,
        verify_ms=elapsed_ms,
        key_fingerprint=key_fingerprint(aep_path),
    )


def key_fingerprint(aep_path: Path) -> str:
    """SHA-256 of the public key embedded in the package."""
    try:
        with zipfile.ZipFile(aep_path) as z:
            return hashlib.sha256(z.read("public_key.pem")).hexdigest()
    except Exception:
        return ""


def b2_signature_only(records: list[PackageRecord]) -> dict[str, Any]:
    ok = all(r.valid for r in records)
    return {"verdict": "accept" if ok else "reject",
            "reasons": [] if ok else ["crypto-invalid"]}


def b1_one_registry(records: list[PackageRecord]) -> dict[str, Any]:
    if not all(r.valid for r in records):
        return {"verdict": "reject", "reasons": ["crypto-invalid"]}
    unresolvable = []
    for r in records:
        issuer = str(r.metadata.get("identity_issuer") or r.metadata.get("action_issuer") or "")
        if issuer not in B1_REGISTRY:
            unresolvable.append(issuer)
    if unresolvable:
        return {"verdict": "reject", "reasons": ["registry-unresolvable:" + ",".join(sorted(set(unresolvable)))]}
    return {"verdict": "accept", "reasons": []}


def issuer_combo(records: list[PackageRecord]) -> str:
    ident = next((str(r.metadata.get("identity_issuer")) for r in records if r.role == "identity"), "?")
    act = next((str(r.metadata.get("action_issuer")) for r in records if r.role == "action"), "?")
    return f"{ident}+{act}"


def is_real_combo(combo: str) -> bool:
    """Federation coverage counts identity+action issuer PAIRS.

    A case with no action receipt (the missing-action-receipt control) has no
    action issuer and therefore no pair. Counting its degenerate `issuer+?`
    string would inflate a baseline's apparent federation coverage purely
    because it wrongly accepted a malformed case.
    """
    return "?" not in combo


def broker_fields(records: list[PackageRecord]) -> dict[str, Any]:
    for r in records:
        if r.role == "action" and r.metadata.get("broker_id"):
            m = r.metadata
            return {
                "broker_id": m.get("broker_id"),
                "broker_selected_identity_issuer": m.get("broker_selected_identity_issuer"),
                "broker_selected_action_issuer": m.get("broker_selected_action_issuer"),
                "broker_assurance": m.get("broker_assurance"),
            }
    return {}


def main() -> int:
    verifier = resolve_verifier()
    index = json.loads((GENERATED / "corpus-index.json").read_text(encoding="utf-8"))
    policy_a = load_policy(EXPERIMENT_ROOT / "policies/rp-a-policy.json")
    policy_b = load_policy(EXPERIMENT_ROOT / "policies/rp-b-policy.json")
    policy_b3 = load_policy(EXPERIMENT_ROOT / "policies/b3-single-root-policy.json")
    # The trust-anchor distribution: which key material each issuer name is bound
    # to. Supplied by the corpus index (the stand-in for a trusted list) so the
    # binding survives key regeneration instead of being hardcoded in policy.
    bindings = index.get("issuer_key_bindings") or {}
    for _p in (policy_a, policy_b, policy_b3):
        _p["issuer_keys"] = dict(bindings)
    RESULTS.mkdir(parents=True, exist_ok=True)

    per_case: list[dict[str, Any]] = []
    records_by_case: dict[str, list[PackageRecord]] = {}
    for case in index["cases"]:
        records = [verify_package(verifier, p) for p in case["packages"]]
        records_by_case[case["case_id"]] = records

        vmr_a = evaluate_case(case, records, policy_a)
        vmr_b = evaluate_case(case, records, policy_b)
        b3 = evaluate_case(case, records, policy_b3)
        expected_codes = sorted(case["expected_reason_codes"])
        # V-MR pass contract: verdict AND expected reason codes present (subset)
        codes_ok = all(code in vmr_a["reason_codes"] for code in expected_codes)
        if not expected_codes:
            codes_ok = vmr_a["reason_codes"] == []
        vmr_pass = (vmr_a["verdict"] == case["expected_verdict"]) and codes_ok

        per_case.append(
            {
                "case_id": case["case_id"],
                "title": case["title"],
                "class": case["class"],
                "expected_verdict": case["expected_verdict"],
                "expected_reason_codes": expected_codes,
                "vmr_rp_a": {"verdict": vmr_a["verdict"], "reason_codes": vmr_a["reason_codes"]},
                "vmr_pass": vmr_pass,
                "vmr_rp_b": {"verdict": vmr_b["verdict"], "reason_codes": vmr_b["reason_codes"]},
                "b1_one_registry": b1_one_registry(records),
                "b2_signature_only": b2_signature_only(records),
                "b3_single_root_policy_bound": {"verdict": b3["verdict"], "reason_codes": b3["reason_codes"]},
                "issuer_combo": issuer_combo(records),
                "metrics": vmr_a["metrics"],
            }
        )

    positives = [c for c in per_case if c["class"] == "positive"]
    negatives = [c for c in per_case if c["class"] == "negative"]

    def rates(name: str, verdict_of) -> dict[str, Any]:
        ta = sum(1 for c in positives if verdict_of(c) == "accept")
        tr = sum(1 for c in negatives if verdict_of(c) in ("reject", "indeterminate"))
        fa = [c["case_id"] for c in negatives if verdict_of(c) == "accept"]
        fr = [c["case_id"] for c in positives if verdict_of(c) != "accept"]
        return {
            "verifier": name,
            "true_accept": f"{ta}/{len(positives)}",
            "true_nonaccept_on_negatives": f"{tr}/{len(negatives)}",
            "false_accepts_on_negatives": fa,
            "false_accept_rate": f"{len(fa)}/{len(negatives)}",
            "false_rejects_on_positives": fr,
        }

    discrimination = [
        rates("V-MR (rp-a)", lambda c: c["vmr_rp_a"]["verdict"]),
        rates("B3 single-root policy-bound", lambda c: c["b3_single_root_policy_bound"]["verdict"]),
        rates("B1 one-registry", lambda c: c["b1_one_registry"]["verdict"]),
        rates("B2 signature-only", lambda c: c["b2_signature_only"]["verdict"]),
    ]

    # Federation isolation: V-MR vs B3 differ ONLY in trusted-issuer breadth, so
    # every disagreement between them is attributable to root count alone.
    vmr_vs_b3 = [
        {
            "case_id": c["case_id"], "class": c["class"],
            "vmr": c["vmr_rp_a"]["verdict"], "b3": c["b3_single_root_policy_bound"]["verdict"],
            "b3_reason_codes": c["b3_single_root_policy_bound"]["reason_codes"],
        }
        for c in per_case if c["vmr_rp_a"]["verdict"] != c["b3_single_root_policy_bound"]["verdict"]
    ]

    # Offline verifiability: every verdict above was produced with --offline-only
    # and no network access. For B1, receipts outside its registry are
    # unresolvable offline (rejected as such) — count adjudicated-with-resolution.
    b1_resolved = sum(
        1 for c in per_case if not any(x.startswith("registry-unresolvable") for x in c["b1_one_registry"]["reasons"])
    )
    offline = {
        "vmr": f"{len(per_case)}/{len(per_case)}",
        "b2": f"{len(per_case)}/{len(per_case)}",
        "b1_resolved_offline": f"{b1_resolved}/{len(per_case)}",
        "note": "all verifier invocations ran with --offline-only; no network endpoints were contacted",
    }

    # Federation coverage: distinct issuer combos ACCEPTED without code change.
    federation = {
        "note": "Distinct identity+action issuer pairs accepted, with no code change. Degenerate combos from cases lacking an action receipt are excluded (see is_real_combo).",
        "vmr_accepted_combos": sorted({c["issuer_combo"] for c in per_case if c["vmr_rp_a"]["verdict"] == "accept" and is_real_combo(c["issuer_combo"])}),
        "b3_accepted_combos": sorted({c["issuer_combo"] for c in per_case if c["b3_single_root_policy_bound"]["verdict"] == "accept" and is_real_combo(c["issuer_combo"])}),
        "b1_accepted_combos": sorted({c["issuer_combo"] for c in per_case if c["b1_one_registry"]["verdict"] == "accept" and is_real_combo(c["issuer_combo"])}),
    }

    # Broker transparency: P4 vs P5 — same action payload, two brokers.
    bt_p4 = broker_fields(records_by_case.get("P4", []))
    bt_p5 = broker_fields(records_by_case.get("P5", []))
    broker_transparency = {
        "P4": bt_p4,
        "P5": bt_p5,
        "routing_recoverable": bool(
            bt_p4.get("broker_id") and bt_p5.get("broker_id") and bt_p4["broker_id"] != bt_p5["broker_id"]
            and bt_p4.get("broker_selected_action_issuer") and bt_p5.get("broker_selected_action_issuer")
        ),
    }

    # R8 policy portability: verdict diffs rp-a vs rp-b, with reason codes.
    portability = [
        {
            "case_id": c["case_id"],
            "rp_a": c["vmr_rp_a"]["verdict"],
            "rp_b": c["vmr_rp_b"]["verdict"],
            "diverges": c["vmr_rp_a"]["verdict"] != c["vmr_rp_b"]["verdict"],
            "rp_b_reason_codes": c["vmr_rp_b"]["reason_codes"],
        }
        for c in per_case
    ]
    divergent = [p for p in portability if p["diverges"]]
    policy_explained = all(
        any(
            code.startswith(("identity-issuer-untrusted", "action-issuer-untrusted", "broker-policy-violation"))
            for code in p["rp_b_reason_codes"]
        )
        for p in divergent
    )

    vmr_all_pass = all(c["vmr_pass"] for c in per_case)
    evaluation = {
        "schema": "urn:lajc-brokered-evidence-evaluation:1.0",
        "verification_time": index["cases"][0]["verification_time"],
        "substrate": index.get("substrate", "external evidence-package runtime (path not recorded, for blind-review safety)"),
        "eatf_sign_version": index.get("eatf_sign_version"),
        "signature_families": index.get("signature_families"),
        "deviation_note": index.get("deviation_note"),
        "cases_total": len(per_case),
        "vmr_cases_passed": sum(1 for c in per_case if c["vmr_pass"]),
        "vmr_all_pass": vmr_all_pass,
        "discrimination": discrimination,
        "offline_verifiability": offline,
        "federation_coverage": federation,
        "federation_isolation_vmr_vs_b3": {
            "note": "V-MR and B3 share the identical policy overlay and differ only in trusted-issuer breadth; every disagreement is therefore attributable to root count alone.",
            "disagreements": vmr_vs_b3,
        },
        "broker_transparency": broker_transparency,
        "policy_portability": {
            "divergent_cases": [p["case_id"] for p in divergent],
            "all_divergence_policy_explained": policy_explained,
            "detail": portability,
        },
        "per_case": per_case,
    }
    (RESULTS / "evaluation.json").write_text(json.dumps(evaluation, indent=2) + "\n", encoding="utf-8")
    write_summary(evaluation)
    print(f"V-MR: {evaluation['vmr_cases_passed']}/{evaluation['cases_total']} cases passed (verdict+reason contract)")
    for d in discrimination:
        print(f"  {d['verifier']}: TA {d['true_accept']}, FA-rate {d['false_accept_rate']}, FR {d['false_rejects_on_positives']}")
    # relative paths only — run.log must stay free of absolute filesystem paths
    print("Wrote results/evaluation.json and results/evaluation-summary.md")
    return 0 if vmr_all_pass else 1


def write_summary(ev: dict[str, Any]) -> None:
    lines = [
        "# LAJC brokered-evidence evaluation summary",
        "",
        f"- Verification time (tau): {ev['verification_time']}",
        f"- Substrate: {ev['substrate']} ({ev['eatf_sign_version']}); verifier mode strictly `--offline-only`.",
        f"- Signature families: {', '.join(ev['signature_families'])} (deviation: plan asked for two families; run uses two independent keys in one family).",
        f"- V-MR conformance: {ev['vmr_cases_passed']}/{ev['cases_total']} cases pass the verdict+reason contract.",
        "",
        "## Discrimination",
        "",
        "| Verifier | True accepts | FA rate on negatives | False rejects |",
        "|---|---|---|---|",
    ]
    for d in ev["discrimination"]:
        lines.append(
            f"| {d['verifier']} | {d['true_accept']} | {d['false_accept_rate']}"
            f" ({', '.join(d['false_accepts_on_negatives']) or '-'}) | {', '.join(d['false_rejects_on_positives']) or '-'} |"
        )
    lines += [
        "",
        "## Offline verifiability",
        "",
        f"- V-MR: {ev['offline_verifiability']['vmr']} adjudicated offline; B2: {ev['offline_verifiability']['b2']}; B1 resolves offline only {ev['offline_verifiability']['b1_resolved_offline']}.",
        "",
        "## Federation coverage (accepted issuer combos, no code change)",
        "",
        f"- V-MR: {len(ev['federation_coverage']['vmr_accepted_combos'])} — {ev['federation_coverage']['vmr_accepted_combos']}",
        f"- B1:   {len(ev['federation_coverage']['b1_accepted_combos'])} — {ev['federation_coverage']['b1_accepted_combos']}",
        "",
        "## Broker transparency (P4 vs P5)",
        "",
        f"- routing recoverable from receipts: {ev['broker_transparency']['routing_recoverable']}",
        f"- P4: {json.dumps(ev['broker_transparency']['P4'])}",
        f"- P5: {json.dumps(ev['broker_transparency']['P5'])}",
        "",
        "## Policy portability (rp-a vs rp-b)",
        "",
        f"- divergent cases: {ev['policy_portability']['divergent_cases']}",
        f"- all divergence explained by policy reason codes: {ev['policy_portability']['all_divergence_policy_explained']}",
        "",
        "## Per-case verdicts",
        "",
        "| Case | Class | Expected | V-MR(rp-a) | pass | B3 | B1 | B2 | V-MR(rp-b) |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for c in ev["per_case"]:
        lines.append(
            "| {id} | {cls} | {exp} | {vmr} ({codes}) | {p} | {b3} | {b1} | {b2} | {vb} |".format(
                id=c["case_id"], cls=c["class"], exp=c["expected_verdict"],
                vmr=c["vmr_rp_a"]["verdict"], codes=", ".join(c["vmr_rp_a"]["reason_codes"]) or "-",
                p="yes" if c["vmr_pass"] else "NO",
                b3=c["b3_single_root_policy_bound"]["verdict"],
                b1=c["b1_one_registry"]["verdict"], b2=c["b2_signature_only"]["verdict"],
                vb=c["vmr_rp_b"]["verdict"],
            )
        )
    d = ev["federation_isolation_vmr_vs_b3"]["disagreements"]
    lines += [
        "",
        "## Federation isolation (V-MR vs B3 — identical policy, different root breadth)",
        "",
        f"- V-MR and B3 disagree on {len(d)} case(s): {[x['case_id'] for x in d]}",
        "- Because B3 runs the same policy overlay, these disagreements isolate root count from policy depth.",
    ]
    lines += [
        "",
        "Claim boundary: research corpus with dev/test keys; not a legal trust service;",
        "timestamp material reused from a bundled fixture, so RFC 3161 imprint binding",
        "is NOT exercised by this corpus (recorded limitation).",
    ]
    (RESULTS / "evaluation-summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
