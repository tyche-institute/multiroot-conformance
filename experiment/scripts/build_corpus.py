#!/usr/bin/env python3
"""Build the LAJC brokered-evidence conformance corpus (manuscript Section 8.2).

Provenance: generator logic adapted 2026-07-23 from a related prior-work corpus
builder. Differences for this paper:

  * per-issuer keypairs — issuer pair a signs with the bundled EATF dev key,
    issuer pair b signs with a locally generated second dev keypair, so the
    corpus spans two independent signing keys (ONE signature family, RSA-SHA256;
    the plan's "two signature families" is a recorded deviation, see README);
  * negative family 1 (tampered payload): after signing, the action package's
    payload entry is byte-flipped INSIDE the .aep so cryptographic verification
    must fail;
  * identity fixtures carry validity windows for the identity-expired family.

EATF runtime resolution order: $EATF_ROOT, then the sibling artifact's vendored
snapshot. The runtime is NOT copied into this package (70 MB); its identity is
recorded in the corpus index and the run log.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any

EXPERIMENT_ROOT = Path(__file__).resolve().parents[1]


def resolve_eatf_root() -> Path:
    """Resolve the signer/verifier runtime from $EATF_ROOT or a local vendor/ dir.

    No absolute author-specific path is hardcoded here: such a path would leak
    the author's home directory and a sibling paper's slug into a blind-review
    artifact if this script were ever shipped to reviewers.
    """
    candidates = []
    if os.environ.get("EATF_ROOT"):
        candidates.append(Path(os.environ["EATF_ROOT"]))
    candidates.append(EXPERIMENT_ROOT / "vendor/eatf")
    for candidate in candidates:
        if (candidate / "cli/eatf-sign/bin/eatf-sign.js").exists() and (
            candidate / "cli/eatf-verify/bin/eatf-verify.js"
        ).exists():
            return candidate
    raise SystemExit(
        "Evidence-package runtime not found. Set EATF_ROOT to the runtime root, "
        f"or place it at {EXPERIMENT_ROOT / 'vendor/eatf'}."
    )


EATF_ROOT = resolve_eatf_root()
EATF_SIGN = EATF_ROOT / "cli/eatf-sign/bin/eatf-sign.js"
KEY_A = EATF_ROOT / "test-vectors/keys/dev-rsa-4096.key"
PUB_A = EATF_ROOT / "test-vectors/keys/dev-rsa-4096.pem"
KEY_B = EXPERIMENT_ROOT / "keys/dev-rsa-b.key"
PUB_B = EXPERIMENT_ROOT / "keys/dev-rsa-b.pem"
TIMESTAMP_SPEC = (
    EATF_ROOT / "test-vectors/valid/valid-overt-profile/package.aep"
).as_posix() + ":timestamp.tsr"


def ensure_key_b() -> None:
    if KEY_B.exists() and PUB_B.exists():
        return
    KEY_B.parent.mkdir(parents=True, exist_ok=True)
    stem = str(KEY_B)[: -len(".key")]
    subprocess.run(
        ["node", str(EATF_SIGN), "--gen-rsa", stem],
        check=True, capture_output=True, text=True,
    )
    if not KEY_B.exists() or not PUB_B.exists():
        raise SystemExit("second dev keypair generation failed")


def keypair_for(item: dict[str, Any]) -> tuple[Path, Path]:
    """Signing keypair. `sign_key` overrides `key` so a fixture can claim one
    issuer while actually being signed under another root's key (the
    key-substitution negative control)."""
    which = item.get("sign_key", item.get("key", "a"))
    return (KEY_A, PUB_A) if which == "a" else (KEY_B, PUB_B)


def embedded_fingerprint(aep: Path) -> str:
    import zipfile
    with zipfile.ZipFile(aep) as z:
        return hashlib.sha256(z.read("public_key.pem")).hexdigest()


def build_metadata(
    case: dict[str, Any], role: str, item: dict[str, Any], identity: dict[str, Any] | None
) -> dict[str, Any]:
    created_at = item.get("issued_at", "2026-07-20T09:00:00Z")
    metadata: dict[str, Any] = {
        "schema": "urn:eatf:spec:aep:metadata:1.0",
        "attestation_id": f"{case['case_id']}-{item['id']}",
        "created_at": created_at,
        "agent_id": f"urn:eatf:agent:{item.get('subject', item['id'])}",
        "action_type": "identity.assert" if role == "identity" else "agent.action",
        "policy_id": "rp-a-offline-multiroot-v1",
        "policy_version": "1.0",
        "policy_coverage": 1.0,
        "policy_decision": "allow",
        "format_version": "ATAP-1.0",
        "evidence_role": role,
        "case_id": case["case_id"],
    }
    if role == "identity":
        metadata.update(
            {
                "identity_issuer": item["issuer"],
                "identity_subject": item["subject"],
                "identity_method": item.get("method", "did:web"),
                "identity_assurance": item.get("assurance", "high"),
                "valid_from": item.get("valid_from", "2026-01-01T00:00:00Z"),
                "valid_to": item.get("valid_to", "2027-01-01T00:00:00Z"),
                "validation_material_embedded": True,
            }
        )
        return metadata

    identity_subject = identity["subject"] if identity else item.get("subject", "unknown")
    metadata.update(
        {
            "action_issuer": item["issuer"],
            "action_issued_at": created_at,
            "identity_attestation_id": f"{case['case_id']}-{item['identity']}",
            "identity_subject": item.get("subject", identity_subject),
            "action_scope": item["scope"],
            "sequence": item.get("sequence", 1),
            "validation_material_embedded": item.get("validation_material_embedded", True),
            "revocation_status_issued_at": item.get(
                "revocation_status_issued_at", "2026-07-20T00:00:00Z"
            ),
            "requires_live_lookup": item.get("requires_live_lookup", False),
            "algorithm_profile": item.get("algorithm_profile", "rsa-sha256-transitional"),
        }
    )
    if item.get("broker"):
        metadata.update(
            {
                "broker_id": item["broker"],
                "broker_assurance": item.get("broker_assurance", "high"),
                "broker_selected_identity_issuer": (
                    identity["issuer"] if identity else item.get("identity_issuer")
                ),
                "broker_selected_action_issuer": item["issuer"],
                "broker_authoritative_verdict": False,
            }
        )
    return {k: v for k, v in metadata.items() if v is not None}


def sign_package(
    *, case, role, item, payload, payload_dir, metadata_dir, aep_dir, identity=None
) -> dict[str, Any]:
    package_id = f"{case['case_id'].lower()}-{item['id']}"
    payload_path = payload_dir / f"{package_id}.txt"
    metadata_path = metadata_dir / f"{package_id}.json"
    aep_path = aep_dir / f"{package_id}.aep"

    payload_path.write_text(payload, encoding="utf-8")
    metadata = build_metadata(case, role, item, identity)
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    key, pub = keypair_for(item)
    subprocess.run(
        [
            "node", str(EATF_SIGN),
            "--payload", str(payload_path),
            "--key", str(key),
            "--public-key", str(pub),
            "--metadata", str(metadata_path),
            "--scope", metadata["action_scope"] if role == "action" else "identity:assertion",
            "--timestamp", TIMESTAMP_SPEC,
            "--iap", metadata.get("action_issuer") or metadata.get("identity_issuer") or "dev",
            "--out", str(aep_path),
        ],
        check=True, capture_output=True, text=True,
    )
    return {
        "role": role,
        "id": item["id"],
        "key_fingerprint": embedded_fingerprint(aep_path),
        "claimed_issuer": metadata.get("action_issuer") or metadata.get("identity_issuer"),
        "signed_under": item.get("sign_key", item.get("key", "a")),
        "intended_key": item.get("key", "a"),
        "attestation_id": metadata["attestation_id"],
        "signing_key": "a" if key == KEY_A else "b",
        "path": str(aep_path.relative_to(EXPERIMENT_ROOT)),
    }


def tamper_payload(aep_path: Path) -> str:
    """Byte-flip the payload entry inside a signed .aep (zip) package."""
    tmp = aep_path.with_suffix(".tampered.tmp")
    with zipfile.ZipFile(aep_path, "r") as zin:
        names = zin.namelist()
        payload_names = [n for n in names if "payload" in n.lower() or n.endswith(".txt")]
        target = payload_names[0] if payload_names else names[0]
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
            for name in names:
                data = zin.read(name)
                if name == target:
                    data = data[:-2] + bytes([data[-2] ^ 0xFF]) + data[-1:] if len(data) >= 2 else b"X"
                zout.writestr(name, data)
    tmp.replace(aep_path)
    return target


def main() -> int:
    ensure_key_b()
    plan = json.loads((EXPERIMENT_ROOT / "case-plan.json").read_text(encoding="utf-8"))
    generated = EXPERIMENT_ROOT / "corpus/generated"
    if generated.exists():
        shutil.rmtree(generated)
    generated.mkdir(parents=True)

    case_index: list[dict[str, Any]] = []
    tampered_entries: dict[str, str] = {}
    issuer_key_bindings: dict[str, str] = {}
    for case in plan["cases"]:
        case_dir = generated / case["case_id"]
        payload_dir, metadata_dir, aep_dir = case_dir / "payloads", case_dir / "metadata", case_dir / "aep"
        for p in (payload_dir, metadata_dir, aep_dir):
            p.mkdir(parents=True)

        identity_map = {i["id"]: i for i in case["identities"]}
        packages = []
        for identity in case["identities"]:
            packages.append(
                sign_package(
                    case=case, role="identity", item=identity,
                    payload=f"identity assertion for {identity['subject']}\n",
                    payload_dir=payload_dir, metadata_dir=metadata_dir, aep_dir=aep_dir,
                )
            )
        for action in case["actions"]:
            identity = identity_map.get(action["identity"])
            pkg = sign_package(
                case=case, role="action", item=action,
                payload=str(action["payload"]) + "\n",
                payload_dir=payload_dir, metadata_dir=metadata_dir, aep_dir=aep_dir,
                identity=identity,
            )
            if case.get("tamper_action_payload"):
                entry = tamper_payload(EXPERIMENT_ROOT / pkg["path"])
                pkg["tampered_entry"] = entry
                tampered_entries[case["case_id"]] = entry
            packages.append(pkg)

        # Trust-anchor distribution: bind each issuer name to the key it is
        # legitimately signed under. Packages that deliberately substitute a key
        # (sign_key != key) must NOT define the binding.
        for pkg in packages:
            if pkg.get("signed_under") == pkg.get("intended_key") and pkg.get("claimed_issuer"):
                issuer_key_bindings.setdefault(pkg["claimed_issuer"], pkg["key_fingerprint"])

        case_index.append(
            {
                "case_id": case["case_id"],
                "title": case["title"],
                "class": case["class"],
                "expected_verdict": case["expected_verdict"],
                "expected_reason_codes": case["expected_reason_codes"],
                "verification_time": plan["verification_time"],
                "packages": packages,
            }
        )

    sign_version = subprocess.run(
        ["node", str(EATF_SIGN), "--version"], capture_output=True, text=True
    ).stdout.strip()
    index = {
        "schema": "urn:lajc-brokered-evidence-corpus-index:1.0",
        # Blind-review safety: never record an absolute filesystem path here — it
        # leaks the author's home directory and the sibling paper's slug.
        "substrate": "external evidence-package signer/verifier runtime, resolved via $EATF_ROOT (path not recorded, for blind-review safety)",
        "eatf_sign_version": sign_version,
        "signing_keys": {
            "a": "bundled EATF dev RSA-4096 (test key)",
            "b": "locally generated dev RSA keypair keys/dev-rsa-b (test key)",
        },
        "signature_families": ["rsa-sha256"],
        "issuer_key_bindings": issuer_key_bindings,
        "issuer_key_binding_note": "Issuer name -> SHA-256 of the public key that issuer is pinned to. Stands in for a trusted list: without it an issuer name is only self-declared metadata.",
        "deviation_note": "Plan section 8.2 asks for two signature families; this run covers two independent signing keys within one family (RSA-SHA256). Recorded as a deviation.",
        "tampered_entries": tampered_entries,
        "key_note": "All keys are dev/test keys; no production trust service is involved.",
        "cases": case_index,
    }
    (generated / "corpus-index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {generated / 'corpus-index.json'} ({len(case_index)} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
