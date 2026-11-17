# LAJC brokered-evidence evaluation summary

- Verification time (tau): 2026-07-23T12:00:00Z
- Substrate: external evidence-package signer/verifier runtime, resolved via $EATF_ROOT (path not recorded, for blind-review safety) (eatf-sign 0.1.3); verifier mode strictly `--offline-only`.
- Signature families: rsa-sha256 (deviation: plan asked for two families; run uses two independent keys in one family).
- V-MR conformance: 15/15 cases pass the verdict+reason contract.

## Discrimination

| Verifier | True accepts | FA rate on negatives | False rejects |
|---|---|---|---|
| V-MR (rp-a) | 5/5 | 0/10 (-) | - |
| B3 single-root policy-bound | 3/5 | 0/10 (-) | P2, P3 |
| B1 one-registry | 3/5 | 8/10 (N2, N3, N4, N5, N6, N7, N8, N9) | P2, P3 |
| B2 signature-only | 5/5 | 9/10 (N2, N3, N4, N5, N6, N7, N8, N9, N10) | - |

## Offline verifiability

- V-MR: 15/15 adjudicated offline; B2: 15/15; B1 resolves offline only 12/15.

## Federation coverage (accepted issuer combos, no code change)

- V-MR: 3 — ['identity-root-a+action-root-a', 'identity-root-a+action-root-b', 'identity-root-b+action-root-b']
- B1:   1 — ['identity-root-a+action-root-a']

## Broker transparency (P4 vs P5)

- routing recoverable from receipts: True
- P4: {"broker_id": "broker-eu-1", "broker_selected_identity_issuer": "identity-root-a", "broker_selected_action_issuer": "action-root-a", "broker_assurance": "high"}
- P5: {"broker_id": "broker-eu-2", "broker_selected_identity_issuer": "identity-root-a", "broker_selected_action_issuer": "action-root-a", "broker_assurance": "high"}

## Policy portability (rp-a vs rp-b)

- divergent cases: ['P1', 'P3', 'P4', 'P5', 'N7']
- all divergence explained by policy reason codes: True

## Per-case verdicts

| Case | Class | Expected | V-MR(rp-a) | pass | B3 | B1 | B2 | V-MR(rp-b) |
|---|---|---|---|---|---|---|---|---|
| P1 | positive | accept | accept (-) | yes | accept | accept | accept | reject |
| P2 | positive | accept | accept (-) | yes | reject | reject | accept | accept |
| P3 | positive | accept | accept (-) | yes | reject | reject | accept | reject |
| P4 | positive | accept | accept (-) | yes | accept | accept | accept | reject |
| P5 | positive | accept | accept (-) | yes | accept | accept | accept | reject |
| N1 | negative | reject | reject (action-receipt-missing, canonical.bin does not match a supported canonical form., eatf-package-invalid) | yes | reject | reject | reject | reject |
| N2 | negative | reject | reject (identity-expired) | yes | reject | accept | accept | reject |
| N3 | negative | reject | reject (identity-hash-missing) | yes | reject | accept | accept | reject |
| N4 | negative | reject | reject (archive-material-insufficient) | yes | reject | accept | accept | reject |
| N5 | negative | reject | reject (scope-mismatch) | yes | reject | accept | accept | reject |
| N6 | negative | reject | reject (broker-policy-violation) | yes | reject | accept | accept | reject |
| N7 | negative | indeterminate | indeterminate (algorithm-unaccepted) | yes | indeterminate | accept | accept | reject |
| N8 | negative | reject | reject (issuer-key-mismatch) | yes | reject | accept | accept | reject |
| N9 | negative | reject | reject (action-receipt-missing) | yes | reject | accept | accept | reject |
| N10 | negative | reject | reject (scope-mismatch) | yes | reject | reject | accept | reject |

## Federation isolation (V-MR vs B3 — identical policy, different root breadth)

- V-MR and B3 disagree on 2 case(s): ['P2', 'P3']
- Because B3 runs the same policy overlay, these disagreements isolate root count from policy depth.

Claim boundary: research corpus with dev/test keys; not a legal trust service;
timestamp material reused from a bundled fixture, so RFC 3161 imprint binding
is NOT exercised by this corpus (recorded limitation).
