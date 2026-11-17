| Case | Multi-root, policy A | Multi-root, policy B | B3 | B1 | B2 | Same |
|---|---|---|---|---|---|---|
| P1 | accept | reject (action-issuer-untrusted, identity-issuer-untrusted) | accept | accept | accept | yes |
| P2 | accept | accept | reject (action-issuer-untrusted, identity-issuer-untrusted) | reject (registry-unresolvable:action-root-b,identity-root-b) | accept | yes |
| P3 | accept | reject (identity-issuer-untrusted) | reject (action-issuer-untrusted) | reject (registry-unresolvable:action-root-b) | accept | yes |
| P4 | accept | reject (action-issuer-untrusted, broker-policy-violation, identity-issuer-untrusted) | accept | accept | accept | yes |
| P5 | accept | reject (action-issuer-untrusted, broker-policy-violation, identity-issuer-untrusted) | accept | accept | accept | yes |
| N1 | reject (action-receipt-missing, canonical.bin does not match a supported canonical form., eatf-package-invalid) | reject (action-receipt-missing, canonical.bin does not match a supported canonical form., eatf-package-invalid, identity-issuer-untrusted) | reject (action-receipt-missing, canonical.bin does not match a supported canonical form., eatf-package-invalid) | reject (crypto-invalid) | reject (crypto-invalid) | yes |
| N2 | reject (identity-expired) | reject (action-issuer-untrusted, identity-expired, identity-issuer-untrusted) | reject (identity-expired) | accept | accept | yes |
| N3 | reject (identity-hash-missing) | reject (action-issuer-untrusted, identity-hash-missing, identity-issuer-untrusted) | reject (identity-hash-missing) | accept | accept | yes |
| N4 | reject (archive-material-insufficient) | reject (action-issuer-untrusted, archive-material-insufficient, identity-issuer-untrusted) | reject (archive-material-insufficient) | accept | accept | yes |
| N5 | reject (scope-mismatch) | reject (action-issuer-untrusted, identity-issuer-untrusted, scope-mismatch) | reject (scope-mismatch) | accept | accept | yes |
| N6 | reject (broker-policy-violation) | reject (action-issuer-untrusted, broker-policy-violation, identity-issuer-untrusted) | reject (broker-policy-violation) | accept | accept | yes |
| N7 | indeterminate (algorithm-unaccepted) | reject (action-issuer-untrusted, algorithm-unaccepted, identity-issuer-untrusted) | indeterminate (algorithm-unaccepted) | accept | accept | yes |
| N8 | reject (issuer-key-mismatch) | reject (action-issuer-untrusted, identity-issuer-untrusted, issuer-key-mismatch) | reject (issuer-key-mismatch) | accept | accept | yes |
| N9 | reject (action-receipt-missing) | reject (action-receipt-missing, identity-issuer-untrusted) | reject (action-receipt-missing) | accept | accept | yes |
| N10 | reject (scope-mismatch) | reject (scope-mismatch) | reject (action-issuer-untrusted, identity-issuer-untrusted, scope-mismatch) | reject (registry-unresolvable:action-root-b,identity-root-b) | accept | yes |

Verdict and reason-code pairs identical: 75 of 75 (15 cases x 5 verifier configurations).
Pass contract (vmr_pass) identical on 15 of 15 cases.
Every other field, per-case timing left out: identical (SHA-256 of the canonical JSON: July 1c08aa08dc960343…, repeat 1c08aa08dc960343…).
Timing, reported only (the repeat ran under strace): median per case July 178.3 ms, repeat 560.0 ms.
Result: NO DIFFERENCE
