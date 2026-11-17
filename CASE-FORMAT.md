# Case format

A case is one JSON object in the `cases` list of `experiment/case-plan.json`.
It names its identity assertions and action receipts, with their issuers,
subjects, scopes, and keys, together with the expected verdict and the
expected reason codes. The corpus builder, `experiment/scripts/build_corpus.py`,
turns the case into signed packages: one identity package for each entry in
`identities`, and one action package for each entry in `actions`.

The plan itself has three further fields: `schema`, `note`, and
`verification_time`, the time at which every case is verified
(2026-07-23T12:00:00Z).

## A case

| Field | Required | Meaning |
|---|---|---|
| `case_id` | yes | Short identifier, such as `N11`; also the folder name under `corpus/generated/` |
| `title` | yes | One line: what the case is; for a negative control, the failure it represents |
| `class` | yes | `positive` or `negative` |
| `expected_verdict` | yes | `accept`, `reject`, or `indeterminate` |
| `expected_reason_codes` | yes | The reason codes the verifier must return; empty for an accepted case |
| `identities` | yes | The identity assertions (a list) |
| `actions` | yes | The action receipts (a list; it may be empty, as in N9) |
| `tamper_action_payload` | no | `true`: after signing, one byte of the payload inside each action package is flipped (family 1) |

## An identity assertion

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Local name, referenced by the actions of the case |
| `issuer` | yes | The identity issuer the package names, such as `identity-root-a` |
| `subject` | yes | The agent the assertion is about |
| `key` | no | The test key pair that signs it: `a` (default) or `b` |
| `sign_key` | no | Sign under this key pair instead of the issuer's (key substitution, family 8) |
| `valid_from`, `valid_to` | no | Validity window; default 2026-01-01T00:00:00Z to 2027-01-01T00:00:00Z |
| `method` | no | Identity method; default `did:web` |
| `assurance` | no | `low`, `medium`, or `high`; default `high` |
| `issued_at` | no | Creation time; default 2026-07-20T09:00:00Z |

## An action receipt

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Local name |
| `issuer` | yes | The action issuer the package names, such as `action-root-a` |
| `identity` | yes | The `id` of the identity assertion the action rests on; an `id` that does not exist gives a broken chain pointer (family 3) |
| `scope` | yes | The action scope, such as `agent:records` |
| `payload` | yes | The text of the action record |
| `subject` | no | The acting agent; default the subject of the referenced identity |
| `key`, `sign_key` | no | As for an identity assertion |
| `broker`, `broker_assurance` | no | The broker that routed the action, and its assurance (default `high`) |
| `validation_material_embedded` | no | `false` declares that validation material is missing (family 4; declared metadata only) |
| `algorithm_profile` | no | Default `rsa-sha256-transitional` |
| `sequence` | no | Sequence number of the action for its subject; default 1 |
| `revocation_status_issued_at` | no | Time of the revocation status; default 2026-07-20T00:00:00Z |
| `requires_live_lookup` | no | `true` marks a receipt that needs an online lookup; default `false` |
| `issued_at` | no | Creation time; default 2026-07-20T09:00:00Z |

Issuer names are bound to keys in `corpus/generated/corpus-index.json`
(`issuer_key_bindings`). The builder binds each issuer name to the key of the
first correctly signed package that names it. A package whose `sign_key`
differs from its `key` creates no binding. What each policy trusts and accepts
is in `experiment/policies/`.

## Verdicts and reason codes

The overlay, `evaluate_case` in `experiment/src/policy_overlay.py`, records
each check as passed, failed, or missing. The verdict is `reject` if any check
failed, `indeterminate` if none failed and some were missing, and `accept`
otherwise. The reason codes are the codes of all checks that did not pass.

| Code | Status | When |
|---|---|---|
| `eatf-package-invalid` | fail | The runtime rejects the package; the runtime's own failure message is added as a further code |
| `receipt-set-empty` | fail | The case has no packages |
| `receipt-role-unknown` | fail | A package is neither an identity assertion nor an action receipt |
| `action-receipt-missing` | fail | The case has no valid action package |
| `identity-receipt-missing` | fail | The case has no valid identity package |
| `issuer-key-mismatch` | fail | A package names an issuer bound to another key than the one it carries |
| `issuer-key-unverifiable` | missing | A package names a bound issuer, but its key cannot be read |
| `identity-issuer-untrusted` | fail | The identity issuer is not trusted by the policy |
| `identity-method-unaccepted` | fail | The identity method is not accepted, or the identity assurance is below the policy's minimum |
| `identity-not-yet-valid` | fail | The identity assertion is valid only after the verification time |
| `identity-expired` | fail | The identity assertion expired before the verification time |
| `action-issuer-untrusted` | fail | The action issuer is not trusted by the policy at the verification time |
| `identity-hash-missing` | fail | The action refers to no valid identity package of the case |
| `identity-substitution` | fail | The action's subject differs from the subject of the identity it refers to |
| `scope-mismatch` | fail | The scope is not accepted by the policy |
| `sequence-replay` | fail | Two actions of one subject carry the same sequence number |
| `network-dependency-forbidden` | fail | The receipt needs an online lookup and the policy is offline-only |
| `network-lookup-required` | missing | The receipt needs an online lookup and the policy is not offline-only |
| `archive-material-insufficient` | fail | Validation material is declared missing and the policy requires it |
| `revocation-missing` | fail or missing | No revocation status; the policy's `revocation.missing` decides which |
| `revocation-stale` | fail or missing | The revocation status is older than the policy allows; `revocation.stale` decides which |
| `algorithm-unaccepted` | missing | The algorithm profile is not accepted |
| `broker-policy-violation` | fail | The broker is not trusted, its assurance is too low, the routing is not exposed, validation material is missing, or the broker claims an authoritative verdict |

A case passes when the multi-root verifier under policy A returns the expected
verdict and every expected reason code; further codes are allowed. A case that
expects no codes passes only if none is returned. In the article's corpus, N1
returns two further codes: `action-receipt-missing`, because its only action
package is invalid, and the runtime's canonical-form message.

## Contributing a negative control

A contributed negative control consists of three things:

1. the case entry, with a new `case_id`;
2. a short statement of the failure it represents;
3. an expected verdict and expected reason codes, fixed before any verifier is
   run on the case.

Send it as a pull request to this repository; there is no submission portal.
Controls written by someone who has not read the overlay code are the most
valuable kind: they double as held-out cases, and they give the expected
results an author other than the implementer.

The evaluation reads its cases from `corpus/generated/corpus-index.json`,
which the builder writes from the case plan, so a new case reaches the
evaluation only through a rebuild. A rebuild signs the second issuer pair
under a new key (see «Rebuilding the corpus» in `README.md`). To try a case
locally, rebuild in a copy of `experiment/`, and send the case entry and the
statement, not the rebuilt corpus.
