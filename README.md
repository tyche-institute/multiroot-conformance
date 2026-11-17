# Isolating Federation from Policy Depth: conformance pilot package

Version 1.0.0 · DOI 10.5281/zenodo.24324993 · released 2026-11-17

This package accompanies the article

> Anton Sokolov, «Isolating Federation from Policy Depth: A Conformance
> Protocol for Multi-Root AI-Agent Evidence», *Latin-American Journal of
> Computing*, accepted in November 2026.

It holds what is needed to repeat, offline, the execution reported in Section
8.7 of the article, and to check what Section 8.5 says about it:

- the fifteen cases (five positive fixtures and ten negative controls) as 29
  signed evidence packages, with their expected verdicts and reason codes;
- the policy overlay, the three baselines, and the policy files;
- the corpus index, from which the issuer-to-key map is read;
- the evaluation scripts and the raw outputs of the run of July 2026;
- a repetition of that run, made on 17 November 2026 with the network
  switched off and traced;
- a build of the evidence-package runtime that signs and verifies the
  packages (signer version 0.1.3).

`SHA256SUMS` lists the SHA-256 of every other regular file in the package.

## Contents

| Path | What it is |
|---|---|
| `experiment/case-plan.json` | The fifteen cases: identity assertions, action receipts, expected verdict, expected reason codes |
| `experiment/corpus/generated/` | The corpus of the article: per case the signed packages (`aep/`), their payloads and metadata; `corpus-index.json` with the issuer-to-key map |
| `experiment/policies/` | Relying-party policies A and B, and the single-root policy of baseline B3 |
| `experiment/src/policy_overlay.py` | The policy overlay (`evaluate_case`), used by the multi-root verifier and by B3 |
| `experiment/scripts/run_evaluation.py` | Runs the five verifier configurations on every case; B1 and B2 are defined here |
| `experiment/scripts/build_corpus.py` | Builds and signs the corpus from the case plan (see «Rebuilding the corpus») |
| `experiment/scripts/make_verdict_grid.py` | Draws Figure 1 of the article from the results |
| `experiment/keys/dev-rsa-b.pem` | Public key of the second issuer pair (a test key) |
| `experiment/results/` | Raw outputs of the July 2026 run reported in the article |
| `experiment/results-2026-11-network-denied/` | The November 2026 repetition with the network disabled and traced; it has its own README |
| `experiment/vendor/eatf/` | The evidence-package runtime (see «The runtime») |
| `CASE-FORMAT.md` | How a case is written, and how to contribute one |
| `LICENSE`, `LICENSE-DATA.md` | Terms of use |
| `CITATION.cff` | How to cite the article and this package |

## Requirements

Python 3 (standard library only) and Node.js. The November repetition used
Python 3.12.3 and Node.js v22.22.3; the July record names Node.js v22.22.3.
Nothing else has to be installed, and no network access is needed: the
runtime is included in built form.

## Reproducing the reported verdicts

The evaluation script writes into `results/` in place, so run it in a copy:

```sh
cp -a experiment /tmp/lajc-repeat
cd /tmp/lajc-repeat
python3 scripts/run_evaluation.py
```

The script finds the runtime in `vendor/eatf`, or in `$EATF_ROOT` if that is
set. It verifies every package with the runtime's offline-only flag, applies
the five verifier configurations to every case, and writes
`results/evaluation.json` and `results/evaluation-summary.md`. It exits with 0
only if the multi-root verifier under policy A passes all fifteen cases. A case
passes when the verifier returns the expected verdict and every expected reason
code; a case that expects no codes must return none.

To compare the new outputs with those reported in the article:

```sh
python3 -I results-2026-11-network-denied/compare_with_july.py \
    <this package>/experiment/results/evaluation.json results/evaluation.json
```

It compares the verdict and the reason codes case by case for all five
configurations, then every other field. Only the per-case timing is expected
to differ. For the November repetition it reported no difference.

With the network switched off and traced (Linux, with bubblewrap and strace),
as for `results-2026-11-network-denied/`:

```sh
bwrap --unshare-net --dev-bind / / \
    strace -f -e trace=%network -o net-trace.log \
    python3 scripts/run_evaluation.py </dev/null
```

## The five verifier configurations

| Key in `evaluation.json` | In the article |
|---|---|
| `vmr_rp_a` | Multi-root verifier, relying-party policy A |
| `vmr_rp_b` | Multi-root verifier, relying-party policy B |
| `b3_single_root_policy_bound` | B3: the same overlay under a single-root policy |
| `b1_one_registry` | B1: one registry, no policy layer |
| `b2_signature_only` | B2: signature only |

`scripts/run_evaluation.py` calls the same function, `evaluate_case` from
`src/policy_overlay.py`, for the multi-root verifier under both policies and
for B3; only the policy argument differs. `policies/rp-a-policy.json` and
`policies/b3-single-root-policy.json` differ in four fields: `policy_id`,
`comment`, `trusted_identity_issuers`, and `trusted_action_issuers`. No policy
file holds the issuer-to-key map: the script reads it from
`corpus/generated/corpus-index.json` (field `issuer_key_bindings`) and gives
the same map to every policy-bound configuration.

## Files kept as recorded

The files of both runs are kept byte for byte. Some of their wording needs a
note.

1. `results/evaluation.json` says «all verifier invocations ran with
   --offline-only; no network endpoints were contacted». The script writes the
   second half as a fixed string. The July run neither disabled nor observed
   the network. The November repetition did both, and its trace records no
   network system call.
2. `results/run.log` and `results/evaluation-summary.md` speak of an «FA-rate»
   and a «false-accept rate». These are counts over hand-built controls, not
   rates, and the article does not call them rates.
3. The `comment` field of `policies/b3-single-root-policy.json` mentions a
   «referee finding», and the `note` of `case-plan.json` a «referee review».
   Both refer to an internal review before submission.
4. `corpus/generated/corpus-index.json`, the July outputs, and both scripts
   in `scripts/` that call the runtime say that its path was «not recorded,
   for blind-review safety», and comments in those scripts speak of a
   blind-review artifact. The article was under double-blind review then. The
   July run recorded the signer version only. The November repetition ran
   against the runtime that this package carries.
5. The outputs keep the verdict and the reason codes of every case, not the
   reason trace of every package.

## Rebuilding the corpus

`scripts/build_corpus.py` builds and signs the corpus from `case-plan.json`.
It deletes `corpus/generated/` first. The first issuer pair signs with a test
key bundled with the runtime. The second signs with `keys/dev-rsa-b.key`, a
test key that is not in this package; only its public half is. When that key
is missing, the builder creates a new key pair and overwrites
`keys/dev-rsa-b.pem`. A rebuilt corpus is therefore signed under a new second
key, and it is not the corpus of the article. Run the builder only in a copy.
To reproduce the reported verdicts, run `scripts/run_evaluation.py` on the
packages as shipped.

## Time evidence

Every package carries the same timestamp token, taken from a test vector of
the runtime. Its message imprint matches none of the 29 packages. The runtime
reports such a mismatch as a note and still accepts the package. Section 9 of
the article states this; the pilot makes no temporal-binding claim.

## The runtime

`experiment/vendor/eatf/` is an unchanged copy of the directory
`papers/dependable-multiroot-agent-evidence/artifact/vendor/eatf` at tag
`eatf-multiroot-softwarex-v0.2.3` (commit
`c421dadc1aacf77342f66aca15247994f0d10fb6`) of
<https://github.com/tyche-institute/eatf-multiroot-softwarex>, archived as
<https://doi.org/10.5281/zenodo.21874026>. Its package files name
`@eatf/sign-cli` 0.1.3, `@eatf/verify-cli` 0.1.1, and `@eatf/verifier` 0.1.3.
The July run recorded signer version 0.1.3 but not which build it used; the
November repetition used this one and reproduced every verdict and reason code
of July. The runtime's terms are in its own `LICENSE` and `NOTICE` files.

The copy contains 11 symbolic links. Two of them,
`cli/eatf-sign/node_modules/@eatf/verifier` and
`cli/eatf-verify/node_modules/@eatf/verifier`, point to `lib/`; a copy that
drops symbolic links breaks the command-line tools. All keys in the package,
including the private key among the runtime's test vectors, are test keys.

## Limits

Sections 8.6 and 9 of the article state the limits. In short: an author-built
pilot corpus of fifteen cases, one case per negative family; one signature
family under two keys; the verifier's offline mode only; the
missing-validation-material control (N4) and the expired-algorithm control
(N7) change declared metadata only; time evidence is not bound to the payload.
The pilot measures conformance and issuer coverage, not resistance to issuer
compromise.

## Contributing a case

`CASE-FORMAT.md` describes the case format. A contribution is a pull request
to this repository; there is no submission portal.

## Licence

The code (`experiment/src/`, `experiment/scripts/`, and
`experiment/results-2026-11-network-denied/compare_with_july.py`) is under the
MIT licence (`LICENSE`). The corpus, the case plan, the policy files, the
outputs, and the documents are under CC BY 4.0 (`LICENSE-DATA.md`). The
runtime in `experiment/vendor/eatf/` has its own terms.

## Citation

Please cite the article. To cite this package, use `CITATION.cff` or the DOI
above.
