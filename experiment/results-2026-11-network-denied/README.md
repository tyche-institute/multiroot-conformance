# Network-denied repetition, 17 November 2026

A repetition of the July 2026 evaluation (`../results/`) with the network
switched off. It answers the point of Reviewer 2 (LAJC paper 503) that asks to
«validate offline execution with network access disabled or instrumented».
Nothing was signed, no case was added and no policy was changed. The run
worked on a copy of this experiment folder, so the July outputs were not
touched.

## Result

- **Same verdicts and reason codes.** For every case, every verifier and both
  policies the verdict and the list of reason codes are the same as in July:
  75 of 75 pairs (15 cases × 5 configurations: the multi-root verifier under
  policy A and under policy B, B3, B1, B2). Every other field of
  `evaluation.json` is the same as well, except the per-case timing. `run.log`
  and `evaluation-summary.md` are byte-identical to the July files.
  Table and checksums: `comparison.md`, made by `compare_with_july.py`.
- **No network system call.** The trace of the whole run
  (`strace -f -e trace=%network`) records none: no socket was created, no
  connection was attempted, nothing was sent. Its 349 lines are 320 exits of
  processes and threads and 29 SIGCHLD deliveries, one for each of the 29
  verifier processes (28 exited with status 0, one with status 1). See
  `net-trace.log`.
- **The sandbox works, and the trace would show a call.** Inside the sandbox
  the only interface was loopback. A connection to an outside address
  (192.0.2.1, a documentation address) failed with ENETUNREACH, a connection to
  the loopback address was refused, and the same trace filter recorded both
  attempts. See `sandbox-controls.txt`.
- **The public build reproduces the July outputs.** The run used the runtime
  build of the public repository named in `environment.txt`. It is the first
  evaluation run against that build.

## What it does not show

- That the July run made no network call. The July run recorded the
  offline-only flag, not a trace. This is a repetition.
- Anything about an online mode. Neither run exercised one.
- That the July run used this very build. The July record names signer
  version 0.1.3; the build was not recorded.
- Timing. Under `strace` every verifier process runs slower: the median per
  case is 560.0 ms here against 178.3 ms in July. The article reports no timing.

## Files

| File | What it is |
|---|---|
| `evaluation.json` | Raw output of `scripts/run_evaluation.py` in this run |
| `evaluation-summary.md` | Its summary; byte-identical to `../results/evaluation-summary.md` |
| `run.log` | Standard output of the run; byte-identical to `../results/run.log` |
| `run-stderr.log` | Standard error of the run; empty |
| `net-trace.log` | Trace of network system calls of the run and all its child processes |
| `sandbox-controls.txt` | Interfaces inside the sandbox and two deliberate connections, traced the same way |
| `comparison.md` | Case-by-case, verifier-by-verifier comparison with `../results/evaluation.json` |
| `compare_with_july.py` | The script that wrote `comparison.md` |
| `environment.txt` | Times, tool versions, the runtime build, the commands |
| `runtime-SHA256SUMS.txt` | SHA-256 of every file of the runtime build that was used |
| `SHA256SUMS.txt` | SHA-256 of every other file in this folder |

To check the folder: `sha256sum -c SHA256SUMS.txt` here. To repeat the
comparison: `python3 -I compare_with_july.py ../results/evaluation.json evaluation.json`.
