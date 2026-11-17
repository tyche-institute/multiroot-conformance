#!/usr/bin/env python3
"""Emit the Section 8.7 centerpiece figure (verdict grid) as TikZ, from evaluation.json.

Emitted as a double-column float (figure*): at 14 cases the grid overflows a
single IEEE column, and shrinking it to fit would make the cells illegible.

Data-driven on purpose: the figure can never drift from the measured results,
because every cell is read out of results/evaluation.json at build time.

Encoding (strict black-and-white house style: black on white, square corners,
no colour, no grey fills):
  filled black square  = accept
  open square          = reject
  square with diagonal = indeterminate
A cell is CORRECT when it matches the case's expected verdict; incorrect cells
are marked with a heavy X overlay so errors are visible at a glance.

Usage: python3 scripts/make_verdict_grid.py > ../build/verdict-grid.tex
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EV = json.loads((ROOT / "results/evaluation.json").read_text(encoding="utf-8"))

ROWS = [
    ("Multi-root", lambda c: c["vmr_rp_a"]["verdict"]),
    ("B3 single-root, policy-bound", lambda c: c["b3_single_root_policy_bound"]["verdict"]),
    ("B1 one-registry", lambda c: c["b1_one_registry"]["verdict"]),
    ("B2 signature-only", lambda c: c["b2_signature_only"]["verdict"]),
]

CELL = 0.46          # cell size in cm
GAP = 0.06


def main() -> int:
    cases = EV["per_case"]
    n = len(cases)
    out: list[str] = []
    w = n * (CELL + GAP)
    out.append(r"\begin{figure*}[!t]")
    out.append(r"\centering")
    out.append(r"\begin{tikzpicture}[x=1cm,y=1cm,line width=0.4pt]")

    # column headers (case ids)
    for j, c in enumerate(cases):
        x = j * (CELL + GAP) + CELL / 2
        out.append(rf"\node[font=\tiny,rotate=90,anchor=west] at ({x:.3f},0.12) {{{c['case_id']}}};")

    for i, (label, getter) in enumerate(ROWS):
        y = -(i + 1) * (CELL + GAP)
        out.append(rf"\node[font=\scriptsize,anchor=east] at (-0.12,{y + CELL/2:.3f}) {{{label}}};")
        for j, c in enumerate(cases):
            x = j * (CELL + GAP)
            v = getter(c)
            exp = c["expected_verdict"]
            # base glyph by verdict
            if v == "accept":
                out.append(rf"\filldraw[black] ({x:.3f},{y:.3f}) rectangle ++({CELL},{CELL});")
            elif v == "reject":
                out.append(rf"\draw[black] ({x:.3f},{y:.3f}) rectangle ++({CELL},{CELL});")
            else:  # indeterminate
                out.append(rf"\draw[black] ({x:.3f},{y:.3f}) rectangle ++({CELL},{CELL});")
                out.append(rf"\draw[black] ({x:.3f},{y:.3f}) -- ++({CELL},{CELL});")
            # Error overlay when the verdict does not match expectation.
            # Must contrast with the cell it sits on: a black X on a black-filled
            # (accept) cell is invisible, which would hide exactly the false
            # accepts this figure exists to expose.
            if v != exp:
                ink = "white" if v == "accept" else "black"
                out.append(
                    rf"\draw[{ink},line width=1.1pt] ({x+0.09:.3f},{y+0.09:.3f}) -- ++({CELL-0.18:.3f},{CELL-0.18:.3f}) "
                    rf"({x+0.09:.3f},{y+CELL-0.09:.3f}) -- ++({CELL-0.18:.3f},{-(CELL-0.18):.3f});"
                )

    # separator between positives and negatives
    npos = sum(1 for c in cases if c["class"] == "positive")
    xs = npos * (CELL + GAP) - GAP / 2
    ybot = -(len(ROWS)) * (CELL + GAP)
    out.append(rf"\draw[black,dashed,line width=0.5pt] ({xs:.3f},0.02) -- ({xs:.3f},{ybot:.3f});")
    out.append(rf"\node[font=\tiny,anchor=north] at ({npos*(CELL+GAP)/2:.3f},{ybot-0.04:.3f}) {{positives}};")
    out.append(
        rf"\node[font=\tiny,anchor=north] at ({(npos*(CELL+GAP)+w)/2:.3f},{ybot-0.04:.3f}) {{negative controls}};"
    )
    out.append(r"\end{tikzpicture}")
    npos_c = sum(1 for c in cases if c["class"] == "positive")
    nneg_c = n - npos_c
    out.append(
        r"\caption{Verdict grid: four verifiers $\times$ " + f"{n}"
        + r" corpus cases}" "\n"
        r"\label{fig:verdict-grid}" "\n"
        r"\begin{minipage}{\textwidth}\footnotesize" "\n"
        r"\emph{Glyphs:} filled $=$ accept, open $=$ reject, diagonal $=$ "
        r"indeterminate. A heavy X (white on filled cells, black on open) marks a "
        r"verdict differing from the federated reference policy's expected "
        r"outcome. B3's two marked positives are policy-correct under its own "
        r"narrower policy: coverage exclusions, not defects. " + f"{npos_c}"
        + r" positives, " + f"{nneg_c}" + r" negative controls."
        r"\end{minipage}" "\n"
        r"\end{figure*}"
    )
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
