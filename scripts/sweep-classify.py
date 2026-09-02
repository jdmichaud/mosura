#!/usr/bin/env python3
"""Rank the oracle sweep's divergence classes by corpus loss — the instrument, not a hand count.

WHY IT IS A SCRIPT. Order K built these classes with a throwaway `classify.py` that lived only in a
scratch directory. Two of its rows were corrected by hand afterwards and the corrections went into
the DOC, not into the counter, so the script and the document disagreed and the script was the one
anybody could re-run. That is an armed trap: re-running it prints `deref-cast 741 TUs / 11,934 loss
/ 65.1 %` — a figure that was measured, published, and WITHDRAWN — with nothing on screen to say so.
The rule this is the second face of (`cast-census.py`): AN INSTRUMENT MUST BE REPRODUCIBLE BY
SOMEONE WHO WAS NOT THERE. A number that only the operator knows is stale is not a measurement.

THE TWO RULES BUILT IN, both paid for by the `deref-cast` class three times over:

  1. NORMALIZE BEFORE MATCHING. Every text is `re.sub(r'\\s+','',...)` before a pattern touches it.
     The two printers spell the same construct differently and the differences are not exotic —
     one class was spelled three ways: `*((T *)x)` against `*(T *)x` (our extra paren), `*(char
     **)x` (a `\\*\\)` pattern cannot match `**)`), and `code * *` against `code **` (a `\\*+`
     pattern will not cross a space). A fourth, in `array-index`, was an array DECLARATION:
     both printers write `int4 aiStack_60 [9];` with a space, so `\\w+\\[` never matched one.

  2. REPORT S|delta|, AND REPORT BOTH DIRECTIONS. A class defined as "TUs where we emit more" is
     one-sided by construction, and then its opposite-direction members are invisible rather than
     zero. `deref-cast` was published as `67 TUs / 2,539 loss / MORE 67 / FEWER 0`; the identical
     pattern run WITHOUT the one-sided filter finds 70 TUs / 2,706 loss / MORE 67 / FEWER 3, and
     the three are real (Ghidra spells cast-derefs we do not, in 01132, 02028, 02549). Both halves
     are printed here, and `S|delta|` is printed next to the TU count so a redistribution of error
     can never read as convergence.

CALIBRATION, AND IT CAN FAIL. `--calibrate <order-K-workdir>` re-measures the two hand-corrected
rows and exits non-zero unless they come back: `deref-cast` MORE-half 67 members / S|delta| 86 (the
published figure) with the two-sided 70 / 94 beside it, and `array-index` 31 TUs / 1,138 loss /
MORE 8 / FEWER 23. If a future edit re-arms the old pattern, the calibration says so instead of the
table quietly printing 741.

WHAT IS NOT HERE. Every mark below is a REGEX over the rendered text, so a class that needs the
declarations to recognise it cannot live in this table. The arithmetic PROMOTION cast is the worked
example (Order P): deciding whether `x * 4` has a narrow operand means knowing `x`'s declared type,
and whether the operand carries a promotion cast means walking the cast chain in front of it. That
class has its own typed scanner; do not read this table as the whole residue.

WHAT A CLASS IS. A construct counted in both renderings of the same function; a TU is a member when
the two counts differ. This is a TEXT scan over two printers' output, so it locates classes — it
does not diagnose them, and a class is a place to look, never a defect count.

Usage:
  sweep-classify.py <sweep-workdir> <all.tsv> <recompile-census.tsv>
  sweep-classify.py --calibrate <order-K-workdir>      # workdir holding sweep/, all.tsv
"""
import collections
import re
import sys

# The corpus-loss census supplies each TU's weight; the sweep supplies the two renderings.
DEFAULT_CENSUS = "/data/be2/g1-rec.tsv"

# Every pattern is applied to WHITESPACE-STRIPPED text (rule 1), which is why they look dense:
# `*(uint1 *)(p + 1)` is `*(uint1*)(p+1)` by the time a pattern sees it.
MARK = {
    # `\(+` admits our extra paren (`*((T *)x)`), `\*+` the pointer-to-pointer spellings.
    "deref-cast": r"\*\(+\w+\*+\)",
    # uses AND declarations: whitespace stripping is what makes `int4 aiStack_60 [9]` match.
    "array-index": r"\w+\[[^\]]+\]",
    "piece-ops": r"\b(?:CONCAT\d+|SUB\d+|ZEXT\d+|SEXT\d+)\b",
    # `\bgoto\b` cannot match here: stripping whitespace glues the label on (`gotoLAB_0001`),
    # so the trailing word boundary never fires. The calibration caught this on its first run —
    # the class silently vanished from the table rather than printing a wrong number.
    "goto": r"\bgoto[A-Za-z_]",
    "do-while": r"\bdo\{",
    "while": r"\bwhile\(",
    "for": r"\bfor\(",
    "switch": r"\bswitch\(",
    "short-circuit": r"(?:&&|\|\|)",
    "halt/trap": r"(?:halt_baddata|__assert|switchD|code\*)",
}

GAME_LIMIT = 0x5191E  # the hand-drawn game/engine line; see the foreign-scope thread


def canon(text):
    """Rule 1. Every comparison in this file starts here."""
    return re.sub(r"\s+", "", text)


def first_signature(text):
    for line in text.splitlines():
        if re.match(r"^[A-Za-z_]\w*[\w \*]*\bfunc\s*\(", line):
            return line
    return ""


def param_count(signature):
    m = re.search(r"\(([^)]*)\)", signature)
    if not m:
        return 0
    args = m.group(1).strip()
    return 0 if args in ("", "void") else args.count(",") + 1


def isolation_sensitive(ghidra, ours):
    """Ghidra's fixture is context-poor here, so a divergence says nothing about the port.

    Two thirds of the swept loss is this and nothing else (Order K §3), which is why it is cut
    BEFORE any class is ranked rather than noted afterwards.
    """
    gp, mp = param_count(first_signature(ghidra)), param_count(first_signature(ours))
    if gp == 0 and mp > 0:
        return True
    if re.search(r"\b(?:extraout_|in_|unaff_)\w*", ghidra):
        return True
    bare = lambda t: len(re.findall(r"func_0x[0-9a-f]+\(\)", t))
    return bare(ghidra) > bare(ours)


def load_census(path):
    loss, orig_n, va = {}, {}, {}
    with open(path) as fh:
        for line in fh:
            f = line.rstrip("\n").split("\t")
            if len(f) < 9 or f[0].startswith("#"):
                continue
            try:
                idx, sim, n = f[0], float(f[6]), int(f[8])
                va[idx] = int(f[1], 16)
            except ValueError:
                continue
            loss[idx], orig_n[idx] = n * (1.0 - sim), n
    return loss, orig_n, va


def read_pairs(workdir, all_tsv):
    with open(all_tsv) as fh:
        for line in fh:
            f = line.rstrip("\n").split("\t")
            if len(f) < 7 or f[3] != "OK":
                continue
            idx = f[0]
            try:
                with open(f"{workdir}/sweep/ghidra/{idx}.c") as g, open(f"{workdir}/sweep/mosura/{idx}.c") as m:
                    yield idx, g.read(), m.read()
            except FileNotFoundError:
                continue


def classify(workdir, all_tsv, census):
    loss, orig_n, va = load_census(census)
    clean, dirty = [], []
    for idx, ghidra, ours in read_pairs(workdir, all_tsv):
        counts = {
            name: (len(re.findall(p, canon(ours))), len(re.findall(p, canon(ghidra))))
            for name, p in MARK.items()
        }
        row = dict(idx=idx, counts=counts)
        (dirty if isolation_sensitive(ghidra, ours) else clean).append(row)
    return clean, dirty, loss, orig_n, va


def table(pool, loss, orig_n, va, title):
    print(f"\n== {title}: classes by corpus loss")
    print(f"  {'class':16} {'TUs':>5} {'loss':>8} {'%':>6} {'S|delta|':>9} {'game':>6} {'band':>6}  direction")
    agg = collections.defaultdict(
        lambda: dict(tus=0, loss=0.0, sab=0, sab_more=0, sab_fewer=0, game=0, band=0, more=0, fewer=0)
    )
    for row in pool:
        idx = row["idx"]
        for name, (ours, theirs) in row["counts"].items():
            d = ours - theirs
            if d == 0:
                continue
            a = agg[name]
            a["tus"] += 1
            a["loss"] += loss.get(idx, 0)
            a["sab"] += abs(d)                      # rule 2: absolute, never signed
            a["sab_more" if d > 0 else "sab_fewer"] += abs(d)
            a["game"] += 1 if va.get(idx, 0) < GAME_LIMIT else 0
            a["band"] += 1 if 20 <= orig_n.get(idx, 0) <= 199 else 0
            a["more" if d > 0 else "fewer"] += 1
    total = sum(loss.get(r["idx"], 0) for r in pool) or 1
    for name, a in sorted(agg.items(), key=lambda kv: -kv[1]["loss"]):
        print(
            f"  {name:16} {a['tus']:5} {a['loss']:8.0f} {100 * a['loss'] / total:5.1f}%"
            f" {a['sab']:9} {a['game']:6} {a['band']:6}  MORE {a['more']}/FEWER {a['fewer']}"
        )
    return agg


def calibrate(workdir):
    """Re-measure the two hand-corrected rows. Exits non-zero if either has drifted."""
    clean, _, loss, orig_n, va = classify(workdir, f"{workdir}/all.tsv", DEFAULT_CENSUS)
    agg = table(clean, loss, orig_n, va, "CALIBRATION (Order K workdir, clean residue)")
    ok = True

    def check(label, got, want):
        nonlocal ok
        mark = "OK  " if got == want else "FAIL"
        if got != want:
            ok = False
        print(f"  {mark} {label}: got {got}, expected {want}")

    print("\n== calibration")
    dc, ai = agg["deref-cast"], agg["array-index"]
    # The PUBLISHED deref-cast row is the MORE half only (docs/oracle-sweep-calibrated.md §8);
    # this instrument reports both directions, so both are checked.
    check("deref-cast MORE members (published)", dc["more"], 67)
    check("deref-cast MORE-half S|delta| (published)", dc["sab_more"], 86)
    check("deref-cast two-sided TUs", dc["tus"], 70)
    check("deref-cast two-sided S|delta|", dc["sab"], 94)
    check("array-index TUs", ai["tus"], 31)
    check("array-index loss", round(ai["loss"]), 1138)
    check("array-index direction", (ai["more"], ai["fewer"]), (8, 23))
    # A class that DISAPPEARS is the failure mode a table cannot show: `goto` did exactly that
    # when its pattern met the stripped text, so its published row is pinned too.
    gt = agg["goto"]
    check("goto TUs", gt["tus"], 3)
    check("goto loss", round(gt["loss"]), 286)
    if dc["tus"] > 700:
        print("  FAIL the pre-fix deref-cast pattern is back (741-TU shape); see rule 1")
        ok = False
    print("\ncalibration", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main(argv):
    if len(argv) >= 3 and argv[1] == "--calibrate":
        return calibrate(argv[2])
    if len(argv) < 3:
        print(__doc__)
        return 2
    workdir, all_tsv = argv[1], argv[2]
    census = argv[3] if len(argv) > 3 else DEFAULT_CENSUS
    clean, dirty, loss, orig_n, va = classify(workdir, all_tsv, census)
    print(f"scored pairs: {len(clean) + len(dirty)}   workdir: {workdir}")
    print(f"ISOLATION-SENSITIVE: {len(dirty)} pairs, loss {sum(loss.get(r['idx'], 0) for r in dirty):.0f}")
    print(f"CLEAN residue:       {len(clean)} pairs, loss {sum(loss.get(r['idx'], 0) for r in clean):.0f}")
    table(clean, loss, orig_n, va, "CLEAN residue (isolation-artifact pairs excluded)")
    table(dirty, loss, orig_n, va, "ISOLATION-SENSITIVE pool (read as artifact-contaminated)")
    print("\nA class is a place to look, not a defect count: this is a text scan over two printers.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
