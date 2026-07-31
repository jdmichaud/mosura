#!/usr/bin/env python3
"""typeprop-diff.py — present Ghidra's and mosura's type-propagation decisions side by side.

Driven by scripts/typeprop-diff.sh; see that file for why this channel exists at all (the rule
trace is an op-mutation log and is structurally blind to type inference).

Line formats, which are near-identical by design because mosura's hook mirrors Ghidra's:

    ghidra   <varnode> : <type> init
             <varnode> : <type> from <op> slot=<n>
             <varnode> : <type> alias <varnode>
    mosura   TYPEPROP <varnode>#<ssa> : <Type(..)> init
             TYPEPROP <varnode>#<ssa> : <Type(..)> from <op> slot=<n>

⚠️ NO PER-VARNODE JOIN, ON PURPOSE. Ghidra prints `CL(0x00100033:da)`, mosura prints
`r0x8:4(0x10001b:74)#494` — register name vs raw offset, hex vs decimal sequence. A varnode identity
map between the engines does not exist, and an approximate one would let this tool report false
agreement, which is exactly the failure the whole trace-instrument family was rebuilt to stop. So it
reports only what is sound without such a map:

  * the DECISION MIX per side (seeds vs propagated edges vs alias) — a side that only ever seeds is
    not doing propagation at all, and that alone is a finding;
  * the WIDTH distribution of the varnodes each side makes type decisions about;
  * every CONSTANT by (value, size), which is directly comparable because a constant's value and
    width mean the same thing on both sides.

The width/constant view is what produced the first result: on orcompare Ghidra's chain is 1 byte
throughout and mosura's is 4, so the two engines run the same algorithm on differently-shaped IR and
no type-preference change could reconcile them.
"""
import re
import sys
from collections import Counter

G_LINE = re.compile(r"^(?P<vn>\S+) : (?P<ty>\S+) (?P<how>init|from|alias)\b(?P<rest>.*)$")
M_LINE = re.compile(r"^TYPEPROP (?P<vn>\S+?)#\d+ : (?P<ty>.+?) (?P<how>init|from|alias)\b(?P<rest>.*)$")
# `#0x1:1` (ghidra) / `#0x1:4` (mosura): a constant varnode is `#<value>:<size>`.
CONST = re.compile(r"^#(0x[0-9a-fA-F]+|\d+):(\d+)$")
# trailing `:<size>` on a non-constant varnode rendering, e.g. `r0x8:4(...)` or `u0x1000001c:1(...)`
WIDTH = re.compile(r":(\d+)\(")


def parse(path, pat):
    rows = []
    for line in open(path):
        line = line.rstrip("\n")
        m = pat.match(line)
        if m:
            rows.append(m.groupdict())
    return rows


def width_of(vn):
    m = CONST.match(vn)
    if m:
        return int(m.group(2))
    m = WIDTH.search(vn)
    return int(m.group(1)) if m else None


def section(title):
    print(f"\n{title}")


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    g = parse(sys.argv[1], G_LINE)
    m = parse(sys.argv[2], M_LINE)

    section("DECISION MIX (a side that only seeds is not propagating at all):")
    for label, rows in (("ghidra", g), ("mosura", m)):
        how = Counter(r["how"] for r in rows)
        print(f"  {label}: {len(rows):4d} total   init={how['init']:4d}  "
              f"from={how['from']:4d}  alias={how['alias']:4d}")

    section("VARNODE WIDTHS the two sides make type decisions about:")
    gw = Counter(width_of(r["vn"]) for r in g)
    mw = Counter(width_of(r["vn"]) for r in m)
    for w in sorted(set(gw) | set(mw), key=lambda x: (x is None, x)):
        tag = "" if gw.get(w, 0) == mw.get(w, 0) else "   <-- differs"
        # `None` is NOT a finding and must not read as one: Ghidra renders a register varnode by
        # NAME (`CL(0x...)`, `ZF(...)`) with no `:size`, so the width is simply not in the text.
        # Labelling that "None-byte" once made it look like Ghidra had 12 unknown-width varnodes.
        label = f"{w}-byte" if w is not None else "width not printed (register name)"
        print(f"  {label:>32}   ghidra={gw.get(w,0):4d}  mosura={mw.get(w,0):4d}{tag}")
    if None in gw or None in mw:
        print("      (that last row is a LIMIT OF THIS PARSER, not a divergence — Ghidra prints")
        print("       register varnodes by name without a width. Widths above it are comparable.)")

    section("TYPE NAMES assigned (vocabularies differ in spelling; compare the SHAPE):")
    gt = Counter(r["ty"] for r in g)
    mt = Counter(r["ty"] for r in m)
    print(f"  ghidra: {', '.join(f'{t}x{c}' for t, c in gt.most_common())}")
    print(f"  mosura: {', '.join(f'{t}x{c}' for t, c in mt.most_common())}")

    section("CONSTANTS by (value, size) — directly comparable, no identity map needed:")
    def consts(rows):
        out = {}
        for r in rows:
            c = CONST.match(r["vn"])
            if c:
                out.setdefault((int(c.group(1), 0), int(c.group(2))), set()).add(r["ty"])
        return out
    gc, mc = consts(g), consts(m)
    for key in sorted(set(gc) | set(mc)):
        val, size = key
        gs = "/".join(sorted(gc.get(key, []))) or "-"
        ms = "/".join(sorted(mc.get(key, []))) or "-"
        flag = ""
        if key not in gc or key not in mc:
            # same value at a different WIDTH on the other side is the interesting case
            other_g = [s for (v, s) in gc if v == val]
            other_m = [s for (v, s) in mc if v == val]
            if other_g and other_m and set(other_g) != set(other_m):
                flag = f"   <-- WIDTH MISMATCH: ghidra has {sorted(other_g)}, mosura has {sorted(other_m)}"
            else:
                flag = "   <-- one side only"
        print(f"  #{val:#x}:{size}   ghidra={gs:12s} mosura={ms:12s}{flag}")

    print("\nNOTE: no per-varnode join is attempted — see this file's docstring. Read the width and")
    print("      constant rows first: if the two sides are typing DIFFERENT-WIDTH varnodes, the")
    print("      divergence is upstream of type inference and no type-ordering change can fix it.")


if __name__ == "__main__":
    main()
