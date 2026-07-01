#!/usr/bin/env python3
"""trace-diff.py — diff a Ghidra rule-application trace against mosura's (Task #2, the "killer feature").

Both traces are emitted in Ghidra's OPACTION_DEBUG `debugModPrint` format:

    DEBUG <n>: <rulename>
    0x<addr>:<uniq>: <op before>
       0x<addr>:<uniq>: <op after>

produced by:
    oracle/capture_trace <ghidra_src> <fixture.xml> --trace        # Ghidra (canonical)
    MOSURA_TRACE=1 cargo run -q --example trace -- <fixture-stem>   # mosura

Ghidra's raw op rendering uses operator glyphs (`&`, `<`, `SBORROW8`) while mosura uses CPUI opcode
names, so we key each firing on (rulename, instruction-address) — enough to answer "which rule fires
where, and where do the two engines diverge". A small alias map bridges the few rules mosura named
differently from Ghidra.

Usage:  trace-diff.py <ghidra.trace> <mosura.trace>
"""
import sys
import re
from collections import Counter

# mosura Rule::name() -> Ghidra Rule getName(), where they differ.
ALIAS = {
    "constfold": "collapseconstants",  # mosura RuleConstFold == Ghidra RuleCollapseConstants
}

HDR = re.compile(r"^DEBUG \d+: (.+)$")
ADDR = re.compile(r"^\s*(0x[0-9a-fA-F]+):")


def parse(path):
    """Return a list of (rulename, addr) firings, in order."""
    firings = []
    name = None
    want_addr = False
    with open(path) as fh:
        for line in fh:
            m = HDR.match(line)
            if m:
                name = ALIAS.get(m.group(1), m.group(1))
                want_addr = True
                continue
            if want_addr:
                a = ADDR.match(line)
                if a:
                    firings.append((name, int(a.group(1), 16)))
                want_addr = False
    return firings


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    g = parse(sys.argv[1])
    m = parse(sys.argv[2])
    gnames = Counter(n for n, _ in g)
    mnames = Counter(n for n, _ in m)

    print(f"=== rule-firing trace diff  (ghidra={len(g)} firings, mosura={len(m)} firings) ===\n")

    only_g = sorted(set(gnames) - set(mnames))
    only_m = sorted(set(mnames) - set(gnames))
    both = sorted(set(gnames) & set(mnames))

    print("RULES GHIDRA FIRES BUT MOSURA NEVER DOES (candidate ports / missing coverage):")
    for n in sorted(only_g, key=lambda n: -gnames[n]):
        print(f"  {gnames[n]:4d}x  {n}")
    print("\nRULES MOSURA FIRES BUT GHIDRA DOES NOT (over-firing / naming / adaptation):")
    for n in sorted(only_m, key=lambda n: -mnames[n]):
        print(f"  {mnames[n]:4d}x  {n}")

    print("\nSHARED RULES — per-rule firing count (ghidra vs mosura) and address deltas:")
    gset = set(g)
    mset = set(m)
    for n in sorted(both, key=lambda n: -(gnames[n] + mnames[n])):
        g_addrs = {a for nn, a in g if nn == n}
        m_addrs = {a for nn, a in m if nn == n}
        gonly = sorted(g_addrs - m_addrs)
        monly = sorted(m_addrs - g_addrs)
        flag = "" if (not gonly and not monly) else "  <-- diverges"
        print(f"  {n:20s} ghidra={gnames[n]:3d} mosura={mnames[n]:3d}{flag}")
        if gonly:
            print(f"        ghidra-only @ {', '.join(f'{a:#x}' for a in gonly)}")
        if monly:
            print(f"        mosura-only @ {', '.join(f'{a:#x}' for a in monly)}")


if __name__ == "__main__":
    main()
