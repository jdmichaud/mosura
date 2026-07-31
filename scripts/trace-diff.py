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
names, so we key each firing on (mechanism, instruction-address) — enough to answer "which rule
fires where, and where do the two engines diverge".

MECHANISM, NOT NAME. This diff used to key on the trace name as a bare STRING, and the port renames
some of them, so its headline column ("rules Ghidra fires but mosura never does") mixed naming
artifacts in with real findings — `collect_terms` (Ghidra) sat in that column while `collectterms`
(mosura) sat in the opposite one, from the same run, same rule, and a reader had no way to tell
that pair from a genuinely missing port. Firings are now resolved to the underlying CLASS via
scripts/trace-names.py (a join on the class name across the two source trees, plus a small cited
table for the classes the port renamed), so:

  * pure-naming pairs collapse into SHARED, where they belong;
  * "Ghidra fires it and mosura has no implementation" is separated from "mosura implements it and
    it is INERT here" — the string diff reported both as the same thing, and they are different
    defects with different fixes;
  * a mosura mechanism covering only PART of a Ghidra class is never folded in as covered;
  * anything that resolves to nothing is reported as UNMAPPED — an extraction defect to fix in
    trace-names.py — and is never allowed to land in a findings column.

Usage:  trace-diff.py <ghidra.trace> <mosura.trace> [--ghidra-cpp DIR] [--mosura-src DIR]
"""
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util as _ilu

_spec = _ilu.spec_from_file_location(
    "trace_names", os.path.join(os.path.dirname(os.path.abspath(__file__)), "trace-names.py"))
trace_names = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(trace_names)

HDR = re.compile(r"^DEBUG \d+: (.+)$")
ADDR = re.compile(r"^\s*(0x[0-9a-fA-F]+):")


def parse(path):
    """Return a list of (tracename, addr) firings, in order."""
    firings = []
    name = None
    want_addr = False
    with open(path) as fh:
        for line in fh:
            m = HDR.match(line)
            if m:
                name = m.group(1)
                want_addr = True
                continue
            if want_addr:
                a = ADDR.match(line)
                if a:
                    firings.append((name, int(a.group(1), 16)))
                want_addr = False
    return firings


def read_stamp(path: str, kind: str) -> str:
    """The provenance stamp trace-diff.sh writes as the first line of each trace.

    REFUSE-ON-MISSING is the point. A trace produced from a CLEAN tree was once compared as though
    it were the patched one, and the rule-firing deltas that fell out were reported as the patch's
    defect when they were the baseline's. Between `git stash` and `git apply` that is a
    one-keystroke mistake, and the rule "prove both sides of an A/B were built from the state you
    think" had already been written down and still did not prevent it. Written rules do not
    self-execute; this check does.
    """
    with open(path) as fh:
        first = fh.readline().strip()
    m = re.match(rf"^# {kind}-TRACE-STAMP (.+)$", first)
    if not m:
        sys.exit(
            f"REFUSING: {path} carries no {kind}-TRACE-STAMP header.\n"
            f"  It was not produced by scripts/trace-diff.sh, or predates provenance stamping.\n"
            f"  Regenerate it — an unstamped trace cannot be attributed to a tree state."
        )
    return m.group(1)


def opt(argv, flag):
    return argv[argv.index(flag) + 1] if flag in argv else None


def main():
    argv = sys.argv[1:]
    positional = [a for i, a in enumerate(argv)
                  if not a.startswith("--") and (i == 0 or argv[i - 1] not in ("--ghidra-cpp", "--mosura-src"))]
    if len(positional) != 2:
        sys.exit(__doc__)
    gstamp = read_stamp(positional[0], "GHIDRA")
    mstamp = read_stamp(positional[1], "MOSURA")
    nm = trace_names.build(opt(argv, "--ghidra-cpp"), opt(argv, "--mosura-src"))

    print(f"=== ghidra: {gstamp}")
    print(f"=== mosura: {mstamp}")
    if "+DIRTY" in mstamp:
        print("=== note: the mosura side has UNCOMMITTED changes under crates/ — the sha alone does")
        print("===       not identify this tree. Record the patch alongside any number you quote.")
    g = parse(positional[0])
    m = parse(positional[1])
    print(f"=== rule-firing trace diff  (ghidra={len(g)} firings, mosura={len(m)} firings) ===")
    print(f"=== name map: {len(nm.g.classes)} ghidra classes / {len(nm.m.classes)} mosura classes "
          f"(scripts/trace-names.py --full to audit)")
    # WHAT THIS INSTRUMENT CANNOT SEE. Ghidra's OPACTION_DEBUG is a p-code-OP mutation log:
    # debugModCheck(PcodeOp*) records ops into modify_list and debugModPrint returns early on
    # `if (modify_list.empty())` (funcdata.cc:1012/1035). An action that mutates only VARNODE state
    # -- datatypes via updateType, flags, cover/merge decisions -- never enters that list, so it
    # never prints, ON EITHER SIDE. ActionInferTypes is the case that cost a pass: it fires zero
    # times in both traces on every fixture, which reads as agreement and is really invisibility.
    # A blind spot that looks like a clean result is the worst kind, so the instrument says so
    # itself rather than leaving it in a memory someone has to have read.
    print("=== ⚠ BLIND SPOT: this is an OP-MUTATION log. Actions that change only VARNODE state")
    print("===   (ActionInferTypes and the type/cast/naming family) mutate no ops and therefore")
    print("===   NEVER appear here, on either side. Their absence is not evidence of agreement.")
    print("===   Do not read a typing conclusion out of this diff; use a type-decision log.\n")

    # ── resolve every firing to a mechanism key ────────────────────────────────────────────────
    # Key space: the Ghidra CLASS name for anything with a counterpart there, "group:<name>" for
    # ActionGroup/ActionPool labels, "mosura:<class>" for port adaptations with no Ghidra class.
    gkeys, mkeys = Counter(), Counter()          # key -> firings
    gaddrs, maddrs = {}, {}                      # key -> set of addresses
    gunmapped, munmapped = Counter(), Counter()
    partial = {}                                 # ghidra class -> (mosura class, firings)
    merged_of = {}                               # ghidra class -> mosura class (N:1 fold)
    split_of = {}                                # ghidra class -> [mosura classes] (1:N fold)
    trace_name = {}                              # key -> (ghidra name, mosura name)

    for name, addr in g:
        kind, key, _ = nm.canon_ghidra(name)
        if kind == "unmapped":
            gunmapped[name] += 1
            continue
        k = key if kind == "class" else f"group:{key}"
        gkeys[k] += 1
        gaddrs.setdefault(k, set()).add(addr)
        trace_name.setdefault(k, [None, None])[0] = name

    for name, addr in m:
        kind, cls, keys, rel = nm.canon_mosura(name)
        if kind == "unmapped":
            munmapped[name] += 1
            continue
        if kind == "group":
            k = f"group:{cls}"
            gk = [k]
        elif rel == "ADAPTATION":
            gk = [f"mosura:{cls}"]
        elif rel == "PARTIAL":
            # Deliberately NOT folded: mosura covers one side effect of this Ghidra class and does
            # not implement the class. Folding would report it as covered.
            for gcls in keys:
                pc, pn = partial.get(gcls, (cls, 0))
                partial[gcls] = (pc, pn + 1)
            continue
        else:
            gk = list(keys)
            for gcls in keys:
                if rel == "MERGE":
                    merged_of[gcls] = cls
                elif rel == "SPLIT":
                    split_of.setdefault(gcls, set()).add(cls)
        for k in gk:
            mkeys[k] += 1
            maddrs.setdefault(k, set()).add(addr)
            trace_name.setdefault(k, [None, None])[1] = name

    # ── instrument health first: nothing unexplained may reach a findings column ────────────────
    problems = nm.audit()
    if gunmapped or munmapped or problems:
        print("⚠ INSTRUMENT PROBLEMS — resolve these before reading anything below as a finding:")
        for side, unm in (("ghidra", gunmapped), ("mosura", munmapped)):
            for n, c in unm.most_common():
                print(f"  ! UNMAPPED {side} trace name {n!r} ({c}x) — no Rule/Action class and no "
                      f"group label extracted for it. Fix scripts/trace-names.py.")
        for p in problems:
            print(f"  ! {p}")
        print()

    def label(k):
        gn, mn = trace_name.get(k, [None, None])
        if k.startswith("group:"):
            return f"{k[6:]} (action group)"
        if k.startswith("mosura:"):
            return f"{mn} [{k[7:]}, port adaptation]"
        names = gn if gn == mn or mn is None else (f"{gn}/{mn}" if gn else mn)
        return f"{names} [{k}]"

    def where(k):
        if k.startswith("mosura:") or k.startswith("group:"):
            return ""
        return "  " + nm.g.where(k) if k in nm.g.classes else ""

    def fold_note(k):
        """Why a one-sided count may not mean what it looks like: a merged mosura action fires once
        where two Ghidra actions fire, and a split one fires twice where Ghidra fires once."""
        if k in merged_of:
            return (f"  [mosura merges this with the rest of {merged_of[k]}; one firing covers "
                    f"several Ghidra actions]")
        if k in split_of:
            return f"  [mosura splits this across {', '.join(sorted(split_of[k]))}; counts summed]"
        return ""

    only_g = sorted(set(gkeys) - set(mkeys), key=lambda k: -gkeys[k])
    only_m = sorted(set(mkeys) - set(gkeys), key=lambda k: -mkeys[k])
    both = sorted(set(gkeys) & set(mkeys), key=lambda k: -(gkeys[k] + mkeys[k]))

    impl = {gc for keys, _ in nm.mos_to_ghidra.values() for gc in keys}
    missing = [k for k in only_g if not k.startswith(("group:", "mosura:")) and k not in impl]
    inert_m = [k for k in only_g if k.startswith(("group:", "mosura:")) or k in impl]

    print("GHIDRA FIRES IT, MOSURA HAS NO IMPLEMENTATION AT ALL (candidate ports):")
    for k in missing or ():
        print(f"  {gkeys[k]:4d}x  {label(k)}{where(k)}")
    if not missing:
        print("  (none)")

    print("\nGHIDRA FIRES IT, MOSURA IMPLEMENTS IT BUT IT IS INERT ON THIS FIXTURE:")
    print("  (the code exists — a different defect from a missing port, and a different fix)")
    for k in inert_m or ():
        gn, mnm = trace_name.get(k, [None, None])
        mos = nm.m.classes.get(k, (None, None, None, None))
        extra = f"  mosura {mos[1]!r} {nm.m.where(k)}" if k in nm.m.classes else ""
        print(f"  {gkeys[k]:4d}x  {label(k)}{extra}")
    if not inert_m:
        print("  (none)")

    if partial:
        print("\n⚠ PARTIAL COVERAGE — mosura implements only part of these Ghidra classes:")
        for gcls, (mcls, n) in sorted(partial.items()):
            fired = f"{n}x" if n else "never fires here"
            print(f"  ghidra {gcls} ({nm.g.classes[gcls][1]!r}, {gkeys.get(gcls, 0)}x) "
                  f"~ mosura {mcls} ({nm.m.classes[mcls][1]!r}, {fired}) — NOT counted as covered")

    print("\nMOSURA FIRES IT, GHIDRA DOES NOT (over-firing / port adaptations):")
    for k in only_m or ():
        print(f"  {mkeys[k]:4d}x  {label(k)}{fold_note(k)}")
    if not only_m:
        print("  (none)")

    print("\nSHARED — per-mechanism firing count (ghidra vs mosura) and address deltas:")
    for k in both:
        gonly = sorted(gaddrs.get(k, set()) - maddrs.get(k, set()))
        monly = sorted(maddrs.get(k, set()) - gaddrs.get(k, set()))
        flag = "" if (not gonly and not monly) else "  <-- diverges"
        print(f"  {label(k):46s} ghidra={gkeys[k]:3d} mosura={mkeys[k]:3d}{flag}{fold_note(k)}")
        if gonly:
            print(f"        ghidra-only @ {', '.join(f'{a:#x}' for a in gonly)}")
        if monly:
            print(f"        mosura-only @ {', '.join(f'{a:#x}' for a in monly)}")


if __name__ == "__main__":
    main()
