#!/usr/bin/env python3
"""WRONG-CODE scan over a directory of mosura-emitted C. A standing land gate.

WHY THIS EXISTS
    Every land battery run before 2026-07-30 reported "clean" while 11 WAR2 functions contained a
    `goto LAB_x` whose label was NEVER DEFINED. That cannot compile — unambiguous wrong code — and
    nothing looked for it. Two separate batteries (including one that was reviewed and ratified)
    over-claimed clean on that blind spot. Before it, the empty-body scan had missed `switch(){}`
    the same way.

    So the rule this file enforces on itself: A SCAN PREDICATE'S SILENCE IS ONLY AS BROAD AS THE
    PREDICATE. Every shape below is named, and the shapes deliberately NOT covered are listed in
    UNCOVERED so a future reader does not read "0 findings" as "no wrong code".

CLASSES
  BLOCKING (real wrong code — these must not increase, and ideally reach 0)
    undefined-label   a `goto LAB_x` with no `LAB_x:` anywhere in the same file. Cannot compile.
                      Cause seen so far: a block was removed while branches into it survived.
    empty-switch      `switch (...) { }` — the dispatch was destroyed; every case is gone.
    empty-while-true  `while (true) { }` — an infinite empty loop, i.e. a deleted loop body.

  INFORMATIONAL (NOT a defect signal — do not gate on these)
    empty-for         `for (...) { }`. A skip-whitespace / pointer-walk loop does all its work in
                      the increment, and GHIDRA EMITS THE SAME EMPTY BODY:
                        ghidra: for (; *param_1 == ' '; param_1 = param_1 + 1) {
                        mosura: for (param_5 = param_5; *param_5 == 0x20; param_5 = param_5 + 1) {}
                      Counted so a change is visible, never gated. Treating a 2->3 move here as a
                      regression was caught before it was reported; do not re-buy it.

UNCOVERED — known wrong-code shapes this scan does NOT detect (file them, don't assume absence)
    - a label defined but never reachable (dead block kept rather than dropped)
    - `case` values that duplicate or that no longer cover the recovered jump-table targets
    - a variable read before any assignment (mosura emits these; the compiler catches some)
    - a call dropped entirely  -> that is the absolute call gauge's job, not this scan's
    - a wrong-but-compilable expression -> only the recompile comparison can see it
    - declared-but-unused / unreferenced parameters, and type errors generally -> wcc386's job

USAGE
    scripts/war2-wrongcode-scan.py <src-dir> [<baseline-src-dir>]
    With a baseline, prints the per-class delta and exits nonzero if any BLOCKING class grew.
"""
import os
import re
import sys
import glob

GOTO = re.compile(r'\bgoto\s+(LAB_[0-9a-fA-F]+)\s*;')
LABEL = re.compile(r'^[ \t]*(LAB_[0-9a-fA-F]+)[ \t]*:', re.M)
OWN_DEF = re.compile(r'^\w[^\n]*\bFUN_([0-9a-fA-F]{8})\s*\(', re.M)

BLOCKING_SHAPES = {
    'empty-switch': re.compile(r'switch\s*\([^)]*\)\s*\{\s*\}'),
    'empty-while-true': re.compile(r'while\s*\(\s*(?:true|1)\s*\)\s*\{\s*\}'),
}
INFO_SHAPES = {
    'empty-for': re.compile(r'for\s*\([^)]*\)\s*\{\s*\}'),
    'empty-while': re.compile(r'while\s*\([^)]*\)\s*\{\s*\}'),
}


def scan(src: str) -> dict:
    """{class: {va: count}} — keyed by the FUN_ each .c defines, never the manifest idx."""
    out = {k: {} for k in list(BLOCKING_SHAPES) + list(INFO_SHAPES) + ['undefined-label']}
    for path in sorted(glob.glob(os.path.join(src, '*.c'))):
        text = open(path, errors='replace').read()
        m = OWN_DEF.search(text)
        key = m.group(1).lower() if m else os.path.basename(path)
        defined = set(LABEL.findall(text))
        missing = sorted({t for t in GOTO.findall(text)} - defined)
        if missing:
            out['undefined-label'][key] = missing
        for cls, rx in {**BLOCKING_SHAPES, **INFO_SHAPES}.items():
            n = len(rx.findall(text))
            if n:
                out[cls][key] = n


        # empty-while-true is a subset of empty-while; report both, gate only the former.
    return out


def total(d: dict) -> int:
    return sum(len(v) if isinstance(v, list) else v for v in d.values())


def report(name: str, res: dict) -> None:
    print(f"\n=== {name} ===")
    for cls in ['undefined-label'] + list(BLOCKING_SHAPES):
        d = res[cls]
        print(f"  [BLOCKING] {cls:18} {total(d):4}  in {len(d)} functions")
        if cls == 'undefined-label':
            for va, labs in sorted(d.items()):
                print(f"                 {va}: {' '.join(labs)}")
    for cls in INFO_SHAPES:
        print(f"  [info]     {cls:18} {total(res[cls]):4}  in {len(res[cls])} functions")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    new = scan(sys.argv[1])
    report(os.path.basename(sys.argv[1].rstrip('/')), new)
    if len(sys.argv) < 3:
        return 0
    base = scan(sys.argv[2])
    report(os.path.basename(sys.argv[2].rstrip('/')) + " (baseline)", base)
    print("\n=== DELTA (baseline -> new) ===")
    grew = []
    for cls in ['undefined-label'] + list(BLOCKING_SHAPES):
        b, n = total(base[cls]), total(new[cls])
        flag = ''
        if n > b:
            flag = '  ⛔ GREW — BLOCKING'
            grew.append(cls)
        elif n < b:
            flag = '  ✅ improved'
        print(f"  [BLOCKING] {cls:18} {b:4} -> {n:4}{flag}")
        # membership, not just totals: a same-size set can still be a different set
        onlyb, onlyn = sorted(set(base[cls]) - set(new[cls])), sorted(set(new[cls]) - set(base[cls]))
        if onlyb:
            print(f"                 fixed: {' '.join(onlyb)}")
        if onlyn:
            print(f"                 NEWLY affected: {' '.join(onlyn)}")
            if cls not in grew:
                grew.append(cls)
    for cls in INFO_SHAPES:
        b, n = total(base[cls]), total(new[cls])
        print(f"  [info]     {cls:18} {b:4} -> {n:4}   (never gated — see the module docstring)")
    if grew:
        print(f"\n⛔ BLOCKING regression in: {', '.join(grew)}")
        return 1
    print("\n✅ no BLOCKING class grew and no function is newly affected")
    return 0


if __name__ == '__main__':
    sys.exit(main())
