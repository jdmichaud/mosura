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
    use-before-def    a declared local READ before its first assignment, in text order. Added
                      2026-08-05 after this scan sat GREEN through two separate loop-shape
                      defects it structurally could not see (e760926's hoisted while-condition
                      and the for-header regression that held a5107c5) — "read before any
                      assignment" had been sitting in the UNCOVERED list below the whole time,
                      and both were caught only by hand-diffing changed functions. Validated
                      against four stamped emit images rather than asserted: it flags
                      FUN_00016764/piVar2, the exact use-before-def e760926 removed, and it
                      GROWS 118 -> 119 on the held-back state, which is the growth that should
                      have blocked. Movement is by set membership, not totals.
    falls-off-end     a NON-VOID function whose body can reach the closing brace without a
                      `return` — one control path returns garbage instead of doing what the
                      machine code does. This one is the reason for the rule above: it was found
                      by hand while reading output, NOT by this scan, and it had been sitting in
                      two functions the whole time. Cause seen so far: a `BlockGoto` was keyed on
                      its source's exit BASIC BLOCK instead of on the composite node Ghidra's
                      `newBlockGoto` wraps (block.cc:1702), so the goto was emitted inside a
                      nested `if` and the composite's other path fell through to nothing.
                      A body ending `} while( true );` is NOT counted — the end is unreachable.

  INFORMATIONAL (NOT a defect signal — do not gate on these)
    empty-for         `for (...) { }`. A skip-whitespace / pointer-walk loop does all its work in
                      the increment, and GHIDRA EMITS THE SAME EMPTY BODY:
                        ghidra: for (; *param_1 == ' '; param_1 = param_1 + 1) {
                        mosura: for (param_5 = param_5; *param_5 == 0x20; param_5 = param_5 + 1) {}
                      Counted so a change is visible, never gated. Treating a 2->3 move here as a
                      regression was caught before it was reported; do not re-buy it.
    uninit-read       a declared local NEVER assigned anywhere in the function. Real wrong code,
                      but it is the PROTOTYPE-RECOVERY gap, not a structuring one: Ghidra names
                      these `in_EAX` / `extraout_ECX` / `unaff_EBX` and mosura emits a bare local
                      (those four prefixes are exempted from both this and use-before-def, since
                      they are uninitialized BY CONSTRUCTION and not defects). It sat at exactly
                      812 across all four images measured — dead flat through changes that moved
                      use-before-def by 17 — so it is a stable background that structuring work
                      cannot move. Informational until the prototype work lands; gate it then.

UNCOVERED — known wrong-code shapes this scan does NOT detect (file them, don't assume absence)
    - a goto emitted at the WRONG NESTING LEVEL that still leaves a `return` reachable at the end
      (falls-off-end sees only the variant where nothing terminates the body)
    - a trailing `switch` with a `default:` arm that FALLS THROUGH rather than returning — excluded
      from falls-off-end to avoid the FUN_00056c3c false positive, so this variant is invisible
    - a trailing `while (cond)` / `for (;;)` whose condition is provably always true (only the
      literal `while( true )` tail is recognised)
    - a label defined but never reachable (dead block kept rather than dropped)
    - `case` values that duplicate or that no longer cover the recovered jump-table targets
    - ⭐ a STALE value — a statement correctly written ONCE before a loop that should re-execute
      INSIDE its condition every iteration. The variable IS defined before use, so use-before-def
      cannot see it, and this is the majority of the defect it was added for: of the 7 functions
      the held a5107c5 would have broken, use-before-def saw only 2 (FUN_00033b6c/pcVar3 and
      FUN_00064e5e/uVar2). The other 5 — 0007002b, 000701b9, 0007500b, 000729cd, 000504ac —
      loaded a real value, then tested that one value forever while the pointer walked away from
      it. Detecting them needs a LOOP-CARRIED analysis: a variable read in a loop condition whose
      only assignment is outside the loop, where the machine code re-reads. Not attempted here;
      the honest position is that this scan's silence still does not cover the class that
      produced both of the last two defects.
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


FN_HEAD = re.compile(r'^(\S.*?)\b(FUN_[0-9a-fA-F]+)\s*\(')

# A local declaration in the emitter's own style: `int4 iVar1;`, `xunknown4 * pxVar2;`,
# `xunknown1 axStack_1c [24];`. Group 2 is the array suffix, when present.
DECL = re.compile(r'^\s*[A-Za-z_]\w*\s*\**\s*\**\s*([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*;\s*$')
# Uninitialized BY CONSTRUCTION, not defects: Ghidra's names for a value arriving in a register,
# and formal parameters. Counting these would bury the real findings under the prototype gap.
EXEMPT_LOCAL = re.compile(r'^(param_\d+|in_[A-Z]|extraout_|unaff_)')


def uninitialized_reads(text: str) -> tuple:
    """(use-before-def, uninit-read) as `[(FUN_, var), ...]` pairs, per function in `text`.

    A local is `use-before-def` when its first READ precedes its first WRITE in text order, and
    `uninit-read` when it is never written at all.

    ⚠️ THE DECLARATION IS NOT A READ. The first version of this counted `int4 iVar1;` as a read of
    `iVar1`, which flagged 1072 of 1303 functions and — far worse — produced the SAME total on
    four different images, so it looked stable while measuring nothing. Equal totals across a real
    change is the signal that a predicate is broken, not that the code is unchanged; scanning
    starts at the first statement for exactly that reason.

    Arrays are excluded: the storage exists, so indexing one is not a use-before-def.
    """
    ubd, uninit = [], []
    lines = text.split('\n')
    i = 0
    while i < len(lines):
        m = FN_HEAD.match(lines[i])
        if not (m and i + 1 < len(lines) and lines[i + 1].strip() == '{'):
            i += 1
            continue
        name, depth, body, j = m.group(2), 0, [], i + 1
        while j < len(lines):
            depth += lines[j].count('{') - lines[j].count('}')
            body.append(lines[j])
            j += 1
            if depth == 0:
                break
        i = j
        inner = body[1:-1]                             # drop the body's own braces
        locs, first_stmt = [], len(inner)
        for k, l in enumerate(inner):
            d = DECL.match(l)
            if d:
                if d.group(2):
                    continue
                if not EXEMPT_LOCAL.match(d.group(1)):
                    locs.append(d.group(1))
            elif l.strip():
                first_stmt = k
                break
        stmts = inner[first_stmt:]
        for v in locs:
            wr = re.compile(r'(?<![\w])' + re.escape(v) + r'\s*=(?!=)')
            rd = re.compile(r'(?<![\w])' + re.escape(v) + r'(?![\w])')
            fw = fr = None
            for k, l in enumerate(stmts):
                for mm in wr.finditer(l):
                    p = k * 100000 + mm.start()
                    if fw is None or p < fw:
                        fw = p
                for mm in rd.finditer(l):
                    if wr.match(l, mm.start()):
                        continue                       # this occurrence IS the assignment target
                    p = k * 100000 + mm.start()
                    if fr is None or p < fr:
                        fr = p
            if fr is None:
                continue                               # never read: dead declaration, not a defect
            if fw is None:
                uninit.append((name, v))
            elif fr < fw:
                ubd.append((name, v))
    return ubd, uninit


def falls_off_end(text: str) -> list:
    """Non-void functions in `text` whose body can reach the closing brace with no `return`.

    Brace-counted rather than regex-matched: the shape is a property of the LAST statement at the
    body's own depth, which no single pattern can see.

    Two tails do NOT count, because the end of the body is unreachable and GHIDRA EMITS THE SAME:
      - `} while( true );` — the loop never exits.
      - a trailing `switch` that has a `default:` arm — every value is covered, so if the arms all
        return, so does the function. FUN_00056c3c is the worked example; Ghidra's output for it is
        the same switch with the same missing terminal return. Excluding it is what keeps this
        predicate from crying wolf on a shape that is correct.
    """
    bad = []
    lines = text.split('\n')
    i = 0
    while i < len(lines):
        m = FN_HEAD.match(lines[i])
        if not (m and i + 1 < len(lines) and lines[i + 1].strip() == '{'):
            i += 1
            continue
        ret, name, depth, body, j = m.group(1).strip(), m.group(2), 0, [], i + 1
        while j < len(lines):
            depth += lines[j].count('{') - lines[j].count('}')
            body.append(lines[j])
            j += 1
            if depth == 0:
                break
        i = j
        if ret in ('void', ''):
            continue                                   # falling off a void function is legal
        inner = body[1:-1]                             # drop the body's own braces
        stripped = [l.strip() for l in inner if l.strip()]
        if not stripped:
            continue
        last = stripped[-1]
        if last.startswith(('return', 'goto')) or last.endswith('break;') or last.startswith('} while'):
            continue
        # The construct the body's final `}` closes: walk depth 0 (relative to the body) and keep the
        # last statement that opened a block there.
        depth, tail_opener, tail_from = 0, None, 0
        for k, l in enumerate(inner):
            if depth == 0 and l.strip():
                opener = l.strip()
            depth += l.count('{') - l.count('}')
            if depth == 1 and '{' in l:
                tail_opener, tail_from = opener, k
        if tail_opener and tail_opener.startswith('switch') \
                and any(x.strip().startswith('default:') for x in inner[tail_from:]):
            continue
        bad.append(name)
    return bad


def scan(src: str) -> dict:
    """{class: {va: count}} — keyed by the FUN_ each .c defines, never the manifest idx."""
    out = {k: {} for k in list(BLOCKING_SHAPES) + list(INFO_SHAPES)
           + ['undefined-label', 'falls-off-end', 'use-before-def', 'uninit-read']}
    for path in sorted(glob.glob(os.path.join(src, '*.c'))):
        text = open(path, errors='replace').read()
        m = OWN_DEF.search(text)
        key = m.group(1).lower() if m else os.path.basename(path)
        defined = set(LABEL.findall(text))
        missing = sorted({t for t in GOTO.findall(text)} - defined)
        if missing:
            out['undefined-label'][key] = missing
        off = falls_off_end(text)
        if off:
            out['falls-off-end'][key] = off
        ubd, uninit = uninitialized_reads(text)
        if ubd:
            out['use-before-def'][key] = [f'{fn}:{v}' for fn, v in ubd]
        if uninit:
            out['uninit-read'][key] = len(uninit)
        for cls, rx in {**BLOCKING_SHAPES, **INFO_SHAPES}.items():
            n = len(rx.findall(text))
            if n:
                out[cls][key] = n


        # empty-while-true is a subset of empty-while; report both, gate only the former.
    return out


def total(d: dict) -> int:
    return sum(len(v) if isinstance(v, list) else v for v in d.values())


def members(d: dict) -> set:
    """The individual findings, so a delta compares what actually changed.

    For a list-valued class the member is `<function>/<finding>` — one function swapping one
    undefined label (or one use-before-def variable) for another is a real change, and keying the
    comparison on the function alone would report it as a wash. For a count-valued class the
    function is all there is.
    """
    out = set()
    for k, v in d.items():
        if isinstance(v, list):
            out.update(f'{k}/{item}' for item in v)
        else:
            out.add(k)
    return out


def report(name: str, res: dict) -> None:
    print(f"\n=== {name} ===")
    for cls in ['undefined-label', 'falls-off-end', 'use-before-def'] + list(BLOCKING_SHAPES):
        d = res[cls]
        print(f"  [BLOCKING] {cls:18} {total(d):4}  in {len(d)} functions")
        if cls in ('undefined-label', 'falls-off-end'):
            for va, labs in sorted(d.items()):
                print(f"                 {va}: {' '.join(labs)}")
    for cls in list(INFO_SHAPES) + ['uninit-read']:
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
    for cls in ['undefined-label', 'falls-off-end', 'use-before-def'] + list(BLOCKING_SHAPES):
        b, n = total(base[cls]), total(new[cls])
        flag = ''
        if n > b:
            flag = '  ⛔ GREW — BLOCKING'
            grew.append(cls)
        elif n < b:
            flag = '  ✅ improved'
        print(f"  [BLOCKING] {cls:18} {b:4} -> {n:4}{flag}")
        # Membership, not just totals: a same-size set can still be a different set — and for the
        # list-valued classes the members are the individual findings, not the functions holding
        # them, so one function trading `iVar1` for `iVar2` is a change and not a wash.
        onlyb, onlyn = sorted(members(base[cls]) - members(new[cls])), sorted(members(new[cls]) - members(base[cls]))
        if onlyb:
            print(f"                 fixed: {' '.join(onlyb)[:400]}")
        if onlyn:
            print(f"                 NEWLY affected: {' '.join(onlyn)[:400]}")
            if cls not in grew:
                grew.append(cls)
    for cls in list(INFO_SHAPES) + ['uninit-read']:
        b, n = total(base[cls]), total(new[cls])
        print(f"  [info]     {cls:18} {b:4} -> {n:4}   (never gated — see the module docstring)")
    if grew:
        print(f"\n⛔ BLOCKING regression in: {', '.join(grew)}")
        return 1
    print("\n✅ no BLOCKING class grew and no function is newly affected")
    return 0


if __name__ == '__main__':
    sys.exit(main())
