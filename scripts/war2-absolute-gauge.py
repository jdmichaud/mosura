#!/usr/bin/env python3
"""ABSOLUTE quality gauge for WAR2: mosura's emitted C vs GHIDRA's, per function.

WHY THIS EXISTS
    A differential scan (this build vs the last build) can only ever see *incremental* loss, so a
    defect present on BOTH sides is structurally invisible to it. That is not a subtlety: a
    92-function call-dropping class sat in master unnoticed for a whole campaign because every scan
    we ran was differential. Differential scans are the right tool for ATTRIBUTION ("did this change
    cause it") and useless for DETECTION.

    So this gauge is ABSOLUTE — it compares against an external reference, never against ourselves.

CHOICE OF REFERENCE
    Ghidra's own per-function decompilation of the same bytes (scripts/ghidra-decompile-war2.sh
    --all). Do NOT substitute a linear disassembly sweep of the original bytes: a linear sweep
    decodes padding and inline data as instructions and overstates the true call count by ~2.3x,
    which once produced a completely wrong headline ("455 functions, 41% of calls").

    Ghidra is not ground truth — the binary is — but it is a decompiler that gets these functions
    right, so a deficit against it is a real defect with a known-good rendering to diff against.

USAGE
    scripts/war2-absolute-gauge.py [--sweep ghidra-all.txt] [--src <dir>] [--manifest <tsv>]
                                   [--top N] [--list-deficits <file>]

    Regenerate the sweep with:  OUT=ghidra-all.txt scripts/ghidra-decompile-war2.sh --all
"""
import argparse
import os
import re
import sys

# --- counting, with the two traps that have actually bitten us -------------------------------
CALL = re.compile(r'\b(?:func_0x[0-9a-fA-F]+|FUN_[0-9a-fA-F]+)\s*\(')


def count_calls(text: str, own_va: str) -> int:
    """Rendered call sites in `text`.

    TRAP 1: an `extern` declaration matches a call regex — `extern int func_0x1ba38();` looks
            exactly like a call site. Skip lines starting with `extern`.
    TRAP 2: filtering out "the function's own definition line" with a pattern that tolerates
            leading whitespace eats every INDENTED line containing a `FUN_xxxx()` CALL. That
            under-counted Ghidra as emitting 1 call for a function that emits 4. The definition
            line is at COLUMN 0 and names THIS function; require both.
    """
    own = own_va.lstrip('0') or '0'
    own_def = re.compile(r'\bFUN_0*' + own + r'\s*\(')
    n = 0
    for line in text.split('\n'):
        if line.startswith('extern'):
            continue
        if line and not line[0].isspace() and own_def.search(line):
            continue
        n += len(CALL.findall(line))
    return n


def split_sweep(path: str) -> dict:
    """Split `ghidra-decompile-war2.sh` output into {va8: c_text}."""
    out, cur, buf = {}, None, []
    with open(path) as fh:
        for line in fh:
            m = re.match(r'^===== FUNC ([0-9a-fA-F]+) =====', line)
            if m:
                if cur:
                    out[cur] = ''.join(buf)
                cur, buf = m.group(1).lower().zfill(8), []
            else:
                buf.append(line)
    if cur:
        out[cur] = ''.join(buf)
    return out


# --- metrics ---------------------------------------------------------------------------------
# Each metric: name -> (extract_from_text(text, va) -> int, "units"). Add absolute metrics here;
# the report machinery below is metric-agnostic on purpose.
METRICS = {
    'calls': (count_calls, 'call sites'),
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--sweep', default='ghidra-all.txt', help="Ghidra sweep output")
    ap.add_argument('--src', default=None, help="dir of mosura-emitted .c (default war2-survey/src)")
    ap.add_argument('--manifest', default=None, help="war2-survey/manifest.tsv")
    ap.add_argument('--top', type=int, default=15)
    ap.add_argument('--list-deficits', default=None, help="write deficit VAs (worst first) here")
    a = ap.parse_args()

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    survey = os.path.join(os.path.dirname(root), 'war2-survey')
    manifest = a.manifest or os.path.join(survey, 'manifest.tsv')
    src = a.src or os.path.join(survey, 'src')

    for p in (a.sweep, manifest, src):
        if not os.path.exists(p):
            print(f"ERROR: missing {p}", file=sys.stderr)
            return 1

    gh = split_sweep(a.sweep)
    va2idx = {}
    for line in open(manifest):
        f = line.rstrip('\n').split('\t')
        if len(f) < 9 or f[0] == 'idx':
            continue
        va2idx[f[1]] = f[0]

    print("=== WAR2 ABSOLUTE GAUGE (mosura vs Ghidra, per function) ===")
    print(f"reference: {a.sweep} ({len(gh)} functions)")
    for mname, (fn, units) in METRICS.items():
        rows = []
        for va, gtext in gh.items():
            idx = va2idx.get(va)
            if not idx:
                continue
            p = os.path.join(src, f'{idx}.c')
            if not os.path.exists(p):
                continue
            rows.append((va, fn(gtext, va), fn(open(p).read(), va)))
        if not rows:
            print(f"  {mname}: no comparable functions"); continue
        tg = sum(r[1] for r in rows)
        tm = sum(r[2] for r in rows)
        deficit = sorted((r for r in rows if r[2] < r[1]), key=lambda r: r[2] - r[1])
        missing = sum(r[1] - r[2] for r in deficit)
        pct = (100.0 * tm / tg) if tg else 0.0
        print(f"\n  [{mname}] {units}")
        print(f"    functions compared : {len(rows)}")
        print(f"    Ghidra             : {tg}")
        print(f"    mosura             : {tm}   ({pct:.1f}% of Ghidra)")
        print(f"    DEFICIT            : {len(deficit)} functions, {missing} {units} missing")
        for va, g, m in deficit[:a.top]:
            print(f"      {va}  ghidra={g:3d}  mosura={m:3d}  (-{g - m})")
        if a.list_deficits and mname == 'calls':
            with open(a.list_deficits, 'w') as out:
                out.write('\n'.join(r[0] for r in deficit) + '\n')
            print(f"    deficit VAs (worst first) -> {a.list_deficits}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
