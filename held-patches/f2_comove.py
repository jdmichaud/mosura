#!/usr/bin/env python3
"""The pre-registered F2 co-move check (brief section 2 item 3 / section 8).

Prediction recorded in docs/byte-exact-families.md before the experiment:

    if the interim build's difference is result-register-assignment preference, patching the
    allocation dial toward WAR2's preference should move F2's rows TOGETHER WITH the regalloc
    MOV>MOV class. If regalloc moves and F2 doesn't (or vice versa), the unification is wrong.

F2's dial-patch-relevant half is the `selection MOV>LEA` signature (the SHL>LEA half was already
fixed by -5r). The regalloc MOV>MOV class is regalloc-class rows where both sides are MOV.
"""
import collections
import sys


def load(path):
    rows = []
    with open(path) as f:
        hdr = f.readline().rstrip('\n').split('\t')
        for line in f:
            p = line.rstrip('\n').split('\t')
            p += [''] * (len(hdr) - len(p))
            rows.append(dict(zip(hdr, p)))
    return rows


def census(rows):
    f2 = [r for r in rows
          if r['class'] == 'selection' and r['orig_mn'] == 'MOV' and r['cand_mn'] == 'LEA']
    f2rev = [r for r in rows
             if r['class'] == 'selection' and r['orig_mn'] == 'LEA' and r['cand_mn'] == 'MOV']
    ra = [r for r in rows
          if r['class'] == 'regalloc' and r['orig_mn'] == 'MOV' and r['cand_mn'] == 'MOV']
    raall = [r for r in rows if r['class'] == 'regalloc']
    return {
        'F2 selection MOV>LEA': (len(f2), len({r['fn_va'] for r in f2})),
        'selection LEA>MOV': (len(f2rev), len({r['fn_va'] for r in f2rev})),
        'regalloc MOV>MOV': (len(ra), len({r['fn_va'] for r in ra})),
        'regalloc (all)': (len(raall), len({r['fn_va'] for r in raall})),
        'ALL rows': (len(rows), len({r['fn_va'] for r in rows})),
    }


def main():
    base, patched = sys.argv[1], sys.argv[2]
    b, p = census(load(base)), census(load(patched))
    print(f'{"class":26s} {"baseline rows":>14s} {"patched rows":>13s} {"delta":>9s}   '
          f'{"base fns":>8s} {"patch fns":>9s}')
    for k in b:
        br, bf = b[k]
        pr, pf = p[k]
        d = pr - br
        print(f'{k:26s} {br:14d} {pr:13d} {d:+9d}   {bf:8d} {pf:9d}')
    print()
    braF2, praF2 = b['F2 selection MOV>LEA'][0], p['F2 selection MOV>LEA'][0]
    braRA, praRA = b['regalloc MOV>MOV'][0], p['regalloc MOV>MOV'][0]
    def pct(a, c):
        return 'n/a' if a == 0 else f'{100.0 * (c - a) / a:+.1f}%'
    print(f'F2 (selection MOV>LEA) moved {pct(braF2, praF2)}; '
          f'regalloc MOV>MOV moved {pct(braRA, praRA)}')


if __name__ == '__main__':
    main()
