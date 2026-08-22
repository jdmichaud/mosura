#!/usr/bin/env python3
"""Size the populations a declaration-order arm would touch, on a given -rec.tsv + recovered tree.

Three populations matter:
  CEILING   SAME_SHAPE with a regalloc class and 2..4 movable register temps -- the pass/fail set.
  RISK      currently-EXACT functions with >=2 movable register temps -- the blast radius. The
            handoff requires ALL of these be compiled at probe scale, not sampled.
  REACH     every function with >=2 movable register temps, by verdict -- the arm's total reach.
"""
import collections
import os
import re
import sys

DECL = re.compile(r'^  ([A-Za-z_][A-Za-z0-9_ ]*?)\s+(\*?\s*)([A-Za-z_][A-Za-z0-9_]*)\s*(\[[^\]]*\])?;\s*$')
FROZEN = re.compile(r'Stack|^local_|^in_|^unaff_|^extraout_')


def split_decls(text):
    lines = text.split('\n')
    open_idx = next((i for i, l in enumerate(lines) if l.strip() == '{'), None)
    if open_idx is None:
        return None
    i, decls = open_idx + 1, []
    while i < len(lines):
        m = DECL.match(lines[i])
        if not m:
            break
        decls.append((lines[i], m.group(3)))
        i += 1
    return lines[:open_idx + 1], decls, lines[i:]


def load(path):
    rows = []
    with open(path) as f:
        hdr = f.readline().rstrip('\n').split('\t')
        for line in f:
            p = line.rstrip('\n').split('\t')
            p += [''] * (len(hdr) - len(p))
            rows.append(dict(zip(hdr, p)))
    return rows


def main():
    rec = sys.argv[1]
    src = sys.argv[2]
    rows = load(rec)
    per = {}
    for r in rows:
        try:
            text = open(os.path.join(src, r['idx'] + '.c')).read()
        except OSError:
            continue
        parts = split_decls(text)
        if not parts:
            continue
        movable = [i for i, (_, nm) in enumerate(parts[1]) if not FROZEN.search(nm)]
        per[r['idx']] = (r, len(movable))

    by_verdict = collections.Counter()
    mov_hist = collections.Counter()
    for idx, (r, n) in per.items():
        if n >= 2:
            by_verdict[r['verdict']] += 1
            mov_hist[min(n, 8)] += 1

    print(f'{rec}: {len(rows)} functions, {len(per)} with a readable declaration block')
    print()
    print('--- REACH: functions with >=2 movable register temps, by verdict ---')
    for v, c in by_verdict.most_common():
        print(f'  {v:14s} {c:5d}')
    print(f'  {"TOTAL":14s} {sum(by_verdict.values()):5d}')
    print()
    print('--- movable-temp count histogram (>=2 only; 8 means 8 or more) ---')
    for k in sorted(mov_hist):
        print(f'  {k:2d} temps  {mov_hist[k]:5d}   ({"n! = %d" % __import__("math").factorial(k)})')
    print()
    risk = [(idx, r) for idx, (r, n) in per.items() if n >= 2 and r['verdict'] == 'EXACT']
    print(f'--- RISK: currently-EXACT with >=2 movable temps = {len(risk)} functions ---')
    print('    (the handoff requires ALL of these compiled at probe scale, not sampled)')
    print()
    ceil = [(idx, r, n) for idx, (r, n) in per.items()
            if r['verdict'] == 'SAME_SHAPE' and 'regalloc' in r['classes'] and 2 <= n <= 4]
    print(f'--- CEILING candidate set = {len(ceil)} functions ---')
    for idx, r, n in sorted(ceil):
        print(f'  {idx} {r["name"]:22s} sim={r["sim"]:>5s} movable={n}  {r["classes"]}')


if __name__ == '__main__':
    main()
