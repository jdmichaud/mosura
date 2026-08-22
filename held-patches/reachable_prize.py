#!/usr/bin/env python3
"""Of the functions holding a REACHABLE (equal-stallable) transposed pair, how many would become
byte-exact if the pair alone were fixed? That is the EXACT prize; the rest is WGSS only."""
import collections
import sys

sys.path.insert(0, '/data/dialpatch')
from transposed_census import load, stallable   # noqa: E402

div, rec = sys.argv[1], sys.argv[2]
rows = load(div)
byfn = collections.defaultdict(list)
for r in rows:
    byfn[r['fn_va']].append(r)

verd = {}
with open(rec) as f:
    hdr = f.readline().rstrip('\n').split('\t')
    for line in f:
        p = line.rstrip('\n').split('\t')
        p += [''] * (len(hdr) - len(p))
        d = dict(zip(hdr, p))
        verd[d['va']] = d

reach_fns = {}
for va, rs in byfn.items():
    rs.sort(key=lambda r: int(r['ci']) if r['ci'].isdigit() else 0)
    for a, b in zip(rs, rs[1:]):
        if not (a['ci'].isdigit() and b['ci'].isdigit()):
            continue
        if int(b['ci']) != int(a['ci']) + 1:
            continue
        if a['orig_text'] != b['cand_text'] or b['orig_text'] != a['cand_text']:
            continue
        s1, s2 = stallable(a['cand_text']), stallable(b['cand_text'])
        if s1 is not None and s1 == s2:
            reach_fns.setdefault(va, []).append((a, b))

print(f'{len(reach_fns)} functions hold at least one REACHABLE transposed pair')
print()
exact_prize, wgss_only = [], []
for va, prs in sorted(reach_fns.items()):
    total_rows = len(byfn[va])
    covered = 2 * len(prs)
    v = verd.get(va, {})
    if total_rows == covered:
        exact_prize.append((va, v, total_rows))
    else:
        wgss_only.append((va, v, total_rows, covered))

print(f'--- would become EXACT (the pair is the function\'s ONLY divergence): '
      f'{len(exact_prize)} ---')
for va, v, n in exact_prize:
    print(f"  {v.get('idx','?')} {v.get('name',va):22s} {v.get('verdict','?'):11s} "
          f"sim={v.get('sim','?'):>5s}  rows={n}  classes={v.get('classes','')}")
print()
print(f'--- WGSS only (other divergences remain): {len(wgss_only)} functions ---')
for va, v, n, c in sorted(wgss_only, key=lambda t: -t[3])[:12]:
    print(f"  {v.get('idx','?')} {v.get('name',va):22s} {v.get('verdict','?'):11s} "
          f"sim={v.get('sim','?'):>5s}  {c} of {n} rows covered")
