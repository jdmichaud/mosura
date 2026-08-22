#!/usr/bin/env python3
"""Rank a WAR2 oracle sweep (war2_oracle_sweep sweep.tsv) joined with a recompile_check
verdict table (for verdict + insn weight): usage: war2-osweep-rank.py <sweep.tsv> <rec.tsv>. lowest scores, largest
weighted divergence, and line-count ratios (dropped/duplicated code shows as a ratio)."""
import sys, collections
W = sys.argv[1] if len(sys.argv) > 1 else '/data/be2/osweep/sweep.tsv'
REC = sys.argv[2] if len(sys.argv) > 2 else '/data/be2/zc29-rec.tsv'
meta = {}
for line in open(REC):
    c = line.rstrip('\n').split('\t')
    if len(c) > 10 and c[0] != 'idx':
        try: meta[c[0]] = (c[3], float(c[6] or 0), int(c[8] or 0), c[10])
        except ValueError: pass
rows = []
st = collections.Counter()
for line in open(W):
    c = line.rstrip('\n').split('\t')
    if len(c) < 7: continue
    st[c[3]] += 1
    if c[3] != 'OK': continue
    idx, va, name, score, ml, gl = c[0], c[1], c[2], float(c[4]), int(c[5]), int(c[6])
    m = meta.get(idx, ('?', 0.0, 0, ''))
    rows.append((score, idx, name, m[0], m[1], m[2], ml, gl, m[3]))
print("status:", dict(st))
sc = [r[0] for r in rows]
print(f"scored {len(rows)}: mean {sum(sc)/len(sc):.4f}; ==1.0: {sum(1 for s in sc if s >= 0.9999)}; <0.8: {sum(1 for s in sc if s < 0.8)}; <0.6: {sum(1 for s in sc if s < 0.6)}")
print("\n== lowest 25 by score:")
for r in sorted(rows)[:25]:
    print(f"  {r[0]:.3f} {r[2]} {r[3]:<11} sim={r[4]:.3f} w={r[5]:<4} lines m/g={r[6]}/{r[7]}")
print("\n== largest weighted divergence (1-score)*w, non-EXACT:")
for r in sorted(rows, key=lambda r: -(1 - r[0]) * r[5])[:25]:
    if r[3] != 'EXACT':
        print(f"  {(1-r[0])*r[5]:6.1f} {r[2]} score={r[0]:.3f} {r[3]:<11} sim={r[4]:.3f} w={r[5]} lines m/g={r[6]}/{r[7]}")
print("\n== line-count ratio outliers (mosura/ghidra < 0.7 or > 1.4), non-EXACT:")
for r in sorted(rows, key=lambda r: abs((r[6] / max(r[7], 1)) - 1), reverse=True)[:20]:
    ratio = r[6] / max(r[7], 1)
    if (ratio < 0.7 or ratio > 1.4) and r[3] != 'EXACT':
        print(f"  ratio={ratio:.2f} {r[2]} score={r[0]:.3f} {r[3]:<11} w={r[5]} lines m/g={r[6]}/{r[7]}")
