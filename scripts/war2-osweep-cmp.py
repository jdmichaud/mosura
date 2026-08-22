#!/usr/bin/env python3
"""Compare two oracle-sweep runs (idx-joined): score deltas, insn-weighted by a recompile_check
verdict table: usage: war2-osweep-cmp.py <old-sweep.tsv> <new-sweep.tsv> <rec.tsv>."""
import sys
A = sys.argv[1]; B = sys.argv[2]
REC = sys.argv[3] if len(sys.argv) > 3 else '/data/be2/zc29-rec.tsv'
meta = {}
for line in open(REC):
    c = line.rstrip('\n').split('\t')
    if len(c) > 10 and c[0] != 'idx':
        try: meta[c[0]] = (c[3], int(c[8] or 0))
        except ValueError: pass
def load(p):
    d = {}
    for line in open(p):
        c = line.rstrip('\n').split('\t')
        if len(c) >= 7 and c[3] == 'OK':
            d[c[0]] = (c[2], float(c[4]), int(c[5]), int(c[6]))
    return d
a, b = load(A), load(B)
common = sorted(set(a) & set(b))
up = down = same = 0; wnet = 0.0; net = 0.0; movers = []
for i in common:
    da, db = a[i][1], b[i][1]; w = meta.get(i, ('?', 0))[1]
    if db > da + 1e-9: up += 1
    elif db < da - 1e-9: down += 1
    else: same += 1
    net += db - da; wnet += (db - da) * w
    if abs(db - da) > 1e-9: movers.append((db - da, w, i, a[i][0], da, db, a[i][2], b[i][2], a[i][3], meta.get(i, ('?', 0))[0]))
print(f"joined {len(common)}: up {up} down {down} same {same}; net score {net:+.3f}; weighted net {wnet:+.1f} (mean score {sum(a[i][1] for i in common)/len(common):.4f} -> {sum(b[i][1] for i in common)/len(common):.4f})")
movers.sort()
print("== largest drops (delta, w, name, old->new, mosura lines old->new, ghidra lines, verdict):")
for m in movers[:15]:
    print(f"  {m[0]:+.3f} w={m[1]:<4} {m[3]} {m[4]:.3f}->{m[5]:.3f} m={m[6]}->{m[7]} g={m[8]} {m[9]}")
print("== largest gains:")
for m in movers[::-1][:15]:
    print(f"  {m[0]:+.3f} w={m[1]:<4} {m[3]} {m[4]:.3f}->{m[5]:.3f} m={m[6]}->{m[7]} g={m[8]} {m[9]}")
