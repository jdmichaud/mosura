#!/usr/bin/env python3
"""Mechanism census over a recompile_check run: WHERE the WGSS loss is (by similarity bucket,
function size, divergence class) and WHAT the divergent rows are (instruction shapes of the
extra/missing/selection/operand-form rows), plus the semantic-vs-form coupling table that
decides whether form divergence (regalloc/selection/operand-form) is independent of semantic
divergence (missing/extra/branch-target) or a consequence of it.

usage: war2-mechanism-census.py <rec.tsv> <div.tsv>   (both from one recompile_check run:
       `--out rec.tsv --divergences div.tsv`)
"""
import sys, re, collections
REC, DIV = sys.argv[1], sys.argv[2]
rec = {}
for line in open(REC):
    c = line.rstrip('\n').split('\t')
    if c[0] != 'idx' and len(c) > 10:
        try: rec[c[1]] = (c[2], c[3], float(c[6]), int(c[8]))
        except ValueError: pass
rows = [l.rstrip('\n').split('\t') for l in open(DIV)]
hdr = rows[0]; rows = rows[1:]; ix = {k: i for i, k in enumerate(hdr)}
W = sum(v[3] for v in rec.values()); L = sum(v[3] * (1 - v[2]) for v in rec.values())
print(f"functions {len(rec)} weight {W} WGSS {1 - L / W:.4f} loss {L:.0f} weighted-insn (0.8 needs loss <= {0.2 * W:.0f})")

def bucket_sim(s): return 'EXACT' if s >= 1 else '[0.8,1)' if s >= .8 else '[0.6,0.8)' if s >= .6 else '[0.4,0.6)' if s >= .4 else '[0.2,0.4)' if s >= .2 else '[0,0.2)'
def bucket_size(w): return '<20' if w < 20 else '20-49' if w < 50 else '50-99' if w < 100 else '100-199' if w < 200 else '200+'
SEM = {'missing', 'branch-target'}; FORM = {'regalloc', 'selection', 'operand-form', 'immediate', 'encoding'}
per = collections.defaultdict(collections.Counter)
for r in rows: per[r[ix['fn_va']]][r[ix['class']]] += 1

print("\n== loss by similarity bucket:")
t = collections.OrderedDict()
for va, (n, v, s, w) in rec.items():
    b = t.setdefault(bucket_sim(s), [0, 0, 0.0]); b[0] += 1; b[1] += w; b[2] += w * (1 - s)
for k in ['EXACT', '[0.8,1)', '[0.6,0.8)', '[0.4,0.6)', '[0.2,0.4)', '[0,0.2)']:
    if k in t: b = t[k]; print(f"  {k:9s} n={b[0]:5d} weight={b[1]:6d} ({100 * b[1] / W:4.1f}%) loss={b[2]:7.0f} ({100 * b[2] / L:4.1f}%)")

print("\n== by function size (orig insns): n EXACT weight WGSS loss(share) | non-equal rows semantic/form/layout:")
t = collections.OrderedDict((k, [0, 0, 0, 0.0, 0, 0, 0]) for k in ['<20', '20-49', '50-99', '100-199', '200+'])
for va, (n, v, s, w) in rec.items():
    b = t[bucket_size(w)]; b[0] += 1; b[1] += v == 'EXACT'; b[2] += w; b[3] += w * (1 - s)
    c = per[va]; b[4] += sum(c[k] for k in SEM); b[5] += sum(c[k] for k in FORM); b[6] += c['layout-shift']
for k, b in t.items():
    print(f"  {k:8s} {b[0]:5d} {b[1]:5d} {b[2]:6d} {1 - b[3] / b[2] if b[2] else 0:.3f} {b[3]:7.0f} ({100 * b[3] / L:4.1f}%) | {b[4]:6d} / {b[5]:6d} / {b[6]:5d}")

print("\n== divergent rows by class:")
tot = collections.Counter(r[ix['class']] for r in rows); s = sum(tot.values())
for k, v in tot.most_common(): print(f"  {k:14s} {v:7d} ({100 * v / s:4.1f}%)")

print("\n== COUPLING (20-199 insn MISMATCH functions): form rows per orig insn, binned by semantic rows per function:")
bins = collections.OrderedDict((k, [0, 0, 0, 0.0]) for k in ['0', '1-2', '3-5', '6-10', '11-20', '21+'])
for va, (n, v, s, w) in rec.items():
    if v != 'MISMATCH' or w < 20 or w >= 200: continue
    c = per[va]; sem = sum(c[k] for k in SEM); form = sum(c[k] for k in FORM)
    k = '0' if sem == 0 else '1-2' if sem <= 2 else '3-5' if sem <= 5 else '6-10' if sem <= 10 else '11-20' if sem <= 20 else '21+'
    b = bins[k]; b[0] += 1; b[1] += w; b[2] += form; b[3] += s * w
for k, b in bins.items():
    if b[0]: print(f"  semantic rows {k:5s}: n={b[0]:4d} weight={b[1]:6d} form rows/insn={b[2] / b[1]:.3f} mean WGSS={b[3] / b[1]:.3f}")

def shape(text):
    t = re.sub(r'0x[0-9a-fA-F]+', 'IMM', (text or '').strip())
    t = re.sub(r'\b(E?[ABCD][XLH]|E?[SD]I|E?[BS]P)\b', 'R', t)
    return re.sub(r'\[R \+ IMM\]', '[R+IMM]', t)
by = collections.defaultdict(collections.Counter); fns = collections.defaultdict(lambda: collections.defaultdict(set))
for r in rows:
    cls = r[ix['class']]
    if cls == 'extra': k = shape(r[ix['cand_text']])
    elif cls == 'missing': k = shape(r[ix['orig_text']])
    elif cls in ('selection', 'operand-form'): k = shape(r[ix['orig_text']]) + '  ->  ' + shape(r[ix['cand_text']])
    else: continue
    by[cls][k] += 1; fns[cls][k].add(r[ix['fn_va']])
for cls in ['missing', 'extra', 'selection', 'operand-form']:
    print(f"\n== {cls} ({tot[cls]} rows): top shapes (rows, functions)")
    for k, v in by[cls].most_common(15): print(f"  {v:6d} {len(fns[cls][k]):4d}  {k}")
