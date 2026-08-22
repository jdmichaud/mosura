#!/usr/bin/env python3
"""List the currently-EXACT functions with >=2 movable register temps -- the blast radius the
handoff requires be probed in full, not sampled."""
import re
import sys

DECL = re.compile(r'^  ([A-Za-z_][A-Za-z0-9_ ]*?)\s+(\*?\s*)([A-Za-z_][A-Za-z0-9_]*)\s*(\[[^\]]*\])?;\s*$')
FROZEN = re.compile(r'Stack|^local_|^in_|^unaff_|^extraout_')

rec, src, want = sys.argv[1], sys.argv[2], sys.argv[3]
rows = []
with open(rec) as f:
    hdr = f.readline().rstrip('\n').split('\t')
    for line in f:
        p = line.rstrip('\n').split('\t')
        p += [''] * (len(hdr) - len(p))
        rows.append(dict(zip(hdr, p)))

out = []
for r in rows:
    if r['verdict'] != want:
        continue
    try:
        lines = open(f"{src}/{r['idx']}.c").read().split('\n')
    except OSError:
        continue
    oi = next((i for i, l in enumerate(lines) if l.strip() == '{'), None)
    if oi is None:
        continue
    i, decls = oi + 1, []
    while i < len(lines):
        m = DECL.match(lines[i])
        if not m:
            break
        decls.append(m.group(3))
        i += 1
    mov = [d for d in decls if not FROZEN.search(d)]
    if len(mov) >= 2:
        out.append((r['idx'], len(mov)))

print(','.join(i for i, _ in out))
print(f'{len(out)} functions; movable-count histogram: '
      + str({n: sum(1 for _, m in out if m == n) for n in sorted({m for _, m in out})}),
      file=sys.stderr)
