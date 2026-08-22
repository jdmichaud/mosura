#!/usr/bin/env python3
"""Measure the EQUIVALENCE CLASSES of local-declaration permutations.

Two declaration orders that make the allocator produce the same register assignment emit
byte-identical code.  So permutations partition into identical-code classes, and that partition
is measurable WITHOUT the oracle: the original's bytes are used only to label which class (if
any) is the byte-exact one.  That is what makes this an unfitted test of a predicate derived
from source.

Code identity is read off the divergence table: for a SAME_SHAPE function every instruction
aligns, so the sequence of (candidate index, candidate instruction text) rows is a faithful
fingerprint of the emitted code.  Zero rows == byte-exact.

Batched one permutation-round per dosemu session, like declorder_ceiling.py.
"""
import hashlib
import itertools
import json
import os
import re
import shutil
import subprocess
import sys

WAR2 = '/home/jd/WAR2.EXE'
CHECK = '/data/wt-dialpatch-target/release/examples/recompile_check'
WATCOM = '/home/jd/projects/warcraft2-re/tmp/watcom-experiments/watcom_10.0a/WATCOM'

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
        decls.append((lines[i], m.group(1).strip(), m.group(2).strip(), m.group(3)))
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
    rec, src, work, cache = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    only_idx = set(sys.argv[5].split(',')) if len(sys.argv) > 5 else None

    rows = load(rec)
    cands = []
    for r in rows:
        if only_idx is not None and r['idx'] not in only_idx:
            continue
        if only_idx is None:
            if r['verdict'] != 'SAME_SHAPE' or 'regalloc' not in r['classes']:
                continue
        try:
            text = open(os.path.join(src, r['idx'] + '.c')).read()
        except OSError:
            continue
        parts = split_decls(text)
        if not parts:
            continue
        head, decls, tail = parts
        movable = [i for i, d in enumerate(decls) if not FROZEN.search(d[3])]
        if only_idx is None and not (2 <= len(movable) <= 4):
            continue
        if len(movable) < 2:
            continue
        cands.append(dict(idx=r['idx'], name=r['name'], head=head, decls=decls,
                          movable=movable, tail=tail, base=r))
    print(f'candidates: {len(cands)}')
    for c in cands:
        c['perms'] = list(itertools.permutations(c['movable']))
        print(f"  {c['idx']} {c['name']:22s} {len(c['movable'])} movable "
              f"({len(c['perms'])} perms): "
              f"{[c['decls'][i][3] for i in c['movable']]}")
    nrounds = max(len(c['perms']) for c in cands)

    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(os.path.join(work, 'recovered'), exist_ok=True)
    shutil.copy(os.path.join(src, '..', 'prelude.h'), os.path.join(work, 'prelude.h'))
    srcdir = os.path.join(work, 'recovered')

    sigs = {c['idx']: {} for c in cands}     # idx -> {perm_index: signature}
    for k in range(nrounds):
        active = []
        for c in cands:
            if k >= len(c['perms']):
                continue
            perm = c['perms'][k]
            order = list(range(len(c['decls'])))
            for slot, s_i in zip(c['movable'], perm):
                order[slot] = s_i
            body = '\n'.join(c['head'] + [c['decls'][j][0] for j in order] + c['tail'])
            open(os.path.join(srcdir, c['idx'] + '.c'), 'w').write(body)
            active.append(c)
        if not active:
            continue
        out = os.path.join(work, f'r{k}.tsv')
        div = os.path.join(work, f'r{k}-div.tsv')
        subprocess.run([CHECK, WAR2, os.path.join(src, '..', 'manifest.tsv'), srcdir, 'recover',
                        WATCOM, '--only', ','.join(c['name'] for c in active),
                        '--cache', cache, '--out', out, '--divergences', div],
                       capture_output=True, text=True)
        if not os.path.exists(out):
            print(f'round {k}: FAILED')
            continue
        verd = {r['idx']: r for r in load(out)}
        drows = {}
        if os.path.exists(div):
            for r in load(div):
                drows.setdefault(r['idx'], []).append((r['ci'], r['cand_mn'], r['cand_text']))
        for c in active:
            body_rows = drows.get(c['idx'], [])
            sig = hashlib.sha1(repr(sorted(body_rows)).encode()).hexdigest()[:12]
            v = verd.get(c['idx'], {}).get('verdict', '?')
            if v == 'EXACT':
                sig = 'EXACT'
            sigs[c['idx']][k] = sig
        print(f'round {k}: {sum(1 for c in active if sigs[c["idx"]][k] == "EXACT")} EXACT '
              f'of {len(active)}', flush=True)

    print()
    result = {}
    for c in cands:
        classes = {}
        for k, sig in sorted(sigs[c['idx']].items()):
            order = [c['decls'][j][3] for j in c['perms'][k]]
            classes.setdefault(sig, []).append((k, ','.join(order)))
        result[c['idx']] = dict(name=c['name'], movable=[c['decls'][i][3] for i in c['movable']],
                                types=[c['decls'][i][1] + ('*' if c['decls'][i][2] else '')
                                       for i in c['movable']],
                                classes={s: v for s, v in classes.items()})
        print(f"=== {c['idx']} {c['name']}  ({len(classes)} classes over "
              f"{len(c['perms'])} permutations) ===")
        for sig, members in sorted(classes.items(), key=lambda t: (t[0] != 'EXACT', -len(t[1]))):
            tag = '  <<< BYTE-EXACT' if sig == 'EXACT' else ''
            print(f'   class {sig}  n={len(members)}{tag}')
            for k, o in members:
                print(f'      p{k:<3d} {o}')
    json.dump(result, open(os.path.join(work, 'classes.json'), 'w'), indent=1)
    print(f"\nwrote {os.path.join(work, 'classes.json')}")


if __name__ == '__main__':
    main()
