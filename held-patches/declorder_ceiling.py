#!/usr/bin/env python3
"""Measure the CEILING of the local-declaration-order lever on the WAR2 corpus.

Finding (2026-08-22): the order in which a function's register-held locals are DECLARED decides
which physical register Watcom's allocator hands each temp on a tie.  Ghidra (and therefore
mosura's faithful printc) declares register temps in FIRST-USE order; the original source
declared them in whatever order its author wrote.  So a regalloc-class residue may be a
declaration-order recovery problem rather than a compiler-identity one.

This measures how much EXACT is reachable: for each candidate function, try every permutation of
its register-temp declarations and record whether ANY is byte-exact.  That is an upper bound on
what a perfect model-inverse emitter arm could win -- it is NOT a landable result by itself
(it is fitted to the oracle).

Batching: one recompile_check invocation per ROUND, with round k holding permutation k of every
candidate simultaneously.  Permutations of different functions are independent, so a round is one
batched dosemu session instead of one session per permutation.
"""
import itertools, json, os, re, shutil, subprocess, sys

WAR2 = '/home/jd/WAR2.EXE'
MANIFEST = '/data/be2/zc26/manifest.tsv'
SRC = '/data/be2/zc26/recovered'
PRELUDE = '/data/be2/zc26/prelude.h'
WATCOM = '/home/jd/projects/warcraft2-re/tmp/watcom-experiments/watcom_10.0a/WATCOM'
CACHE = '/data/be2/cache-declorder'
CHECK = '/data/wt-dialpatch-target/release/examples/recompile_check'
WORK = '/data/dialpatch/ceiling'

DECL = re.compile(r'^  ([A-Za-z_][A-Za-z0-9_ ]*?)\s+(\*?\s*)([A-Za-z_][A-Za-z0-9_]*)\s*(\[[^\]]*\])?;\s*$')
# Ghidra names stack-resident locals with a Stack_/local_ marker; those must not be permuted
# because their declaration order IS their frame layout.
FROZEN = re.compile(r'Stack_|^local_|^in_|^unaff_|^extraout_')


def split_decls(text):
    lines = text.split('\n')
    open_idx = next((i for i, l in enumerate(lines) if l.strip() == '{'), None)
    if open_idx is None:
        return None
    i = open_idx + 1
    decls = []
    while i < len(lines):
        m = DECL.match(lines[i])
        if not m:
            break
        decls.append((lines[i], m.group(3)))
        i += 1
    return lines[:open_idx + 1], decls, lines[i:]


def load_rows(path):
    rows = []
    with open(path) as f:
        hdr = f.readline().rstrip('\n').split('\t')
        for line in f:
            p = line.rstrip('\n').split('\t')
            p += [''] * (len(hdr) - len(p))
            rows.append(dict(zip(hdr, p)))
    return rows


def main():
    rec = sys.argv[1] if len(sys.argv) > 1 else '/data/be2/zc26-rec.tsv'
    want_verdicts = set((sys.argv[2] if len(sys.argv) > 2 else 'SAME_SHAPE').split(','))
    maxlocals = int(sys.argv[3]) if len(sys.argv) > 3 else 4
    need_class = sys.argv[4] if len(sys.argv) > 4 else 'regalloc'
    sim_floor = float(sys.argv[5]) if len(sys.argv) > 5 else 0.0
    global WORK, CACHE
    WORK = os.environ.get('CEILING_WORK', WORK)
    CACHE = os.environ.get('CEILING_CACHE', CACHE)

    rows = load_rows(rec)
    cands = []
    for r in rows:
        if r['verdict'] not in want_verdicts:
            continue
        if need_class and need_class not in r['classes']:
            continue
        if sim_floor and (not r['sim'] or float(r['sim']) < sim_floor):
            continue
        try:
            text = open(os.path.join(SRC, r['idx'] + '.c')).read()
        except OSError:
            continue
        parts = split_decls(text)
        if not parts:
            continue
        head, decls, tail = parts
        movable = [i for i, (_, nm) in enumerate(decls) if not FROZEN.search(nm)]
        if not (2 <= len(movable) <= maxlocals):
            continue
        cands.append(dict(idx=r['idx'], name=r['name'], head=head, decls=decls,
                          movable=movable, tail=tail, base_sim=r['sim'],
                          base_verdict=r['verdict'], classes=r['classes']))

    sample = int(os.environ.get('CEILING_SAMPLE', '0'))
    if sample and len(cands) > sample:
        # deterministic even stride, so the sample is reproducible and spread over the corpus
        step = len(cands) / sample
        cands = [cands[int(i * step)] for i in range(sample)]
        print(f'sampled {len(cands)} candidates by even stride (reproducible)')
    print(f'candidates: {len(cands)} functions with 2..{maxlocals} movable locals, '
          f'verdict in {sorted(want_verdicts)}, regalloc in classes')
    if not cands:
        return
    for c in cands:
        c['perms'] = list(itertools.permutations(c['movable']))
    nrounds = max(len(c['perms']) for c in cands)
    print(f'rounds: {nrounds} (max permutation count)')

    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(os.path.join(WORK, 'recovered'), exist_ok=True)
    shutil.copy(PRELUDE, os.path.join(WORK, 'prelude.h'))
    srcdir = os.path.join(WORK, 'recovered')

    best = {c['idx']: dict(name=c['name'], base_verdict=c['base_verdict'],
                           base_sim=c['base_sim'], classes=c['classes'],
                           exact_orders=[], best_sim=0.0, best_verdict='?',
                           nperm=len(c['perms'])) for c in cands}

    for k in range(nrounds):
        names = []
        for c in cands:
            perm = c['perms'][k % len(c['perms'])]
            order = list(range(len(c['decls'])))
            for slot, src_i in zip(c['movable'], perm):
                order[slot] = src_i
            body = '\n'.join(c['head'] + [c['decls'][j][0] for j in order] + c['tail'])
            open(os.path.join(srcdir, c['idx'] + '.c'), 'w').write(body)
            names.append(c['name'])
        cmd = [CHECK, WAR2, MANIFEST, srcdir, 'recover', WATCOM,
               '--only', ','.join(names), '--cache', CACHE,
               '--out', os.path.join(WORK, f'round{k}.tsv')]
        p = subprocess.run(cmd, capture_output=True, text=True)
        if not os.path.exists(os.path.join(WORK, f'round{k}.tsv')):
            print(f'round {k}: FAILED\n{p.stdout[-2000:]}\n{p.stderr[-2000:]}')
            continue
        got = load_rows(os.path.join(WORK, f'round{k}.tsv'))
        nex = 0
        for r in got:
            b = best.get(r['idx'])
            if b is None:
                continue
            sim = float(r['sim']) if r['sim'] else 0.0
            if r['verdict'] == 'EXACT':
                nex += 1
                c = next(c for c in cands if c['idx'] == r['idx'])
                perm = c['perms'][k % len(c['perms'])]
                names_in_order = [c['decls'][j][1] for j in perm]
                if names_in_order not in b['exact_orders']:
                    b['exact_orders'].append(names_in_order)
            if sim > b['best_sim']:
                b['best_sim'] = sim
                b['best_verdict'] = r['verdict']
        print(f'round {k}: {nex} EXACT of {len(got)}', flush=True)

    reachable = [b for b in best.values() if b['exact_orders']]
    print()
    print(f'=== CEILING: {len(reachable)} of {len(cands)} candidate functions have a '
          f'byte-exact declaration order ===')
    for idx, b in sorted(best.items()):
        mark = 'REACHABLE' if b['exact_orders'] else '   --    '
        print(f"  {idx} {b['name']:22s} {mark} base={b['base_verdict']}/{b['base_sim']} "
              f"best={b['best_verdict']}/{b['best_sim']:.4f} perms={b['nperm']}")
        for o in b['exact_orders'][:3]:
            print(f'        exact order: {",".join(o)}')
    json.dump(best, open(os.path.join(WORK, 'ceiling.json'), 'w'), indent=1)
    print(f"\nwrote {os.path.join(WORK, 'ceiling.json')}")


if __name__ == '__main__':
    main()
