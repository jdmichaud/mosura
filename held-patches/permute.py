#!/usr/bin/env python3
"""Search local-DECLARATION-ORDER permutations of a recovered function for a byte-exact one.

Rationale: 2026-08-22 probe showed that the order in which a function's locals are DECLARED
(not the order in which they are assigned) determines which physical register the Watcom
allocator hands each temp on a tie.  So a regalloc-only SAME_SHAPE residue may be a
declaration-order recovery problem, not a compiler-identity one.
"""
import itertools, os, re, shutil, subprocess, sys

WAR2 = '/home/jd/WAR2.EXE'
MANIFEST = '/data/be2/zc26/manifest.tsv'
SRC = '/data/be2/zc26/recovered'
PRELUDE = '/data/be2/zc26/prelude.h'
WATCOM = '/home/jd/projects/warcraft2-re/tmp/watcom-experiments/watcom_10.0a/WATCOM'
CACHE = '/data/be2/cache'
CHECK = '/data/wt-dialpatch-target/release/examples/recompile_check'
WORK = '/data/dialpatch/perm'

DECL = re.compile(r'^  [A-Za-z_][A-Za-z0-9_ ]*\*?\s*\*?[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?;\s*$')


def split_decls(text):
    """Return (head_lines, decl_lines, tail_lines) around the function's local decl block."""
    lines = text.split('\n')
    # the function body opens at the last line that is exactly '{'
    open_idx = None
    for i, l in enumerate(lines):
        if l.strip() == '{' and open_idx is None:
            open_idx = i
    if open_idx is None:
        return None
    i = open_idx + 1
    decls = []
    while i < len(lines) and DECL.match(lines[i]):
        decls.append(lines[i])
        i += 1
    return lines[:open_idx + 1], decls, lines[i:]


def run(idx, name, srcdir):
    cmd = [CHECK, WAR2, MANIFEST, srcdir, 'recover', WATCOM,
           '--only', name, '--cache', CACHE]
    p = subprocess.run(cmd, capture_output=True, text=True)
    out = p.stdout + p.stderr
    verdict = 'ERROR'
    for v in ('EXACT', 'SAME_CODE', 'SAME_SHAPE', 'MISMATCH', 'COMPILE_FAIL'):
        if re.search(r'^\s+1\s+' + v + r'\s*$', out, re.M):
            verdict = v
            break
    m = re.search(r'([0-9.]+)\s+insn-weighted \((\d+)/(\d+)', out)
    sim = m.group(1) if m else ('1.0000' if verdict == 'EXACT' else '?')
    return verdict, sim, out


def main():
    idx = sys.argv[1]
    name = sys.argv[2]
    text = open(os.path.join(SRC, idx + '.c')).read()
    parts = split_decls(text)
    if not parts:
        print('could not find a declaration block')
        return
    head, decls, tail = parts
    print(f'{idx} {name}: {len(decls)} local declarations')
    for d in decls:
        print('   ' + d.strip())
    if len(decls) < 2:
        print('nothing to permute')
        return
    perms = list(itertools.permutations(range(len(decls))))
    if len(perms) > 40:
        print(f'{len(perms)} permutations - too many, capping at 40')
        perms = perms[:40]
    base = os.path.join(WORK, idx)
    shutil.rmtree(base, ignore_errors=True)
    results = []
    for k, perm in enumerate(perms):
        d = os.path.join(base, f'p{k}', 'recovered')
        os.makedirs(d, exist_ok=True)
        shutil.copy(PRELUDE, os.path.join(base, f'p{k}', 'prelude.h'))
        body = '\n'.join(head + [decls[j] for j in perm] + tail)
        open(os.path.join(d, idx + '.c'), 'w').write(body)
        verdict, sim, _ = run(idx, name, d)
        order = ','.join(decls[j].strip().rstrip(';').split()[-1].lstrip('*') for j in perm)
        star = '  <<< EXACT' if verdict == 'EXACT' else ''
        print(f'  p{k:<3d} [{order}]  {verdict:11s} sim={sim}{star}')
        results.append((verdict, sim, perm, order))
    ex = [r for r in results if r[0] == 'EXACT']
    print()
    print(f'RESULT {idx} {name}: {len(ex)}/{len(perms)} permutations byte-exact')
    for r in ex:
        print(f'   EXACT order: {r[3]}')


if __name__ == '__main__':
    main()
