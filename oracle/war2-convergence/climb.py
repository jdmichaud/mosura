#!/usr/bin/env python3
"""Hill-climb the local DECLARATION ORDER of one function's C, scored on exactly-matched
instruction rows against the original.

Watcom breaks register-allocation ties on symbol order, so the declaration sequence is a live
input to codegen (docs/byte-exact-source-forms.md). On FUN_0006c6f0 this moved matched rows
172 -> 184 with the C otherwise byte-identical.

PATHS BELOW ARE HARDCODED to the session this came from -- edit SRC and CHECK (and the cwd in
the subprocess call) to point at your own scratch tree before running. Structural edits
invalidate whatever order this finds, so run it LAST.
"""
import re, subprocess, sys

SRC='/data/be2/exp3/src/02714.c'
CHECK=['/home/jd/projects/mosura/mosura/target/release/examples/recompile_check','/home/jd/WAR2.EXE','sb16/manifest.tsv','exp3/src','recover','/home/jd/projects/warcraft2-re/tmp/watcom-experiments/watcom_10.0a/WATCOM','--cache','cache','--only','02714','--verbose']

s=open(SRC).read()
i=s.index("void FUN_0006c6f0")
i=s.index("{\n", i)
j=s.index("\n\n", i)
head,tail=s[:i+2],s[j:]
decls=[d for d in s[i+2:j].rstrip().split('\n') if d.strip()]

def score(order):
    open(SRC,'w').write(head+'\n'.join(order)+tail)
    out=subprocess.run(CHECK,capture_output=True,text=True,cwd='/data/be2').stdout
    return sum(1 for l in out.splitlines() if l.startswith('  0006'))

import random, json, time
random.seed(2714)
best=decls[:]
bestscore=score(best)
print(f"start: {bestscore}", flush=True)
t0=time.time()
def local(b, bs):
    improved=True
    while improved and time.time()-t0<520:
        improved=False
        n=len(b)
        for k in range(n):
            for pos in (0, max(0,k-3), min(n-1,k+3)):
                if pos==k: continue
                c=b[:k]+b[k+1:]; c.insert(pos, b[k])
                sc=score(c)
                if sc>bs:
                    b,bs=c,sc; improved=True
                    print(f"  move {k}->{pos}: {bs}", flush=True)
                    break
            else: continue
            break
    return b,bs
best,bestscore=local(best,bestscore)
while time.time()-t0<520:
    cand=best[:]
    random.shuffle(cand)
    cs=score(cand)
    cand,cs=local(cand,cs)
    if cs>bestscore:
        best,bestscore=cand,cs
        print(f"restart improved: {bestscore}", flush=True)
score(best)
open('/data/be2/exp3/best-decls.json','w').write(json.dumps(best))
print(f"final: {bestscore}", flush=True)
