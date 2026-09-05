#!/usr/bin/env python3
"""The declaration-order -> register-assignment predicate, derived from Open Watcom source.

Nothing here is calibrated against the subject corpus. Every step is a source line:

  ConfList order   = declaration order            (cdecl2.c:623 append; cgen2.c:1670 forward walk;
                                                   makeaddr.c:590 temp creation; namelist.c:97
                                                   prepend and dataflo.c:112-121 + conflict.c:61
                                                   prepend, which cancel)
  sort             = identity under equal savings (regalloc.c:1127 ConfBefore is strict '>')
  assignment       = first still-available entry of the width's register table, walked in table
                     order, availability tested by PHYSICAL overlap
                                                  (regalloc.c:843-868, HW_Ovlap cghwreg.h:265)

10.0a's tables (NOT the OW 1.0 DoubleRegs order -- see watcom-dial-patch-results.md section 1).
"""
import itertools
import json
import sys

# physical register model: a name -> the set of atomic byte-lanes it occupies
LANES = {
    'AL': {'al'}, 'AH': {'ah'}, 'AX': {'al', 'ah'}, 'EAX': {'al', 'ah', 'axh'},
    'BL': {'bl'}, 'BH': {'bh'}, 'BX': {'bl', 'bh'}, 'EBX': {'bl', 'bh', 'bxh'},
    'CL': {'cl'}, 'CH': {'ch'}, 'CX': {'cl', 'ch'}, 'ECX': {'cl', 'ch', 'cxh'},
    'DL': {'dl'}, 'DH': {'dh'}, 'DX': {'dl', 'dh'}, 'EDX': {'dl', 'dh', 'dxh'},
    'SI': {'si'}, 'ESI': {'si', 'sih'},
    'DI': {'di'}, 'EDI': {'di', 'dih'},
    'BP': {'bp'}, 'SP': {'sp'},
}

TABLE = {
    4: ['EAX', 'EDX', 'EBX', 'ECX', 'ESI', 'EDI', 'BP', 'SP'],
    2: ['AX', 'DX', 'BX', 'CX', 'SI', 'DI'],
    1: ['AL', 'AH', 'DL', 'DH', 'BL', 'BH', 'CL', 'CH'],
}

# `CurrProc->state.unalterable` under -5r: the frame and stack pointers are never handed out
EXCLUDED = {'BP', 'SP'}


def width_of(ctype):
    """Width in bytes of a recovered-C declaration's type, pointers included."""
    t = ctype.replace('unsigned', '').replace('signed', '').strip()
    if t.endswith('*') or '*' in ctype:
        return 4
    for k, w in (('1', 1), ('2', 2), ('4', 4), ('8', 8)):
        if t.endswith(k):
            return w
    return {'char': 1, 'short': 2, 'int': 4, 'long': 4}.get(t, 4)


def predict(decl_order, widths, excluded=EXCLUDED):
    """decl_order: list of names, in DECLARATION order. widths: {name: bytes}."""
    taken = set()
    out = {}
    for name in decl_order:
        w = widths[name]
        if w not in TABLE:
            out[name] = None
            continue
        for reg in TABLE[w]:
            if reg in excluded:
                continue
            lanes = LANES[reg]
            if lanes & taken:
                continue
            out[name] = reg
            taken |= lanes
            break
        else:
            out[name] = None
    return out


def classes_for(names, widths):
    """Partition all permutations of `names` by predicted assignment."""
    part = {}
    for k, perm in enumerate(itertools.permutations(range(len(names)))):
        order = [names[i] for i in perm]
        a = predict(order, widths)
        key = tuple(sorted(a.items()))
        part.setdefault(key, []).append((k, ','.join(order)))
    return part


def main():
    measured = json.load(open(sys.argv[1]))
    agree = disagree = 0
    for idx in sorted(measured):
        m = measured[idx]
        names, types = m['movable'], m['types']
        widths = {n: width_of(t) for n, t in zip(names, types)}
        pred = classes_for(names, widths)
        # compare partitions by their member sets (permutation indices)
        mset = {frozenset(k for k, _ in v) for v in m['classes'].values()}
        pset = {frozenset(k for k, _ in v) for v in pred.values()}
        ok = mset == pset
        agree += ok
        disagree += (not ok)
        print(f"{'OK  ' if ok else 'FAIL'}  {idx} {m['name']:22s} "
              f"widths={[widths[n] for n in names]}  "
              f"measured {len(mset)} classes {sorted(sorted(s) for s in mset)}  "
              f"predicted {len(pset)} classes {sorted(sorted(s) for s in pset)}")
        if not ok:
            for key, v in pred.items():
                asg = ', '.join(f'{n}={r}' for n, r in key)
                print(f"        predicted class {[k for k, _ in v]}: {asg}")
    print()
    print(f'predicate reproduces the measured partition on {agree} of {agree + disagree} '
          f'candidates')


if __name__ == '__main__':
    main()
