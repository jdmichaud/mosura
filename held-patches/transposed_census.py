#!/usr/bin/env python3
"""Census the adjacent-transposed instruction pairs, split by whether the scheduler decides them
on `stallable` (unreachable from C) or on the source-order key (reachable).

A transposed pair is two consecutive divergence rows where the original and the candidate hold
the same two instructions in opposite order.

InsStallable (inssched.c:127-155) scores each operand: N_INDEXED +3, N_REGISTER +2, N_MEMORY +1,
and +3 more if the RESULT is N_INDEXED. `stallable` is compared BEFORE the ins->id (source order)
key, so a pair whose two instructions score differently is decided above the id key and no
instruction-creation order can flip it.
"""
import collections
import re
import sys


def stallable(text):
    """Approximate InsStallable for a single instruction from its disassembly text.
    Returns None when the shape is not one of the forms we can score confidently."""
    t = text.strip()
    m = re.match(r'^(\w+)\s+(.*)$', t)
    if not m:
        return None
    mn, rest = m.group(1), m.group(2)
    ops = [o.strip() for o in rest.split(',')] if rest else []
    if not ops:
        return None
    src = ops[-1] if len(ops) > 1 else ops[0]
    dst = ops[0]

    def cls(o):
        if 'ptr [' in o or o.startswith('['):
            # [reg + disp] / [reg*n + disp] are N_INDEXED; a bare absolute is N_MEMORY
            inner = o[o.find('[') + 1:o.rfind(']')]
            return 3 if re.search(r'[A-Z]', inner) else 1
        if re.fullmatch(r'-?0x[0-9a-f]+|-?\d+', o):
            return 0                      # N_CONSTANT
        if re.fullmatch(r'[A-Z]{2,3}', o):
            return 2                      # N_REGISTER
        return None

    w = {3: 3, 2: 2, 1: 1, 0: 0}
    if mn == 'MOV':
        s, d = cls(src), cls(dst)
        if s is None or d is None:
            return None
        score = w[s]
        if d == 3:
            score += 3                    # result N_INDEXED
        return score
    if mn == 'XOR' and len(ops) == 2 and ops[0] == ops[1]:
        return 2                          # one register operand (the other is the result)
    return None


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
    rows = load(sys.argv[1])
    byfn = collections.defaultdict(list)
    for r in rows:
        byfn[(r['idx'], r['fn_va'])].append(r)

    pairs = []
    for key, rs in byfn.items():
        rs.sort(key=lambda r: int(r['ci']) if r['ci'].isdigit() else 0)
        for a, b in zip(rs, rs[1:]):
            if not (a['ci'].isdigit() and b['ci'].isdigit()):
                continue
            if int(b['ci']) != int(a['ci']) + 1:
                continue
            if a['orig_text'] == b['cand_text'] and b['orig_text'] == a['cand_text']:
                pairs.append((key, a, b))

    buckets = collections.Counter()
    fnsets = collections.defaultdict(set)
    examples = collections.defaultdict(list)
    for key, a, b in pairs:
        s1, s2 = stallable(a['cand_text']), stallable(b['cand_text'])
        if s1 is None or s2 is None:
            k = 'unscored'
        elif s1 == s2:
            k = f'REACHABLE (equal stallable = {s1})'
        else:
            k = f'unreachable (stallable {min(s1,s2)} vs {max(s1,s2)})'
        buckets[k] += 1
        fnsets[k].add(key[1])
        if len(examples[k]) < 3:
            examples[k].append(f"{key[1]} @{a['addr']}  {a['orig_text']}  /  {b['orig_text']}")

    print(f'{len(pairs)} adjacent transposed pairs in {len({k for k, _, _ in pairs})} functions')
    print()
    for k, n in sorted(buckets.items(), key=lambda t: -t[1]):
        print(f'  {n:5d} pairs  {len(fnsets[k]):5d} fns   {k}')
        for e in examples[k]:
            print(f'            e.g. {e}')
    print()
    reach = sum(n for k, n in buckets.items() if k.startswith('REACHABLE'))
    unreach = sum(n for k, n in buckets.items() if k.startswith('unreachable'))
    unsc = buckets['unscored']
    print(f'REACHABLE (id-decided): {reach} pairs / '
          f'{len(set().union(*[fnsets[k] for k in fnsets if k.startswith("REACHABLE")]) ) if reach else 0} fns')
    print(f'unreachable (stallable-decided): {unreach} pairs')
    print(f'unscored shapes: {unsc} pairs')


if __name__ == '__main__':
    main()
