#!/usr/bin/env python3
"""Count C cast expressions in a directory of emitted .c files.

WHY IT IS A SCRIPT. The cast census is a standing gate — every type-layer change is expected to
report it — but until now it was a hand-rolled `grep | wc -l` whose exact pattern lived only in
whoever ran it. Two commits quote "10060" and "10344" with the words "same definition both sides",
and the definition itself is nowhere in the tree, so those absolute numbers cannot be reproduced or
compared against by anyone else. Task #1's rule is instruments, not hand-rolled counts. This is the
instrument; from here the numbers are comparable across sessions because the definition is.

⛔ THE EARLIER ABSOLUTES ARE VOID — DO NOT DIFFERENCE AGAINST THEM. The lead confirmed the original
recipe is LOST: 10060 (`5c9afe2`) and 10344 (`4dc2897`) were produced by a session whose context is
gone. "Same definition both sides" was carrying the whole claim — the DELTAS within those sessions
were sound, the ABSOLUTES were never reproducible by anyone else, and subtracting one of them from a
number this script prints would be comparing two different definitions and calling it a regression.
This script's output is the canonical definition from `e517104` on; the anchor future deltas measure
against is **9031** over the 1303-function WAR2 emit at that commit.

⭐ AND THE GENERAL RULE THIS COST US, which applies to every gate, not just this one: AN INSTRUMENT
MUST BE REPRODUCIBLE BY SOMEONE WHO WAS NOT THERE. A gate whose recipe lives only in the operator is
not a gate. This is the third face of the same coin as "state what a predicate literally tests" and
"state which oracle you are quoting". Anything gated on that is not in the tree as a script is in
exactly this position.

WHAT COUNTS. A cast is a parenthesised type name in OPERAND POSITION: `(type)` or `(type *)` (any
number of stars) immediately followed by something a value can start with. The position test is what
separates a cast from a parameter list or a parenthesised subexpression, and it is why a bare
`grep -o '(char)'` overcounts. Multi-word types (`unsigned int`, `long long`) are accepted.

WHAT IT DOES NOT COUNT, deliberately, so the number is not read as more than it is:
  - a cast whose type is a struct/union/typedef this scan cannot distinguish from a variable name
    when it appears without a star — `(foo)x` is ambiguous in C without the declarations
  - implicit conversions, which are the interesting half of any cast comparison against Ghidra and
    are invisible in the text
So this measures CAST TOKENS EMITTED, and its job is delta detection between two emits of the same
corpus — not a claim about how many conversions the program performs.

Usage:  scripts/cast-census.py <src-dir> [<baseline-src-dir>]
"""
import re
import sys
from pathlib import Path

# `(type)` / `(type *)` followed by the start of an operand. The trailing lookahead is the position
# test: an identifier, a nested parenthesis, an address-of/deref/negation, or a literal.
CAST = re.compile(
    r"\((?:unsigned\s+|signed\s+|const\s+)*"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\s+[A-Za-z_][A-Za-z0-9_]*)*"
    r"\s*\**\)"
    r"(?=\s*[A-Za-z_(&*\-~!'\"0-9])"
)
# Control-flow keywords take a parenthesised expression, never a cast; without this `if (x)` and
# friends land in the count whenever the body starts on the same line.
KEYWORD = re.compile(r"\((?:if|for|while|switch|return|sizeof)\s*\**\)$")


def census(srcdir: Path) -> tuple[int, dict[str, int]]:
    total = 0
    per_file: dict[str, int] = {}
    for path in sorted(srcdir.glob("*.c")):
        n = 0
        for line in path.read_text(errors="replace").splitlines():
            for m in CAST.finditer(line):
                if KEYWORD.search(m.group(0)):
                    continue
                # A cast never directly follows an identifier or a closing paren — that shape is a
                # call or an index, e.g. `foo(bar)` and `arr[i](x)`.
                if m.start() > 0 and (line[m.start() - 1].isalnum() or line[m.start() - 1] in "_)]"):
                    continue
                n += 1
        total += n
        if n:
            per_file[path.name] = n
    return total, per_file


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    new_total, new_per = census(Path(sys.argv[1]))
    print(f"cast census: {new_total} in {sys.argv[1]}")
    if len(sys.argv) < 3:
        return 0
    old_total, old_per = census(Path(sys.argv[2]))
    print(f"cast census: {old_total} in {sys.argv[2]} (baseline)")
    print(f"DELTA: {old_total} -> {new_total} ({new_total - old_total:+d})")
    moved = sorted(
        (name for name in set(new_per) | set(old_per) if new_per.get(name, 0) != old_per.get(name, 0)),
        key=lambda n: -abs(new_per.get(n, 0) - old_per.get(n, 0)),
    )
    print(f"functions whose cast count moved: {len(moved)}")
    for name in moved[:20]:
        print(f"    {name}  {old_per.get(name, 0)} -> {new_per.get(name, 0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
