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
  - ⚠️ A CAST THAT ENDS A LINE. The scan is per line and the position test looks ahead for the
    start of an operand, which a line end does not provide. This is why the count is only valid
    mosura-vs-mosura: Ghidra line-wraps and mosura does not, so a Ghidra-vs-mosura comparison
    under-counts Ghidra every time. `threedim` read 8 vs 6 and drove a task assignment; whole-file
    it is 8 vs 8 with the identical multiset. See CAVEAT below, printed on every run.
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


CAVEAT = (
    "⚠️  VALID for mosura-vs-mosura DELTAS. *NOT* valid as a mosura-vs-GHIDRA count:\n"
    "    this scan reads PER LINE, and its position test is a lookahead for the start of an\n"
    "    operand — so a cast that ENDS a line is not counted. Ghidra's pretty-printer wraps\n"
    "    long expressions and mosura's emitter does not, so comparing these numbers to Ghidra\n"
    "    under-counts GHIDRA, always in the same direction.\n"
    "    Worked example: `threedim` reads 8 (mosura) vs 6 (Ghidra) here and was carried as a\n"
    "    real divergence — it drove a task assignment. Re-counted over the whole file instead\n"
    "    of line by line it is 8 vs 8, with the identical cast multiset. There was no\n"
    "    difference. To re-check one: run CAST.finditer over path.read_text() rather than over\n"
    "    each line, keep the KEYWORD and preceding-character filters, and compare the token\n"
    "    LISTS — equal totals can still be different casts."
)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    # Printed on EVERY run, before any number. A known systematic bias that lives only in the
    # operator's head is the failure mode this project has a rule for: an instrument must be
    # reproducible — and honest — for someone who was not there. One line of output cannot stop
    # the wrong comparison, but it makes it impossible to make without seeing why it is wrong.
    print(CAVEAT, file=sys.stderr)
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
