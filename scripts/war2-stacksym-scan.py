#!/usr/bin/env python3
"""SOURCE SCAN for task #6 / B2's three sub-classes over an emitted WAR2 `src/` directory.

The wcc386 ladder reports only the FIRST error per function, so it cannot count a class that a
different class masks (docs/war2-recompile-remeasure.md). These predicates read the emitted C
directly, so each class count is independent of every other class.

    scripts/war2-stacksym-scan.py <src-dir> [<baseline-src-dir>]

Classes (each printed with its file count and its occurrence count):

  (a) spacebase-leak      — the internal TYPE_SPACEBASE name reaching a declaration or a cast.
  (b) undeclared-stack    — a `[a-z]+Stack[X]?_<hex>` identifier USED in a body with no declaration
                            of that identifier anywhere in the file. Array element uses (`aiStack_8
                            [i]`) count as a use of `aiStack_8`, which is what is declared.
  (b2) duplicate decls    — the same stack identifier DECLARED twice. `ScopeLocal::restructure`
                            builds a disjoint cover (one Symbol per address), so this is always a
                            defect; it only stayed legal C while two print-time name synthesizers
                            disagreed about a slot's stem.
  (c) non-C-width types   — a `int<N>`/`uint<N>`/`xunknown<N>` type name with no typedef in
                            prelude.h. Split at Ghidra's `max_basetype_size` (10, architecture.cc:
                            1422): at or below it Ghidra emits the same odd width (`uint6`, `int3`
                            are in ghidra-all.txt), so those are FAITHFUL and the gap is the
                            prelude's; ABOVE it `TypeFactory::getBase` (type.cc:3652) returns
                            `undefined1[N]` instead, so those are ours.

UNCOVERED by this scan, stated so its silence is never read as completeness: a stack local that is
declared with the WRONG TYPE (the name agrees, so (b) is silent); a declared-but-unused local; any
wrong VALUE. Use scripts/war2-wrongcode-scan.py and the absolute call gauge for those.
"""
import re
import sys
from pathlib import Path

# `xStack_1c`, `aiStackX_8`, `puStack_ffffffdc` — the stem is one or more lower-case letters.
STACK_IDENT = re.compile(r"\b([a-z]+Stack X?_[0-9a-f]+)\b".replace(" ", ""))
# A declaration line: `  <type> <name>;` or `  <type> <name> [<n>];` in the decl block.
# ⚠️ The leading token MUST be excluded when it is a statement keyword. Without KEYWORDS below,
# `  return xStack_38;` parses as "type `return`, name `xStack_38`" — which makes an UNDECLARED
# local look declared, i.e. it silently undercounts the class this scan exists to count. Found by a
# duplicate-declaration cross-check reporting 17 phantom files; the instrument was the defect.
DECL = re.compile(
    r"^\s{2}([A-Za-z_][A-Za-z0-9_]*)(?:\s*\*)*\s+([a-z]+StackX?_[0-9a-f]+)\s*(\[[0-9]+\])?\s*;"
)
KEYWORDS = {"return", "if", "else", "while", "do", "for", "switch", "case", "break",
            "continue", "goto", "sizeof", "typedef", "extern"}
WIDTH_TY = re.compile(r"\b(int|uint|xunknown|undefined|float)([0-9]+)\b")
MAX_BASETYPE_SIZE = 10  # Ghidra architecture.cc:1422


def declared_name(line):
    """The stack local this line DECLARES, or None."""
    m = DECL.match(line)
    if m and m.group(1) not in KEYWORDS:
        return m.group(2)
    return None


def prelude_types(src: Path) -> set:
    header = src.parent / "prelude.h"
    if not header.exists():
        return set()
    return set(re.findall(r"\b(?:int|uint|xunknown|undefined|float)[0-9]+\b", header.read_text()))


def scan(src: Path):
    known = prelude_types(src)
    spacebase = {}
    undeclared = {}
    duplicated = {}
    widths = {}
    for path in sorted(src.glob("*.c")):
        text = path.read_text()
        n = text.count("spacebase")
        if n:
            spacebase[path.name] = n
        declared, dupes = set(), set()
        for line in text.splitlines():
            n = declared_name(line)
            if n is not None:
                (dupes if n in declared else declared).add(n)
        used = set(STACK_IDENT.findall(text)) - declared
        if used:
            undeclared[path.name] = sorted(used)
        if dupes:
            duplicated[path.name] = sorted(dupes)
        missing = {t for t in (a + b for a, b in WIDTH_TY.findall(text)) if t not in known}
        if missing:
            widths[path.name] = sorted(missing)
    return spacebase, undeclared, duplicated, widths


def summarize(label, spacebase, undeclared, duplicated, widths):
    print(f"===== {label} =====")
    print(f"(a) spacebase-leak   files={len(spacebase)} occurrences={sum(spacebase.values())}")
    print(f"(b) undeclared-stack files={len(undeclared)} identifiers={sum(len(v) for v in undeclared.values())}")
    print(f"(b2) DUPLICATE decls  files={len(duplicated)} identifiers={sum(len(v) for v in duplicated.values())}")
    per_ty = {}
    for names in widths.values():
        for t in names:
            per_ty[t] = per_ty.get(t, 0) + 1
    ours, prelude_gap = {}, {}
    for t, c in per_ty.items():
        width = int(re.search(r"[0-9]+$", t).group())
        (ours if width > MAX_BASETYPE_SIZE else prelude_gap)[t] = c
    print(f"(c) non-C widths     files={len(widths)} distinct={len(per_ty)}")
    print(f"      <= max_basetype_size ({MAX_BASETYPE_SIZE}) — FAITHFUL, prelude gap: "
          f"{sorted(prelude_gap.items())}")
    print(f"      >  max_basetype_size — OURS (getBase should array-ize): {sorted(ours.items())}")
    return {
        "a_files": len(spacebase), "a_occ": sum(spacebase.values()),
        "b_files": len(undeclared), "b_ids": sum(len(v) for v in undeclared.values()),
        "bdup_files": len(duplicated), "bdup_ids": sum(len(v) for v in duplicated.values()),
        "c_files": len(widths), "c_ours": sum(ours.values()),
    }


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    new = Path(sys.argv[1])
    if not new.is_dir():
        sys.exit(f"not a directory: {new}")
    print(f"scanning {new} ({len(list(new.glob('*.c')))} files)")
    cur = summarize(str(new), *scan(new))
    if len(sys.argv) > 2:
        base = Path(sys.argv[2])
        if not base.is_dir():
            sys.exit(f"not a directory: {base}")
        print(f"scanning {base} ({len(list(base.glob('*.c')))} files)")
        old = summarize(str(base), *scan(base))
        print("===== delta (new - baseline) =====")
        for k in cur:
            d = cur[k] - old[k]
            print(f"  {k:10s} {old[k]:5d} -> {cur[k]:5d}  ({d:+d})")


if __name__ == "__main__":
    main()
