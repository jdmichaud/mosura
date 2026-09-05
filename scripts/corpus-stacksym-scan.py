#!/usr/bin/env python3
"""SOURCE SCAN for task #6 / B2's three sub-classes over an emitted the subject `src/` directory.

The wcc386 ladder reports only the FIRST error per function, so it cannot count a class that a
different class masks (docs/corpus-round-runbook.md). These predicates read the emitted C
directly, so each class count is independent of every other class.

    scripts/corpus-stacksym-scan.py <src-dir> [<baseline-src-dir>]

Classes (each printed with its file count and its occurrence count):

  (a) spacebase-leak      — the internal TYPE_SPACEBASE name reaching a declaration or a cast.
  (b) undeclared-stack    — a stack identifier USED in a body with no declaration of that identifier
                            anywhere in the file, in EITHER shape (see STACK_IDENT): the mapped
                            `xStack_18` form and the unmapped `xStack0000000c` form. Array element
                            uses (`aiStack_8[i]`) count as a use of `aiStack_8`, which is declared.
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
wrong VALUE. Use scripts/corpus-wrongcode-scan.py and the absolute call gauge for those.
"""
import re
import sys
from pathlib import Path

# Two shapes, and BOTH must be here:
#   `xStack_1c` / `aiStackX_8` / `puStack_ffffffdc` — `ScopeLocal::buildVariableName` (varmap.cc:548),
#      a MAPPED local: stem, `Stack`, optional caller-allocated `X`, `_`, the frame offset.
#   `xStack0000000c` — `ScopeInternal::buildVariableName` (database.cc:2483), an UNMAPPED stack
#      address: stem, `Stack`, then `2*addrSize` hex digits and NO separator.
# ⚠️ The second shape was missing here and it cost a wrong headline: this scan reported the
# undeclared-locals class as 32 -> 0 across B2 when the true figure was 32 -> 4, because B2 itself
# introduced the no-underscore form and the pattern still required the `_`. A predicate that predates
# a rendering cannot see it — when a change adds an output SHAPE, extend the scan in the same commit.
STACK_IDENT = re.compile(
    r"\b([a-z]+Stack(?:X?_[0-9a-f]+|[0-9a-f]{8,}))\b"
)
# A declaration line: `  <type> <name>;` or `  <type> <name> [<n>];` in the decl block.
# ⚠️ The leading token MUST be excluded when it is a statement keyword. Without KEYWORDS below,
# `  return xStack_38;` parses as "type `return`, name `xStack_38`" — which makes an UNDECLARED
# local look declared, i.e. it silently undercounts the class this scan exists to count. Found by a
# duplicate-declaration cross-check reporting 17 phantom files; the instrument was the defect.
# The leading indent is `\s{0,2}`, not `\s{2}`: a column-0 match is the EMITTER's synthesized
# file-scope declaration (`corpus_emit.rs`'s `build_tu`, the same synthesis that covers
# `extraout_`/`unaff_`/`in_`/`register0x`), and it declares the identifier just as a local does.
# Requiring the indent made every synthesized declaration invisible and kept 4 files in the
# undeclared class after they had been closed.
DECL = re.compile(
    r"^\s{0,2}([A-Za-z_][A-Za-z0-9_]*)(?:\s*\*)*\s+"
    r"([a-z]+Stack(?:X?_[0-9a-f]+|[0-9a-f]{8,}))\s*(\[[0-9]+\])?\s*;"
)
KEYWORDS = {"return", "if", "else", "while", "do", "for", "switch", "case", "break",
            "continue", "goto", "sizeof", "typedef", "extern"}
WIDTH_TY = re.compile(r"\b(int|uint|xunknown|undefined|float)([0-9]+)\b")
MAX_BASETYPE_SIZE = 10  # Ghidra architecture.cc:1422


def declared_name(line):
    """`(name, scope)` for the stack identifier this line DECLARES, or None.

    `scope` is "file" for a column-0 declaration (the emitter's synthesis) and "block" for an
    indented one (the decompiler's). The two are DIFFERENT SCOPES: a block declaration legally
    shadows a file one, so a name appearing at both is valid C and must NOT count as a duplicate.
    Collapsing them reported 91 files / 139 phantom duplicates.
    """
    m = DECL.match(line)
    if m and m.group(1) not in KEYWORDS:
        return m.group(2), ("block" if line[:1].isspace() else "file")
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
        by_scope = {"file": set(), "block": set()}
        dupes = set()
        for line in text.splitlines():
            d = declared_name(line)
            if d is not None:
                name, scope = d
                (dupes if name in by_scope[scope] else by_scope[scope]).add(name)
        declared = by_scope["file"] | by_scope["block"]
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
