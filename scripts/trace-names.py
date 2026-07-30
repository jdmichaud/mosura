#!/usr/bin/env python3
"""trace-names.py — the Ghidra-name <-> mosura-name correspondence used by trace-diff.py.

WHY THIS EXISTS. `trace-diff.py` used to compare action/rule names as bare STRINGS, and the port
renames some of them. Its headline column, "RULES GHIDRA FIRES BUT MOSURA NEVER DOES", therefore
carried naming artifacts indistinguishable from real findings: `collect_terms` (Ghidra) sat in that
column while `collectterms` (mosura) sat in the opposite one, from the same run, same rule. That
column is what every "why does mosura differ from Ghidra on X" question starts from, so an artifact
in it is a defect in the instrument, not a cosmetic wart.

HOW THE MAP IS BUILT — derived, not hand-listed. The port mirrors Ghidra's class names
(`RuleCollectTerms` is `RuleCollectTerms` on both sides), so the correspondence is a JOIN ON THE
CLASS NAME, extracted from the two source trees at every run:

    Ghidra   `RuleCollectTerms(const string &g) : Rule(g, 0, "collect_terms") {}`   (*.hh/*.cc)
    mosura   `impl Rule for RuleCollectTerms { fn name(&self) -> &str { "collectterms" } }`

Nothing is checked in and nothing can go stale (cf. the prelude.h incident: never hand-maintain a
generated artifact — generate it). The only hand-written part is `PORT_CLASS_MAP` below, for the
handful of classes the port did NOT name after its Ghidra original; every entry cites the port's own
doc comment as its evidence, and `audit()` fails loudly if an entry names a class that no longer
exists on either side.

LOUDNESS IS THE POINT. Any trace name that resolves to nothing is reported as UNMAPPED — an
extraction failure to be fixed here — and never allowed to fall into a findings column. A name that
is both a class and a group name on the same side is reported as AMBIGUOUS rather than silently
matched (mosura's rule `condnegate` and its `ActionPool` named "condnegate" are exactly this).

Run standalone to audit the correspondence:
    scripts/trace-names.py            # summary + every unmapped/ambiguous name
    scripts/trace-names.py --full     # plus the entire class-by-class table
"""
import glob
import os
import re
import sys

# ── Ghidra declaration forms ──────────────────────────────────────────────────────────────────
#   RuleEarlyRemoval(const string &g) : Rule(g, 0, "earlyremoval") {}
#   ActionActiveReturn(const string &g) : Action( 0, "activereturn",g) {}
#   new ActionGroup(Action::rule_repeatapply,"mainloop")
G_RULE = re.compile(r'^\s*(\w+)\s*\([^)]*\)\s*:\s*Rule\s*\(\s*\w+\s*,\s*[^,]+,\s*"([^"]+)"')
G_ACTION = re.compile(r'^\s*(\w+)\s*\([^)]*\)\s*:\s*Action\s*\(\s*[^,]+,\s*"([^"]+)"')
G_GROUP = re.compile(r'new\s+(?:ActionGroup|ActionPool|ActionRestartGroup)\s*\(\s*[^,]+,\s*"([^"]+)"')

# ── mosura declaration forms ──────────────────────────────────────────────────────────────────
#   impl Rule for RuleEarlyRemoval { fn name(&self) -> &str { "earlyremoval" } }
#   impl super::action::Action for ActionDeadCode { fn name(&self) -> &str { "deadcode" } }
#   ActionGroup::restart("mainloop") / ActionPool::new("oppool")
M_IMPL = re.compile(r'impl\s+(?:[\w:]+::)?(Rule|Action)\s+for\s+(\w+)(?:<[^>]*>)?\s*\{')
M_NAME = re.compile(r'fn\s+name\(&self\)\s*->\s*&str\s*\{\s*"([^"]+)"\s*\}', re.S)
M_GROUP = re.compile(r'ActionGroup::(?:once|restart)\(\s*"([^"]+)"|ActionPool::new\(\s*"([^"]+)"')

# ── the hand-written part: classes the port did not name after their Ghidra original ──────────
#
# Each entry is (mosura class -> [Ghidra classes], relation), and the comment is the port's own
# doc comment that establishes it. Relations, because they are NOT interchangeable when reading a
# diff:
#
#   SAME    1:1. Same mechanism, class renamed by the port. Fold the counts.
#   MERGE   N:1 onto mosura. One mosura class does the work of several Ghidra ones. Fold, and say
#           so — a merged action fires once where Ghidra's fire twice, and that is not a deficit.
#   SPLIT   1:N onto Ghidra. Several mosura classes divide one Ghidra class's work, and mosura
#           implements the rest of it under the original name too. Sum the mosura side.
#   PARTIAL mosura covers only PART of a Ghidra class it does not otherwise implement. NEVER
#           folded: reporting it as covered would make the instrument lie in the optimistic
#           direction, which is the worse direction. Gets its own section.
PORT_CLASS_MAP = {
    # rules.rs:110 "a port of Ghidra's `RuleCollapseConstants`" (same IR, computed per-op).
    "RuleConstFold": (["RuleCollapseConstants"], "SAME"),
    # pipeline.rs:96 "Ghidra's `ActionActiveParam` / `ActionReturnRecovery`" in one action.
    "ActionResolveCalls": (["ActionActiveParam", "ActionReturnRecovery"], "MERGE"),
    # pipeline.rs:549 "The consume-analysis half of Ghidra `ActionDeadCode`, split out as its own
    # action so `Varnode::consume` is fresh when the rule pool runs". mosura has ActionDeadCode too.
    "ActionConsume": (["ActionDeadCode"], "SPLIT"),
    # pipeline.rs:314 the `ActionRestructureVarnode`/`syncVarnodesWithSymbols` + `markUnaliased`
    # update, split out; mosura has ActionRestructureVarnode too.
    "ActionMarkAddrTied": (["ActionRestructureVarnode"], "SPLIT"),
    # merge.rs:2167 "`Merge::mergeMarker` ... run inside `ActionMergeRequired`"; mosura has
    # ActionMergeRequired too.
    "ActionMergeMarkerTrim": (["ActionMergeRequired"], "SPLIT"),
    # structure.rs:3282 "the mosura analogue of the `negateCondition` calls Ghidra's
    # `CollapseStructure` makes during `ActionBlockStructure`" — one side effect of that action,
    # and mosura has no ActionBlockStructure of its own. PARTIAL, deliberately not folded.
    "ActionOrientBranches": (["ActionBlockStructure"], "PARTIAL"),
}


class Side:
    """One side's extracted vocabulary: class -> (kind, registered name, file, line)."""

    def __init__(self, label, classes, groups):
        self.label = label
        self.classes = classes                                  # class -> (kind, name, file, line)
        self.groups = groups                                    # group name -> (file, line)
        self.by_name = {}                                       # registered name -> class
        self.dup_names = {}                                     # registered name -> [classes]
        for cls, (_kind, name, _f, _l) in classes.items():
            self.by_name.setdefault(name, cls)
            self.dup_names.setdefault(name, []).append(cls)
        self.dup_names = {n: c for n, c in self.dup_names.items() if len(c) > 1}
        # A name that is both a class and an ActionGroup/ActionPool label cannot be attributed from
        # the trace text alone — Ghidra's OPACTION_DEBUG prints actions and rules in one format.
        self.ambiguous = sorted(set(self.by_name) & set(self.groups))

    def where(self, cls):
        _k, _n, f, l = self.classes[cls]
        return f"{f}:{l}"


def scan_ghidra(cpp_dir):
    classes, groups = {}, {}
    files = sorted(glob.glob(os.path.join(cpp_dir, "*.hh")) + glob.glob(os.path.join(cpp_dir, "*.cc")))
    if not files:
        sys.exit(f"REFUSING: no Ghidra decompiler sources under {cpp_dir} — the name map cannot be built.")
    for path in files:
        base = os.path.basename(path)
        for i, line in enumerate(open(path, errors="replace"), 1):
            if line.lstrip().startswith("//"):
                continue
            for kind, pat in (("Rule", G_RULE), ("Action", G_ACTION)):
                m = pat.match(line)
                if m:
                    classes.setdefault(m.group(1), (kind, m.group(2), base, i))
            for m in G_GROUP.finditer(line):
                groups.setdefault(m.group(1), (base, i))
    return Side("ghidra", classes, groups)


def scan_mosura(src_dir):
    classes, groups = {}, {}
    files = sorted(glob.glob(os.path.join(src_dir, "**", "*.rs"), recursive=True))
    if not files:
        sys.exit(f"REFUSING: no mosura sources under {src_dir} — the name map cannot be built.")
    for path in files:
        rel = os.path.relpath(path, os.path.dirname(os.path.dirname(src_dir)))
        src = open(path).read()
        # Unit-test helper Rules/Actions (`MarkOneDead`, `KillAdds`, …) are not pipeline vocabulary
        # and would otherwise land in the ADAPTATION list, where the retirement track reads them as
        # real inventions. Test modules sit at the end of the file by convention.
        cut = src.find("#[cfg(test)]")
        live = src if cut < 0 else src[:cut]
        for m in M_IMPL.finditer(live):
            nm = M_NAME.search(live[m.end():m.end() + 400])
            if nm:  # ActionGroup/ActionPool take their name at construction, not from a literal
                classes.setdefault(m.group(2), (m.group(1), nm.group(1), rel, live[:m.start()].count("\n") + 1))
        for m in M_GROUP.finditer(live):
            groups.setdefault(m.group(1) or m.group(2), (rel, live[:m.start()].count("\n") + 1))
    return Side("mosura", classes, groups)


class NameMap:
    """Resolves a trace name on either side to a canonical key, or reports why it cannot."""

    def __init__(self, ghidra, mosura):
        self.g = ghidra
        self.m = mosura
        # mosura class -> ([ghidra classes], relation). Identity where the port kept the name.
        self.mos_to_ghidra = {}
        for cls in mosura.classes:
            if cls in PORT_CLASS_MAP:
                self.mos_to_ghidra[cls] = PORT_CLASS_MAP[cls]
            elif cls in ghidra.classes:
                self.mos_to_ghidra[cls] = ([cls], "SAME")
            else:
                self.mos_to_ghidra[cls] = ([], "ADAPTATION")

    def canon_ghidra(self, name):
        """Ghidra trace name -> (kind, key, detail). kind in {class, group, unmapped}."""
        if name in self.g.by_name:
            return ("class", self.g.by_name[name], None)
        if name in self.g.groups:
            return ("group", name, None)
        return ("unmapped", name, None)

    def canon_mosura(self, name):
        """mosura trace name -> (kind, [ghidra keys], relation | detail)."""
        if name in self.m.by_name:
            cls = self.m.by_name[name]
            keys, rel = self.mos_to_ghidra[cls]
            return ("class", cls, keys, rel)
        if name in self.m.groups:
            return ("group", name, [name] if name in self.g.groups else [], "GROUP")
        return ("unmapped", name, [], None)

    def audit(self):
        """Problems with the map itself. Returned as a list of strings; empty means healthy."""
        problems = []
        for mcls, (gclasses, rel) in PORT_CLASS_MAP.items():
            if mcls not in self.m.classes:
                problems.append(f"PORT_CLASS_MAP names mosura class {mcls}, which no longer exists")
            for gcls in gclasses:
                if gcls not in self.g.classes:
                    problems.append(f"PORT_CLASS_MAP maps {mcls} -> {gcls}, absent from Ghidra")
            if rel == "SPLIT":
                for gcls in gclasses:
                    if gcls not in self.m.classes:
                        problems.append(
                            f"PORT_CLASS_MAP calls {mcls} a SPLIT of {gcls}, but mosura has no "
                            f"{gcls} to hold the other half — it is PARTIAL, not SPLIT")
        for side in (self.g, self.m):
            for name, classes in sorted(side.dup_names.items()):
                problems.append(f"{side.label}: name {name!r} registered by {len(classes)} classes: "
                                f"{', '.join(classes)}")
            for name in side.ambiguous:
                problems.append(f"{side.label}: name {name!r} is BOTH a "
                                f"{side.classes[side.by_name[name]][0]} class ({side.by_name[name]}, "
                                f"{side.where(side.by_name[name])}) and an ActionGroup/ActionPool label "
                                f"({side.groups[name][0]}:{side.groups[name][1]}) — a firing under this "
                                f"name cannot be attributed from the trace text")
        return problems


def default_roots():
    here = os.path.dirname(os.path.abspath(__file__))
    mosura_root = os.path.dirname(here)
    workspace = os.path.dirname(mosura_root)
    ghidra = os.environ.get("GHIDRA_SRC", os.path.join(workspace, "ghidra"))
    return (os.path.join(ghidra, "Ghidra", "Features", "Decompiler", "src", "decompile", "cpp"),
            os.path.join(mosura_root, "crates", "mosura", "src"))


def build(cpp_dir=None, src_dir=None):
    d_cpp, d_src = default_roots()
    return NameMap(scan_ghidra(cpp_dir or d_cpp), scan_mosura(src_dir or d_src))


def main():
    nm = build()
    print(f"ghidra: {len(nm.g.classes)} Rule/Action classes, {len(nm.g.groups)} group labels")
    print(f"mosura: {len(nm.m.classes)} Rule/Action classes, {len(nm.m.groups)} group labels")
    rels = {}
    for cls, (keys, rel) in nm.mos_to_ghidra.items():
        rels.setdefault(rel, []).append(cls)
    for rel in sorted(rels):
        print(f"  {rel:11s} {len(rels[rel]):3d}")
    renamed = [(c, nm.g.classes[c][1], nm.m.classes[c][1]) for c in sorted(nm.m.classes)
               if c in nm.g.classes and nm.g.classes[c][1] != nm.m.classes[c][1]]
    print(f"\nPURE NAMING PAIRS — same class, different registered name ({len(renamed)}); these are "
          f"the artifacts\n  the string diff reported as findings:")
    for cls, gn, mn in renamed:
        print(f"  {cls:24s} ghidra={gn!r:22s} mosura={mn!r}")
    for rel in ("MERGE", "SPLIT", "PARTIAL", "ADAPTATION"):
        members = sorted(rels.get(rel, []))
        if not members:
            continue
        print(f"\n{rel} ({len(members)}):")
        for cls in members:
            keys = nm.mos_to_ghidra[cls][0]
            arrow = " + ".join(keys) if keys else "(no Ghidra class named in the port)"
            print(f"  {cls:24s} {nm.m.classes[cls][1]!r:22s} -> {arrow}   {nm.m.where(cls)}")
    problems = nm.audit()
    print(f"\nAUDIT: {len(problems)} problem(s)")
    for p in problems:
        print(f"  ! {p}")
    if "--full" in sys.argv:
        print("\nGHIDRA CLASSES WITH NO MOSURA IMPLEMENTATION:")
        impl = {g for keys, _ in nm.mos_to_ghidra.values() for g in keys}
        for cls in sorted(nm.g.classes):
            if cls not in impl:
                kind, name, f, l = nm.g.classes[cls]
                print(f"  {kind:6s} {cls:32s} {name!r:24s} {f}:{l}")


if __name__ == "__main__":
    main()
