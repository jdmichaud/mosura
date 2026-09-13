# Global symbols and memory views

A global reached through a byte pointer can also be read or written as a word. Declaring it
as a word changes the pointer's stride; declaring it as a byte truncates an ordinary direct
access. The storage object and the type of each access must be represented separately.

## Reference decompilation

`Funcdata` retains the global entries created by spacebase-pointer recovery. `ActionMapGlobals`
runs at Ghidra's `fixateglobals` position, grouping overlapping persistent Varnodes and preserving
existing mappings. The source is `Funcdata::mapGlobals` and `coverVarnodes` in the pinned
`funcdata_varnode.cc`. Container lookup chooses the smallest containing entry, as
`ScopeInternal::findContainer` does.

`PrintC` queries the first byte of a global's storage, following `linkSymbol` and
`PrintLanguage::pushSymbolDetail`. A fitting access uses the symbol or its partial field.
A wider access at the same starting address uses Ghidra's underscore mismatch name; an interior
mismatch uses the unnamed location. The warning header remains part of the reference rendering.
Global PTRSUB references use the symbol's type and offset, including the size-zero partial-symbol
rule and the address-of rules for arrays and code.

The Varnode bank excludes destroyed arena slots. `clearDeadVarnodes` runs at the dead-code and
input-prototype boundaries, freeing detached values and unused unlocked inputs. Locked inputs
remain present. Cleanup must occur at these boundaries because individual graph edits can detach
and then reattach a value. Treating every retained arena slot as a bank entry lets old word-wide
values create symbols after heritage has replaced them with live halfwords.

## Compilable emission

`global-views=ghidra|typed` controls the `global_views` arm. Its generic value seam receives the
linked symbol, access address, offset and Varnode. The typed rendering uses an lvalue through
that symbol's storage with the access's actual type. The same seam covers reads and assignment
targets. Byte offsets are applied through a character pointer. Existing volatile facts qualify
both declarations and access pointers.

Recovery accepts a view only when the original normalized instructions contain a memory operand
covering its storage range. Removing that evidence or disabling `global_views` restores the
reference C exactly. The reference choices default to `ghidra`; the Watcom compiler profile
selects `typed`. The core printer has no compiler predicate.

The recompiler passes the global scope into TU synthesis. Used global declarations come from
the symbol types, rather than reconstructing types solely from identifier prefixes. A remaining
underscore mismatch is a compilation diagnostic: independently allocating it would break the
storage relationship. This represents each function's objects; allocating and linking a complete
application's address space is a separate consumer responsibility still under review.

## Source and object checks

`mixed_global_views.S` is compiled for i386 and x86-64, with stripped artifacts and build-derived
truth. It exercises a direct word read plus a byte-indexed copy, a wider destination store, and
two partially overlapping source reads. The mapped C++ oracle splits the last pair into
halfwords at their own addresses.

The saved mapping implementation failed the interior storage regression because obsolete arena
slots produced a spurious offset-suffixed symbol. The bank cleanup corrects that mismatch without
changing the address-name parser. The current checks cover six bodies and 1542 executions against
the source-defined memory effects, preserving the emitted declarations and function bodies.
Separate GCC object checks use the original pointer widths and compare production relocations
with a resolver built from the storage map. Arm-off and absent-evidence controls hold for every
body. These checks do not establish complete application storage allocation or observation order
between callbacks.

Package and corpus validation is recorded in [the issue tracker](bob-issue-tracker.md).
