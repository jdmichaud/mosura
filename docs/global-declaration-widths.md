# Global declaration widths

An address-only global still needs a declaration whose size agrees with its pointer type.
`function::global_widths` previously collected RAM varnodes only. A base represented by
`PTRSUB(<ram spacebase>, address)` had no entry, so TU synthesis fell back to `int` for
an unknown type. Adding a byte offset to that global's address then scaled the offset
by four in C.

The collector now includes the pointee sizes of live global PTRSUBs. This retains the
declaration fact already used by the faithful printer and the mapped C++ oracle.
It applies independently of the `global-width` emission arm and does not change the IR,
reference expression or compiler profile. Taking an address does not resize an object
whose storage width is already established.

`oracle/ground-truth/src/indexed_globals.S` copies five adjacent words using both byte
offsets and scaled element indices. Its i386 and x86-64 artifacts are stripped after
their truth is derived from the build. Before the correction, the declaration gate
fails for all four copy bodies and actual generated-C execution fails the first source
case. Afterward, all four bodies pass, including 1028 executions checking the complete
surrounding memory window. The execution harness preserves the emitted declaration
type and supplies the physical address binding separately.

This repairs missing declarations for address-only bases. It does not establish a
shared allocation for differently typed views, or resolve an existing object whose
address is used through a different pointer type. Those require consistent global
symbol/type information and explicit view conversions. A mixed direct-word and
byte-indexed access is a separate known case; shrinking its word declaration would
truncate the direct access. The [global symbol and view port](global-symbol-views.md) addresses
that distinction and is undergoing package validation. The complete storage scope remains open under issue #4 in
[the issue tracker](bob-issue-tracker.md).
