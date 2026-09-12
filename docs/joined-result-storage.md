# Joined result storage

A function may return one logical value through several physical registers. The declaration
must name that storage; writing a register alone does not establish that it is an output.

The library's `Knobs.function_outputs` accepts `RegisterOutput { registers, datatype }`.
`registers` lists pieces from most significant to least significant, matching Ghidra's
`JoinRecord`. One register uses ordinary storage; a void result has an empty list. The total
storage size must match the type, and physical pieces must not overlap. Input declarations
continue to use `RegisterParameter`, with one register per parameter.

For example, a 12-byte structure with three four-byte fields can use the logical storage
`ECX, EBX, EAX`. On little-endian x86, field offsets 0, 4 and 8 then occupy EAX, EBX and ECX.
These are explicit interface facts, independent of the compiler specification's default ABI.

The public text option currently exposes scalar/flag declarations. Text syntax for joined
storage, compiler lowering, mutable pointer outputs and automatic recovery remain open.

## Ported path

`AddrSpaceManager::findAddJoin` interns a logical address with its ordered physical pieces.
The definition and each direct call receive that same result declaration before heritage.
`Heritage::processJoins`, `splitJoinRead`, `splitJoinWrite` and `splitJoinLevel` expand it into
PIECE/SUBPIECE expressions before ordinary SSA construction touches the physical registers.

For a composite result, the downstream port retains the structure:

- `RulePieceStructure` normalizes piece addresses and registers its CONCAT roots.
- `Merge::groupPartials` groups the root and its pieces as one variable.
- `RuleSubRight` preserves field extraction with `special_print`.
- `TypeStruct::findTruncation` supplies formal field types and printing paths.
- `ActionSetCasts` skips operations already marked nonprinting by `ActionCopyMarker`.

PrintC consumes these facts as field assignments and field reads. It does not infer a custom
ABI or provide compiler-specific assembly lowering.

## Source-built witness

`oracle/ground-truth/src/register_results.S` is compiled for i386 and x86-64. The build derives
the three-function population from the unstripped executable, then strips the analyzed artifact.
The producer accepts EDI and returns three independent values in EAX, EBX and ECX. The caller
adds the first two and XORs the third. Each result therefore contributes to observable behavior.

`declared_register_results_preserve_all_pieces_at_definitions_and_calls` in
`ground_truth_parity.rs` supplies the declaration at both boundaries and evaluates the resulting
IR for zero, ordinary, sign-boundary and wraparound inputs. It also checks the aggregate CALL
storage and the field construction/extraction in the printed C.

Before join heritage was ported, the typed result remained a free 12-byte Varnode and all
producer calculations disappeared. After heritage alone, the values survived but the C still
cast the structure to an integer for shifts and constructed a return with CONCAT. The downstream
consumers above remove those invalid representations.

The pinned C++ decompiler oracle was run on the same source-built bytes with EDI:uint4 input
storage and a `result_tuple` structure containing three uint4 fields. Its return symbol uses
`<addr space="join" piece1="ECX" piece2="EBX" piece3="EAX"/>`. Both architectures produce
one 12-byte CALL result and extract offsets 8, 4 and 0. The producer's C assigns three fields;
the caller computes `first + second ^ third` from that aggregate. This comparison supplies
identical interface facts to both engines; it is not a claim of automatic ABI recovery.

The existing unlocked return-recovery and double-precision consumers still need their own
`constructJoinAddress` port. Adding explicit join storage does not complete those paths.
