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

`decompile.function-outputs` accepts the same storage through the CLI, Rust binding and C API:

```text
0x401012=join(ECX,EBX,EAX):struct12(0:uint4,4:uint4,8:uint4)
```

`join` lists physical registers from most significant to least significant. `structN` gives
the exact byte size; each field specifies its byte offset and scalar type. Offsets are decimal
or `0x` hexadecimal, ordered and non-overlapping, and every field must fit inside the structure.
Gaps and trailing padding are explicit in the layout. Scalar types are `bool`, `char`, `intN`,
`uintN`, `floatN` and `unknownN`; nested composite types are not part of this text grammar.
Storage and type are independent: a join can also hold a scalar, and one register can hold a
structure. Existing `hex=REGISTER:type` and `hex=void` declarations keep their meaning.
Separate function declarations with semicolons.

A simultaneous value and condition flag uses the same storage model. For example,
`join(CF,EDI):struct5(0:uint4,4:bool)` puts EDI in the four-byte value field and CF in
the one-byte boolean field. The five-byte logical layout is an assembly interface fact;
it does not imply that a C compiler returns that structure through those registers.

The declaration applies to both a function definition and its direct calls. Supply matching
[input declarations](function-input-contracts.md) when the function also has non-default inputs.
Omitting the output option on a later request restores ordinary recovery; declarations change
the decompilation result key, including piece order and field types, without changing stored
analysis. Compiler emission, mutable pointer outputs and automatic recovery remain separate work.

`decompile <entry> --as table:joins` exposes the logical-to-physical storage records alongside
the other function tables. Its columns are `join_space`, `join_offset`, `join_size`, `piece`,
`space`, `offset` and `size`. `piece` is zero-based in significance order. The first three
columns identify logical storage; the last three identify that piece in the program's physical
address spaces. A joined prototype output's `(space, offset, size)` matches the corresponding
`(join_space, join_offset, join_size)`. These records belong to the decompilation result, so
they remain available when that result is read from the session store.
Use the same declaration options when requesting `table:joins` as when requesting C or raw IR.

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
When a physical write divides a scalar field, it can retain Ghidra's partial-field notation
such as `.field_0x8._0_1_`; making that notation compilable belongs to emission/TU lowering.

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

`oracle/ground-truth/src/value_flag_result.S` exercises mixed-width result pieces on both
x86 modes. Its producer returns an updated EDI and CF, one caller selects an expression with
CF, and another repeats the call with the returned EDI until CF is set. The build supplies
four function boundaries. The ground-truth gate executes the final IR, including simultaneous
phi assignments, branch orientation and the actual decompiled producer at each call. It checks
all three functions on eight boundary inputs per architecture, including the sequence of
values passed around the retry loop. This validates the existing joined-result port; it did
not establish a new production defect or require a new core change.

The mapped C++ oracle uses the same five-byte structure (field offsets zero and four,
alignment one) and `<addr space="join" piece1="CF" piece2="EDI"/>`. Both engines retain
the same return fields, flag-dependent result branches and loop-carried input. Register
addresses are taken from each language: EDI is at register offset 0x1c on i386 and 0x38
on x86-64. A local host-C execution check also covers the 48 function/input cases with
ordinary host declarations; that check validates logical C behavior, not compiler ABI lowering.

The existing unlocked return-recovery and double-precision consumers still need their own
`constructJoinAddress` port. Adding explicit join storage does not complete those paths.
