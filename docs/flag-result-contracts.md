# Explicit flag-result contracts: grounding

Status: scalar/register/void result primitive implemented and gated; broader reports remain open.

A result in a condition flag is an explicit assembly calling convention. Writing a flag does not
by itself prove that it is a result: ordinary arithmetic writes flags too. Supporting this protocol
must preserve the same declared storage and meaning at the function return and every consuming
call. It must not alter the platform's default ABI or infer an application predicate's meaning.

## Self-compiled specimen

`oracle/ground-truth/src/flag_result.S` defines a predicate ending in `testl %edi,%esi; ret`.
Its source-owned result is ZF, meaning `(value & mask) == 0`. Two callers use JE and JNE,
respectively, and return distinct constants, so reversing the meaning is observable. There are no
copied survey bytes. The build script compiles the source, derives function locations through
`nm`/`objdump`, and strips the analyzed artifact.

Without an output declaration the CLI on this fixture renders the predicate as a void function and the first caller
with a disconnected one-byte local controlling its branch. This demonstrates the missing result
under the default model; it does not alone establish a divergence from Ghidra.

## Pinned C++ oracle

The Ghidra 12.0.3 C++ console was given a binary image containing the compiled allocated sections
and all function symbols. Without a prototype declaration it also eliminates the predicate:
the raw graph contains only `return(#0x0)`. This is the same default-ABI question as the CLI run.

After selecting `flag_test`, the following declarations supply the specimen's source facts:

```text
map param 0 [register,0x38,4] uint4 value
map param 1 [register,0x30,4] uint4 mask
map return [register,0x206,1] bool result
decompile
print raw
print C
```

The resulting IR retains the AND, compares it with zero into ZF, and passes ZF as the RETURN's
result. The C++ printer produces `return (mask & value) == 0;`. Each caller's CALL now defines ZF
and takes both declared inputs. JE and JNE retain opposite interpretations of that same result.

The fixture also includes `flag_set` (`stc; ret`) and `flag_clear` (`clc; ret`). With CF declared
as Boolean, the pinned C++ oracle keeps a COPY of 1/0 into CF and renders `bool` functions returning
`true`/`false`. The initial implementation printed `xunknown1` for these functions despite the
explicit Boolean declaration. The expanded MVE failed before the return-type consumers were ported.

The measured behavior corresponds to Ghidra's locked-output branches in
`ActionPrototypeTypes::apply` (`coreaction.cc:4637`) and `ActionFuncLink::funcLinkOutput`
(`coreaction.cc:1540`): materialize the declared return/call storage before heritage, retain the
declared type, and mark a one-byte Boolean call result appropriately. The unlocked branches open
ordinary output trials instead. These are generic prototype mechanisms, not flag-specific rules.

## Implemented mechanism

`decompile.function-outputs` accepts declarations by function entry, for example
`0x401015=ZF:bool` for the self-compiled fixture. Multiple declarations are separated with `;`;
`hex=void` explicitly locks a void result. Register names come from the selected SLEIGH language.
Types are `bool`, `char`, `intN`, `uintN`, `floatN` or `unknownN`, with widths in bytes. Register and
result widths must agree. Invalid names, widths, types and duplicate function entries are rejected.

The request supplies a typed `ProtoParameter` to both the function and its direct calls before
heritage. The declaration is rebound after a restart, including when `ActionDeindirect` has proved
a formerly indirect target. Locked returns bypass output trials; locked void calls cannot acquire
an inferred result. Call type propagation, `calculated_bool`, nonzero masks and Boolean rules retain
the declared type. `TypeOpReturn::getInputLocal` supplies the prototype type to returned values,
including constants. RETURN uses the base `TypeOp::getInputCast` consumer, and
`PrintC::emitPrototypeOutput` reads the declared prototype output type.
These are the pinned C++ mechanisms; no condition-flag name is special in the
implementation.

The option participates in cache identity and is applied to both cached and thawed programs without
changing later requests that omit it. It is accepted by `function.decompile`; compiler emission and
round operations do not accept it. [Joined result declarations](joined-result-storage.md) now
represent multiple noncontiguous registers as one typed value. Stack results, mutable pointer
output declarations and custom compiler lowering remain separate work. This interface does
not itself supply callee inputs. [Function input declarations](function-input-contracts.md)
provide the matching definition/caller input list; automatic input-contract recovery is separate.

## Compiler-spec extensions

`ParamEntry` now decodes the compiler specification's zero, sign, integer-type and left-justification
attributes. `ParamEntry::assumedExtension` determines the containing register or aligned slot;
`ActionFuncLink` adds the promised extension immediately after the call. Model serialization retains
these attributes in `param_entries` schema v2. Existing v1 analysis sets are refused and need
fresh analysis, following the pre-1.0 policy in `docs/product/architecture.md` (D6); there is no
compatibility fallback. An explicit narrow result does not authorize retaining stale bits in its ABI's
larger result register.

`result_extension.S` is an independent AArch64/Clang MVE. It supplies explicit `w0:uint4` and
`x0:uint8` results and reads the upper word of x0 after the call. Before the extension port, mosura's
IR returned a COPY of `0xffffffff`, retaining the incoming upper bits. The pinned C++ oracle returns
a COPY of zero under the AAPCS64 zero-extension entry, and the implemented port does the same. The
regression follows the storage-anchoring COPY before comparing the result value, as both decompilers
keep that COPY for a locked return.

The build recipe uses Clang's integrated assembler, Rust's bundled LLD and LLVM's symbol/disassembly
tools, while GNU objdump reads the generic ELF section headers. Function facts still come from the
compiled artifact. The disassembly parser accepts GNU and LLVM whitespace layouts.

## Remaining work and validation limits

- The initial flag-result regression failed before implementation. The implemented regression
  checks the producer RETURN, the caller's typed output and one-bit mask, both original branch
  polarities, constant carry results and an explicit void declaration.
- The AArch64 extension MVE also failed before implementation and now agrees with the oracle's
  zero result. This is separate evidence for the compiler-spec path, not an x86-only adaptation.
- Final `cargo test --workspace`: 1308/1308 executed tests pass, 23 ignored. This includes
  `ir_parity` 9/9, `ground_truth_parity` 34/34 (1 ignored), `disasm_golden` 1/1 and the CLI
  golden harness 1/1 (1 ignored). All three repository guard harnesses pass.
- Final release emission is identical for 751/751 translation units, with no added or missing
  functions and equal arms stamps. The comparison uses native analysis in a fresh schema-v2
  session and the previous input-contract package as baseline; no result declarations are
  accepted by emission.
- The earlier discovery-only run covered 103/103 evaluated binaries, including 4/4 functions in
  the flag fixture. That predates the extension fixture and is not the current package census.
- General multi-register result contracts and the remaining declaration/storage interfaces are
  still open. A completed primitive does not close every reported result-channel defect.

If a consumer gives the predicate the opposite meaning in its own replacement implementation,
that is a consumer integration error. Changing the generic printer's predicate polarity cannot
resolve two contradictory consumer contracts.

## Separate printer gap

`PrintC::pushBoolConstant` is not yet ported: the printer spells Boolean constants numerically.
The extended fixture exposed this because the C++ oracle prints `return true/false`, whereas
mosura prints `return 1/0` in a Boolean function. The IR already has a Boolean constant copied
into CF and a Boolean RETURN value, matching the C++ oracle. A literal-spelling assertion was
therefore replaced with assertions on that type and exact 0/1 value; it was outside the result
contract invariant. Porting the general Boolean constant printer remains separate work, with its
own emission comparison/round because it also affects existing undeclared functions.
