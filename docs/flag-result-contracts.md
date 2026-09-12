# Explicit flag-result contracts: grounding

Status: investigation and fixture preparation. No result-contract implementation has landed.

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

The current CLI on this fixture renders the predicate as a void function and the first caller
with a disconnected one-byte local controlling its branch. This demonstrates the missing result
under the default model; it does not alone establish a divergence from Ghidra.

## Pinned C++ oracle

The Ghidra 12.0.3 C++ console was given a binary image containing the compiled allocated sections
and all four function symbols. Without a prototype declaration it also eliminates the predicate:
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

The measured behavior corresponds to Ghidra's locked-output branches in
`ActionPrototypeTypes::apply` (`coreaction.cc:4637`) and `ActionFuncLink::funcLinkOutput`
(`coreaction.cc:1540`): materialize the declared return/call storage before heritage, retain the
declared type, and mark a one-byte Boolean call result appropriately. The unlocked branches open
ordinary output trials instead. These are generic prototype mechanisms, not flag-specific rules.

## Remaining work and validation limits

- Establish a failing regression in `ground_truth_parity.rs` with matching explicit declarations
  on both sides before implementing the missing prototype path.
- Keep explicit declarations distinct from recovered, unlocked prototypes; preserve declaration
  types, storage and lock state through the relevant interfaces.
- Port the mechanism, then validate caller and callee IR and both predicate polarities. Compiler
  lowering of an assembly protocol needs its own supported representation and byte evidence.
- The existing source-derived analysis gate discovers all 4/4 fixture functions with 0 spurious
  entries. Its corpus run passed on 103/103 evaluated binaries. This verifies discovery only;
  it is not a passing flag-result regression or a completed implementation package.

If a consumer gives the predicate the opposite meaning in its own replacement implementation,
that is a consumer integration error. Changing the generic printer's predicate polarity cannot
resolve two contradictory consumer contracts.
