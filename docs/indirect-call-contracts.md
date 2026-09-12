# Indirect-call input contracts

`ActionDeindirect` resolves a constant CALLIND target only when the program's function database
contains that address. It follows Ghidra's COPY traversal, addressable-unit conversion and pointer
encoding alignment (`coreaction.cc:1219`). The call becomes CALL, and an indirect override survives
the restart so ordinary callee-contract binding runs on fresh p-code before heritage and dead-code
elimination. This matters when two branches share argument setup: discovering the target after
one branch's arguments have been eliminated cannot repair the old graph by adding operand names.

The implementation currently takes `FuncCallSpecs::deindirect`'s restart path (`fspec.cc:5443`).
Its `lateRestriction` transfer path, external-reference lookup and `TypeCode`-attached `FuncProto`
propagation are still missing. This is partial class coverage, not a full `ActionDeindirect` port.

## Explicit mutable-slot inputs

A writable pointer's initializer does not identify every future callee. When an operator knows
the slot's protocol independently, the decompile operation accepts an input declaration:

```sh
mosura -S <session> -o 'decompile.indirect-inputs=0x403010=BX,BP' decompile <function>
```

Addresses are hexadecimal addresses in the program's default space. Registers are names from the
selected SLEIGH language, in parameter order; their storage determines argument width. Separate
slots with `;`. An empty right-hand side explicitly declares no inputs. Duplicate slots, unknown
registers and overlapping register storage are errors. The declaration participates in the result
cache key and does not alter requests that omit it.

Slot binding supplies the input portion of a call-site prototype override. It recognizes the slot
as the call operand or through COPYs, carries the declaration across restart when discovered late,
and preserves the runtime pointer. `ActionFuncLink` uses Ghidra's locked, non-variadic register
branch (`coreaction.cc:1474-1512`): create inputs at their declared storage and width, leave argument
recovery inactive, and keep the convention's stack-placeholder bookkeeping. An explicit declaration
is not a recovered read-set and does not become an invented convention model.

This is a decompilation input, available on `function.decompile`. Emission and recompilation reject
the option: lowering arbitrary pointer calling conventions into compiler declarations needs its
own byte-witnessed implementation. Return storage, clobbers, stack parameters, computed slot
addresses and full type propagation are not supplied by this input-only interface. Compiler quirks
continue to belong in compiler specs; there is no target inference from argument-setup instructions.

## Reproduction and evidence

`oracle/ground-truth/src/indirect_contract.S` is a self-compiled GNU assembler fixture with its
required properties documented in the source. The ground-truth build script compiles it without
a runtime, derives function facts using `nm`/`objdump`, and strips the analyzed artifact.
`known_indirect_target_restores_both_call_contracts` in `ground_truth_parity.rs` failed before the
change: neither known target became direct, and one branch had lost its arguments. It now checks
both branch contracts, a custom BX/BP callee, mutable-slot calls through memory and a register,
exact 16-bit values, exclusion of an unrelated argument-register write and an empty declaration.
The API regression checks cached-program reconfiguration, separate result keys and invalid storage.

The pinned Ghidra C++ console's `print raw` on the same compiled instructions confirms:

- A declared `target(int4,int4)` produces CALL with `0xb:4,0x16:4` on both branches.
- Mapping the custom callee's inputs to `register:0x18:2` and `register:0x28:2` produces CALL
  with `0x21:2,0x2c:2` in `custom_literal`.
- `override prototype` on `writable_call` preserves CALLIND and supplies `0xb:4,0x16:4`.

Merely putting a symbol in the oracle's binary image does not declare its prototype. Oracle
comparisons must install the same prototype facts as mosura. Likewise, read-only propagation is
off by default in Ghidra; this change does not use a pointer slot's initial bytes as a substitute
for a prototype declaration.
