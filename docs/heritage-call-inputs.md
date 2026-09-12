# Phi placement for call inputs

A register may carry both an incoming call argument and a call result or clobber. Heritage puts
an INDIRECT guard immediately before the call in the physical operation list. The argument reads
the value before that effect, as `renameRecurse` in the pinned Ghidra C++ implementation specifies.

The former global-location scan required a read before any write in a basic block. At a shared
call reached from several argument-producing branches, the preceding output guard counted as a
write and hid the call input. No phi was placed; renaming substituted an incoming function
register, then dead-code removal deleted the branch definitions. This was an incorrect pruning
adaptation, not a compiler convention.

`Heritage::placeMultiequals` (`heritage.cc:2599–2644`) passes the complete normalized `writevars`
set to `calcMultiequals`. The port now takes every active-heritage output into the existing
iterated dominance-frontier calculation. Renaming still honors the simultaneous INDIRECT/call
effect ordering. No architecture or compiler exception is needed.

## Reproducible witness

`oracle/ground-truth/src/branch_argument.S` builds freestanding x86-32 and x86-64 ELF programs.
A mutable selection chooses one of three integer values for EAX, then one shared indirect call
consumes the declared EAX argument. The x86-64 build is a same-source control. The source records
the required branch shape, memory input and output-guard interaction.

Before the port, `branch_selected_call_input_survives_output_guard` failed on x86-32: the argument
was an incoming register with no definition. The x86-64 control passed. The regression requires
a three-input MULTIEQUAL and executes its branch/phi graph at five unsigned boundary values per
architecture, comparing the callback argument with the source's 17, 29 and 43.

The pinned C++ `decomp_dbg` oracle was loaded with the compiled image and matching call-site
prototype `void __regparm3 callback(uint4 value)`. Its IR preserves the three-input EAX phi.
A second oracle run declaring a uint4 result preserves the same input phi, ruling out a
void-output-only explanation. Mosura's operation trace instead showed the missing phi at heritage
and deletion of all three constant definitions at deadcode, before control-flow simplification.

## Validation

The focused regression passes after the port. The final workspace run passes 1312/1312
executed tests (23 ignored), including IR parity 9/9, source ground truth 36/36, disassembly
1/1, CLI goldens and all three repository guards. The external declaration restores all three
selected pointer values and both other inputs, matching its 12 native instructions.

The initial compiled comparison exposed a separate target declaration defect, documented in
[target-model-declarations.md](target-model-declarations.md), and a stale-emission fingerprint.
Those fixes landed independently. With identical target lowering on both sides, phi placement
changes 17/751 TUs, with zero verdict flips, no new failure and no EXACT lost. Both populations
contain 19 EXACT, 1 SAME_CODE, 16 SAME_SHAPE, 548 MISMATCH and 167 COMPILE_FAIL. Twelve
structural-similarity movers (seven up, five down) are diagnostics; the IR/source gates establish
the restored data flow.

All eight corpus gates pass. The profile covers one native branch chain, two native switch-label
sets and all 19 baseline EXACT functions. Its string-operation bar has zero candidates in the
588 user-classified TUs; across all 751 TUs, memcpy/memset counts remain 40/5. The repeated
candidate uses 751/751 cached units with zero verdict flips, similarity movers or membership
changes. These measurements do not claim whole-program correctness or close other call contracts.
