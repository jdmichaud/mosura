# Named prototype models in target declarations

Ghidra's `PrintC::emitFunctionDeclaration` prints a non-default prototype model between the
return type and function name (`printc.cc:2584`). A model identifier such as `__regparm3` is
decompiler notation; Watcom does not recognize it as a C declaration keyword. Retaining that
identifier in a Watcom TU causes E1009, even when the TU already declares the correct registers
with an aux pragma.

The target emitter now substitutes its concrete register contract for the model notation at
the function definition. It checks every rendered input and output against Watcom's supported
register storage and verifies any required non-default `parm` or `value` clause. Register
defaults need no redundant pragma. Stack, variadic, joined, floating-point-register and
otherwise unrepresentable contracts retain their notation until their target lowering exists.
The original PrintC declaration and IR are unchanged. This is Watcom TU synthesis, not a
compiler conditional in the decompiler or a macro that silently discards convention facts.

`oracle/ground-truth/src/model_declaration.S` owns the witness: an i386 function computes
`(EAX - EDX) ^ ECX`; its control computes `EAX - EDX`. Both are directly reachable and return
in EAX. The pinned C++ `decomp_dbg` oracle prints `__regparm3` and keeps those three inputs in
its final IR. The ground-truth regression fails before lowering because the TU retains the
unsupported keyword. It then passes while checking that a missing non-default parameter
pragma still leaves the model visible and that raw PrintC output remains identical.

Compiled with Watcom 10.0a, the lowered witnesses reproduce all three and both original
instructions respectively: two EXACT functions, five instructions in total. The isolated target-layer comparison changes 222/751 TUs, exclusively by lowering the
model notation. Compiled verdicts improve for 190 functions, with zero regressions: EXACT
14 to 19, SAME_CODE 0 to 1, SAME_SHAPE 14 to 16, MISMATCH 366 to 548, and COMPILE_FAIL
357 to 167. All eight corpus gates pass. Gate 4 has zero string-operation candidates in its
588 user-classified TUs; across all 751 TUs the memcpy/memset counts remain 40/5. The other
profile checks cover one native branch chain, two native switch-label sets, and all baseline
EXACT functions. These corpus counts are diagnostics, not a claim of whole-program correctness.

The first corpus rerun revealed an independent cache defect: `recompile/tu.rs`, `pragma.rs`
and the emission orchestrator were absent from the emit fingerprint. Changing them could
reuse a stale translation unit. The fingerprint now conservatively includes the recompile
subtree consumed by emission; source-edit and dependency-addition regressions cover that
boundary. Input analysis still has its independent fingerprint.
