/* Ground-truth corpus program (issues-become-source-tests (subject-profile note)): the self-compiled repro of
 * `<subject-profile>/notes/function-discovery-backlog.md` §9 #5 — INLINE CALL PARAMETERS DECODED AS CODE, the
 * blocker that holds `held-patches/listing-command-channel.patch`.
 *
 * ⚠️ THE FIXTURE IS `src/inlineparam_cstart.asm`, NOT THIS FILE. The idiom cannot be expressed
 * in C at all: it needs a callee that pops its own return address and reads the word the call is
 * followed by. This file exists because the Watcom column's `build_watcom` recipe compiles
 * `src/<prog>.c` alongside `src/<prog>_cstart.asm`, and it supplies the `main_` that
 * the stub references. Read the `.asm` for the shape and the byte-level reason
 * the parameter bytes are what they are.
 *
 * WHAT IT REPRODUCES. mosura's `falls_through` (`analysis/analyzers/mod.rs:90`) re-derives
 * fall-through from the p-code opcode: a `CALL` falls through unless the callee is flagged
 * no-return. Nothing flags this callee, so mosura decodes the 2-byte inline parameter as an
 * instruction — and, with the parameter bytes chosen here, that decode runs 3 bytes past the
 * parameter and DESTROYS THE NEXT LABEL'S ENTRY. On the subject MZ stub the destroyed instruction
 * is `00013a56 POP BX`, which the committed Ghidra golden has.
 *
 * WHAT GHIDRA ACTUALLY DOES, measured against `goldens/analysis/analysis.snapshot (subject profile)` rather than
 * assumed — and it is NOT a fall-through override:
 *
 *   - Ghidra's listing has NO code unit at any of the four the subject parameter addresses, and no code
 *     unit at return+2 either (`000154b7`, `00017519` absent; `00015176` present only because
 *     `ref 0001514d 00015176 CONDITIONAL_JUMP` reaches it independently). Ghidra does not resume
 *     after these calls — it stops.
 *   - The mechanism is `FindNoReturnFunctionsAnalyzer` ("Non-Returning Functions - Discovered",
 *     INSTRUCTION_ANALYZER at `DISASSEMBLY.after()`, evidence threshold 3), which is UNPORTED —
 *     mosura's `noreturn.rs` is the other one, `NoReturnFunctionAnalyzer` ("Known"), driven by a
 *     name list that matches nothing here.
 *   - Its indicator that fires on this shape is `checkNonReturningIndicators`
 *     (FindNoReturnFunctionsAnalyzer.java:552): *the code unit at the call's fall-through
 *     CONTAINS the next function's entry*. The bad decode is the EVIDENCE. Ghidra then applies
 *     `instr.setFlowOverride(FlowOverride.CALL_RETURN)` to every call reference to the target
 *     (:218) and repairs the damaged decodes.
 *
 * PROPERTIES THIS PROGRAM DEPENDS ON — do not "simplify" any of them away:
 *
 *  1. THE DISPATCHER LEAVES BY `push ebx; ret`, NOT BY AN INDIRECT JUMP. That is the real
 *     "return to a computed address" idiom and it is what makes the fixture's premise true:
 *     control resumes two bytes past the call, so the call site is never returned to. An
 *     indirect `jmp` would express the same thing, but `derive_truth_elf` classifies every x86
 *     `jmp *` as a switch dispatch (build.sh:131) and would add a jump-table recovery obligation
 *     this fixture has no business creating — `ground_truth_parity` would go RED for an unrelated
 *     reason and the signal would stop being attributable.
 *
 *  2. THE INLINE PARAMETER BYTES ARE `b8 11`, AND THAT CHOICE IS THE TEST. Decoded linearly they
 *     start a 5-byte `mov eax,imm32` that consumes the 2 parameter bytes plus 3 bytes of the
 *     next label — swallowing its entry. Parameter bytes that decode within 2 bytes (`90 90`,
 *     say) would leave every entry intact, the fixture would still LOOK like an inline-parameter
 *     repro, and it would measure nothing. This is the `mve-obvious-version-tests-nothing` trap:
 *     the obvious parameter passes unfixed.
 *
 *  3. THE THUNKS ARE ADJACENT, with the parameter bytes sitting exactly between one thunk's call
 *     and the next thunk's entry, and `dispatch_` immediately after the last parameter. The
 *     `byte public` segment and link order (the stub links FIRST) are what guarantee it. Insert
 *     anything between them — alignment, another function — and the over-decode lands in filler
 *     instead of on an entry.
 *
 *  4. `_cstart_` CALLS ALL THREE THUNKS, so each is call-reachable in the truth and the recall
 *     half of `ground_truth_parity` covers them. Those call sites deliberately carry NO inline
 *     parameter: the parameter belongs to the call *inside* each thunk, which is the one whose
 *     return address `dispatch_` pops.
 *
 *  5. THERE ARE THREE THUNKS, NOT ONE. Ghidra's evidence threshold is 3 (`OPTION_DEFAULT_
 *     EVIDENCE_THRESHOLD`), counted over the call references to a single target, so one or two
 *     call sites would not cross it and a faithful port would correctly leave the fixture RED
 *     forever. Anything that reduces the family below three stops this being a gate a faithful
 *     fix can turn green.
 *
 *  6. The thunks are bare `label near`, not `proc`/`endp`, so no symbol size claims the parameter
 *     bytes as part of a function body. A body that included them would be reported as
 *     uncovered-after-the-fix by `recovered_functions_are_in_the_listing`, which measures body
 *     bytes with no code unit — the fix would then trade one violation for another.
 *
 *  7. The dispatcher's `pop ebx; mov cx,[ebx]` is the subject idiom verbatim (`5b` / `2e 8b 0f`
 *     there, segment-prefixed for 16-bit real mode). It is what makes the family recognisable as
 *     an inline-parameter dispatcher rather than an ordinary tail call, and it is why step 2 of
 *     the port is an ANALYZER and not a decode rule.
 */

/* This file exists only to satisfy `build_watcom`'s `src/<prog>.c` + `main_` requirement — the
 * fixture is entirely in `src/inlineparam_cstart.asm`. */
int main(void) {
    return 0;
}
