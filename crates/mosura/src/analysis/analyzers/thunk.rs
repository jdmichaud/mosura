//! Thunk resolution — a port of the slice of `CreateThunkFunctionCmd` that
//! `CreateFunctionCmd.resolveThunk` drives.
//!
//! **What Ghidra does.** A function whose entry is a lone unconditional jump is a *thunk*, and
//! Ghidra resolves it before the function's body is ever stored:
//!
//! - `CreateFunctionCmd.createFunction` (CreateFunctionCmd.java:365) — *"check for a thunk
//!   first"* — calls `resolveThunk(entry, body, monitor)` immediately before
//!   `listing.createFunction(...)`.
//! - `CreateFunctionCmd.fixupFunctionBody` (:664-673) computes `newBody`, then runs the same
//!   check — *"function could now be a thunk, since someone is calling this because of a
//!   potential body flow change"* — and returns before `func.setBody(newBody)`.
//! - `resolveThunk` (:494-516) → [`thunked_addr`] → `CreateThunkFunctionCmd.getReferencedFunction`
//!   (CreateThunkFunctionCmd.java:319-378), whose last arm runs
//!   **`new CreateFunctionCmd(referencedFunctionAddr).applyTo(program)`** — that call is what
//!   creates the function at the jump target.
//!
//! **Why the order is the whole point.** Both call sites run the check while the thunk's own body
//! is still the pre-flow one (a loader's one-byte placeholder), so
//! `getFunctionContaining(thunkedAddr)` does not see the target as already owned. mosura had no
//! thunk model at all (`function_start.rs:766` recorded this), so
//! [`super::compute_function_bodies`]'s walk followed the `jmp`, swallowed the target into the
//! jumping function's body, and the overlap refusal then declined a function there permanently.
//! WAR2's entry `0x601f8` is exactly this shape: `EB 76`, a short jump over the inline Watcom
//! copyright banner (`analysis/loader/watcom.rs`), and `0x601f8 + 2 + 0x76 = 0x60270` — the
//! address Ghidra creates `FUN_00060270` at and mosura did not. `SharedReturnAnalysisCmd` cannot
//! be the mechanism there: the span between source and target is a *string*, so no function entry
//! lies in it and `assumeContiguousFunctions`' forward arm (`destAddr >= functionAfterSrc`) does
//! not fire in Ghidra either.
//!
//! **What is deliberately NOT ported**, so the subset is explicit rather than accidental:
//!
//! - `getThunkedAddr`'s multi-instruction walk (CreateThunkFunctionCmd.java:598-648) — up to
//!   `MAX_NUMBER_OF_THUNKING_INSTRUCTIONS` instructions with register-side-effect tracking. Only
//!   the `getSimpleFlow` fast path (:580-583) is here, so this can only *under*-report a thunk,
//!   never invent one.
//! - `getThunkedExternalFunctionAddress`, `resolveComputableFlow` and `getFirstBlockJumpCall`
//!   (:284-305) — the fallbacks consulted when the simple flow yields nothing.
//! - The thunk *relationship* itself (`Function.setThunkedFunction`, name/signature inheritance).
//!   mosura has no thunk flag; what this port takes is the half that changes the recovered
//!   function set. Once the target is a function, [`super::compute_function_bodies`]'s walk stops
//!   at it on its own (it stops at every other function's entry), so the thunk's body comes out
//!   as just its jump without any further modelling.

use crate::analysis::flowtype::flow_props;
use crate::analysis::program::{AddressSet, Program, RefType, SymbolType};
use crate::decompile::space::Address;
use crate::sleigh::engine::Spec;

/// Max x86 instruction length — the decode window, as in `shared_return.rs`.
const MAX_INSN_LEN: usize = 16;

/// `CreateThunkFunctionCmd.getSimpleFlow` (CreateThunkFunctionCmd.java:815) — *"Treat single jump
/// or call-return as thunk"*.
///
/// `instr.getDelaySlotDepth() == 0` is not a condition mosura can fail: no ported language has
/// delay slots (the SLEIGH engine lifts them inline), so the arm is unconditionally true here.
///
/// `instr.getFlowType()` includes the instruction's flow override. Reading the un-overridden flow
/// is equivalent for the only override mosura's analyzers set: `FlowOverride::CallReturn` maps
/// `UNCONDITIONAL_JUMP` → `CALL_TERMINATOR`, which passes this predicate through the
/// `isCall() && isTerminal()` arm exactly as the jump passed through `isJump()`, and maps
/// `CONDITIONAL_JUMP` → `CONDITIONAL_CALL_TERMINATOR`, which fails the `isConditional()` guard
/// either way.
fn simple_flow(
    program: &Program,
    addr: Address,
    ops: &[crate::sleigh::pcode::PcodeOp],
    len: u64,
) -> Option<Address> {
    let props = flow_props(ops, addr.offset, addr.offset + len);
    if props.conditional || !(props.jump || (props.call && props.terminal)) {
        return None;
    }
    // `instr.getFlows()` (InstructionDB.java:289): the flow references from this address,
    // dropping the INDIRECT ones (`RefType.isIndirect()` is true only for `INDIRECTION`,
    // RefType.java:567), collected into a SET — so duplicate targets collapse.
    let mut flows: Vec<Address> = Vec::new();
    for r in program.reference_manager.refs_from(addr) {
        if !r.ref_type.is_flow() || r.ref_type == RefType::Indirection {
            continue;
        }
        if !flows.contains(&r.to) {
            flows.push(r.to);
        }
    }
    // `if (flows.length == 1) return flows[0];`
    match flows.as_slice() {
        [only] => Some(*only),
        _ => None,
    }
}

/// `CreateThunkFunctionCmd.getThunkedAddr(program, entry, checkForSideEffects)`
/// (CreateThunkFunctionCmd.java:548) — the `getSimpleFlow` fast path only; see the module note
/// for the arms this deliberately omits.
pub fn thunked_addr(program: &Program, spec: &Spec, ctx: &[u32], entry: Address) -> Option<Address> {
    let decode = |a: Address| {
        let window = program.memory.read_window(a, MAX_INSN_LEN);
        spec.disassemble_ctx(&window, a.offset, ctx).into_iter().next()
    };
    // `Instruction instr = listing.getInstructionAt(entry);`
    program.listing.code_unit_at(entry)?;
    let mut at = entry;
    let mut insn = decode(at)?;
    // "if there is no pcode, go to the next instruction / assume fallthrough (ie. x86 instruction
    // ENDBR64)" (:567-572) — `instr = listing.getInstructionAfter(entry)`, which for a decoded
    // stream is the code unit abutting this one.
    if insn.ops.is_empty() {
        at = Address::new(entry.space, entry.offset + insn.bytes.len() as u64);
        program.listing.code_unit_at(at)?;
        insn = decode(at)?;
    }
    simple_flow(program, at, &insn.ops, insn.bytes.len() as u64)
}

/// One pass of `CreateFunctionCmd.resolveThunk` (CreateFunctionCmd.java:494) plus the creating
/// tail of `CreateThunkFunctionCmd.getReferencedFunction` (CreateThunkFunctionCmd.java:319-375),
/// over every current function entry. Returns the entries created.
///
/// **Called from [`super::compute_function_bodies`] AFTER its walk has stored the bodies**, and
/// that placement is the whole difficulty. Ghidra's two call sites both run while the thunk's own
/// body is unstored — the create path has not reached `listing.createFunction` yet
/// (CreateFunctionCmd.java:365), and `fixupFunctionBody` has not reached `func.setBody` yet
/// (:664-673) — so `getFunctionContaining(thunkedAddr)` never sees a *thunk's* body owning the
/// target. mosura recomputes every body at once, so neither naive placement reproduces that:
///
/// - **Before the walk**, every body is EMPTY, so `getFunctionContaining` can only answer `None`
///   and the guard is vacuous. A predicate whose answer is fixed in advance measures nothing, and
///   this one is a safety veto, so the vacuous version silently *permits*. Measured directly in
///   the pipeline at that point: `bodies non-empty: 0 of 157`. This is
///   `empty-bodies-take-the-permissive-branch` in its exact recorded form.
/// - **After the walk with no correction**, every thunk's body has swallowed its own target and
///   vetoes it — and excluding merely the candidate's own body is not enough, because *sibling*
///   thunks veto each other. WAR2's MZ stub is the live case: `0x17c4c` and `0x17c50` both jump to
///   `0x17dbe`, so each one's body contains the other's target.
///
/// So the veto reads **non-thunk bodies only**. That is not an extra condition bolted on; it
/// restores Ghidra's ordering invariant — that no thunk has a stored body at the moment any thunk
/// is resolved. Against a genuine function's body the veto stays live and can fire, which is the
/// thing it exists for: refusing to mint a function in the middle of real code.
pub fn resolve_thunks(program: &mut Program, spec: &Spec, ctx: &[u32]) -> AddressSet {
    let mut entries: Vec<Address> =
        program.function_manager.functions().map(|f| f.entry_point()).collect();
    entries.sort_by_key(|a| (a.space.0, a.offset));

    // Every thunk, resolved before any of them is acted on — this is the set whose bodies must not
    // take part in the containment veto below.
    let candidates: Vec<(Address, Address)> = entries
        .into_iter()
        .filter_map(|e| thunked_addr(program, spec, ctx, e).map(|t| (e, t)))
        .collect();
    let thunk_entries: std::collections::HashSet<(u32, u64)> =
        candidates.iter().map(|(e, _)| (e.space.0, e.offset)).collect();

    let mut created = AddressSet::new();
    for (entry, thunked) in candidates {
        // `if (thunkedAddr == null || thunkedAddr.equals(entry)) return false;`
        // (CreateFunctionCmd.java:501).
        if thunked == entry {
            continue;
        }
        // `Function f = listing.getFunctionAt(referencedFunctionAddr); if (f != null) return f;`
        // (:319-338) — the thunk resolves to a function that already exists, so there is nothing
        // to create. This is also the cycle terminator: `A jmp B; B jmp A` creates B, and B's own
        // resolution then finds a function already at A.
        if program.function_manager.function_at(thunked).is_some() {
            continue;
        }
        // `if (!program.getMemory().contains(referencedFunctionAddr)) return getExternalFunction(..)`
        // (:356) — an off-image target is the external-function arm, which is not ported.
        if !program.memory.contains(thunked) {
            continue;
        }
        // `f = listing.getFunctionContaining(referencedFunctionAddr); if (f != null ...) return null;`
        // (:360-364), reading non-thunk bodies only — see the note above.
        let owned_by_a_real_function = program.function_manager.functions().any(|f| {
            let e = f.entry_point();
            !thunk_entries.contains(&(e.space.0, e.offset)) && f.body().contains(thunked)
        });
        if owned_by_a_real_function {
            continue;
        }
        // `|| listing.getInstructionAt(referencedFunctionAddr) == null` (:361).
        if program.listing.code_unit_at(thunked).is_none() {
            continue;
        }
        // `new CreateFunctionCmd(referencedFunctionAddr, ...).applyTo(program)` (:371).
        let name = format!("FUN_{:08x}", thunked.offset);
        if program.function_manager.create_function(thunked, &name, AddressSet::new()) {
            if !program.symbol_table.has_symbol_at(thunked) {
                program.symbol_table.add_with_primary(thunked, &name, SymbolType::Function, true);
            }
            created.add_range(thunked.space, thunked.offset, thunked.offset);
        }
    }
    created
}
