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

/// `CreateFunctionCmd.resolveThunk` (CreateFunctionCmd.java:494) followed by the creating tail of
/// `CreateThunkFunctionCmd.getReferencedFunction` (CreateThunkFunctionCmd.java:319-375). Returns
/// the address a function must be created at, or `None` when the entry is not a thunk or the
/// thunked address is already accounted for.
fn thunked_function_to_create(
    program: &Program,
    spec: &Spec,
    ctx: &[u32],
    entry: Address,
) -> Option<Address> {
    let thunked = thunked_addr(program, spec, ctx, entry)?;
    // `if (thunkedAddr == null || thunkedAddr.equals(entry)) return false;` (CreateFunctionCmd:501)
    if thunked == entry {
        return None;
    }
    // `Function f = listing.getFunctionAt(referencedFunctionAddr); if (f != null) return f;`
    // (:319-338) — the thunk resolves to a function that already exists; nothing to create.
    if program.function_manager.function_at(thunked).is_some() {
        return None;
    }
    // `if (!program.getMemory().contains(referencedFunctionAddr)) return getExternalFunction(...)`
    // (:356) — off-image targets are the external-function arm, which is not ported.
    if !program.memory.contains(thunked) {
        return None;
    }
    // `f = listing.getFunctionContaining(referencedFunctionAddr);`
    // `if (f != null || listing.getInstructionAt(referencedFunctionAddr) == null) { ... return null; }`
    // (:360-364).
    if program.function_manager.function_containing(thunked).is_some() {
        return None;
    }
    if program.listing.code_unit_at(thunked).is_none() {
        return None;
    }
    Some(thunked)
}

/// Run thunk resolution over every current function entry, creating the thunked functions —
/// `CreateThunkFunctionCmd.getReferencedFunction`'s `new CreateFunctionCmd(...).applyTo(program)`
/// arm (CreateThunkFunctionCmd.java:371). Returns the entries created.
///
/// **Called from the top of [`super::compute_function_bodies`]**, which is mosura's whole-program
/// stand-in for `fixupFunctionBody`. Placing it there rather than after the walk is what makes it
/// faithful: Ghidra runs the check while the thunk's own body is still unstored (:664-673), so
/// `getFunctionContaining(thunkedAddr)` cannot see the target as already owned by the jumping
/// function. Running it after the walk would let every thunk veto its own target.
///
/// The loop repeats because `CreateFunctionCmd` recurses — a thunk whose target is itself a thunk
/// is chased all the way down (`referringThunkAddresses` is Ghidra's cycle guard; here a cycle
/// terminates because the second hop finds a function already at its target). It terminates
/// because each round strictly grows a bounded function set.
pub fn resolve_thunks(program: &mut Program, spec: &Spec, ctx: &[u32]) -> AddressSet {
    let mut created = AddressSet::new();
    loop {
        let mut entries: Vec<Address> =
            program.function_manager.functions().map(|f| f.entry_point()).collect();
        entries.sort_by_key(|a| (a.space.0, a.offset));
        let targets: Vec<Address> = entries
            .into_iter()
            .filter_map(|e| thunked_function_to_create(program, spec, ctx, e))
            .collect();
        let mut any = false;
        for t in targets {
            let name = format!("FUN_{:08x}", t.offset);
            if program.function_manager.create_function(t, &name, AddressSet::new()) {
                if !program.symbol_table.has_symbol_at(t) {
                    program.symbol_table.add_with_primary(t, &name, SymbolType::Function, true);
                }
                created.add_range(t.space, t.offset, t.offset);
                any = true;
            }
        }
        if !any {
            return created;
        }
    }
}
