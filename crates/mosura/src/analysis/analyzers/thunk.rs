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
use crate::decompile::opcode::OpCode;
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
) -> Result<Address, Outcome> {
    let props = flow_props(ops, addr.offset, addr.offset + len);
    if props.conditional {
        return Err(Outcome::FlowConditional);
    }
    if !(props.jump || (props.call && props.terminal)) {
        return Err(Outcome::FlowNotJumpOrTerminalCall);
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
        [only] => Ok(*only),
        [] => Err(Outcome::NoFlow),
        many => Err(Outcome::MultipleFlows(many.len())),
    }
}

/// `CreateThunkFunctionCmd.getThunkedAddr(program, entry, checkForSideEffects)`
/// (CreateThunkFunctionCmd.java:548) — the `getSimpleFlow` fast path only; see the module note
/// for the arms this deliberately omits.
pub fn thunked_addr(program: &Program, spec: &Spec, ctx: &[u32], entry: Address) -> Option<Address> {
    thunked_addr_reporting(program, spec, ctx, entry).ok()
}

/// [`thunked_addr`], naming the guard that declined instead of collapsing to `None` — the
/// resolution half of [`report`]. The control flow is the same; only the `?`s carry a reason.
fn thunked_addr_reporting(
    program: &Program,
    spec: &Spec,
    ctx: &[u32],
    entry: Address,
) -> Result<Address, Outcome> {
    let decode = |a: Address| {
        let window = program.memory.read_window(a, MAX_INSN_LEN);
        spec.disassemble_ctx(&window, a.offset, ctx).into_iter().next()
    };
    // `Instruction instr = listing.getInstructionAt(entry);`
    if program.listing.code_unit_at(entry).is_none() {
        return Err(Outcome::NoInstructionAtEntry);
    }
    let mut at = entry;
    let mut insn = decode(at).ok_or(Outcome::UndecodableAtEntry)?;
    // "if there is no pcode, go to the next instruction / assume fallthrough (ie. x86 instruction
    // ENDBR64)" (:567-572) — `instr = listing.getInstructionAfter(entry)`, which for a decoded
    // stream is the code unit abutting this one.
    if insn.ops.is_empty() {
        at = Address::new(entry.space, entry.offset + insn.bytes.len() as u64);
        if program.listing.code_unit_at(at).is_none() {
            return Err(Outcome::NoInstructionAfterEmptyPcode);
        }
        insn = decode(at).ok_or(Outcome::UndecodableAfterEmptyPcode)?;
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
        if creation_guards(program, entry, thunked, &thunk_entries).is_err() {
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

/// The guards `getReferencedFunction` applies to a resolved thunked address before creating a
/// function there — `Ok(())` means create. Named so [`report`] can run exactly the same chain
/// read-only and say which one declined.
fn creation_guards(
    program: &Program,
    entry: Address,
    thunked: Address,
    thunk_entries: &std::collections::HashSet<(u32, u64)>,
) -> Result<(), Outcome> {
    // `if (thunkedAddr == null || thunkedAddr.equals(entry)) return false;`
    // (CreateFunctionCmd.java:501).
    if thunked == entry {
        return Err(Outcome::TargetIsEntry);
    }
    // `Function f = listing.getFunctionAt(referencedFunctionAddr); if (f != null) return f;`
    // (:319-338) — the thunk resolves to a function that already exists, so there is nothing
    // to create. This is also the cycle terminator: `A jmp B; B jmp A` creates B, and B's own
    // resolution then finds a function already at A.
    if program.function_manager.function_at(thunked).is_some() {
        return Err(Outcome::FunctionAlreadyAtTarget);
    }
    // `if (!program.getMemory().contains(referencedFunctionAddr)) return getExternalFunction(..)`
    // (:356) — an off-image target is the external-function arm, which is not ported.
    if !program.memory.contains(thunked) {
        return Err(Outcome::TargetNotInMemory);
    }
    // `f = listing.getFunctionContaining(referencedFunctionAddr); if (f != null ...) return null;`
    // (:360-364), reading non-thunk bodies only — see the note above.
    let owner = program.function_manager.functions().find(|f| {
        let e = f.entry_point();
        !thunk_entries.contains(&(e.space.0, e.offset)) && f.body().contains(thunked)
    });
    if let Some(f) = owner {
        return Err(Outcome::TargetInsideFunctionBody(f.entry_point()));
    }
    // `|| listing.getInstructionAt(referencedFunctionAddr) == null` (:361).
    if program.listing.code_unit_at(thunked).is_none() {
        return Err(Outcome::NoInstructionAtTarget);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The instrument. Not part of the port: it runs the *ported* chain above read-only and names the
// guard that answered, so "does the subset under-fire?" is measured rather than argued.
// ---------------------------------------------------------------------------------------------

/// What thunk resolution answered for one function entry — the arm that decided, named for the
/// Ghidra line it ports. Every early return in [`thunked_addr_reporting`] and
/// [`creation_guards`] has exactly one variant here, so a candidate is always classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// `listing.getInstructionAt(entry) == null` (CreateThunkFunctionCmd.java:561) — the entry
    /// is not in the listing at all, so resolution never looks at its bytes.
    NoInstructionAtEntry,
    /// The entry is in the listing but its bytes do not decode (mosura-side; Ghidra reads the
    /// stored code unit rather than re-decoding).
    UndecodableAtEntry,
    /// Empty p-code at the entry, and `getInstructionAfter(entry)` is not in the listing (:567-572).
    NoInstructionAfterEmptyPcode,
    /// Empty p-code at the entry, and the following code unit does not decode.
    UndecodableAfterEmptyPcode,
    /// `getSimpleFlow`: `flowType.isConditional()` (CreateThunkFunctionCmd.java:817).
    FlowConditional,
    /// `getSimpleFlow`: neither `isJump()` nor `isCall() && isTerminal()` (:817) — the ordinary
    /// answer for a function that starts with real code.
    FlowNotJumpOrTerminalCall,
    /// `getSimpleFlow`: `instr.getFlows()` minus INDIRECTION was **empty** (:822) — a jump-shaped
    /// entry whose target was never recovered as a reference.
    NoFlow,
    /// `getSimpleFlow`: more than one distinct non-indirect flow (:822) — e.g. a computed jump
    /// with a recovered table. Carries the count.
    MultipleFlows(usize),
    /// `thunkedAddr.equals(entry)` (CreateFunctionCmd.java:501).
    TargetIsEntry,
    /// `listing.getFunctionAt(thunkedAddr) != null` (:319-338) — nothing to create. ⚠️ At the
    /// analysis fixpoint this is also what a thunk the port *did* fire on looks like: see
    /// [`Candidate::target_inbound`] for what else could have created it.
    FunctionAlreadyAtTarget,
    /// `!memory.contains(thunkedAddr)` (:356) — the external-function arm, not ported.
    TargetNotInMemory,
    /// `getFunctionContaining(thunkedAddr) != null` (:360-364) — carries the owning entry.
    TargetInsideFunctionBody(Address),
    /// `listing.getInstructionAt(thunkedAddr) == null` (:361).
    NoInstructionAtTarget,
    /// Every guard passed: `new CreateFunctionCmd(thunkedAddr).applyTo(program)` would run.
    /// **Must not occur in a report taken after analysis has converged** — if it does,
    /// `compute_function_bodies` stopped short of its own fixpoint.
    WouldCreate,
}

impl Outcome {
    /// Did resolution get as far as a thunked address (i.e. is this entry thunk-*shaped*)?
    pub fn resolved(self) -> bool {
        !matches!(
            self,
            Outcome::NoInstructionAtEntry
                | Outcome::UndecodableAtEntry
                | Outcome::NoInstructionAfterEmptyPcode
                | Outcome::UndecodableAfterEmptyPcode
                | Outcome::FlowConditional
                | Outcome::FlowNotJumpOrTerminalCall
                | Outcome::NoFlow
                | Outcome::MultipleFlows(_)
        )
    }
}

/// One function entry as thunk resolution sees it.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub entry: Address,
    /// The first bytes at the entry, decoded **directly from memory, ignoring the listing** — so
    /// an entry that never made it into the listing is still described. This is the generalisation
    /// of "does the entry start with a jump opcode": `mnemonic`, the instruction length, and
    /// `uncond_jump_target` for a non-conditional direct branch (any encoding, `eb` and `e9`
    /// alike, since SLEIGH decodes it).
    pub raw_mnemonic: Option<String>,
    pub raw_len: usize,
    pub raw_uncond_jump_target: Option<u64>,
    /// Flow references *out of* the entry — `getFlows()`' raw material, so a `NoFlow` or
    /// `MultipleFlows` decline can be read rather than guessed at.
    pub entry_outbound: Vec<(RefType, Address)>,
    /// The thunked address, when resolution produced one.
    pub thunked: Option<Address>,
    pub outcome: Outcome,
    /// Is there a function at `thunked` in the state this report was taken in?
    pub target_is_function: bool,
    /// Flow references *into* `thunked` — the other mechanisms that could have put a function
    /// there. A target with an inbound call would be a function with or without this port; a
    /// target whose only inbound edge is the thunk's own jump would not.
    pub target_inbound: Vec<(RefType, Address)>,
}

/// Run the resolution + creation chain over every function entry **read-only**, recording which
/// arm decided each one.
///
/// ⚠️ **WHEN THIS IS VALID.** Two of the guards are body queries
/// (`TargetInsideFunctionBody`) or function-set queries (`FunctionAlreadyAtTarget`), so the answer
/// depends on *when* it is asked — the trap that already bit this port once, where empty bodies
/// made the veto vacuous. Take this report **after analysis has converged**: the last thing
/// [`super::compute_function_bodies`] does is walk every body and then call [`resolve_thunks`],
/// looping until that call creates nothing. So at return the program is in exactly the state the
/// final live `resolve_thunks` ran in — same function set, same bodies — and this replay
/// reproduces that call's decisions, `WouldCreate` included (it must be empty, which is the loop's
/// own exit condition and therefore a check on the instrument as much as on the pipeline).
///
/// What it cannot distinguish, and does not claim to: an entry the port fired on in an *earlier*
/// round now reports `FunctionAlreadyAtTarget`, the same as a target some other analyzer created.
/// [`Candidate::target_inbound`] carries the evidence to separate those by hand.
pub fn report(program: &Program, spec: &Spec, ctx: &[u32]) -> Vec<Candidate> {
    let mut entries: Vec<Address> =
        program.function_manager.functions().map(|f| f.entry_point()).collect();
    entries.sort_by_key(|a| (a.space.0, a.offset));

    // The resolution phase for every entry, exactly as `resolve_thunks` runs it — the thunk set
    // (whose bodies are excluded from the containment veto) is the entries that resolve.
    let resolved: Vec<(Address, Result<Address, Outcome>)> = entries
        .iter()
        .map(|&e| (e, thunked_addr_reporting(program, spec, ctx, e)))
        .collect();
    let thunk_entries: std::collections::HashSet<(u32, u64)> = resolved
        .iter()
        .filter(|(_, r)| r.is_ok())
        .map(|(e, _)| (e.space.0, e.offset))
        .collect();

    resolved
        .into_iter()
        .map(|(entry, r)| {
            let (thunked, outcome) = match r {
                Err(o) => (None, o),
                Ok(t) => (
                    Some(t),
                    match creation_guards(program, entry, t, &thunk_entries) {
                        Err(o) => o,
                        Ok(()) => Outcome::WouldCreate,
                    },
                ),
            };
            let window = program.memory.read_window(entry, MAX_INSN_LEN);
            let raw = spec.disassemble_ctx(&window, entry.offset, ctx).into_iter().next();
            let (raw_mnemonic, raw_len, raw_uncond_jump_target) = match &raw {
                None => (None, 0, None),
                Some(insn) => {
                    let len = insn.bytes.len();
                    let props = flow_props(&insn.ops, entry.offset, entry.offset + len as u64);
                    let target = (props.jump && !props.conditional)
                        .then(|| {
                            insn.ops
                                .iter()
                                .filter(|op| {
                                    matches!(OpCode::from_u32(op.opcode), Some(OpCode::Branch))
                                })
                                .find_map(super::static_target)
                        })
                        .flatten();
                    (Some(insn.mnemonic.clone()), len, target)
                }
            };
            let entry_outbound = program
                .reference_manager
                .refs_from(entry)
                .filter(|r| r.ref_type.is_flow())
                .map(|r| (r.ref_type, r.to))
                .collect();
            let target_is_function =
                thunked.is_some_and(|t| program.function_manager.function_at(t).is_some());
            let target_inbound = thunked
                .map(|t| {
                    program
                        .reference_manager
                        .refs_to(t)
                        .filter(|r| r.ref_type.is_flow())
                        .map(|r| (r.ref_type, r.from))
                        .collect()
                })
                .unwrap_or_default();
            Candidate {
                entry,
                raw_mnemonic,
                raw_len,
                raw_uncond_jump_target,
                entry_outbound,
                thunked,
                outcome,
                target_is_function,
                target_inbound,
            }
        })
        .collect()
}
