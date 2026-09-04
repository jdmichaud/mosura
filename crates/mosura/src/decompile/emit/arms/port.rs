//! The renderings still resident in printc.rs (the R2b backlog): their report candidates and
//! witnessed decisions live here so the printer holds the registry opaquely, and each moves
//! into its own arm module with its rendering.
use crate::decompile::op::OpId;
use crate::decompile::varnode::VarnodeId;

/// The port's candidates the report pass collects (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// Every DECLARED local the `local-width` axis would re-declare, as `(HighVariable
    /// representative, defining instruction address)`. The address is what a target rule
    /// scores: it is where the ORIGINAL either widened the value (`XOR r32,r32` near a
    /// narrow write into its low part, or a full-register write) or kept it narrow.
    /// Filtered to candidates with an EXPLICIT member — an inline value never declares, so
    /// widening it is inert and its presence only diluted the per-function calibration.
    pub local_width_candidates: Vec<(u32, u64)>,
    /// Every tier-2 materialization candidate of the same axis (narrow loads and byte/word
    /// extracts the `Storage` value would force explicit), as `(value, op address)`. Scored
    /// by the same def-site classifier; VarnodeIds are stable within one decompile, which is
    /// the report → recovered-print lifetime.
    pub tier2_candidates: Vec<(VarnodeId, u64)>,
    /// Runs of two or more CONSECUTIVE pure global-store statements, as
    /// `(op, global address, size)` per store in OUR statement order — the persist-store
    /// ordering candidates. Ghidra's rendering order for adjacent global stores is
    /// oracle-verified faithful yet differs from the original's; the order decides both
    /// Watcom's scheduling and its immediate-vs-register store selection (probe: reordering
    /// two stores alone took `FUN_000165f4` MISMATCH → EXACT). A target rule reads the
    /// original's own store sequence at those addresses and returns the emission order.
    /// Pure = the stored value renders without reading memory (a constant, an input, or a
    /// named local), and every address is a distinct constant global, so any order computes
    /// the same state.
    pub store_runs: Vec<Vec<(OpId, u64, u32)>>,
    /// The same runs for STACK stores, as `(op, stack-space offset, size)` — a frame slot or an
    /// element of the frame aggregate written from a constant, a parameter or a named local. The
    /// pipeline's own placement of such a store is not the source's: a slot the callee reads
    /// through an INDIRECT is snipped into a COPY placed right before the call (Ghidra's
    /// `Merge::snipIndirect`, ported), so the parameter's store prints after the constant stores
    /// the original wrote it before (WAR2 FUN_00012e40's `[8] = param_1` after `[6] = 0xe; [0] =
    /// 9`). A target rule reads the original's own `MOV [EBP + off],..` sequence
    /// (`buildconfig::stack_store_orders_from_evidence`) and returns the emission order.
    pub stack_store_runs: Vec<Vec<(OpId, i64, u32)>>,
    /// Every RETURN whose value is narrower than the recovered return storage, as
    /// `(RETURN instruction address, value size, recovered storage size)`. The target rule
    /// reads the ORIGINAL's last write to the return register before that address: a narrow
    /// write (`MOV AL,..`) with no widening means the original's contract really was narrow —
    /// the reference decompiler's `return-width=value` — while a full-register write
    /// (`AND EAX,0xff`, `MOVZX`, a call) means the widened declaration is right.
    pub return_width_candidates: Vec<(u64, u32, u32)>,
    /// Every direct call with arguments, as `(call instruction address, callee address,
    /// per-argument reorder-safety)` — the argument-order candidates. C argument order is
    /// invisible in the bytes when it matches the convention's storage order, but the
    /// compiler MATERIALIZES register arguments in reverse declared order, so the original's
    /// setup sequence at its call sites is a readout of the parameter order its source
    /// declared (`buildconfig::param_orders_from_evidence`). An argument is reorder-safe
    /// when it is a CONSTANT: its materialization is one immediate move at the call.
    /// Identifier arguments measured UNSAFE — permuting register-held variables re-orders
    /// their shuffle and ripples the allocation through the whole function (three
    /// SAME_SHAPE siblings fell to MISMATCH as pure regalloc cascades).
    pub call_order_candidates: Vec<(u64, u64, Vec<bool>)>,
    /// Two-arm constant joins (`if/else` whose arms each assign one CONSTANT to the same
    /// variable): `(branch pc, then constant, else constant)`. The original's own layout —
    /// which constant it materializes first past the conditional jump — decides the printed
    /// arm order (wc2src D3b; the `.SAV`/`.NET` ternary of `sfile_make_name`).
    pub arm_swap_candidates: Vec<(u64, u64, u64)>,
}

/// The port's witnessed decisions the recovered pass renders (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Sites {
    /// The witnessed narrow return WIDTH in bytes (`AL` = 1, `AX` = 2; 0 = not witnessed, the
    /// value's own width applies) — meaningful only with `narrow_return`.
    pub narrow_return_width: u32,
    /// The function's return declaration stays at the VALUE's width (the reference
    /// decompiler's rendering) instead of the recovered storage width — per function, since
    /// one declaration covers every RETURN (`return-width`).
    pub narrow_return: bool,
    /// That narrow return declaration is SIGNED — witnessed by the sign-extended-constant idiom
    /// (`MOV EAX,0xffff8000` returning a 2-byte value). Only meaningful with `narrow_return`; a
    /// return narrowed on narrow-write evidence alone leaves this false and keeps the inferred
    /// type's own signedness, so no pre-existing firing changes spelling.
    pub narrow_return_signed: bool,
    /// HighVariable representatives whose declaration widens to int width (`local-width`,
    /// per declared local instead of the arm's whole-function blanket).
    pub widen_local_reps: std::collections::HashSet<u32>,
    /// The widened representatives' candidate ADDRESSES (`local_width_candidates`' defining
    /// instruction per decided rep) — the stable key the fixpoint check compares: a
    /// representative index is a HighVariable number a re-render can renumber, an address is
    /// not (review finding 3, 2026-09-04).
    pub widen_local_pcs: std::collections::HashSet<u64>,
    /// Values whose tier-2 materialization applies (`local-width` tier 2, per site).
    pub tier2_sites: std::collections::HashSet<VarnodeId>,
    /// Per store-run emission orders, keyed by the run's FIRST op in block order: the ops
    /// re-emitted in the original's store order (`store_runs` evidence).
    pub store_orders: std::collections::HashMap<OpId, Vec<OpId>>,
    /// Per call site, the argument order to RENDER, keyed by the call instruction's address:
    /// `perm[j]` is the reference rendering's argument index that prints at position `j`.
    /// Value-identical only together with a matching `#pragma aux ... parm [..]` in the same
    /// TU (the caller emits both from one per-callee decision — `call_order_candidates`).
    pub call_arg_orders: std::collections::HashMap<u64, Vec<usize>>,
    /// Two-arm constant joins to print with the arms SWAPPED (condition negated): the
    /// original materializes the else-arm's constant first (`arm_swap_candidates` evidence,
    /// `buildconfig::arm_swaps_from_evidence`).
    pub arm_swap_sites: std::collections::HashSet<u64>,
    /// Statement-interleave orders (allocator thread lever 3): per basic block whose
    /// independent adjacent statements the original computed in the reverse order, keyed
    /// by the block's first re-emitted statement op, the block's assign/gstore/store
    /// statements in the ORIGINAL's order (`interleave_orders`). Statements of other kinds
    /// (calls, control) keep their positions; the re-emitted ops are skipped when the block
    /// walk reaches them, as `store_orders` does.
    pub ilv_orders: std::collections::HashMap<OpId, Vec<OpId>>,
}
