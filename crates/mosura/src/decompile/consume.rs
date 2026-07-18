//! Bit-level consume analysis — Ghidra's `ActionDeadCode::pushConsumed` / `propagateConsumed` /
//! `markConsumedParameters` / `gatherConsumedReturn` / the seeding in `ActionDeadCode::apply`
//! (`coreaction.cc:3556`, `3576`, `3840`, `3871`, `3925`).
//!
//! For each Varnode, `consume` is the mask of bits that are actually *used* downstream — the
//! backward dual of [`nzm`](super::varnode::Varnode::nzm). It is seeded at the sinks (a value read
//! by a RETURN/BRANCH/STORE/CBRANCH is fully consumed; a compared value is consumed per the
//! comparison; a call parameter is consumed per its minimal mask) and propagated *backward* through
//! the SSA graph by [`consume_transfer`], with a worklist fixpoint. `consume` grows monotonically
//! (each push is an OR, bounded by the full mask), so the worklist terminates without loop-clipping.
//!
//! The SubVariableFlow driving rules read `consume` to prove a wide Varnode is only used through a
//! narrow logical sub-value (`(vn.getConsume() & ~mask) != 0` gates `setReplacement`, etc.).
//!
//! After the fixpoint, [`calc_consume`] runs the `neverConsumed` arm of Ghidra's
//! `ActionDeadCode::apply` final sweep (`coreaction.cc:4046`): a Varnode the backward sweep
//! *reached* (vacuous) but whose consumed bits are all zero carries a provably-unused value, so
//! [`never_consumed`] replaces its reads with a constant 0 and destroys its def. This is the
//! bit-level fold that collapses the x86-64 sub-register widened-write round-trip — the CONCAT/PIECE
//! upper (`SUBPIECE(prev_whole,4)`), never consumed, becomes `#0x0`, so `PIECE(0,lo)` reduces to a
//! clean `ZEXT(lo)` before the rule pool. The *other* sweep arm — destroying Varnodes never reached
//! at all — stays in mosura's whole-varnode [`super::deadcode`] pass (all-or-nothing removal).
//!
//! Like [`super::nzmask`], mosura is `u64`-only, so Ghidra's extended-precision
//! (`size > sizeof(uintb)`) branches collapse to their reachable `u64` counterpart — a faithful
//! subset (no Varnode in the corpus exceeds 8 bytes).

use super::block::BlockId;
use super::funcdata::Funcdata;
use super::nzmask::{calc_mask, coveringmask, leastsigbit_set, minimalmask, pcode_left, pcode_right};
use super::opcode::OpCode;
use super::varnode::VarnodeId;

/// Ghidra `ActionDeadCode::pushConsumed` (`coreaction.cc:3556`): OR `val` into `vn`'s consume mask
/// (clamped to its size); if that changed the mask (or it is the first touch), enqueue the Varnode
/// for backward propagation. `in_list`/`vacuous` mirror Ghidra's per-Varnode `consumeList`/
/// `consumeVacuous` flags as transient worklist bookkeeping (mosura keeps them local so no transient
/// flag lands on the Varnode).
fn push_consumed(
    f: &mut Funcdata,
    val: u64,
    vn: VarnodeId,
    worklist: &mut Vec<VarnodeId>,
    in_list: &mut [bool],
    vacuous: &mut [bool],
) {
    let idx = vn.0 as usize;
    let cur = f.vn(vn).consume;
    let newval = (val | cur) & calc_mask(f.vn(vn).size);
    if newval == cur && vacuous[idx] {
        return;
    }
    vacuous[idx] = true;
    if !in_list[idx] {
        in_list[idx] = true;
        if f.vn(vn).is_written() {
            worklist.push(vn);
        }
    }
    f.vn_mut(vn).consume = newval;
}

/// Ghidra `ActionDeadCode::propagateConsumed` (`coreaction.cc:3576`): given the consume mask `outc`
/// of a written Varnode `vn`, return the `(consume, target)` pushes back to the inputs of the op
/// that defined it. The per-opcode transfer is ported verbatim from the `switch` there; the
/// `size > sizeof(uintb)` extended branches collapse to their `u64` counterpart (see module docs).
fn consume_transfer(f: &Funcdata, vn: VarnodeId, outc: u64) -> Vec<(u64, VarnodeId)> {
    let mut pushes: Vec<(u64, VarnodeId)> = Vec::new();
    let Some(def) = f.vn(vn).def else { return pushes };
    let o = f.op(def);
    let vnsize = f.vn(vn).size;
    let full = u64::MAX;
    let in_vn = |slot: usize| o.input(slot).expect("op input slot must exist");
    let in_const = |slot: usize| f.vn(in_vn(slot)).is_constant();
    let in_val = |slot: usize| f.vn(in_vn(slot)).constant_value();
    let in_size = |slot: usize| f.vn(in_vn(slot)).size;
    let in_nzm = |slot: usize| f.vn(in_vn(slot)).nzm;

    match o.code() {
        OpCode::IntMult => {
            let b = coveringmask(outc);
            let a = if in_const(1) {
                let least_set = leastsigbit_set(in_val(1));
                if least_set >= 0 {
                    pcode_right(calc_mask(vnsize), least_set as u32) & b
                } else {
                    0
                }
            } else {
                b
            };
            pushes.push((a, in_vn(0)));
            pushes.push((b, in_vn(1)));
        }
        OpCode::IntAdd | OpCode::IntSub => {
            // Fill out to a contiguous mask so a borrow/carry across the value is accounted for.
            let a = coveringmask(outc);
            pushes.push((a, in_vn(0)));
            pushes.push((a, in_vn(1)));
        }
        OpCode::Subpiece => {
            let sz = in_val(1); // truncation amount in bytes
            let mut a = if sz >= 8 { 0 } else { pcode_left(outc, sz as u32 * 8) };
            // Ghidra `CPUI_SUBPIECE` extended-precision case: if the consumed mask came out 0 only
            // because the u64 field can't cover the whole (>8-byte) source, yet the output still
            // consumes bits, set the highest bit to signal "some upper bits are consumed" — otherwise
            // a 128-bit product read only through its high `SUBPIECE` (the div-by-mult idiom) would
            // wrongly propagate consume 0 to the multiply.
            if a == 0 && outc != 0 && in_size(0) > 8 {
                a = 1u64 << 63;
            }
            let b = if outc == 0 { 0 } else { full };
            pushes.push((a, in_vn(0)));
            pushes.push((b, in_vn(1)));
        }
        OpCode::Piece => {
            let sa = 8 * in_size(1); // bits of the least-significant (low) piece
            let (a, b);
            if vnsize > 8 {
                // Ghidra `CPUI_PIECE` extended-precision case: the concatenation is wider than the
                // u64 consume field, so bits above the field are assumed consumed. This keeps the
                // high piece of a 16-byte `CONCAT88` (feeding e.g. a 16-byte STORE) marked consumed
                // rather than folded to 0.
                if in_size(1) >= 8 {
                    a = full; // whole high piece lies at/above the field boundary
                    b = outc;
                } else {
                    a = pcode_right(outc, sa) ^ pcode_left(full, 8 * (8 - in_size(1)));
                    b = outc ^ pcode_left(a, sa);
                }
            } else {
                a = pcode_right(outc, sa);
                b = outc ^ pcode_left(a, sa);
            }
            pushes.push((a, in_vn(0)));
            pushes.push((b, in_vn(1)));
        }
        OpCode::Indirect => {
            // Consume-value propagation is just to in(0). Ghidra's IOP branch (`setIndirectSource`
            // and the COPY-overlap full-consume) is a dead-code-*removal* detail, not needed until
            // consume is wired into elimination; omitted here (deadcode stays whole-varnode).
            pushes.push((outc, in_vn(0)));
        }
        OpCode::Copy | OpCode::IntNegate => {
            pushes.push((outc, in_vn(0)));
        }
        OpCode::IntXor | OpCode::IntOr => {
            pushes.push((outc, in_vn(0)));
            pushes.push((outc, in_vn(1)));
        }
        OpCode::IntAnd => {
            if in_const(1) {
                let val = in_val(1);
                pushes.push((outc & val, in_vn(0)));
                pushes.push((outc, in_vn(1)));
            } else {
                pushes.push((outc, in_vn(0)));
                pushes.push((outc, in_vn(1)));
            }
        }
        OpCode::Multiequal => {
            for i in 0..o.num_inputs() {
                pushes.push((outc, in_vn(i)));
            }
        }
        OpCode::IntZext => {
            pushes.push((outc, in_vn(0)));
        }
        OpCode::IntSext => {
            let b = calc_mask(in_size(0));
            let mut a = outc & b;
            if outc > b {
                a |= b ^ (b >> 1); // make sure the sign bit is marked used
            }
            pushes.push((a, in_vn(0)));
        }
        OpCode::IntLeft => {
            if in_const(1) {
                let sa = in_val(1);
                let a = if sa >= 64 { 0 } else { pcode_right(outc, sa as u32) };
                let b = if outc == 0 { 0 } else { full };
                pushes.push((a, in_vn(0)));
                pushes.push((b, in_vn(1)));
            } else {
                let a = if outc == 0 { 0 } else { full };
                pushes.push((a, in_vn(0)));
                pushes.push((a, in_vn(1)));
            }
        }
        OpCode::IntRight => {
            if in_const(1) {
                let sa = in_val(1);
                let a = if sa >= 64 { 0 } else { pcode_left(outc, sa as u32) };
                let b = if outc == 0 { 0 } else { full };
                pushes.push((a, in_vn(0)));
                pushes.push((b, in_vn(1)));
            } else {
                let a = if outc == 0 { 0 } else { full };
                pushes.push((a, in_vn(0)));
                pushes.push((a, in_vn(1)));
            }
        }
        OpCode::IntLess | OpCode::IntLessequal | OpCode::IntEqual | OpCode::IntNotequal => {
            // Anywhere a comparison input is known zero is not "consumed".
            let a = if outc == 0 { 0 } else { in_nzm(0) | in_nzm(1) };
            pushes.push((a, in_vn(0)));
            pushes.push((a, in_vn(1)));
        }
        OpCode::Insert => {
            // in: (src, val, position, size). Insert mask = (1<<size)-1, shifted by position.
            let insert_mask = 1u64.checked_shl(in_val(3) as u32).unwrap_or(0).wrapping_sub(1);
            pushes.push((insert_mask, in_vn(1)));
            let shifted = pcode_left(insert_mask, in_val(2) as u32);
            pushes.push((outc & !shifted, in_vn(0)));
            let b = if outc == 0 { 0 } else { full };
            pushes.push((b, in_vn(2)));
            pushes.push((b, in_vn(3)));
        }
        OpCode::Extract => {
            // in: (src, position, size). Extract mask = (1<<size)-1 & outc, shifted by position.
            let mut a = 1u64.checked_shl(in_val(2) as u32).unwrap_or(0).wrapping_sub(1);
            a &= outc;
            a = pcode_left(a, in_val(1) as u32);
            pushes.push((a, in_vn(0)));
            let b = if outc == 0 { 0 } else { full };
            pushes.push((b, in_vn(1)));
            pushes.push((b, in_vn(2)));
        }
        OpCode::Popcount | OpCode::Lzcount => {
            // Mask of bits the count output could set; if any is consumed, all input bits are.
            let a = (16 * in_size(0) as u64 - 1) & outc;
            let b = if a == 0 { 0 } else { full };
            pushes.push((b, in_vn(0)));
        }
        OpCode::Call | OpCode::Callind => {
            // Call output doesn't indicate consumption of inputs (handled by markConsumedParameters).
        }
        OpCode::FloatInt2float => {
            let a = if outc != 0 { coveringmask(in_nzm(0)) } else { 0 };
            pushes.push((a, in_vn(0)));
        }
        _ => {
            // All-or-nothing for every other op.
            let a = if outc == 0 { 0 } else { full };
            for i in 0..o.num_inputs() {
                pushes.push((a, in_vn(i)));
            }
        }
    }
    pushes
}

/// Ghidra `ActionDeadCode::gatherConsumedReturn` (`coreaction.cc:3871`): the bit mask consumed by
/// the function's return values. mosura has no proto output-lock, so only the active-recovery guard
/// applies; otherwise OR the minimal mask of each RETURN's value input. (`getReturnBytesConsumed`
/// is not modelled in mosura, so no additional clamp.)
fn gather_consumed_return(f: &Funcdata) -> u64 {
    if f.active_output.is_some() {
        return u64::MAX;
    }
    let mut consume = 0u64;
    for op in f.op_ids() {
        let o = f.op(op);
        if o.is_dead() {
            continue;
        }
        if o.code() == OpCode::Return && o.num_inputs() > 1 {
            consume |= minimalmask(f.vn(o.input(1).unwrap()).nzm);
        }
    }
    consume
}

/// Ghidra `ActionDeadCode::neverConsumed` (`coreaction.cc:3809`): `vn`'s value is provably unused —
/// the backward sweep reached it (it is vacuously consumed) yet its `consume` mask is 0 — so replace
/// every read of it with a constant 0 and destroy its defining op. Ghidra makes a fresh constant per
/// read (`newConstant`) and does not worry about feeding a marker, because an unconsumed input to a
/// marker means the marker's output is unconsumed too and about to be removed. Ghidra's
/// `size > sizeof(uintb)` precision guard is the extended branch (mosura is u64-only → `size > 8`).
fn never_consumed(f: &mut Funcdata, vn: VarnodeId) -> bool {
    if f.vn(vn).size > 8 {
        return false; // Not enough precision to really tell
    }
    let size = f.vn(vn).size;
    // Replace vn with 0 wherever it is read (a fresh constant per slot, mirroring Ghidra).
    for op in f.vn(vn).descend.clone() {
        for slot in 0..f.op(op).num_inputs() {
            if f.op(op).input(slot) == Some(vn) {
                let zero = f.new_const(size, 0);
                f.op_set_input(op, slot, zero);
            }
        }
    }
    // Otherwise completely remove the defining op. (Ghidra `opUnsetOutput`s a CALL def instead;
    // mosura has no such primitive and the sweep below never selects a CALL output, so only the
    // non-call `opDestroy` arm is reachable here.)
    if let Some(def) = f.vn(vn).def {
        f.op_destroy(def);
    }
    true
}

/// Ghidra `ActionDeadCode::apply` seeding + `markConsumedParameters` (`coreaction.cc:3925`, `3840`):
/// compute every Varnode's `consume` mask. Seeds from the sinks and call parameters, then propagates
/// backward to a fixpoint, then runs the `neverConsumed` sweep (`coreaction.cc:4046`).
pub fn calc_consume(f: &mut Funcdata) {
    let nvn = f.num_varnodes();
    for i in 0..nvn as u32 {
        f.vn_mut(VarnodeId(i)).consume = 0;
    }

    let return_consume = gather_consumed_return(f);

    // Collect alive ops (those still in blocks), preserving the seeding order.
    let mut all_ops = Vec::new();
    for b in 0..f.num_blocks() as u32 {
        all_ops.extend(f.block(BlockId(b)).ops.iter().copied());
    }

    // Build the seed pushes (pure reads), mirroring the ActionDeadCode::apply op scan.
    let mut seeds: Vec<(u64, VarnodeId)> = Vec::new();
    for &op in &all_ops {
        let o = f.op(op);
        let code = o.code();
        let has_out = o.output.is_some();
        if o.is_call() {
            // CALL/CALLIND params are postponed to markConsumedParameters; CALLOTHER has no
            // call-spec (`isCallWithoutSpec`), so all its inputs are fully consumed here.
            if !matches!(code, OpCode::Call | OpCode::Callind) {
                for i in 0..o.num_inputs() {
                    seeds.push((u64::MAX, o.input(i).unwrap()));
                }
            }
            if !has_out {
                continue;
            }
            // (Ghidra's holdOutput full-consume is not modelled in mosura; auto-live output below.)
        } else if !has_out {
            match code {
                OpCode::Return => {
                    if o.num_inputs() > 0 {
                        seeds.push((u64::MAX, o.input(0).unwrap())); // return address, fully consumed
                    }
                    for i in 1..o.num_inputs() {
                        seeds.push((return_consume, o.input(i).unwrap()));
                    }
                }
                OpCode::Branchind => {
                    // Ghidra restricts to `jt->getSwitchVarConsume()`; mosura conservatively
                    // fully-consumes the switch variable (switch pulls are a later stage).
                    if o.num_inputs() > 0 {
                        seeds.push((u64::MAX, o.input(0).unwrap()));
                    }
                }
                _ => {
                    for i in 0..o.num_inputs() {
                        seeds.push((u64::MAX, o.input(i).unwrap()));
                    }
                }
            }
            continue;
        } else {
            // Assignment op: only auto-live inputs are pre-consumed.
            for i in 0..o.num_inputs() {
                let v = o.input(i).unwrap();
                if f.vn(v).is_auto_live() {
                    seeds.push((u64::MAX, v));
                }
            }
        }
        // Common tail (call-with-output or assignment): an auto-live output is fully consumed.
        if let Some(out) = f.op(op).output {
            if f.vn(out).is_auto_live() {
                seeds.push((u64::MAX, out));
            }
        }
    }

    // markConsumedParameters for each CALL/CALLIND.
    for &op in &all_ops {
        if !matches!(f.op(op).code(), OpCode::Call | OpCode::Callind) {
            continue;
        }
        let o = f.op(op);
        let n = o.num_inputs();
        if n > 0 {
            seeds.push((u64::MAX, o.input(0).unwrap())); // first operand (target) fully consumed
        }
        // Ghidra: isInputLocked() || isInputActive(). mosura has no input-lock; active recovery is
        // an entry in active_inputs → treat all parameters as fully consumed while resolving.
        if f.active_inputs.contains_key(&op) {
            for i in 1..n {
                seeds.push((u64::MAX, o.input(i).unwrap()));
            }
        } else {
            for i in 1..n {
                let v = o.input(i).unwrap();
                let cv = if f.vn(v).is_auto_live() { u64::MAX } else { minimalmask(f.vn(v).nzm) };
                // (getInputBytesConsumed is not modelled in mosura → no additional clamp.)
                seeds.push((cv, v));
            }
        }
    }

    // Persistent global live-out. Ghidra keeps a direct write to a `persist`/global location alive by
    // marking it `addrforce` (→ `isAutoLive`), so `ActionDeadCode` seeds it fully-consumed; its value
    // (and the backward chain feeding it) is therefore never `neverConsumed`-folded to 0. mosura only
    // flags globals `persist` after type recovery, so — exactly as `deadcode::dead_code`'s persistent
    // live-out roots do — it uses the `ram` space as the proxy: a written `ram` Varnode is a global
    // side effect, live to the caller. Seeding it fully-consumed keeps the two liveness views in step
    // (else the whole-varnode `dead_code` would keep the store while the bit-level sweep zeroes it).
    if let Some(ram) = f.spaces.by_name("ram") {
        for i in 0..nvn as u32 {
            let vn = VarnodeId(i);
            if f.vn(vn).is_written() && f.vn(vn).loc.space == ram {
                seeds.push((u64::MAX, vn));
            }
        }
    }

    // Apply the seeds, then propagate backward to a fixpoint.
    let mut worklist: Vec<VarnodeId> = Vec::new();
    let mut in_list = vec![false; nvn];
    let mut vacuous = vec![false; nvn];
    for (val, vn) in seeds {
        push_consumed(f, val, vn, &mut worklist, &mut in_list, &mut vacuous);
    }
    while let Some(vn) = worklist.pop() {
        in_list[vn.0 as usize] = false;
        let outc = f.vn(vn).consume;
        for (val, tgt) in consume_transfer(f, vn, outc) {
            push_consumed(f, val, tgt, &mut worklist, &mut in_list, &mut vacuous);
        }
    }

    // Ghidra `ActionDeadCode::apply` final sweep (`coreaction.cc:4032-4052`), the `neverConsumed`
    // arm: for each written Varnode in a dead-code space (`doesDeadcode`/`deadRemovalAllowed`, i.e.
    // heritaged here — const/annotation spaces excluded) that was reached by the backward sweep
    // (`isConsumeVacuous`) but consumes no bits (`getConsume()==0`), fold it to 0. `nvn` predates the
    // fresh constants `never_consumed` mints, so collect targets first, then rewrite. A CALL def is
    // skipped (Ghidra `opUnsetOutput`s it — mosura lacks that primitive; such outputs do not arise).
    let mut targets: Vec<VarnodeId> = Vec::new();
    // faithful port of Ghidra's per-Varnode sweep; `i` is the VarnodeId, not merely a slice index
    #[allow(clippy::needless_range_loop)]
    for i in 0..nvn {
        let vn = VarnodeId(i as u32);
        let v = f.vn(vn);
        if v.is_written()
            && vacuous[i]
            && v.consume == 0
            && f.spaces.get(v.loc.space).is_heritaged()
            && v.def.map(|d| !f.op(d).is_call()).unwrap_or(false)
        {
            targets.push(vn);
        }
    }
    for vn in targets {
        never_consumed(f, vn);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::block::BlockBasic;
    use super::super::op::SeqNum;
    use super::super::opcode::OpCode;
    use super::super::space::{Address, SpaceManager};

    /// Build a function, run nzmask (needed by the compare/int2float transfers), then calc_consume.
    fn run(f: &mut Funcdata) {
        let dom = super::super::dominator::compute(f);
        super::super::nzmask::calc_nzmask(f, &dom);
        calc_consume(f);
    }

    #[test]
    fn subpiece_low_byte_consumes_only_low_byte() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        let x = f.new_input(4, Address::new(reg, 0x10));
        let c0 = f.new_const(4, 0);
        // sub = SUBPIECE(x, 0) : 1-byte truncation of x's low byte
        let sub = f.new_op(OpCode::Subpiece, seq, vec![x, c0]);
        let sub_out = f.new_output(sub, 1, Address::new(reg, 0x20));
        // STORE(space, ptr, sub_out) — a sink that fully consumes its value input.
        let sid = f.new_const(8, ram.0 as u64);
        let ptr = f.new_input(8, Address::new(reg, 0x30));
        let store = f.new_op(OpCode::Store, seq, vec![sid, ptr, sub_out]);

        f.set_blocks(vec![BlockBasic { ops: vec![sub, store], ..Default::default() }]);
        run(&mut f);

        assert_eq!(f.vn(sub_out).consume, 0xff); // fully consumed (1-byte value)
        assert_eq!(f.vn(x).consume, 0xff); // only the low byte of x is used
    }

    #[test]
    fn and_with_mask_consumes_masked_bits() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        let x = f.new_input(4, Address::new(reg, 0x10));
        let c_ff = f.new_const(4, 0xff);
        let and = f.new_op(OpCode::IntAnd, seq, vec![x, c_ff]);
        let and_out = f.new_output(and, 4, Address::new(reg, 0x20));
        let sid = f.new_const(8, ram.0 as u64);
        let ptr = f.new_input(8, Address::new(reg, 0x30));
        let store = f.new_op(OpCode::Store, seq, vec![sid, ptr, and_out]);

        f.set_blocks(vec![BlockBasic { ops: vec![and, store], ..Default::default() }]);
        run(&mut f);

        assert_eq!(f.vn(and_out).consume, 0xffff_ffff); // stored → fully consumed
        assert_eq!(f.vn(x).consume, 0xff); // only the masked (low) byte is used
    }

    #[test]
    fn compare_consumes_per_nonzero_mask() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        let x = f.new_input(4, Address::new(reg, 0x10));
        let c_ff = f.new_const(4, 0xff);
        // narrow = x & 0xff → nzm 0xff
        let narrow = f.new_op(OpCode::IntAnd, seq, vec![x, c_ff]);
        let narrow_out = f.new_output(narrow, 4, Address::new(reg, 0x20));
        let c5 = f.new_const(4, 5);
        // eq = (narrow == 5) — a comparison consumes only its inputs' non-zero bits.
        let eq = f.new_op(OpCode::IntEqual, seq, vec![narrow_out, c5]);
        let eq_out = f.new_output(eq, 1, Address::new(reg, 0x28));
        // CBRANCH(target, eq_out) — a sink that fully consumes the condition.
        let target = f.new_const(8, 0);
        let cbr = f.new_op(OpCode::Cbranch, seq, vec![target, eq_out]);

        f.set_blocks(vec![BlockBasic { ops: vec![narrow, eq, cbr], ..Default::default() }]);
        run(&mut f);

        // The compare consumes nzm(narrow) | nzm(5) = 0xff | 5 = 0xff; the AND then restricts to
        // the low byte of x, so x is consumed only in its low byte.
        assert_eq!(f.vn(narrow_out).consume, 0xff);
        assert_eq!(f.vn(x).consume, 0xff);
    }

    #[test]
    fn shift_moves_the_consumed_window() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        let x = f.new_input(4, Address::new(reg, 0x10));
        let c8 = f.new_const(4, 8);
        // shl = x << 8, then mask the result to a single byte at bits 8..16 with & 0xff00.
        let shl = f.new_op(OpCode::IntLeft, seq, vec![x, c8]);
        let shl_out = f.new_output(shl, 4, Address::new(reg, 0x20));
        let c_ff00 = f.new_const(4, 0xff00);
        let and = f.new_op(OpCode::IntAnd, seq, vec![shl_out, c_ff00]);
        let and_out = f.new_output(and, 4, Address::new(reg, 0x28));
        let sid = f.new_const(8, ram.0 as u64);
        let ptr = f.new_input(8, Address::new(reg, 0x30));
        let store = f.new_op(OpCode::Store, seq, vec![sid, ptr, and_out]);

        f.set_blocks(vec![BlockBasic { ops: vec![shl, and, store], ..Default::default() }]);
        run(&mut f);

        // and_out consumes 0xff00 (stored → full, then AND restricts in(0) to 0xff00).
        assert_eq!(f.vn(shl_out).consume, 0xff00);
        // Backward through `<< 8`: consume(x) = 0xff00 >> 8 = 0xff.
        assert_eq!(f.vn(x).consume, 0xff);
    }

    #[test]
    fn never_consumed_folds_an_unconsumed_widened_write_upper() {
        // Ghidra `ActionDeadCode::neverConsumed`: a PIECE's high input that is written but never
        // consumed (the sub-register widened-write round-trip) is folded to constant 0 and its def
        // destroyed — the fold that lets `PIECE(0,lo)` reduce to a clean ZEXT before the pool.
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let uniq = spaces.by_name("unique").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        let whole_in = f.new_input(8, Address::new(reg, 0x0)); // e.g. incoming RAX
        let c4 = f.new_const(8, 4);
        // hi = SUBPIECE(whole_in, 4): the upper 4 bytes — written, but never consumed below.
        let hi = f.new_op(OpCode::Subpiece, seq, vec![whole_in, c4]);
        let hi_out = f.new_output(hi, 4, Address::new(uniq, 0x100));
        let lo = f.new_input(4, Address::new(reg, 0x40)); // the logical value
        // piece = PIECE(hi_out, lo): the widened write reconstructing 8 bytes from upper + value.
        let piece = f.new_op(OpCode::Piece, seq, vec![hi_out, lo]);
        let piece_out = f.new_output(piece, 8, Address::new(uniq, 0x108));
        let c0 = f.new_const(8, 0);
        // low = SUBPIECE(piece, 0): only the low 4 bytes are ever read.
        let low = f.new_op(OpCode::Subpiece, seq, vec![piece_out, c0]);
        let low_out = f.new_output(low, 4, Address::new(uniq, 0x110));
        let sid = f.new_const(8, ram.0 as u64);
        let ptr = f.new_input(8, Address::new(reg, 0x30));
        let store = f.new_op(OpCode::Store, seq, vec![sid, ptr, low_out]);

        f.set_blocks(vec![BlockBasic { ops: vec![hi, piece, low, store], ..Default::default() }]);
        run(&mut f);

        // The upper SUBPIECE was never consumed → folded to constant 0, its def destroyed.
        assert!(!f.vn(hi_out).is_written(), "the unconsumed upper's def is destroyed");
        let new_hi = f.op(piece).input(0).unwrap();
        assert!(
            f.vn(new_hi).is_constant() && f.vn(new_hi).constant_value() == 0,
            "the PIECE high input is folded to constant 0",
        );
        // The low value stays fully consumed (extended-precision PIECE transfer keeps it whole).
        assert_eq!(f.vn(lo).consume, 0xffffffff);
    }
}
