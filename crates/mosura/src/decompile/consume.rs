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
//! This is the consume *analysis* only: it fills `Varnode::consume`. mosura's dead-code
//! *elimination* ([`super::deadcode`]) stays whole-varnode (all-or-nothing); the bit-refinement of
//! elimination (`neverConsumed`, the vacuous-consume sweep) is a later addition and is not wired
//! here, so this pass is output-neutral until the subvar rules consume the field.
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
            // (Ghidra's `in(0).size > sizeof(uintb)` top-bit special case is the extended-precision
            // branch, omitted in the u64-only subset.)
            let a = if sz >= 8 { 0 } else { pcode_left(outc, sz as u32 * 8) };
            let b = if outc == 0 { 0 } else { full };
            pushes.push((a, in_vn(0)));
            pushes.push((b, in_vn(1)));
        }
        OpCode::Piece => {
            let sa = 8 * in_size(1); // bits of the least-significant piece
            let a = pcode_right(outc, sa);
            let b = outc ^ pcode_left(a, sa);
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

/// Ghidra `ActionDeadCode::apply` seeding + `markConsumedParameters` (`coreaction.cc:3925`, `3840`):
/// compute every Varnode's `consume` mask. Seeds from the sinks and call parameters, then propagates
/// backward to a fixpoint.
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
}
