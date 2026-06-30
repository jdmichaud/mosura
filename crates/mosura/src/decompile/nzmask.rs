//! Non-zero-mask analysis — Ghidra's `Varnode::nzm` / `PcodeOp::getNZMaskLocal` /
//! `Funcdata::calcNZMask` (`op.cc:547`, `funcdata_varnode.cc:856`) wrapped by `ActionNonzeroMask`.
//!
//! For each Varnode, `nzm` is a mask of the bits that *may* be non-zero — every bit cleared in
//! `nzm` is provably 0 in every execution. It is computed bottom-up over the SSA graph: each op's
//! output mask is a function of its inputs' masks ([`op_nzmask_local`]), with a worklist fixpoint
//! over MULTIEQUAL loops ([`calc_nzmask`]). Simplification rules read it to prove, e.g., that a
//! shifted value compared to zero loses no information (`RuleShiftCompare`).
//!
//! mosura is `u64`-only, so Ghidra's extended-precision (`size > sizeof(uintb)`) branches collapse
//! to their `fullmask` fallback — a faithful subset (no Varnode in the corpus exceeds 8 bytes).

use std::collections::HashSet;

use super::dominator::Dominators;
use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;

/// Ghidra `calc_mask` (`address.cc`): the all-ones mask for a Varnode of `size` bytes.
pub fn calc_mask(size: u32) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * size)) - 1
    }
}

/// Ghidra `pcode_left` (`address.hh:514`): `val << sa`, but 0 once the shift clears the whole word
/// (C++ left-shift by `>= 64` is undefined; Rust would panic).
fn pcode_left(val: u64, sa: u32) -> u64 {
    if sa >= 64 {
        0
    } else {
        val << sa
    }
}

/// Ghidra `pcode_right` (`address.hh:505`): `val >> sa`, 0 once the shift clears the whole word.
fn pcode_right(val: u64, sa: u32) -> u64 {
    if sa >= 64 {
        0
    } else {
        val >> sa
    }
}

/// Ghidra `coveringmask` (`address.cc:800`): smear every set bit down, so the result is a
/// contiguous run of ones from the most-significant set bit of `val` down to bit 0.
fn coveringmask(mut val: u64) -> u64 {
    let mut sz = 1;
    while sz < 64 {
        val |= val >> sz;
        sz <<= 1;
    }
    val
}

/// Ghidra `mostsigbit_set` (`address.cc:735`): position of the most-significant set bit, or `-1`.
fn mostsigbit_set(val: u64) -> i32 {
    if val == 0 {
        -1
    } else {
        63 - val.leading_zeros() as i32
    }
}

/// Ghidra `leastsigbit_set` (`address.cc:714`): position of the least-significant set bit, or `-1`.
fn leastsigbit_set(val: u64) -> i32 {
    if val == 0 {
        -1
    } else {
        val.trailing_zeros() as i32
    }
}

/// Ghidra `sign_extend(in, sizein, sizeout)` (`address.cc:666`): sign-extend the mask of a
/// `sizein`-byte value to `sizeout` bytes. If the input's sign bit may be set, the new high bits
/// are unknown (all ones).
fn sign_extend_mask(inmask: u64, sizein: u32, sizeout: u32) -> u64 {
    let sizein = sizein.min(8) as i32;
    let sizeout = sizeout.min(8) as i32;
    if sizeout <= sizein {
        return inmask & calc_mask(sizeout as u32);
    }
    let sval = (inmask as i64).wrapping_shl(((8 - sizein) * 8) as u32);
    let mut res = (sval >> ((sizeout - sizein) * 8)) as u64; // arithmetic (signed) right shift
    res >>= ((8 - sizeout) * 8) as u32;
    res
}

/// Ghidra `PcodeOp::getNZMaskLocal(cliploop)` (`op.cc:547`): the non-zero mask of `op`'s output,
/// assuming each input Varnode's `nzm` is already computed. `op` must have an output.
///
/// `cliploop` excludes known back-edges from a MULTIEQUAL (so the initial bottom-up pass terminates
/// without the not-yet-computed loop input); the worklist re-includes them to a fixpoint.
pub fn op_nzmask_local(f: &Funcdata, op: OpId, cliploop: bool, dom: &Dominators) -> u64 {
    let o = f.op(op);
    let out = o.output.expect("op must have an output");
    let size = f.vn(out).size;
    let fullmask = calc_mask(size);
    let in_nzm = |slot: usize| f.vn(o.input(slot).unwrap()).nzm;
    let in_size = |slot: usize| f.vn(o.input(slot).unwrap()).size;
    let in_const = |slot: usize| f.vn(o.input(slot).unwrap()).is_constant();
    let in_val = |slot: usize| f.vn(o.input(slot).unwrap()).constant_value();

    match o.code() {
        // Ops whose result is strictly boolean: only the low bit may be set.
        OpCode::IntEqual
        | OpCode::IntNotequal
        | OpCode::IntSless
        | OpCode::IntSlessequal
        | OpCode::IntLess
        | OpCode::IntLessequal
        | OpCode::IntCarry
        | OpCode::IntScarry
        | OpCode::IntSborrow
        | OpCode::BoolNegate
        | OpCode::BoolXor
        | OpCode::BoolAnd
        | OpCode::BoolOr
        | OpCode::FloatEqual
        | OpCode::FloatNotequal
        | OpCode::FloatLess
        | OpCode::FloatLessequal
        | OpCode::FloatNan => 1,
        OpCode::Copy | OpCode::IntZext => in_nzm(0),
        OpCode::IntSext => sign_extend_mask(in_nzm(0), in_size(0), size),
        OpCode::IntXor | OpCode::IntOr => {
            let mut resmask = in_nzm(0);
            if resmask != fullmask {
                resmask |= in_nzm(1);
            }
            resmask
        }
        OpCode::IntAnd => {
            let mut resmask = in_nzm(0);
            if resmask != 0 {
                resmask &= in_nzm(1);
            }
            resmask
        }
        OpCode::IntLeft => {
            if !in_const(1) {
                fullmask
            } else {
                pcode_left(in_nzm(0), in_val(1) as u32) & fullmask
            }
        }
        OpCode::IntRight => {
            // mosura caps at 8 bytes, so Ghidra's `sz1 > sizeof(uintb)` extended branch is unreached.
            if !in_const(1) {
                fullmask
            } else {
                pcode_right(in_nzm(0), in_val(1) as u32)
            }
        }
        OpCode::IntSright => {
            if !in_const(1) || size > 8 {
                fullmask
            } else {
                let sa = in_val(1) as u32;
                let resmask = in_nzm(0);
                let signbit = fullmask ^ (fullmask >> 1);
                if resmask & signbit == 0 {
                    pcode_right(resmask, sa)
                } else {
                    pcode_right(resmask, sa) | (pcode_right(fullmask, sa) ^ fullmask)
                }
            }
        }
        OpCode::IntDiv => {
            let mut resmask = coveringmask(in_nzm(0));
            if in_const(1) {
                let sa = mostsigbit_set(in_nzm(1));
                if sa != -1 {
                    resmask = pcode_right(resmask, sa as u32);
                }
            }
            resmask
        }
        OpCode::IntRem => coveringmask(in_nzm(1).wrapping_sub(1)),
        OpCode::Popcount => coveringmask(in_nzm(0).count_ones() as u64) & fullmask,
        OpCode::Lzcount => coveringmask(in_size(0) as u64 * 8) & fullmask,
        OpCode::Subpiece => {
            let mut resmask = in_nzm(0);
            let sz1 = in_val(1) as u32; // truncation amount in bytes
            if in_size(0) <= 8 {
                resmask = if sz1 < 8 { pcode_right(resmask, 8 * sz1) } else { 0 };
            }
            resmask & fullmask
        }
        OpCode::Piece => {
            let sa = in_size(1); // bytes of the least-significant piece
            let mut resmask = if sa < 8 { pcode_left(in_nzm(0), 8 * sa) } else { 0 };
            resmask |= in_nzm(1);
            resmask
        }
        OpCode::IntMult => {
            let val = in_nzm(0);
            let resmask = in_nzm(1);
            if size > 8 {
                fullmask
            } else {
                let sz1 = mostsigbit_set(val);
                let sz2 = mostsigbit_set(resmask);
                if sz1 == -1 || sz2 == -1 {
                    0
                } else {
                    let l1 = leastsigbit_set(val);
                    let l2 = leastsigbit_set(resmask);
                    let sa = l1 + l2;
                    if sa >= 8 * size as i32 {
                        0
                    } else {
                        let sz1 = sz1 - l1 + 1;
                        let sz2 = sz2 - l2 + 1;
                        let mut total = sz1 + sz2;
                        if sz1 == 1 || sz2 == 1 {
                            total -= 1;
                        }
                        let mut r = fullmask;
                        if total < 8 * size as i32 {
                            r = pcode_right(r, (8 * size as i32 - total) as u32);
                        }
                        pcode_left(r, sa as u32) & fullmask
                    }
                }
            }
        }
        OpCode::IntAdd => {
            let mut resmask = in_nzm(0);
            if resmask != fullmask {
                resmask |= in_nzm(1);
                resmask |= resmask << 1; // account for possible carries
                resmask &= fullmask;
            }
            resmask
        }
        OpCode::Multiequal => {
            if o.num_inputs() == 0 {
                fullmask
            } else {
                let mut resmask = 0u64;
                for i in 0..o.num_inputs() {
                    if cliploop && is_loop_in(f, op, i, dom) {
                        continue;
                    }
                    resmask |= in_nzm(i);
                }
                resmask
            }
        }
        // CALL/CALLIND/CPOOLREF: Ghidra returns 1 for a known calculated-bool output; mosura does
        // not model that, so they fall through to the conservative full mask, like every other op.
        _ => fullmask,
    }
}

/// Ghidra `BlockBasic::isLoopIn(slot)`: is the MULTIEQUAL `op`'s input `slot` a back-edge? Its
/// predecessor is `parent.in_edges[slot]`; the edge is a loop edge iff `parent` dominates it.
fn is_loop_in(f: &Funcdata, op: OpId, slot: usize, dom: &Dominators) -> bool {
    let Some(parent) = f.op(op).parent else { return false };
    let preds = &f.blocks()[parent.0 as usize].in_edges;
    let Some(pred) = preds.get(slot) else { return false };
    dom.dominates(parent.0 as usize, pred.0 as usize)
}

/// Ghidra `Funcdata::calcNZMask` (`funcdata_varnode.cc:856`): compute every Varnode's `nzm`.
///
/// Phase 1 is a marked DFS in op post-order (so an op's inputs are computed before it), using
/// `cliploop = true` so MULTIEQUAL back-edges (whose source may not be computed yet) are excluded.
/// Free/input leaves get the full mask (a spacebase input is treated as aligned: low byte cleared);
/// constants get their literal value. Phase 2 is a worklist seeded with the MULTIEQUALs, recomputing
/// with `cliploop = false` (all edges) and re-pushing descendants on change, to a loop fixpoint.
pub fn calc_nzmask(f: &mut Funcdata, dom: &Dominators) {
    let mut all_ops: Vec<OpId> = Vec::new();
    for b in 0..f.num_blocks() {
        all_ops.extend(f.blocks()[b].ops.iter().copied());
    }

    // Phase 1: bottom-up DFS.
    let mut marked: HashSet<OpId> = HashSet::new();
    for &seed in &all_ops {
        if !marked.insert(seed) {
            continue;
        }
        let mut stack: Vec<(OpId, usize)> = vec![(seed, 0)];
        while let Some(&(op, slot)) = stack.last() {
            let ninput = f.op(op).num_inputs();
            if slot >= ninput {
                if f.op(op).output.is_some() {
                    let m = op_nzmask_local(f, op, true, dom);
                    f.vn_mut(f.op(op).output.unwrap()).nzm = m;
                }
                stack.pop();
                continue;
            }
            stack.last_mut().unwrap().1 += 1;
            // Clip a MULTIEQUAL back-edge (don't descend into the not-yet-computed loop source).
            if f.op(op).code() == OpCode::Multiequal && is_loop_in(f, op, slot, dom) {
                continue;
            }
            let vn = f.op(op).input(slot).unwrap();
            if !f.vn(vn).is_written() {
                let m = if f.vn(vn).is_constant() {
                    f.vn(vn).constant_value() & calc_mask(f.vn(vn).size)
                } else {
                    let mut m = calc_mask(f.vn(vn).size);
                    if f.vn(vn).is_spacebase() {
                        m &= !0xffu64; // treat spacebase input as aligned
                    }
                    m
                };
                f.vn_mut(vn).nzm = m;
            } else if let Some(def) = f.vn(vn).def {
                if marked.insert(def) {
                    stack.push((def, 0));
                }
            }
        }
    }

    // Phase 2: worklist fixpoint, seeded with MULTIEQUALs, recomputing with all edges.
    let mut worklist: Vec<OpId> =
        all_ops.into_iter().filter(|&op| f.op(op).code() == OpCode::Multiequal).collect();
    while let Some(op) = worklist.pop() {
        let Some(out) = f.op(op).output else { continue };
        let nzmask = op_nzmask_local(f, op, false, dom);
        if nzmask != f.vn(out).nzm {
            f.vn_mut(out).nzm = nzmask;
            for d in f.vn(out).descend.clone() {
                worklist.push(d);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::block::BlockBasic;
    use super::super::op::SeqNum;
    use super::super::space::{Address, SpaceManager};

    #[test]
    fn computes_masks_on_a_small_function() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        let x = f.new_input(4, Address::new(reg, 0x10)); // full 4-byte input → 0xffffffff
        let c_ff = f.new_const(4, 0xff);
        let c8 = f.new_const(4, 8);

        // and = x & 0xff  → nzm 0xff
        let and = f.new_op(OpCode::IntAnd, seq, vec![x, c_ff]);
        let and_out = f.new_output(and, 4, Address::new(reg, 0x20));
        // shl = x << 8    → nzm 0xffffff00
        let shl = f.new_op(OpCode::IntLeft, seq, vec![x, c8]);
        let shl_out = f.new_output(shl, 4, Address::new(reg, 0x28));
        // eq = (x == 0xff) → bool, nzm 1 ; zext = ZEXT(eq) → nzm 1
        let eq = f.new_op(OpCode::IntEqual, seq, vec![x, c_ff]);
        let eq_out = f.new_output(eq, 1, Address::new(reg, 0x30));
        let zext = f.new_op(OpCode::IntZext, seq, vec![eq_out]);
        let zext_out = f.new_output(zext, 4, Address::new(reg, 0x38));

        f.set_blocks(vec![BlockBasic { ops: vec![and, shl, eq, zext], ..Default::default() }]);
        let dom = super::super::dominator::compute(&f);
        calc_nzmask(&mut f, &dom);

        assert_eq!(f.vn(x).nzm, 0xffff_ffff);
        assert_eq!(f.vn(and_out).nzm, 0xff);
        assert_eq!(f.vn(shl_out).nzm, 0xffff_ff00);
        assert_eq!(f.vn(eq_out).nzm, 1);
        assert_eq!(f.vn(zext_out).nzm, 1); // ZEXT of a boolean stays a single bit
    }

    #[test]
    fn helpers() {
        assert_eq!(calc_mask(1), 0xff);
        assert_eq!(calc_mask(4), 0xffff_ffff);
        assert_eq!(calc_mask(8), u64::MAX);
        assert_eq!(coveringmask(0b1000), 0b1111);
        assert_eq!(coveringmask(0), 0);
        assert_eq!(mostsigbit_set(0), -1);
        assert_eq!(mostsigbit_set(0b1000), 3);
        assert_eq!(leastsigbit_set(0b1000), 3);
        assert_eq!(leastsigbit_set(0), -1);
        assert_eq!(pcode_left(1, 64), 0);
        assert_eq!(pcode_right(u64::MAX, 64), 0);
        // sign-extend a 1-byte mask whose sign bit may be set → high bytes unknown.
        assert_eq!(sign_extend_mask(0xff, 1, 4), 0xffff_ffff);
        // sign bit known zero → no high bits added.
        assert_eq!(sign_extend_mask(0x7f, 1, 4), 0x7f);
    }
}
