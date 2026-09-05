//! Double-precision LOAD/STORE recombination — a port of Ghidra's `RuleDoubleLoad` +
//! `RuleDoubleStore` (`double.cc:3370-3660`, declared `double.hh:348`/`:361`, wired into `oppool1`
//! at `coreaction.cc:5643-5644`, groups `doubleload`/`doubleprecis` — both enabled in the
//! `decompile` root, `coreaction.cc:5429`). When two adjacent LOADs are concatenated into one
//! logical value (`PIECE(load_hi, load_lo)` over contiguous pointers), `RuleDoubleLoad` replaces
//! them with a single wide LOAD; when the two halves of a double-precision whole (`SUBPIECE`s
//! marked `PRECISLO`/`PRECISHI`) are stored through contiguous pointers, `RuleDoubleStore`
//! replaces the pair with a single wide STORE of the whole.
//!
//! The shared `noWriteConflict` scan proves no aliasing write/branch sits between the two memory
//! ops; `RuleDoubleStore` additionally accounts for the INDIRECT effects the two STOREs project
//! (`testIndirectUse` + `reassignIndirects`).
//!
//! `RuleDoubleStore` is gated on the `PRECISLO`/`PRECISHI` varnode flags, which only the
//! double-precision marking machinery sets (Ghidra `ActionParamDouble` coreaction.cc:1597,
//! `SplitVarnode` double.cc:509/557/568, heritage `splitPieces` heritage.cc:2147 — none ported
//! yet), so it is dormant machinery until a marker port lands. `RuleDoubleLoad` has no such gate.
//! On the current x86-64 corpus Ghidra fires NEITHER rule (trace survey 2026-07-17: only
//! `RuleDoubleOut` of the double family fires, on `revisit`/`doublemove`).
//!
//! Little-endian only (x86-64): Ghidra's big-endian arms — the significance→address swap in
//! `testContiguousPointers` and the discarded-most-significant pointer adjust in
//! `RuleDoubleLoad::applyOp` (double.cc:3486-3496) — are omitted, the same convention as
//! [`super::lanedivide`]/[`super::transform`].

use super::action::Rule;
use super::block::BlockId;
use super::op::SeqNum;
use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::space::SpaceId;
use super::varnode::VarnodeId;

/// Ghidra `SplitVarnode::adjacentOffsets` (double.cc:713): do the two pointer varnodes address
/// adjacent memory regions, with `vn1 + size1 == vn2`? Either both are constants, or `vn2` is
/// `vn1 + #size1`, or both are `base + #c` off the same base with `c1 + size1 == c2`.
fn adjacent_offsets(data: &Funcdata, vn1: VarnodeId, vn2: VarnodeId, size1: u64) -> bool {
    if data.vn(vn1).is_constant() {
        if !data.vn(vn2).is_constant() {
            return false;
        }
        return data.vn(vn1).constant_value().wrapping_add(size1) == data.vn(vn2).constant_value();
    }
    if !data.vn(vn2).is_written() {
        return false;
    }
    let Some(op2) = data.vn(vn2).def else { return false };
    if data.op(op2).code() != OpCode::IntAdd {
        return false;
    }
    let Some(op2_in1) = data.op(op2).input(1) else { return false };
    if !data.vn(op2_in1).is_constant() {
        return false;
    }
    let c2 = data.vn(op2_in1).constant_value();
    if data.op(op2).input(0) == Some(vn1) {
        return size1 == c2;
    }
    if !data.vn(vn1).is_written() {
        return false;
    }
    let Some(op1) = data.vn(vn1).def else { return false };
    if data.op(op1).code() != OpCode::IntAdd {
        return false;
    }
    let Some(op1_in1) = data.op(op1).input(1) else { return false };
    if !data.vn(op1_in1).is_constant() {
        return false;
    }
    let c1 = data.vn(op1_in1).constant_value();
    if data.op(op1).input(0) != data.op(op2).input(0) {
        return false;
    }
    c1.wrapping_add(size1) == c2
}

/// The address space a LOAD/STORE's constant space-id input refers to (Ghidra
/// `getSpaceFromConst`; mosura encodes it as the constant's offset, see `check_spacebase`).
fn space_from_const(data: &Funcdata, vn: VarnodeId) -> SpaceId {
    SpaceId(data.vn(vn).loc.offset as u32)
}

/// Ghidra `SplitVarnode::testContiguousPointers` (double.cc:755): verify the pointers of two
/// LOADs (or two STOREs) address contiguous memory. `most`/`least` are the ops referring to the
/// most/least significant region; on success returns `(first, second, spc)` where `first`/`second`
/// are address-sorted (little-endian: `first = least`) and `spc` is the memory space.
fn test_contiguous_pointers(
    data: &Funcdata,
    most: OpId,
    least: OpId,
) -> Option<(OpId, OpId, SpaceId)> {
    let spc = space_from_const(data, data.op(least).input(0)?);
    if space_from_const(data, data.op(most).input(0)?) != spc {
        return None;
    }
    // Little-endian: significance order → address order puts the least significant piece first
    // (Ghidra's big-endian swap omitted).
    let (first, second) = (least, most);
    let firstptr = data.op(first).input(1)?;
    if data.vn(firstptr).is_free() {
        return None;
    }
    // Number of bytes read/written at the lowest address.
    let sizeres = if data.op(first).code() == OpCode::Load {
        data.vn(data.op(first).output?).size
    } else {
        data.vn(data.op(first).input(2)?).size
    };
    // Check if the accesses are adjacent to each other.
    adjacent_offsets(data, data.op(first).input(1)?, data.op(second).input(1)?, sizeres as u64)
        .then_some((first, second, spc))
}

/// The position of `op` in its basic block's op list, with the block id.
fn block_pos(data: &Funcdata, op: OpId) -> Option<(super::block::BlockId, usize)> {
    let b = data.op(op).parent?;
    let pos = data.block(b).ops.iter().position(|&o| o == op)?;
    Some((b, pos))
}

/// Ghidra `RuleDoubleLoad::noWriteConflict` (double.cc:3370): scan for conflicts between two
/// LOADs or STOREs that would prevent them from being combined. Both ops must be in the same
/// basic block; every op in between is examined for a write into `spc` (or a control-flow op),
/// which makes combining impossible. Returns the later of the two ops if they can be combined.
///
/// For STOREs, `indirects` collects the INDIRECT ops caused by the two STOREs themselves.
fn no_write_conflict(
    data: &Funcdata,
    op1: OpId,
    op2: OpId,
    spc: SpaceId,
    mut indirects: Option<&mut Vec<OpId>>,
) -> Option<OpId> {
    let (b1, pos1) = block_pos(data, op1)?;
    let (b2, pos2) = block_pos(data, op2)?;
    if b1 != b2 {
        return None; // Force the two ops to be in the same basic block
    }
    let (op1, op2, pos1, pos2) = if pos2 < pos1 { (op2, op1, pos2, pos1) } else { (op1, op2, pos1, pos2) };
    let mut start = pos1;
    if data.op(op1).code() == OpCode::Store {
        // Extend the range of ops to include any INDIRECTs associated with the initial STORE.
        while start > 0 {
            let prev = data.block(b1).ops[start - 1];
            if data.op(prev).code() != OpCode::Indirect {
                break;
            }
            start -= 1;
        }
    }
    for i in start..pos2 {
        let curop = data.block(b1).ops[i];
        if curop == op1 {
            continue;
        }
        match data.op(curop).code() {
            OpCode::Store => {
                if space_from_const(data, data.op(curop).input(0)?) == spc {
                    return None; // Don't go any further trying to resolve alias
                }
            }
            OpCode::Indirect => {
                let affector = data.op(curop).guarded_op();
                if affector == Some(op1) || affector == Some(op2) {
                    if let Some(inds) = indirects.as_deref_mut() {
                        inds.push(curop);
                    }
                } else if let Some(out) = data.op(curop).output {
                    if data.vn(out).loc.space == spc {
                        return None;
                    }
                }
            }
            OpCode::Call
            | OpCode::Callind
            | OpCode::Callother
            | OpCode::Return
            | OpCode::Branch
            | OpCode::Cbranch
            | OpCode::Branchind => return None,
            _ => {
                if let Some(out) = data.op(curop).output {
                    if data.vn(out).loc.space == spc {
                        return None;
                    }
                }
            }
        }
    }
    Some(op2)
}

/// Ghidra `RuleDoubleLoad` (double.cc:3436, `oppool1` coreaction.cc:5643, group `doubleload`):
/// convert a concatenation of two adjacent LOADs — `PIECE(LOAD(ptr+size), LOAD(ptr))` — into one
/// wide LOAD of the combined region, turning the PIECE into a COPY of the new LOAD's output.
pub struct RuleDoubleLoad;

impl Rule for RuleDoubleLoad {
    fn name(&self) -> &str {
        "doubleload"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Piece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(piece0) = data.op(op).input(0) else { return 0 }; // most significant
        let Some(piece1) = data.op(op).input(1) else { return 0 }; // least significant
        if !data.vn(piece0).is_written() || !data.vn(piece1).is_written() {
            return 0;
        }
        let load1 = data.vn(piece1).def.expect("written varnode has a def");
        if data.op(load1).code() != OpCode::Load {
            return 0;
        }
        let mut load0 = data.vn(piece0).def.expect("written varnode has a def");
        let mut opc = data.op(load0).code();
        if opc == OpCode::Subpiece {
            // Check for 2 LOADs but most significant part of most significant LOAD is discarded.
            // (Little-endian: the discarded bytes sit at the top addresses, so no pointer adjust
            // is needed — Ghidra's isBigEndian offset arm, double.cc:3486-3496, is omitted.)
            let Some(off_vn) = data.op(load0).input(1) else { return 0 };
            if data.vn(off_vn).constant_value() != 0 {
                return 0;
            }
            let Some(vn0) = data.op(load0).input(0) else { return 0 };
            if !data.vn(vn0).is_written() {
                return 0;
            }
            load0 = data.vn(vn0).def.expect("written varnode has a def");
            opc = data.op(load0).code();
        }
        if opc != OpCode::Load {
            return 0;
        }
        let Some((loadlo, loadhi, spc)) = test_contiguous_pointers(data, load0, load1) else {
            return 0;
        };

        let size = data.vn(piece0).size + data.vn(piece1).size;
        let Some(latest) = no_write_conflict(data, loadlo, loadhi, spc, None) else {
            return 0; // There was a conflict
        };

        // Create new load op that combines the two smaller loads.
        let spc_in = data.op(loadlo).input(0).expect("LOAD has a space input");
        let spcvn = data.new_const(data.vn(spc_in).size, spc.0 as u64);
        let addrvn = data.op(loadlo).input(1).expect("LOAD has a pointer input");
        let pc = data.op(latest).seqnum.pc;
        let uniq = data.num_ops() as u32;
        let newload = data.new_op(OpCode::Load, super::op::SeqNum { pc, uniq }, vec![spcvn, addrvn]);
        let vnout = data.new_output_unique(newload, size);
        // We need to guarantee that the new load reads its pointer after it has been defined,
        // so insert it after the latest of the two original loads.
        data.op_insert_after(newload, latest);

        // Change the concatenation to a copy from the big load.
        data.op_remove_input(op, 1);
        data.op_set_opcode(op, OpCode::Copy);
        data.op_set_input(op, 0, vnout);
        1
    }
}

/// Ghidra `RuleDoubleStore` (double.cc:3507, `oppool1` coreaction.cc:5644, group `doubleprecis`):
/// combine two STOREs of the `PRECISLO`/`PRECISHI` `SUBPIECE` halves of a double-precision whole
/// through contiguous pointers into one wide STORE of the whole.
pub struct RuleDoubleStore;

impl Rule for RuleDoubleStore {
    fn name(&self) -> &str {
        "doublestore"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Store]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(vnlo) = data.op(op).input(2) else { return 0 };
        if !data.vn(vnlo).is_precis_lo() {
            return 0;
        }
        if !data.vn(vnlo).is_written() {
            return 0;
        }
        let subpiece_op_lo = data.vn(vnlo).def.expect("written varnode has a def");
        if data.op(subpiece_op_lo).code() != OpCode::Subpiece {
            return 0;
        }
        let Some(lo_off) = data.op(subpiece_op_lo).input(1) else { return 0 };
        if data.vn(lo_off).constant_value() != 0 {
            return 0;
        }
        let Some(whole) = data.op(subpiece_op_lo).input(0) else { return 0 };
        if data.vn(whole).is_free() {
            return 0;
        }
        for subpiece_op_hi in data.vn(whole).descend.clone() {
            if data.op(subpiece_op_hi).code() != OpCode::Subpiece {
                continue;
            }
            if subpiece_op_hi == subpiece_op_lo {
                continue;
            }
            let Some(hi_off) = data.op(subpiece_op_hi).input(1) else { continue };
            let offset = data.vn(hi_off).constant_value();
            if offset != data.vn(vnlo).size as u64 {
                continue;
            }
            let Some(vnhi) = data.op(subpiece_op_hi).output else { continue };
            if !data.vn(vnhi).is_precis_hi() {
                continue;
            }
            if data.vn(vnhi).size as u64 != data.vn(whole).size as u64 - offset {
                continue;
            }
            for store_op2 in data.vn(vnhi).descend.clone() {
                if data.op(store_op2).code() != OpCode::Store {
                    continue;
                }
                if data.op(store_op2).input(2) != Some(vnhi) {
                    continue;
                }
                let Some((storelo, storehi, spc)) = test_contiguous_pointers(data, store_op2, op)
                else {
                    continue;
                };
                let mut indirects: Vec<OpId> = Vec::new();
                let Some(latest) = no_write_conflict(data, storelo, storehi, spc, Some(&mut indirects))
                else {
                    continue; // There was a conflict
                };
                if !test_indirect_use(data, storelo, storehi, &indirects) {
                    continue;
                }
                // Create new STORE op that combines the two smaller STOREs.
                let spc_in = data.op(storelo).input(0).expect("STORE has a space input");
                let spcvn = data.new_const(data.vn(spc_in).size, spc.0 as u64);
                let mut addrvn = data.op(storelo).input(1).expect("STORE has a pointer input");
                if data.vn(addrvn).is_constant() {
                    addrvn = data.new_const(data.vn(addrvn).size, data.vn(addrvn).constant_value());
                }
                let pc = data.op(latest).seqnum.pc;
                let uniq = data.num_ops() as u32;
                let newstore =
                    data.new_op(OpCode::Store, super::op::SeqNum { pc, uniq }, vec![spcvn, addrvn, whole]);
                // We need to guarantee that the new store reads its pointer after it has been
                // defined, so insert it after the latest of the two original stores.
                data.op_insert_after(newstore, latest);
                // Get rid of the original STOREs (opDestroy also unlinks from the block in Ghidra).
                data.op_uninsert(op);
                data.op_destroy(op);
                data.op_uninsert(store_op2);
                data.op_destroy(store_op2);
                reassign_indirects(data, newstore, &indirects);
                return 1;
            }
        }
        0
    }
}

/// Ghidra `RuleDoubleStore::testIndirectUse` (double.cc:3578): test that no output varnode of the
/// collected INDIRECTs is used anywhere within the range of ops bounded by the two STOREs — except
/// the expected pairing where the first STORE's INDIRECT feeds the second STORE's INDIRECT.
fn test_indirect_use(data: &Funcdata, op1: OpId, op2: OpId, indirects: &[OpId]) -> bool {
    let Some((_, pos1)) = block_pos(data, op1) else { return false };
    let Some((_, pos2)) = block_pos(data, op2) else { return false };
    let (op1, op2, pos1, pos2) = if pos2 < pos1 { (op2, op1, pos2, pos1) } else { (op1, op2, pos1, pos2) };
    let parent1 = data.op(op1).parent;
    for &ind in indirects {
        let Some(outvn) = data.op(ind).output else { continue };
        let mut usecount = 0;
        let mut usebyop2 = 0;
        for &user in &data.vn(outvn).descend {
            usecount += 1;
            if data.op(user).parent != parent1 {
                continue;
            }
            let Some((_, upos)) = block_pos(data, user) else { continue };
            if upos < pos1 || upos > pos2 {
                continue;
            }
            // It's likely that INDIRECTs from the first STORE feed INDIRECTs for the second STORE.
            if data.op(user).code() == OpCode::Indirect && data.op(user).guarded_op() == Some(op2) {
                usebyop2 += 1; // Note this pairing
                continue;
            }
            return false;
        }
        // As an INDIRECT whose output feeds into later INDIRECTs must be removed: if some uses of
        // the output feed into later INDIRECTs, but not ALL do, then fail.
        if usebyop2 > 0 && usecount != usebyop2 {
            return false;
        }
        if usebyop2 > 1 {
            return false;
        }
    }
    true
}

/// Ghidra `RuleDoubleStore::reassignIndirects` (double.cc:3622): move the INDIRECTs associated
/// with the removed STOREs next to the new combined STORE and point their affect at it. INDIRECT
/// pairs (the first STORE's INDIRECT feeding the second's) collapse: the earlier is deleted and
/// the later takes over its input.
fn reassign_indirects(data: &mut Funcdata, new_store: OpId, indirects: &[OpId]) {
    // Search for INDIRECT pairs. The earlier is deleted; the later gains the earlier's input.
    for &op in indirects {
        data.op_mut(op).set_mark();
        let Some(vn) = data.op(op).input(0) else { continue };
        if !data.vn(vn).is_written() {
            continue;
        }
        let earlyop = data.vn(vn).def.expect("written varnode has a def");
        if data.op(earlyop).is_mark() {
            let early_in = data.op(earlyop).input(0).expect("INDIRECT has an input");
            data.op_set_input(op, 0, early_in); // grab the earlier op's input, replacing its output
            data.op_uninsert(earlyop);
            data.op_destroy(earlyop);
        }
    }
    for &op in indirects {
        data.op_mut(op).clear_mark();
        if data.op(op).is_dead() {
            continue;
        }
        data.op_uninsert(op);
        data.op_insert_before(op, new_store); // move the INDIRECT to the new STORE
        data.op_mut(op).guarded_op = Some(new_store); // assign the INDIRECT to the new STORE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::block::{BlockBasic, BlockId};
    use super::super::op::SeqNum;
    use super::super::space::{Address, SpaceManager};
    use super::super::varnode::flags;

    /// `PIECE(LOAD(ptr+8), LOAD(ptr))` over contiguous pointers combines into one 16-byte LOAD;
    /// the PIECE becomes a COPY of the new LOAD's output (double.cc:3442's fire shape).
    #[test]
    fn double_load_combines_adjacent_loads() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = |uniq| SeqNum { pc: Address::new(ram, 0x100), uniq };
        let ptr = f.new_input(8, Address::new(reg, 0x100));
        let sid = f.new_const(8, ram.0 as u64);
        // lo:8 = LOAD(ram, ptr)
        let load_lo = f.new_op(OpCode::Load, seq(0), vec![sid, ptr]);
        let lo = f.new_output_unique(load_lo, 8);
        // ptr_hi = ptr + 8 ; hi:8 = LOAD(ram, ptr_hi)
        let eight = f.new_const(8, 8);
        let addop = f.new_op(OpCode::IntAdd, seq(1), vec![ptr, eight]);
        let ptr_hi = f.new_output_unique(addop, 8);
        let sid2 = f.new_const(8, ram.0 as u64);
        let load_hi = f.new_op(OpCode::Load, seq(2), vec![sid2, ptr_hi]);
        let hi = f.new_output_unique(load_hi, 8);
        // whole:16 = PIECE(hi, lo)
        let piece = f.new_op(OpCode::Piece, seq(3), vec![hi, lo]);
        f.new_output_unique(piece, 16);
        f.set_blocks(vec![BlockBasic {
            ops: vec![load_lo, addop, load_hi, piece],
            ..Default::default()
        }]);
        for op in [load_lo, addop, load_hi, piece] {
            f.op_mut(op).parent = Some(BlockId(0));
        }

        assert_eq!(RuleDoubleLoad.apply_op(piece, &mut f), 1, "the adjacent LOADs combine");
        assert_eq!(f.op(piece).code(), OpCode::Copy, "the PIECE became a COPY");
        let src = f.op(piece).input(0).unwrap();
        assert!(f.vn(src).is_written());
        let newload = f.vn(src).def.unwrap();
        assert_eq!(f.op(newload).code(), OpCode::Load);
        assert_eq!(f.vn(src).size, 16, "the combined LOAD reads 16 bytes");
        assert_eq!(f.op(newload).input(1), Some(ptr), "reads from the low address pointer");
        // Inserted after the latest of the two original loads.
        let pos_new = f.block(BlockId(0)).ops.iter().position(|&o| o == newload).unwrap();
        let pos_hi = f.block(BlockId(0)).ops.iter().position(|&o| o == load_hi).unwrap();
        assert_eq!(pos_new, pos_hi + 1);
    }

    /// A STORE into the same space between the two LOADs is a write conflict — the rule declines
    /// (noWriteConflict, double.cc:3403).
    #[test]
    fn double_load_declines_on_write_conflict() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = |uniq| SeqNum { pc: Address::new(ram, 0x100), uniq };
        let ptr = f.new_input(8, Address::new(reg, 0x100));
        let sid = f.new_const(8, ram.0 as u64);
        let load_lo = f.new_op(OpCode::Load, seq(0), vec![sid, ptr]);
        let lo = f.new_output_unique(load_lo, 8);
        // A conflicting STORE into ram between the loads.
        let other_ptr = f.new_input(8, Address::new(reg, 0x110));
        let val = f.new_input(8, Address::new(reg, 0x120));
        let sid_c = f.new_const(8, ram.0 as u64);
        let conflict = f.new_op(OpCode::Store, seq(1), vec![sid_c, other_ptr, val]);
        let eight = f.new_const(8, 8);
        let addop = f.new_op(OpCode::IntAdd, seq(2), vec![ptr, eight]);
        let ptr_hi = f.new_output_unique(addop, 8);
        let sid2 = f.new_const(8, ram.0 as u64);
        let load_hi = f.new_op(OpCode::Load, seq(3), vec![sid2, ptr_hi]);
        let hi = f.new_output_unique(load_hi, 8);
        let piece = f.new_op(OpCode::Piece, seq(4), vec![hi, lo]);
        f.new_output_unique(piece, 16);
        f.set_blocks(vec![BlockBasic {
            ops: vec![load_lo, conflict, addop, load_hi, piece],
            ..Default::default()
        }]);
        for op in [load_lo, conflict, addop, load_hi, piece] {
            f.op_mut(op).parent = Some(BlockId(0));
        }

        assert_eq!(RuleDoubleLoad.apply_op(piece, &mut f), 0, "the aliasing STORE blocks the combine");
        assert_eq!(f.op(piece).code(), OpCode::Piece, "the PIECE is untouched");
    }

    /// Two STOREs of the PRECISLO/PRECISHI SUBPIECE halves of a whole through contiguous pointers
    /// combine into one 16-byte STORE of the whole (double.cc:3513's fire shape).
    #[test]
    fn double_store_combines_adjacent_precis_stores() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = |uniq| SeqNum { pc: Address::new(ram, 0x100), uniq };
        let src = f.new_input(16, Address::new(reg, 0x1200));
        let copyop = f.new_op(OpCode::Copy, seq(0), vec![src]);
        let whole = f.new_output_unique(copyop, 16);
        // lo:8 = SUBPIECE(whole, 0) [PRECISLO] ; hi:8 = SUBPIECE(whole, 8) [PRECISHI]
        let z = f.new_const(4, 0);
        let sub_lo = f.new_op(OpCode::Subpiece, seq(1), vec![whole, z]);
        let lo = f.new_output_unique(sub_lo, 8);
        f.vn_mut(lo).flags |= flags::PRECISLO;
        let c8 = f.new_const(4, 8);
        let sub_hi = f.new_op(OpCode::Subpiece, seq(2), vec![whole, c8]);
        let hi = f.new_output_unique(sub_hi, 8);
        f.vn_mut(hi).flags |= flags::PRECISHI;
        // STORE(ram, ptr, lo) ; STORE(ram, ptr+8, hi)
        let ptr = f.new_input(8, Address::new(reg, 0x100));
        let sid = f.new_const(8, ram.0 as u64);
        let store_lo = f.new_op(OpCode::Store, seq(3), vec![sid, ptr, lo]);
        let eight = f.new_const(8, 8);
        let addop = f.new_op(OpCode::IntAdd, seq(4), vec![ptr, eight]);
        let ptr_hi = f.new_output_unique(addop, 8);
        let sid2 = f.new_const(8, ram.0 as u64);
        let store_hi = f.new_op(OpCode::Store, seq(5), vec![sid2, ptr_hi, hi]);
        f.set_blocks(vec![BlockBasic {
            ops: vec![copyop, sub_lo, sub_hi, store_lo, addop, store_hi],
            ..Default::default()
        }]);
        for op in [copyop, sub_lo, sub_hi, store_lo, addop, store_hi] {
            f.op_mut(op).parent = Some(BlockId(0));
        }

        assert_eq!(RuleDoubleStore.apply_op(store_lo, &mut f), 1, "the halved STOREs combine");
        assert!(f.op(store_lo).is_dead() && f.op(store_hi).is_dead(), "originals destroyed");
        let stores: Vec<OpId> = (0..f.num_ops() as u32)
            .map(OpId)
            .filter(|&o| !f.op(o).is_dead() && f.op(o).code() == OpCode::Store)
            .collect();
        assert_eq!(stores.len(), 1, "one combined STORE remains");
        assert_eq!(f.op(stores[0]).input(2), Some(whole), "it stores the whole");
        assert_eq!(f.op(stores[0]).input(1), Some(ptr), "at the low address pointer");
    }

    /// Without the PRECISLO marking the rule declines immediately — the corpus-dormancy gate
    /// (the flags are only set by the unported double-precision marking machinery).
    #[test]
    fn double_store_declines_without_precis_marking() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = |uniq| SeqNum { pc: Address::new(ram, 0x100), uniq };
        let src = f.new_input(16, Address::new(reg, 0x1200));
        let copyop = f.new_op(OpCode::Copy, seq(0), vec![src]);
        let whole = f.new_output_unique(copyop, 16);
        let z = f.new_const(4, 0);
        let sub_lo = f.new_op(OpCode::Subpiece, seq(1), vec![whole, z]);
        let lo = f.new_output_unique(sub_lo, 8); // NOT marked PRECISLO
        let ptr = f.new_input(8, Address::new(reg, 0x100));
        let sid = f.new_const(8, ram.0 as u64);
        let store_lo = f.new_op(OpCode::Store, seq(2), vec![sid, ptr, lo]);
        f.set_blocks(vec![BlockBasic { ops: vec![copyop, sub_lo, store_lo], ..Default::default() }]);
        for op in [copyop, sub_lo, store_lo] {
            f.op_mut(op).parent = Some(BlockId(0));
        }

        assert_eq!(RuleDoubleStore.apply_op(store_lo, &mut f), 0, "unmarked halves decline");
        assert!(!f.op(store_lo).is_dead());
    }
}

/// Ghidra `SplitVarnode::isAddrTiedContiguous` (double.cc): the two halves occupy adjacent,
/// address-tied storage that could be a single wider variable, and no explicit symbol contradicts
/// joining them.
///
/// mosura has no Scope object for register storage, so `getSymbolEntry()` is `None` on both halves
/// and Ghidra's "one is marked with a symbol, the other is not" guard passes vacuously — the
/// conservative direction is unreachable rather than skipped. Little-endian only, matching the rest
/// of this file (`RuleDoubleLoad`/`RuleDoubleStore`).
fn is_addr_tied_contiguous(
    data: &Funcdata,
    lo: VarnodeId,
    hi: VarnodeId,
) -> Option<super::space::Address> {
    if !data.vn(lo).is_addrtied() || !data.vn(hi).is_addrtied() {
        return None;
    }
    let spc = data.vn(lo).loc.space;
    if spc != data.vn(hi).loc.space {
        return None;
    }
    let looffset = data.vn(lo).loc.offset;
    let hioffset = data.vn(hi).loc.offset;
    if looffset >= hioffset {
        return None;
    }
    if looffset + data.vn(lo).size as u64 != hioffset {
        return None;
    }
    Some(data.vn(lo).loc)
}

/// Ghidra `RuleDoubleOut::attemptMarking` (double.cc): decide whether a `PIECE(hi, lo)` really is
/// the two halves of one logical double-precision value, and if so mark them `precishi`/`precislo`.
///
/// The evidence Ghidra accepts is that *something reads the concatenation arithmetically* — a
/// logical whole is a thing you do arithmetic on, whereas two unrelated adjacent registers are not.
/// The halves must be the same size, and must not belong to different symbols.
///
/// This is what wakes the rest of the double-precision machinery, `RuleDoubleStore` included: those
/// rules key on the PRECIS markers, and until this ran nothing set them.
fn double_out_attempt_marking(
    data: &mut Funcdata,
    vnhi: VarnodeId,
    vnlo: VarnodeId,
    piece_op: OpId,
) -> u32 {
    let Some(whole) = data.op(piece_op).output else { return 0 };
    if data.vn(whole).is_typelock() && !data.vn(whole).get_type().is_primitive_whole() {
        return 0; // don't mark for double precision if not a primitive type
    }
    if data.vn(vnhi).size != data.vn(vnlo).size {
        return 0;
    }
    // Ghidra compares the two halves' SymbolEntries here; mosura has no symbol entries for register
    // storage, so both are absent and the check passes — see `is_addr_tied_contiguous`.
    let is_whole = data
        .vn(whole)
        .descend
        .iter()
        .any(|&op| data.op(op).is_arithmetic_op() || data.op(op).is_floatingpoint_op());
    if !is_whole {
        return 0;
    }
    data.vn_mut(vnhi).set_precis_hi();
    data.vn_mut(vnlo).set_precis_lo();
    1
}

/// Ghidra `RuleDoubleOut` (double.cc, oppool1 slot :5646): a `PIECE` of two contiguous, persistent
/// INPUT varnodes is a double-precision parameter that arrived as two halves — fuse them into one
/// wider input ([`Funcdata::combine_input_varnodes`]) so the function takes the whole value.
///
/// Before the halves are marked `precishi`/`precislo` the rule instead tries to mark them
/// ([`double_out_attempt_marking`]); the fuse happens on a later pass, once they are.
pub struct RuleDoubleOut;

impl Rule for RuleDoubleOut {
    fn name(&self) -> &str {
        "doubleout"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Piece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let (Some(vnhi), Some(vnlo)) = (data.op(op).input(0), data.op(op).input(1)) else {
            return 0;
        };
        // Currently this only implements collapsing INPUT varnodes read by a PIECE.
        if !data.vn(vnhi).is_input() || !data.vn(vnlo).is_input() {
            return 0;
        }
        if !data.vn(vnhi).is_persist() || !data.vn(vnlo).is_persist() {
            return 0;
        }
        if !data.vn(vnhi).is_precis_hi() || !data.vn(vnlo).is_precis_lo() {
            return double_out_attempt_marking(data, vnhi, vnlo, op);
        }
        if data.has_unreachable_blocks() {
            return 0;
        }
        if is_addr_tied_contiguous(data, vnlo, vnhi).is_none() {
            return 0;
        }
        if !data.combine_input_varnodes(vnhi, vnlo) {
            return 0;
        }
        1
    }
}


#[cfg(test)]
mod double_out_tests {
    use super::*;
    use crate::decompile::op::SeqNum;
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::varnode::flags as vflags;
    use crate::decompile::BlockBasic;
    use crate::decompile::block::BlockId;

    fn fd() -> (Funcdata, Address) {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        (Funcdata::new("t", Address::new(ram, 0), spaces), Address::new(ram, 0))
    }

    /// `PIECE(hi@+2, lo@+0)` of two contiguous persistent inputs, read arithmetically.
    fn double_in_halves(arith_reader: bool) -> (Funcdata, OpId, VarnodeId, VarnodeId) {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let lo = f.new_input(2, Address::new(reg, 0x40));
        let hi = f.new_input(2, Address::new(reg, 0x42));
        for v in [lo, hi] {
            f.vn_mut(v).flags |= vflags::PERSIST | vflags::ADDRTIED;
        }
        let piece = f.new_op(OpCode::Piece, seq(0), vec![hi, lo]);
        let whole = f.new_output_unique(piece, 4);
        let mut ops = vec![piece];
        if arith_reader {
            let k = f.new_const(4, 1);
            let add = f.new_op(OpCode::IntAdd, seq(1), vec![whole, k]);
            f.new_output_unique(add, 4);
            ops.push(add);
        }
        f.set_blocks(vec![BlockBasic { ops: ops.clone(), ..Default::default() }]);
        for op in ops {
            f.op_mut(op).parent = Some(BlockId(0));
        }
        (f, piece, hi, lo)
    }

    #[test]
    fn double_out_marks_the_halves_when_read_arithmetically() {
        // First pass: nothing is marked yet, so the rule marks instead of fusing.
        let (mut f, piece, hi, lo) = double_in_halves(true);
        assert_eq!(RuleDoubleOut.apply_op(piece, &mut f), 1);
        assert!(f.vn(hi).is_precis_hi());
        assert!(f.vn(lo).is_precis_lo());
        assert_eq!(f.op(piece).code(), OpCode::Piece, "marking only — the fuse is a later pass");
    }

    #[test]
    fn double_out_declines_marking_without_an_arithmetic_reader() {
        // Two adjacent registers that are never used as one arithmetic value are not a logical
        // whole — this is the evidence test that keeps the rule from fusing unrelated storage.
        let (mut f, piece, hi, lo) = double_in_halves(false);
        assert_eq!(RuleDoubleOut.apply_op(piece, &mut f), 0);
        assert!(!f.vn(hi).is_precis_hi());
        assert!(!f.vn(lo).is_precis_lo());
    }

    #[test]
    fn double_out_fuses_marked_contiguous_inputs() {
        // Second pass: with the markers set, the halves become ONE wider input and the PIECE that
        // recombined them becomes a COPY of it (Funcdata::combineInputVarnodes).
        let (mut f, piece, hi, lo) = double_in_halves(true);
        assert_eq!(RuleDoubleOut.apply_op(piece, &mut f), 1); // marks
        assert_eq!(RuleDoubleOut.apply_op(piece, &mut f), 1); // fuses
        assert_eq!(f.op(piece).code(), OpCode::Copy);
        assert_eq!(f.op(piece).num_inputs(), 1);
        let whole_in = f.op(piece).input(0).unwrap();
        assert!(f.vn(whole_in).is_input());
        assert_eq!(f.vn(whole_in).size, 4, "the two 2-byte halves became one 4-byte input");
        assert_eq!(f.vn(whole_in).loc, f.vn(lo).loc, "starting at the LOW half's address");
        let _ = hi;
    }

    #[test]
    fn double_out_declines_when_blocks_were_unreachable() {
        // Ghidra refuses to act on a function that had unreachable code removed.
        let (mut f, piece, _, _) = double_in_halves(true);
        assert_eq!(RuleDoubleOut.apply_op(piece, &mut f), 1); // marks
        f.blocks_unreachable = true;
        assert_eq!(RuleDoubleOut.apply_op(piece, &mut f), 0);
        assert_eq!(f.op(piece).code(), OpCode::Piece);
    }
}


// ---------------------------------------------------------------------------------------------
// SplitVarnode — Ghidra's model of a double-precision value carried in two Varnode halves
// (double.cc / double.hh). This is the engine `RuleDoubleIn` drives: given one marked half, find
// (or build) the `whole`, then find arithmetic performed on the pair and rewrite it on the whole.
// ---------------------------------------------------------------------------------------------

/// Ghidra `SplitVarnode` (double.hh:60).
#[derive(Clone, Debug, Default)]
pub struct SplitVarnode {
    pub lo: Option<VarnodeId>,
    pub hi: Option<VarnodeId>,
    pub whole: Option<VarnodeId>,
    pub defpoint: Option<OpId>,
    pub defblock: Option<BlockId>,
    pub val: u64,
    pub wholesize: u32,
}

/// Ghidra `SeqNum::getOrder()` — mosura's per-address sequence counter.
fn seq_order(data: &Funcdata, op: OpId) -> (u64, u32) {
    let s = data.op(op).seqnum;
    (s.pc.offset, s.uniq)
}

/// Ghidra's `while(curbl) { curbl = curbl->getImmedDom(); if (curbl == target) ... }` walk: does
/// `dom_block` STRICTLY dominate `bl`?
fn dominated_by(data: &Funcdata, bl: BlockId, dom_block: BlockId) -> bool {
    let dom = super::dominator::compute(data);
    let mut cur = bl.0 as usize;
    loop {
        let next = dom.idom[cur];
        if next == cur {
            return false;
        }
        cur = next;
        if cur == dom_block.0 as usize {
            return true;
        }
    }
}

impl SplitVarnode {
    /// Ghidra `SplitVarnode(int4 sz,uintb v)`.
    pub fn from_constant(sz: u32, v: u64) -> Self {
        let mut r = SplitVarnode::default();
        r.init_partial_const(sz, v);
        r
    }

    /// Ghidra `SplitVarnode(Varnode *l,Varnode *h)`.
    pub fn from_pieces(data: &Funcdata, l: VarnodeId, h: VarnodeId) -> Self {
        let sz = data.vn(l).size + data.vn(h).size;
        let mut r = SplitVarnode::default();
        r.init_partial(sz, Some(l), Some(h));
        r
    }

    /// Ghidra `SplitVarnode::initAll`.
    pub fn init_all(&mut self, w: VarnodeId, l: Option<VarnodeId>, h: Option<VarnodeId>, wholesize: u32) {
        self.wholesize = wholesize;
        self.lo = l;
        self.hi = h;
        self.whole = Some(w);
        self.defpoint = None;
        self.defblock = None;
    }

    /// Ghidra `SplitVarnode::initPartial(int4 sz,uintb v)`.
    pub fn init_partial_const(&mut self, sz: u32, v: u64) {
        self.wholesize = sz;
        self.val = if sz >= 8 { v } else { v & ((1u64 << (8 * sz)) - 1) };
        self.lo = None;
        self.hi = None;
        self.whole = None;
        self.defpoint = None;
        self.defblock = None;
    }

    /// Ghidra `SplitVarnode::initPartial(int4 sz,Varnode *l,Varnode *h)`.
    pub fn init_partial(&mut self, sz: u32, l: Option<VarnodeId>, h: Option<VarnodeId>) {
        self.wholesize = sz;
        self.lo = l;
        self.hi = h;
        self.whole = None;
        self.defpoint = None;
        self.defblock = None;
    }

    pub fn is_constant(&self) -> bool {
        self.lo.is_none()
    }
    pub fn has_both_pieces(&self) -> bool {
        self.hi.is_some() && self.lo.is_some()
    }
    pub fn get_size(&self) -> u32 {
        self.wholesize
    }

    /// Ghidra `SplitVarnode::exceedsConstPrecision`: mosura is u64-only, so a constant whole wider
    /// than 8 bytes cannot be represented — Ghidra's `sizeof(uintb)` guard, same threshold.
    pub fn exceeds_const_precision(&self) -> bool {
        self.is_constant() && self.wholesize > 8
    }

    /// Ghidra `SplitVarnode::findWholeSplitToPieces`.
    fn find_whole_split_to_pieces(&mut self, data: &Funcdata) -> bool {
        if self.whole.is_none() {
            let (Some(hi), Some(lo)) = (self.hi, self.lo) else { return false };
            if !data.vn(hi).is_written() {
                return false;
            }
            let mut subhi = data.vn(hi).def.unwrap();
            if data.op(subhi).code() == OpCode::Copy {
                let Some(otherhi) = data.op(subhi).input(0) else { return false };
                if !data.vn(otherhi).is_written() {
                    return false;
                }
                subhi = data.vn(otherhi).def.unwrap();
            }
            if data.op(subhi).code() != OpCode::Subpiece {
                return false;
            }
            let off = data.op(subhi).input(1).map(|v| data.vn(v).constant_value());
            if off != Some((self.wholesize - data.vn(hi).size) as u64) {
                return false;
            }
            let Some(putative) = data.op(subhi).input(0) else { return false };
            if data.vn(putative).size != self.wholesize {
                return false;
            }
            if !data.vn(lo).is_written() {
                return false;
            }
            let mut sublo = data.vn(lo).def.unwrap();
            if data.op(sublo).code() == OpCode::Copy {
                let Some(otherlo) = data.op(sublo).input(0) else { return false };
                if !data.vn(otherlo).is_written() {
                    return false;
                }
                sublo = data.vn(otherlo).def.unwrap();
            }
            if data.op(sublo).code() != OpCode::Subpiece {
                return false;
            }
            if data.op(sublo).input(0) != Some(putative) {
                return false;
            }
            if data.op(sublo).input(1).map(|v| data.vn(v).constant_value()) != Some(0) {
                return false;
            }
            self.whole = Some(putative);
        }
        let whole = self.whole.unwrap();
        if data.vn(whole).is_written() {
            let def = data.vn(whole).def.unwrap();
            self.defpoint = Some(def);
            self.defblock = data.op(def).parent;
        } else if data.vn(whole).is_input() {
            self.defpoint = None;
            self.defblock = None;
        }
        true
    }

    /// Ghidra `SplitVarnode::findDefinitionPoint`.
    fn find_definition_point(&mut self, data: &Funcdata) -> bool {
        if self.hi.is_some_and(|h| data.vn(h).is_constant()) {
            return false;
        }
        let Some(lo) = self.lo else { return false };
        if data.vn(lo).is_constant() {
            return false;
        }
        match self.hi {
            None => {
                if data.vn(lo).is_input() {
                    self.defblock = None;
                    self.defpoint = None;
                } else if data.vn(lo).is_written() {
                    let def = data.vn(lo).def.unwrap();
                    self.defpoint = Some(def);
                    self.defblock = data.op(def).parent;
                } else {
                    return false;
                }
            }
            Some(hi) if data.vn(hi).is_written() => {
                if !data.vn(lo).is_written() {
                    return false;
                }
                let lastop = data.vn(hi).def.unwrap();
                let lastop2 = data.vn(lo).def.unwrap();
                let Some(defblock) = data.op(lastop).parent else { return false };
                let Some(otherblock) = data.op(lastop2).parent else { return false };
                if defblock != otherblock {
                    self.defpoint = Some(lastop);
                    self.defblock = Some(defblock);
                    if dominated_by(data, defblock, otherblock) {
                        return true;
                    }
                    self.defblock = Some(otherblock);
                    self.defpoint = Some(lastop2);
                    if dominated_by(data, otherblock, defblock) {
                        return true;
                    }
                    self.defblock = None;
                    return false;
                }
                let last = if seq_order(data, lastop2) > seq_order(data, lastop) { lastop2 } else { lastop };
                self.defblock = Some(defblock);
                self.defpoint = Some(last);
            }
            Some(hi) if data.vn(hi).is_input() => {
                if !data.vn(lo).is_input() {
                    return false;
                }
                self.defblock = None;
                self.defpoint = None;
            }
            Some(_) => return false,
        }
        true
    }

    /// Ghidra `SplitVarnode::findEarliestSplitPoint`.
    pub fn find_earliest_split_point(&self, data: &Funcdata) -> Option<OpId> {
        let (Some(hi), Some(lo)) = (self.hi, self.lo) else { return None };
        if !data.vn(hi).is_written() || !data.vn(lo).is_written() {
            return None;
        }
        let hiop = data.vn(hi).def.unwrap();
        let loop_ = data.vn(lo).def.unwrap();
        if data.op(loop_).parent != data.op(hiop).parent {
            return None;
        }
        Some(if seq_order(data, loop_) < seq_order(data, hiop) { loop_ } else { hiop })
    }

    /// Ghidra `SplitVarnode::findWholeBuiltFromPieces`.
    fn find_whole_built_from_pieces(&mut self, data: &Funcdata) -> bool {
        let (Some(hi), Some(lo)) = (self.hi, self.lo) else { return false };
        let bb = if data.vn(lo).is_written() {
            data.op(data.vn(lo).def.unwrap()).parent
        } else if data.vn(lo).is_input() {
            None
        } else {
            return false;
        };
        let mut res: Option<OpId> = None;
        for op in data.vn(lo).descend.clone() {
            if data.op(op).code() != OpCode::Piece || data.op(op).input(0) != Some(hi) {
                continue;
            }
            match bb {
                Some(bb) => {
                    if data.op(op).parent != Some(bb) {
                        continue;
                    }
                }
                None => {
                    if data.op(op).parent != Some(BlockId(0)) {
                        continue;
                    }
                }
            }
            res = match res {
                None => Some(op),
                Some(cur) if seq_order(data, op) < seq_order(data, cur) => Some(op),
                keep => keep,
            };
        }
        match res {
            None => self.whole = None,
            Some(op) => {
                self.defpoint = Some(op);
                self.defblock = data.op(op).parent;
                self.whole = data.op(op).output;
            }
        }
        self.whole.is_some()
    }

    /// Ghidra `SplitVarnode::isWholeFeasible`.
    pub fn is_whole_feasible(&mut self, data: &Funcdata, existop: OpId) -> bool {
        if self.is_constant() {
            return true;
        }
        if let (Some(lo), Some(hi)) = (self.lo, self.hi) {
            if data.vn(lo).is_constant() != data.vn(hi).is_constant() {
                return false;
            }
        }
        if !self.find_whole_split_to_pieces(data)
            && !self.find_whole_built_from_pieces(data)
            && !self.find_definition_point(data)
        {
            return false;
        }
        let Some(defblock) = self.defblock else { return true };
        let Some(curbl) = data.op(existop).parent else { return false };
        if curbl == defblock {
            let Some(defpoint) = self.defpoint else { return false };
            return seq_order(data, defpoint) <= seq_order(data, existop);
        }
        dominated_by(data, curbl, defblock)
    }

    /// Ghidra `SplitVarnode::isWholePhiFeasible`.
    pub fn is_whole_phi_feasible(&mut self, data: &Funcdata, bl: BlockId) -> bool {
        if self.is_constant() {
            return false;
        }
        if !self.find_whole_split_to_pieces(data)
            && !self.find_whole_built_from_pieces(data)
            && !self.find_definition_point(data)
        {
            return false;
        }
        let Some(defblock) = self.defblock else { return true };
        if bl == defblock {
            return true;
        }
        dominated_by(data, bl, defblock)
    }

    /// Ghidra `SplitVarnode::findCreateWhole`.
    pub fn find_create_whole(&mut self, data: &mut Funcdata) {
        if self.is_constant() {
            self.whole = Some(data.new_const(self.wholesize, self.val));
            return;
        }
        if let Some(lo) = self.lo {
            data.vn_mut(lo).set_precis_lo();
        }
        if let Some(hi) = self.hi {
            data.vn_mut(hi).set_precis_hi();
        }
        if self.whole.is_some() {
            return;
        }
        let mut topblock = None;
        let addr = match self.defblock {
            Some(_) => data.op(self.defpoint.expect("defblock implies defpoint")).seqnum.pc,
            None => {
                let bl = BlockId(0);
                topblock = Some(bl);
                data.block(bl).ops.first().map(|&o| data.op(o).seqnum.pc).unwrap_or(data.addr)
            }
        };
        let uniq = data.num_ops() as u32;
        let concatop = match self.hi {
            Some(hi) => {
                let lo = self.lo.expect("non-constant has lo");
                data.new_op(OpCode::Piece, SeqNum { pc: addr, uniq }, vec![hi, lo])
            }
            None => {
                let lo = self.lo.expect("non-constant has lo");
                data.new_op(OpCode::IntZext, SeqNum { pc: addr, uniq }, vec![lo])
            }
        };
        self.whole = Some(data.new_output_unique(concatop, self.wholesize));
        match (self.defblock, topblock) {
            (Some(_), _) => data.op_insert_after(concatop, self.defpoint.unwrap()),
            (None, Some(bl)) => data.op_insert_begin(concatop, bl),
            _ => {}
        }
        self.defpoint = Some(concatop);
        self.defblock = data.op(concatop).parent;
    }

    /// Ghidra `SplitVarnode::findCreateOutputWhole`.
    pub fn find_create_output_whole(&mut self, data: &mut Funcdata) {
        if let Some(lo) = self.lo {
            data.vn_mut(lo).set_precis_lo();
        }
        if let Some(hi) = self.hi {
            data.vn_mut(hi).set_precis_hi();
        }
        if self.whole.is_some() {
            return;
        }
        self.whole = Some(data.new_unique(self.wholesize));
    }

    /// Ghidra `SplitVarnode::createJoinedWhole`. Ghidra's non-contiguous fallback builds a `join`
    /// address; mosura has no join space, so that case returns `false` and the caller declines
    /// rather than mis-joining pieces held in unrelated storage.
    pub fn create_joined_whole(&mut self, data: &mut Funcdata) -> bool {
        let (Some(lo), Some(hi)) = (self.lo, self.hi) else { return false };
        data.vn_mut(lo).set_precis_lo();
        data.vn_mut(hi).set_precis_hi();
        if self.whole.is_some() {
            return true;
        }
        let Some(newaddr) = is_addr_tied_contiguous(data, lo, hi) else { return false };
        let w = data.new_varnode(self.wholesize, newaddr);
        data.vn_mut(w).set_write_mask();
        self.whole = Some(w);
        true
    }

    /// Ghidra `SplitVarnode::buildLoFromWhole` / `buildHiFromWhole`: redefine a piece as a SUBPIECE
    /// of the new whole, re-inserting where the original opcode requires — a MULTIEQUAL stays in
    /// the block's phi run, an INDIRECT stays after its affector.
    fn build_piece_from_whole(&self, data: &mut Funcdata, piece: VarnodeId, offset: u32) -> bool {
        let Some(op) = data.vn(piece).def else { return false };
        let whole = self.whole.expect("findCreateOutputWhole ran first");
        let off = data.new_const(4, offset as u64);
        match data.op(op).code() {
            OpCode::Multiequal => {
                let Some(bl) = data.op(op).parent else { return false };
                data.op_uninsert(op);
                data.op_set_opcode(op, OpCode::Subpiece);
                data.op_set_all_input(op, &[whole, off]);
                data.op_insert_begin(op, bl);
            }
            OpCode::Indirect => {
                let affector = data.op(op).guarded_op();
                let alive = affector.is_some_and(|a| !data.op(a).is_dead());
                if alive {
                    data.op_uninsert(op);
                }
                data.op_set_opcode(op, OpCode::Subpiece);
                data.op_set_all_input(op, &[whole, off]);
                if alive {
                    data.op_insert_after(op, affector.unwrap());
                }
            }
            _ => {
                data.op_set_opcode(op, OpCode::Subpiece);
                data.op_set_all_input(op, &[whole, off]);
            }
        }
        true
    }

    pub fn build_lo_from_whole(&self, data: &mut Funcdata) -> bool {
        let Some(lo) = self.lo else { return false };
        self.build_piece_from_whole(data, lo, 0)
    }

    pub fn build_hi_from_whole(&self, data: &mut Funcdata) -> bool {
        let (Some(hi), Some(lo)) = (self.hi, self.lo) else { return false };
        let off = data.vn(lo).size;
        self.build_piece_from_whole(data, hi, off)
    }
}


impl SplitVarnode {
    /// Ghidra `SplitVarnode::inHandHi` (double.cc): given a marked HIGH piece split from a whole,
    /// find its LOW companion split from the same whole.
    pub fn in_hand_hi(&mut self, data: &Funcdata, h: VarnodeId) -> bool {
        if !data.vn(h).is_precis_hi() {
            return false; // quick reject on the mark
        }
        if !data.vn(h).is_written() {
            return false;
        }
        let op = data.vn(h).def.unwrap();
        if data.op(op).code() != OpCode::Subpiece {
            return false;
        }
        let Some(w) = data.op(op).input(0) else { return false };
        let hsize = data.vn(h).size;
        let wsize = data.vn(w).size;
        if data.op(op).input(1).map(|v| data.vn(v).constant_value()) != Some((wsize - hsize) as u64) {
            return false;
        }
        for tmpop in data.vn(w).descend.clone() {
            if data.op(tmpop).code() != OpCode::Subpiece {
                continue;
            }
            let Some(tmplo) = data.op(tmpop).output else { continue };
            if !data.vn(tmplo).is_precis_lo() || data.vn(tmplo).size + hsize != wsize {
                continue;
            }
            if data.op(tmpop).input(1).map(|v| data.vn(v).constant_value()) != Some(0) {
                continue;
            }
            self.init_all(w, Some(tmplo), Some(h), wsize);
            return true;
        }
        false
    }

    /// Ghidra `SplitVarnode::inHandLo` (double.cc): the mirror of [`Self::in_hand_hi`].
    pub fn in_hand_lo(&mut self, data: &Funcdata, l: VarnodeId) -> bool {
        if !data.vn(l).is_precis_lo() || !data.vn(l).is_written() {
            return false;
        }
        let op = data.vn(l).def.unwrap();
        if data.op(op).code() != OpCode::Subpiece {
            return false;
        }
        if data.op(op).input(1).map(|v| data.vn(v).constant_value()) != Some(0) {
            return false;
        }
        let Some(w) = data.op(op).input(0) else { return false };
        let lsize = data.vn(l).size;
        let wsize = data.vn(w).size;
        for tmpop in data.vn(w).descend.clone() {
            if data.op(tmpop).code() != OpCode::Subpiece {
                continue;
            }
            let Some(tmphi) = data.op(tmpop).output else { continue };
            if !data.vn(tmphi).is_precis_hi() || data.vn(tmphi).size + lsize != wsize {
                continue;
            }
            if data.op(tmpop).input(1).map(|v| data.vn(v).constant_value()) != Some(lsize as u64) {
                continue;
            }
            self.init_all(w, Some(l), Some(tmphi), wsize);
            return true;
        }
        false
    }

    /// Ghidra `SplitVarnode::inHandLoNoHi` (double.cc): as [`Self::in_hand_lo`], but the high piece
    /// may be absent (an implied zero extension).
    pub fn in_hand_lo_no_hi(&mut self, data: &Funcdata, l: VarnodeId) -> bool {
        if !data.vn(l).is_precis_lo() || !data.vn(l).is_written() {
            return false;
        }
        let op = data.vn(l).def.unwrap();
        if data.op(op).code() != OpCode::Subpiece {
            return false;
        }
        if data.op(op).input(1).map(|v| data.vn(v).constant_value()) != Some(0) {
            return false;
        }
        let Some(w) = data.op(op).input(0) else { return false };
        let lsize = data.vn(l).size;
        let wsize = data.vn(w).size;
        for tmpop in data.vn(w).descend.clone() {
            if data.op(tmpop).code() != OpCode::Subpiece {
                continue;
            }
            let Some(tmphi) = data.op(tmpop).output else { continue };
            if !data.vn(tmphi).is_precis_hi() || data.vn(tmphi).size + lsize != wsize {
                continue;
            }
            if data.op(tmpop).input(1).map(|v| data.vn(v).constant_value()) != Some(lsize as u64) {
                continue;
            }
            self.init_all(w, Some(l), Some(tmphi), wsize);
            return true;
        }
        self.init_all(w, Some(l), None, wsize);
        true
    }

    /// Ghidra `SplitVarnode::inHandHiOut` (double.cc): the high piece is concatenated into a whole
    /// with a marked low piece, and that concatenation must be unique.
    pub fn in_hand_hi_out(&mut self, data: &Funcdata, h: VarnodeId) -> bool {
        let mut lo_tmp = None;
        let mut outvn = None;
        for pieceop in data.vn(h).descend.clone() {
            if data.op(pieceop).code() != OpCode::Piece || data.op(pieceop).input(0) != Some(h) {
                continue;
            }
            let Some(l) = data.op(pieceop).input(1) else { continue };
            if !data.vn(l).is_precis_lo() {
                continue;
            }
            if lo_tmp.is_some() {
                return false; // whole is not unique
            }
            lo_tmp = Some(l);
            outvn = data.op(pieceop).output;
        }
        match (lo_tmp, outvn) {
            (Some(l), Some(o)) => {
                let wsize = data.vn(o).size;
                self.init_all(o, Some(l), Some(h), wsize);
                true
            }
            _ => false,
        }
    }

    /// Ghidra `SplitVarnode::inHandLoOut` (double.cc): the mirror of [`Self::in_hand_hi_out`].
    pub fn in_hand_lo_out(&mut self, data: &Funcdata, l: VarnodeId) -> bool {
        let mut hi_tmp = None;
        let mut outvn = None;
        for pieceop in data.vn(l).descend.clone() {
            if data.op(pieceop).code() != OpCode::Piece || data.op(pieceop).input(1) != Some(l) {
                continue;
            }
            let Some(h) = data.op(pieceop).input(0) else { continue };
            if !data.vn(h).is_precis_hi() {
                continue;
            }
            if hi_tmp.is_some() {
                return false;
            }
            hi_tmp = Some(h);
            outvn = data.op(pieceop).output;
        }
        match (hi_tmp, outvn) {
            (Some(h), Some(o)) => {
                let wsize = data.vn(o).size;
                self.init_all(o, Some(l), Some(h), wsize);
                true
            }
            _ => false,
        }
    }

    /// Ghidra `SplitVarnode::wholeList` (double.cc): every double-precision pair split out of `w`
    /// by SUBPIECE, plus the COPY-propagated variants ([`Self::find_copies`]).
    pub fn whole_list(data: &Funcdata, w: VarnodeId) -> Vec<SplitVarnode> {
        let mut basic = SplitVarnode { whole: Some(w), wholesize: data.vn(w).size, ..Default::default() };
        let mut res = 0u32;
        for subop in data.vn(w).descend.clone() {
            if data.op(subop).code() != OpCode::Subpiece {
                continue;
            }
            let Some(vn) = data.op(subop).output else { continue };
            let off = data.op(subop).input(1).map(|v| data.vn(v).constant_value());
            if data.vn(vn).is_precis_hi() {
                if off != Some((basic.wholesize - data.vn(vn).size) as u64) {
                    continue;
                }
                basic.hi = Some(vn);
                res |= 2;
            } else if data.vn(vn).is_precis_lo() {
                if off != Some(0) {
                    continue;
                }
                basic.lo = Some(vn);
                res |= 1;
            }
        }
        let mut splitvec = Vec::new();
        if res == 0 {
            return splitvec;
        }
        if res == 3 {
            let (lo, hi) = (basic.lo.unwrap(), basic.hi.unwrap());
            if data.vn(lo).size + data.vn(hi).size != basic.wholesize {
                return splitvec;
            }
        }
        splitvec.push(basic.clone());
        SplitVarnode::find_copies(data, &basic, &mut splitvec);
        splitvec
    }

    /// Ghidra `SplitVarnode::findCopies` (double.cc): a pair that was COPYed to another contiguous
    /// storage pair, in the same block, is the same logical value.
    pub fn find_copies(data: &Funcdata, in_: &SplitVarnode, splitvec: &mut Vec<SplitVarnode>) {
        if !in_.has_both_pieces() {
            return;
        }
        let (lo, hi) = (in_.lo.unwrap(), in_.hi.unwrap());
        for loop_ in data.vn(lo).descend.clone() {
            if data.op(loop_).code() != OpCode::Copy {
                continue;
            }
            let Some(locpy) = data.op(loop_).output else { continue };
            // Little-endian: the high half sits just above the low copy.
            let addr = super::space::Address::new(
                data.vn(locpy).loc.space,
                data.vn(locpy).loc.offset + data.vn(locpy).size as u64,
            );
            for hiop in data.vn(hi).descend.clone() {
                if data.op(hiop).code() != OpCode::Copy {
                    continue;
                }
                let Some(hicpy) = data.op(hiop).output else { continue };
                if data.vn(hicpy).loc != addr {
                    continue;
                }
                if data.op(hiop).parent != data.op(loop_).parent {
                    continue;
                }
                let mut newsplit = SplitVarnode::default();
                if let Some(w) = in_.whole {
                    newsplit.init_all(w, Some(locpy), Some(hicpy), in_.wholesize);
                    splitvec.push(newsplit);
                }
            }
        }
    }

    /// Ghidra `SplitVarnode::getTrueFalse` (double.cc): the true/false successors of a CBRANCH,
    /// accounting for `boolean_flip` and the caller's own `flip`. Ghidra's edge convention is
    /// `getFalseOut() == getOut(0)`, `getTrueOut() == getOut(1)` (block.hh:299).
    pub fn get_true_false(
        data: &Funcdata,
        boolop: OpId,
        flip: bool,
    ) -> Option<(BlockId, BlockId)> {
        let parent = data.op(boolop).parent?;
        let outs = &data.block(parent).out_edges;
        let falseblock = outs.first().copied()?;
        let trueblock = outs.get(1).copied()?;
        if data.op(boolop).is_boolean_flip() != flip {
            Some((falseblock, trueblock))
        } else {
            Some((trueblock, falseblock))
        }
    }

    /// Ghidra `SplitVarnode::otherwiseEmpty` (double.cc): the branch's block contains nothing but
    /// the branch and (optionally) the op computing its condition.
    pub fn otherwise_empty(data: &Funcdata, branchop: OpId) -> bool {
        let Some(bl) = data.op(branchop).parent else { return false };
        if data.block(bl).in_edges.len() != 1 {
            return false;
        }
        let otherop = data.op(branchop).input(1).and_then(|v| {
            if data.vn(v).is_written() { data.vn(v).def } else { None }
        });
        for &op in &data.block(bl).ops {
            if Some(op) == otherop || op == branchop {
                continue;
            }
            return false;
        }
        true
    }

    /// Ghidra `SplitVarnode::verifyMultNegOne` (double.cc): the op is `V * -1`.
    pub fn verify_mult_neg_one(data: &Funcdata, op: OpId) -> bool {
        if data.op(op).code() != OpCode::IntMult {
            return false;
        }
        let Some(in1) = data.op(op).input(1) else { return false };
        if !data.vn(in1).is_constant() {
            return false;
        }
        data.vn(in1).constant_value() == super::nzmask::calc_mask(data.vn(in1).size)
    }
}


impl SplitVarnode {
    /// Ghidra `SplitVarnode::findOutExist` (double.cc): the point at which the OUTPUT whole must
    /// exist — the concatenation that already builds it, else the earlier of the halves' defs.
    pub fn find_out_exist(&mut self, data: &Funcdata) -> Option<OpId> {
        if self.find_whole_built_from_pieces(data) {
            return self.defpoint;
        }
        self.find_earliest_split_point(data)
    }

    /// Ghidra `SplitVarnode::prepareBinaryOp` (double.cc).
    pub fn prepare_binary_op(
        data: &Funcdata,
        out: &mut SplitVarnode,
        in1: &mut SplitVarnode,
        in2: &mut SplitVarnode,
    ) -> Option<OpId> {
        let existop = out.find_out_exist(data)?;
        if !in1.is_whole_feasible(data, existop) || !in2.is_whole_feasible(data, existop) {
            return None;
        }
        Some(existop)
    }

    /// Ghidra `SplitVarnode::createBinaryOp` (double.cc): emit the whole-width operation. If the
    /// output whole already existed as a PIECE, that op is REPLACED in place; otherwise a new op is
    /// inserted and both halves are rebuilt as SUBPIECEs of its output.
    pub fn create_binary_op(
        data: &mut Funcdata,
        out: &mut SplitVarnode,
        in1: &mut SplitVarnode,
        in2: &mut SplitVarnode,
        existop: OpId,
        opc: OpCode,
    ) {
        out.find_create_output_whole(data);
        in1.find_create_whole(data);
        in2.find_create_whole(data);
        let (w_out, w1, w2) = (out.whole.unwrap(), in1.whole.unwrap(), in2.whole.unwrap());
        if data.op(existop).code() != OpCode::Piece {
            let pc = data.op(existop).seqnum.pc;
            let uniq = data.num_ops() as u32;
            let newop = data.new_op(opc, SeqNum { pc, uniq }, vec![w1, w2]);
            data.op_set_output(newop, w_out);
            data.op_insert_before(newop, existop);
            out.build_lo_from_whole(data);
            out.build_hi_from_whole(data);
        } else {
            data.op_set_opcode(existop, opc);
            data.op_set_all_input(existop, &[w1, w2]);
        }
    }

    /// Ghidra `SplitVarnode::prepareShiftOp` (double.cc).
    pub fn prepare_shift_op(
        data: &Funcdata,
        out: &mut SplitVarnode,
        in_: &mut SplitVarnode,
    ) -> Option<OpId> {
        let existop = out.find_out_exist(data)?;
        if !in_.is_whole_feasible(data, existop) {
            return None;
        }
        Some(existop)
    }

    /// Ghidra `SplitVarnode::createShiftOp` (double.cc).
    pub fn create_shift_op(
        data: &mut Funcdata,
        out: &mut SplitVarnode,
        in_: &mut SplitVarnode,
        sa: VarnodeId,
        existop: OpId,
        opc: OpCode,
    ) {
        out.find_create_output_whole(data);
        in_.find_create_whole(data);
        let sa = if data.vn(sa).is_constant() {
            let (size, val) = (data.vn(sa).size, data.vn(sa).constant_value());
            data.new_const(size, val)
        } else {
            sa
        };
        let (w_out, w_in) = (out.whole.unwrap(), in_.whole.unwrap());
        if data.op(existop).code() != OpCode::Piece {
            let pc = data.op(existop).seqnum.pc;
            let uniq = data.num_ops() as u32;
            let newop = data.new_op(opc, SeqNum { pc, uniq }, vec![w_in, sa]);
            data.op_set_output(newop, w_out);
            data.op_insert_before(newop, existop);
            out.build_lo_from_whole(data);
            out.build_hi_from_whole(data);
        } else {
            data.op_set_opcode(existop, opc);
            data.op_set_all_input(existop, &[w_in, sa]);
        }
    }

    /// Ghidra `SplitVarnode::prepareBoolOp` (double.cc).
    pub fn prepare_bool_op(
        data: &Funcdata,
        in1: &mut SplitVarnode,
        in2: &mut SplitVarnode,
        testop: OpId,
    ) -> bool {
        in1.is_whole_feasible(data, testop) && in2.is_whole_feasible(data, testop)
    }

    /// Ghidra `SplitVarnode::createBoolOp` (double.cc): a fresh whole-width comparison feeding the
    /// CBRANCH, built at the address of the comparison it replaces.
    pub fn create_bool_op(
        data: &mut Funcdata,
        cbranch: OpId,
        in1: &mut SplitVarnode,
        in2: &mut SplitVarnode,
        opc: OpCode,
    ) {
        let boolvn = data.op(cbranch).input(1);
        let addrop = match boolvn {
            Some(v) if data.vn(v).is_written() => data.vn(v).def.unwrap(),
            _ => cbranch,
        };
        in1.find_create_whole(data);
        in2.find_create_whole(data);
        let (w1, w2) = (in1.whole.unwrap(), in2.whole.unwrap());
        let pc = data.op(addrop).seqnum.pc;
        let uniq = data.num_ops() as u32;
        let newop = data.new_op(opc, SeqNum { pc, uniq }, vec![w1, w2]);
        let newbool = data.new_output_unique(newop, 1);
        data.op_insert_before(newop, cbranch);
        data.op_set_input(cbranch, 1, newbool);
    }

    /// Ghidra `SplitVarnode::replaceBoolOp` (double.cc): rewrite an existing comparison in place.
    pub fn replace_bool_op(
        data: &mut Funcdata,
        boolop: OpId,
        in1: &mut SplitVarnode,
        in2: &mut SplitVarnode,
        opc: OpCode,
    ) {
        in1.find_create_whole(data);
        in2.find_create_whole(data);
        let (w1, w2) = (in1.whole.unwrap(), in2.whole.unwrap());
        data.op_set_opcode(boolop, opc);
        data.op_set_all_input(boolop, &[w1, w2]);
    }
}


impl SplitVarnode {
    /// Ghidra `SplitVarnode::preparePhiOp` (double.cc): the output whole must be definable at a
    /// MULTIEQUAL, and every incoming pair's whole must be definable at the end of the matching
    /// predecessor block.
    ///
    /// Ghidra throws if the exist point is not a MULTIEQUAL; mosura returns `None` and the caller
    /// declines, since a rule aborting the decompile is worse than a rewrite not happening.
    pub fn prepare_phi_op(
        data: &Funcdata,
        out: &mut SplitVarnode,
        inlist: &mut [SplitVarnode],
    ) -> Option<OpId> {
        let existop = out.find_earliest_split_point(data)?;
        if data.op(existop).code() != OpCode::Multiequal {
            return None;
        }
        let bl = data.op(existop).parent?;
        let ins = data.block(bl).in_edges.clone();
        if ins.len() != inlist.len() {
            return None;
        }
        for (i, item) in inlist.iter_mut().enumerate() {
            if !item.is_whole_phi_feasible(data, ins[i]) {
                return None;
            }
        }
        Some(existop)
    }

    /// Ghidra `SplitVarnode::createPhiOp` (double.cc): a whole-width MULTIEQUAL. Unlike the boolean
    /// case this ALWAYS builds a new op even when the output whole exists, because a MULTIEQUAL has
    /// placement constraints (it must sit in the block's phi run).
    pub fn create_phi_op(
        data: &mut Funcdata,
        out: &mut SplitVarnode,
        inlist: &mut [SplitVarnode],
        existop: OpId,
    ) {
        out.find_create_output_whole(data);
        for item in inlist.iter_mut() {
            item.find_create_whole(data);
        }
        let inputs: Vec<VarnodeId> = inlist.iter().map(|i| i.whole.unwrap()).collect();
        let pc = data.op(existop).seqnum.pc;
        let uniq = data.num_ops() as u32;
        let newop = data.new_op(OpCode::Multiequal, SeqNum { pc, uniq }, inputs);
        let w_out = out.whole.unwrap();
        data.op_set_output(newop, w_out);
        data.op_insert_before(newop, existop);
        out.build_lo_from_whole(data);
        out.build_hi_from_whole(data);
    }

    /// Ghidra `SplitVarnode::prepareIndirectOp` (double.cc).
    pub fn prepare_indirect_op(
        data: &Funcdata,
        in_: &mut SplitVarnode,
        affector: OpId,
    ) -> bool {
        in_.is_whole_feasible(data, affector)
    }

    /// Ghidra `SplitVarnode::replaceIndirectOp` (double.cc): a whole-width INDIRECT guarding the
    /// same affector. Declines when the output pieces cannot be joined into real storage (mosura
    /// has no `join` space — see [`Self::create_joined_whole`]).
    pub fn replace_indirect_op(
        data: &mut Funcdata,
        out: &mut SplitVarnode,
        in_: &mut SplitVarnode,
        affector: OpId,
    ) -> bool {
        if !out.create_joined_whole(data) {
            return false;
        }
        in_.find_create_whole(data);
        let (w_out, w_in) = (out.whole.unwrap(), in_.whole.unwrap());
        let pc = data.op(affector).seqnum.pc;
        let uniq = data.num_ops() as u32;
        let newop = data.new_op(OpCode::Indirect, SeqNum { pc, uniq }, vec![w_in]);
        // Ghidra's second input is a `newVarnodeIop(affector)` annotation; mosura carries the same
        // reference on the op itself (`guarded_op`), which is what `indirect_source` reads back.
        data.op_mut(newop).guarded_op = Some(affector);
        data.op_set_output(newop, w_out);
        data.op_insert_before(newop, affector);
        out.build_lo_from_whole(data);
        out.build_hi_from_whole(data);
        true
    }

    /// Ghidra `SplitVarnode::replaceCopyForce` (double.cc): two address-forced COPYs of the halves
    /// become one whole-width COPY. The return-form variant needs an extra COPY first, because a
    /// global propagated past a RETURN must be placed at the forced address.
    pub fn replace_copy_force(
        data: &mut Funcdata,
        addr: super::space::Address,
        in_: &SplitVarnode,
        copylo: OpId,
        copyhi: OpId,
    ) {
        let mut in_vn = in_.whole.expect("whole created by the caller");
        let return_form = data.op(copyhi).is_return_copy();
        if return_form && data.vn(in_vn).loc != addr {
            let p1 = data.op(copyhi).input(0).and_then(|v| data.vn(v).def);
            let p2 = data.op(copylo).input(0).and_then(|v| data.vn(v).def);
            let (Some(p1), Some(p2)) = (p1, p2) else { return };
            // Both are COPYs in the same basic block; take the later one.
            let other_point = if seq_order(data, p1) < seq_order(data, p2) { p2 } else { p1 };
            let pc = data.op(other_point).seqnum.pc;
            let uniq = data.num_ops() as u32;
            let other_copy = data.new_op(OpCode::Copy, SeqNum { pc, uniq }, vec![in_vn]);
            let vn = data.new_output(other_copy, in_.wholesize, addr);
            data.op_insert_before(other_copy, other_point);
            in_vn = vn;
        }
        let pc = data.op(copyhi).seqnum.pc;
        let uniq = data.num_ops() as u32;
        let whole_copy = data.new_op(OpCode::Copy, SeqNum { pc, uniq }, vec![in_vn]);
        let out_vn = data.new_output(whole_copy, in_.wholesize, addr);
        data.vn_mut(out_vn).set_addr_force();
        if return_form {
            data.op_mut(whole_copy).mark_return_copy();
        }
        data.op_insert_before(whole_copy, copyhi);
        // Destroy the original COPYs — their outputs have no descendants.
        data.op_destroy(copyhi);
        data.op_destroy(copylo);
    }
}


// ---------------------------------------------------------------------------------------------
// The `*Form` recognizers (double.cc). Each one answers: "given one double-precision pair and an
// op reading one of its halves, is this piece-wise arithmetic that means a whole-width operation?"
// `SplitVarnode::apply_rule_in` dispatches to them by opcode.
// ---------------------------------------------------------------------------------------------

/// The recognized carry shape and the second low operand it implies.
struct CarryMatch {
    /// The second low operand, or `None` when the addend is a constant.
    lo2: Option<VarnodeId>,
    /// The constant addend, when `lo2` is `None`.
    negconst: u64,
}

/// Ghidra `AddForm::checkForCarry` (double.cc): does `op` build the carry out of `lo1`? Ghidra
/// accepts four spellings — a real `INT_CARRY`, an `INT_LESS` against `lo1`, an `INT_LESS` against
/// the low sum, and an `INT_NOTEQUAL` against zero (carry from adding -1).
fn add_form_check_for_carry(data: &Funcdata, op: OpId, lo1: VarnodeId) -> Option<CarryMatch> {
    if data.op(op).code() != OpCode::IntZext {
        return None;
    }
    let in0 = data.op(op).input(0)?;
    if !data.vn(in0).is_written() {
        return None;
    }
    let carryop = data.vn(in0).def.unwrap();
    let mask = super::nzmask::calc_mask(data.vn(lo1).size);
    match data.op(carryop).code() {
        OpCode::IntCarry => {
            let (a, b) = (data.op(carryop).input(0)?, data.op(carryop).input(1)?);
            let lo2 = if a == lo1 {
                b
            } else if b == lo1 {
                a
            } else {
                return None;
            };
            if data.vn(lo2).is_constant() {
                return None;
            }
            Some(CarryMatch { lo2: Some(lo2), negconst: 0 })
        }
        OpCode::IntLess => {
            let tmpvn = data.op(carryop).input(0)?;
            if data.vn(tmpvn).is_constant() {
                if data.op(carryop).input(1) != Some(lo1) {
                    return None;
                }
                // The `<=` to `<` conversion adds 1, and the two's complement subtracts 1 and
                // negates — so all that is left is the negation.
                let negconst = (!data.vn(tmpvn).constant_value()) & mask;
                return Some(CarryMatch { lo2: None, negconst });
            }
            if !data.vn(tmpvn).is_written() {
                return None;
            }
            // The carry may instead be computed relative to the result of the low add.
            let loadd_op = data.vn(tmpvn).def.unwrap();
            if data.op(loadd_op).code() != OpCode::IntAdd {
                return None;
            }
            let (a, b) = (data.op(loadd_op).input(0)?, data.op(loadd_op).input(1)?);
            let othervn = if a == lo1 {
                b
            } else if b == lo1 {
                a
            } else {
                return None; // one side of the add must be lo1
            };
            if data.vn(othervn).is_constant() {
                let negconst = data.vn(othervn).constant_value();
                let relvn = data.op(carryop).input(1)?;
                if relvn == lo1 {
                    return Some(CarryMatch { lo2: None, negconst }); // relative to lo1
                }
                if !data.vn(relvn).is_constant() || data.vn(relvn).constant_value() != negconst {
                    return None; // else must be relative to the constant lo2
                }
                Some(CarryMatch { lo2: None, negconst })
            } else {
                let compvn = data.op(carryop).input(1)?;
                if compvn == othervn || compvn == lo1 {
                    Some(CarryMatch { lo2: Some(othervn), negconst: 0 })
                } else {
                    None
                }
            }
        }
        OpCode::IntNotequal => {
            // Possible carry against -1.
            let c = data.op(carryop).input(1)?;
            if !data.vn(c).is_constant() || data.vn(c).constant_value() != 0 {
                return None;
            }
            if data.op(carryop).input(0) != Some(lo1) {
                return None;
            }
            Some(CarryMatch { lo2: None, negconst: mask })
        }
        _ => None,
    }
}

/// What a Form's `verify` recovers: the second input pair and the result pair.
struct FormMatch {
    hi2: Option<VarnodeId>,
    lo2: Option<VarnodeId>,
    reshi: VarnodeId,
    reslo: VarnodeId,
}

/// Ghidra `AddForm::verify` (double.cc): the piece-wise 64-bit add. The high half is
/// `hi1 + hi2 + ZEXT(carry(lo1,lo2))`, which the compiler may spell as one add or two, in either
/// association; the low half is the matching `lo1 + lo2`.
fn add_form_verify(data: &Funcdata, h: VarnodeId, l: VarnodeId, op: OpId) -> Option<FormMatch> {
    let hi1 = h;
    let lo1 = l;
    let slot1 = (0..data.op(op).num_inputs()).find(|&i| data.op(op).input(i) == Some(hi1))?;
    for i in 0..3 {
        let (reshi, hizext1, hizext2, add2_ok);
        match i {
            0 => {
                // Assume we have to descend one more add.
                let out = match data.op(op).output {
                    Some(o) => o,
                    None => continue,
                };
                let Some(add2) = data.lone_descend(out) else { continue };
                if data.op(add2).code() != OpCode::IntAdd {
                    continue;
                }
                let Some(r) = data.op(add2).output else { continue };
                let Some(s) = (0..data.op(add2).num_inputs())
                    .find(|&k| data.op(add2).input(k) == Some(out))
                else {
                    continue;
                };
                reshi = r;
                hizext1 = data.op(op).input(1 - slot1);
                hizext2 = data.op(add2).input(1 - s);
                add2_ok = true;
            }
            1 => {
                // Assume we are at the bottom-most of two adds.
                let Some(tmpvn) = data.op(op).input(1 - slot1) else { continue };
                if !data.vn(tmpvn).is_written() {
                    continue;
                }
                let add2 = data.vn(tmpvn).def.unwrap();
                if data.op(add2).code() != OpCode::IntAdd {
                    continue;
                }
                let Some(r) = data.op(op).output else { continue };
                reshi = r;
                hizext1 = data.op(add2).input(0);
                hizext2 = data.op(add2).input(1);
                add2_ok = true;
            }
            _ => {
                // Assume a single add, with the second add implied by zero.
                let Some(r) = data.op(op).output else { continue };
                reshi = r;
                hizext1 = data.op(op).input(1 - slot1);
                hizext2 = None;
                add2_ok = true;
            }
        }
        if !add2_ok {
            continue;
        }
        for j in 0..2 {
            let (zextop, hi2) = if i == 2 {
                let Some(z) = hizext1 else { continue };
                if !data.vn(z).is_written() {
                    continue;
                }
                (data.vn(z).def.unwrap(), None) // hi2 is an implied 0
            } else if j == 0 {
                let Some(z) = hizext1 else { continue };
                if !data.vn(z).is_written() {
                    continue;
                }
                (data.vn(z).def.unwrap(), hizext2)
            } else {
                let Some(z) = hizext2 else { continue };
                if !data.vn(z).is_written() {
                    continue;
                }
                (data.vn(z).def.unwrap(), hizext1)
            };
            let Some(carry) = add_form_check_for_carry(data, zextop, lo1) else { continue };
            for loadd in data.vn(lo1).descend.clone() {
                if data.op(loadd).code() != OpCode::IntAdd {
                    continue;
                }
                let Some(s) = (0..data.op(loadd).num_inputs())
                    .find(|&k| data.op(loadd).input(k) == Some(lo1))
                else {
                    continue;
                };
                let Some(tmpvn) = data.op(loadd).input(1 - s) else { continue };
                let lo2 = match carry.lo2 {
                    None => {
                        // Must add the same constant used to compute the carry.
                        if !data.vn(tmpvn).is_constant()
                            || data.vn(tmpvn).constant_value() != carry.negconst
                        {
                            continue;
                        }
                        tmpvn
                    }
                    Some(l2) if data.vn(l2).is_constant() => {
                        if !data.vn(tmpvn).is_constant()
                            || data.vn(l2).constant_value() != data.vn(tmpvn).constant_value()
                        {
                            continue;
                        }
                        l2
                    }
                    Some(l2) => {
                        if tmpvn != l2 {
                            continue; // must add the same value used to compute the carry
                        }
                        l2
                    }
                };
                let Some(reslo) = data.op(loadd).output else { continue };
                return Some(FormMatch { hi2, lo2: Some(lo2), reshi, reslo });
            }
        }
    }
    None
}


/// Ghidra `SubForm::verify` (double.cc): the piece-wise 64-bit subtract. Compilers spell it as an
/// ADD of negated operands — `hi1 + (-hi2) + (-ZEXT(lo1 < lo2))` over `lo1 + (-lo2)` — so every
/// operand arrives through a `* -1` and the borrow is an `INT_LESS`.
fn sub_form_verify(data: &Funcdata, h: VarnodeId, l: VarnodeId, op: OpId) -> Option<FormMatch> {
    let (hi1, lo1) = (h, l);
    let slot1 = (0..data.op(op).num_inputs()).find(|&i| data.op(op).input(i) == Some(hi1))?;
    for i in 0..2 {
        let (reshi, hineg1, hineg2);
        if i == 0 {
            // Assume we have to descend one more add.
            let Some(out) = data.op(op).output else { continue };
            let Some(add2) = data.lone_descend(out) else { continue };
            if data.op(add2).code() != OpCode::IntAdd {
                continue;
            }
            let Some(r) = data.op(add2).output else { continue };
            let Some(s) =
                (0..data.op(add2).num_inputs()).find(|&k| data.op(add2).input(k) == Some(out))
            else {
                continue;
            };
            reshi = r;
            hineg1 = data.op(op).input(1 - slot1);
            hineg2 = data.op(add2).input(1 - s);
        } else {
            let Some(tmpvn) = data.op(op).input(1 - slot1) else { continue };
            if !data.vn(tmpvn).is_written() {
                continue;
            }
            let add2 = data.vn(tmpvn).def.unwrap();
            if data.op(add2).code() != OpCode::IntAdd {
                continue;
            }
            let Some(r) = data.op(op).output else { continue };
            reshi = r;
            hineg1 = data.op(add2).input(0);
            hineg2 = data.op(add2).input(1);
        }
        let (Some(hineg1), Some(hineg2)) = (hineg1, hineg2) else { continue };
        if !data.vn(hineg1).is_written() || !data.vn(hineg2).is_written() {
            continue;
        }
        let (neg1, neg2) = (data.vn(hineg1).def.unwrap(), data.vn(hineg2).def.unwrap());
        if !SplitVarnode::verify_mult_neg_one(data, neg1)
            || !SplitVarnode::verify_mult_neg_one(data, neg2)
        {
            continue;
        }
        let (Some(hizext1), Some(hizext2)) = (data.op(neg1).input(0), data.op(neg2).input(0))
        else {
            continue;
        };
        for j in 0..2 {
            let (zextop, hi2) = if j == 0 {
                if !data.vn(hizext1).is_written() {
                    continue;
                }
                (data.vn(hizext1).def.unwrap(), Some(hizext2))
            } else {
                if !data.vn(hizext2).is_written() {
                    continue;
                }
                (data.vn(hizext2).def.unwrap(), Some(hizext1))
            };
            if data.op(zextop).code() != OpCode::IntZext {
                continue;
            }
            let Some(zin) = data.op(zextop).input(0) else { continue };
            if !data.vn(zin).is_written() {
                continue;
            }
            let lessop = data.vn(zin).def.unwrap();
            if data.op(lessop).code() != OpCode::IntLess {
                continue;
            }
            if data.op(lessop).input(0) != Some(lo1) {
                continue;
            }
            let Some(lo2) = data.op(lessop).input(1) else { continue };
            for loadd in data.vn(lo1).descend.clone() {
                if data.op(loadd).code() != OpCode::IntAdd {
                    continue;
                }
                let Some(s) =
                    (0..data.op(loadd).num_inputs()).find(|&k| data.op(loadd).input(k) == Some(lo1))
                else {
                    continue;
                };
                let Some(tmpvn) = data.op(loadd).input(1 - s) else { continue };
                if !data.vn(tmpvn).is_written() {
                    continue;
                }
                let negop = data.vn(tmpvn).def.unwrap();
                if !SplitVarnode::verify_mult_neg_one(data, negop) {
                    continue;
                }
                if data.op(negop).input(0) != Some(lo2) {
                    continue;
                }
                let Some(reslo) = data.op(loadd).output else { continue };
                return Some(FormMatch { hi2, lo2: Some(lo2), reshi, reslo });
            }
        }
    }
    None
}

/// Ghidra `AddForm::applyRule` / `SubForm::applyRule` (double.cc) — identical apart from which
/// `verify` runs and which opcode is emitted, so they share one body here.
fn add_sub_apply_rule(
    data: &mut Funcdata,
    i: &SplitVarnode,
    op: OpId,
    workishi: bool,
    is_add: bool,
) -> bool {
    if !workishi || !i.has_both_pieces() {
        return false;
    }
    let (hi, lo) = (i.hi.unwrap(), i.lo.unwrap());
    let m = if is_add {
        add_form_verify(data, hi, lo, op)
    } else {
        sub_form_verify(data, hi, lo, op)
    };
    let Some(m) = m else { return false };
    let mut in_ = i.clone();
    let mut indoub = SplitVarnode::default();
    indoub.init_partial(in_.get_size(), m.lo2, m.hi2);
    if indoub.exceeds_const_precision() {
        return false;
    }
    let mut outdoub = SplitVarnode::default();
    outdoub.init_partial(in_.get_size(), Some(m.reslo), Some(m.reshi));
    let Some(existop) =
        SplitVarnode::prepare_binary_op(data, &mut outdoub, &mut in_, &mut indoub)
    else {
        return false;
    };
    let opc = if is_add { OpCode::IntAdd } else { OpCode::IntSub };
    SplitVarnode::create_binary_op(data, &mut outdoub, &mut in_, &mut indoub, existop, opc);
    true
}


/// Ghidra `LogicalForm::findHiMatch` (double.cc): given the op computing the LOW half of a bitwise
/// operation, find the op computing the HIGH half. Three routes, in Ghidra's order: the double
/// output is already known and its high piece is built by a matching op; the other input pair is
/// already known and its high piece feeds a matching op; or the other operand is constant and there
/// is exactly ONE candidate reading `hi1` (ambiguity is refused, not guessed).
fn logical_form_find_hi_match(
    data: &Funcdata,
    in_: &SplitVarnode,
    hi1: VarnodeId,
    loop_: OpId,
) -> Option<OpId> {
    let lo1 = in_.lo?;
    let slot = (0..data.op(loop_).num_inputs()).find(|&i| data.op(loop_).input(i) == Some(lo1))?;
    let vn2 = data.op(loop_).input(1 - slot)?;
    let opc = data.op(loop_).code();

    let mut out = SplitVarnode::default();
    if out.in_hand_lo_out(data, lo1) {
        if let Some(hi) = out.hi {
            if data.vn(hi).is_written() {
                let maybeop = data.vn(hi).def.unwrap();
                if data.op(maybeop).code() == opc {
                    let (a, b) = (data.op(maybeop).input(0), data.op(maybeop).input(1));
                    if a == Some(hi1) {
                        if b.is_some_and(|v| data.vn(v).is_constant())
                            == data.vn(vn2).is_constant()
                        {
                            return Some(maybeop);
                        }
                    } else if b == Some(hi1)
                        && a.is_some_and(|v| data.vn(v).is_constant()) == data.vn(vn2).is_constant()
                    {
                        return Some(maybeop);
                    }
                }
            }
        }
    }

    if !data.vn(vn2).is_constant() {
        let mut in2 = SplitVarnode::default();
        if in2.in_hand_lo(data, vn2) {
            if let Some(hi2) = in2.hi {
                for maybeop in data.vn(hi2).descend.clone() {
                    if data.op(maybeop).code() == opc
                        && (data.op(maybeop).input(0) == Some(hi1)
                            || data.op(maybeop).input(1) == Some(hi1))
                    {
                        return Some(maybeop);
                    }
                }
            }
        }
        return None;
    }
    // Constant other operand: accept only a unique candidate.
    let mut count = 0;
    let mut lastop = None;
    for maybeop in data.vn(hi1).descend.clone() {
        if data.op(maybeop).code() == opc
            && data.op(maybeop).input(1).is_some_and(|v| data.vn(v).is_constant())
        {
            count += 1;
            if count > 1 {
                break;
            }
            lastop = Some(maybeop);
        }
    }
    if count == 1 {
        return lastop;
    }
    None
}

/// Ghidra `LogicalForm::applyRule` (double.cc): a bitwise AND/OR/XOR done half at a time is the
/// same operation on the whole. Note this Form runs from the LOW half (`workishi` false), which is
/// why it searches upward for the high op rather than downward.
fn logical_form_apply_rule(
    data: &mut Funcdata,
    i: &SplitVarnode,
    lop: OpId,
    workishi: bool,
) -> bool {
    if workishi || !i.has_both_pieces() {
        return false;
    }
    let (hi1, lo1) = (i.hi.unwrap(), i.lo.unwrap());
    let Some(hiop) = logical_form_find_hi_match(data, i, hi1, lop) else { return false };
    let lo_slot =
        match (0..data.op(lop).num_inputs()).find(|&k| data.op(lop).input(k) == Some(lo1)) {
            Some(s) => s,
            None => return false,
        };
    let hi_slot =
        match (0..data.op(hiop).num_inputs()).find(|&k| data.op(hiop).input(k) == Some(hi1)) {
            Some(s) => s,
            None => return false,
        };
    let (Some(lo2), Some(hi2)) = (data.op(lop).input(1 - lo_slot), data.op(hiop).input(1 - hi_slot))
    else {
        return false;
    };
    // No manipulation of itself.
    if lo2 == lo1 || lo2 == hi1 || hi2 == hi1 || hi2 == lo1 || lo2 == hi2 {
        return false;
    }
    let (Some(reslo), Some(reshi)) = (data.op(lop).output, data.op(hiop).output) else {
        return false;
    };
    let mut in_ = i.clone();
    let mut outdoub = SplitVarnode::default();
    outdoub.init_partial(in_.get_size(), Some(reslo), Some(reshi));
    let mut indoub = SplitVarnode::default();
    indoub.init_partial(in_.get_size(), Some(lo2), Some(hi2));
    if indoub.exceeds_const_precision() {
        return false;
    }
    let Some(existop) =
        SplitVarnode::prepare_binary_op(data, &mut outdoub, &mut in_, &mut indoub)
    else {
        return false;
    };
    let opc = data.op(lop).code();
    SplitVarnode::create_binary_op(data, &mut outdoub, &mut in_, &mut indoub, existop, opc);
    true
}


/// Ghidra `Equal1Form::applyRule` (double.cc): the BRANCHING equality — the compiler tests the high
/// halves, and only if they match tests the low halves. Two nestings are accepted (hi first, or lo
/// first); the outer CBRANCH becomes a whole-width comparison and the inner one is made
/// unconditional so it always reaches its original TRUE block.
fn equal1_form_apply_rule(
    data: &mut Funcdata,
    i: &SplitVarnode,
    hop: OpId,
    workishi: bool,
) -> bool {
    if !workishi || !i.has_both_pieces() {
        return false;
    }
    let (hi1, lo1) = (i.hi.unwrap(), i.lo.unwrap());
    let Some(hi1slot) = (0..data.op(hop).num_inputs()).find(|&k| data.op(hop).input(k) == Some(hi1))
    else {
        return false;
    };
    let Some(hi2) = data.op(hop).input(1 - hi1slot) else { return false };
    let notequalformhi = data.op(hop).code() == OpCode::IntNotequal;
    let Some(hi_out) = data.op(hop).output else { return false };

    for loop_ in data.vn(lo1).descend.clone() {
        let notequalformlo = match data.op(loop_).code() {
            OpCode::IntEqual => false,
            OpCode::IntNotequal => true,
            _ => continue,
        };
        let Some(lo1slot) =
            (0..data.op(loop_).num_inputs()).find(|&k| data.op(loop_).input(k) == Some(lo1))
        else {
            continue;
        };
        let Some(lo2) = data.op(loop_).input(1 - lo1slot) else { continue };
        let Some(lo_out) = data.op(loop_).output else { continue };
        for hibool in data.vn(hi_out).descend.clone() {
            for lobool in data.vn(lo_out).descend.clone() {
                let mut in2 = SplitVarnode::default();
                in2.init_partial(i.get_size(), Some(lo2), Some(hi2));
                if in2.exceeds_const_precision() {
                    continue;
                }
                if data.op(hibool).code() != OpCode::Cbranch
                    || data.op(lobool).code() != OpCode::Cbranch
                {
                    continue;
                }
                let Some((hibooltrue, hiboolfalse)) =
                    SplitVarnode::get_true_false(data, hibool, notequalformhi)
                else {
                    continue;
                };
                let Some((lobooltrue, loboolfalse)) =
                    SplitVarnode::get_true_false(data, lobool, notequalformlo)
                else {
                    continue;
                };
                let mut in1 = i.clone();
                if Some(hibooltrue) == data.op(lobool).parent
                    && hiboolfalse == loboolfalse
                    && SplitVarnode::otherwise_empty(data, lobool)
                {
                    // hi is checked first, then lo.
                    if SplitVarnode::prepare_bool_op(data, &mut in1, &mut in2, hibool) {
                        let opc = if notequalformhi { OpCode::IntNotequal } else { OpCode::IntEqual };
                        SplitVarnode::create_bool_op(data, hibool, &mut in1, &mut in2, opc);
                        // Make lobool always take the original TRUE block.
                        let k = data.new_const(1, if notequalformlo { 0 } else { 1 });
                        data.op_set_input(lobool, 1, k);
                        return true;
                    }
                } else if Some(lobooltrue) == data.op(hibool).parent
                    && hiboolfalse == loboolfalse
                    && SplitVarnode::otherwise_empty(data, hibool)
                {
                    // lo is checked first, then hi.
                    if SplitVarnode::prepare_bool_op(data, &mut in1, &mut in2, lobool) {
                        let opc = if notequalformlo { OpCode::IntNotequal } else { OpCode::IntEqual };
                        SplitVarnode::create_bool_op(data, lobool, &mut in1, &mut in2, opc);
                        let k = data.new_const(1, if notequalformhi { 0 } else { 1 });
                        data.op_set_input(hibool, 1, k);
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Ghidra `Equal2Form::applyRule` (double.cc): the BOOLEAN equality — `(hi1==hi2) && (lo1==lo2)`
/// (or `||` of the `!=` form) is one whole-width comparison. A mixed constant/non-constant pair is
/// refused; two constants are folded into one double-precision constant.
fn equal2_form_apply_rule(
    data: &mut Funcdata,
    i: &SplitVarnode,
    op: OpId,
    workishi: bool,
) -> bool {
    if !workishi || !i.has_both_pieces() {
        return false;
    }
    let (hi1, lo1) = (i.hi.unwrap(), i.lo.unwrap());
    let eq_code = data.op(op).code();
    let Some(hi1slot) = (0..data.op(op).num_inputs()).find(|&k| data.op(op).input(k) == Some(hi1))
    else {
        return false;
    };
    let Some(hi2) = data.op(op).input(1 - hi1slot) else { return false };
    let Some(outvn) = data.op(op).output else { return false };
    for bool_and_or in data.vn(outvn).descend.clone() {
        let code = data.op(bool_and_or).code();
        if eq_code == OpCode::IntEqual && code != OpCode::BoolAnd {
            continue;
        }
        if eq_code == OpCode::IntNotequal && code != OpCode::BoolOr {
            continue;
        }
        let Some(slot) = (0..data.op(bool_and_or).num_inputs())
            .find(|&k| data.op(bool_and_or).input(k) == Some(outvn))
        else {
            continue;
        };
        let Some(othervn) = data.op(bool_and_or).input(1 - slot) else { continue };
        if !data.vn(othervn).is_written() {
            continue;
        }
        let equal_lo = data.vn(othervn).def.unwrap();
        if data.op(equal_lo).code() != eq_code {
            continue;
        }
        let lo2 = if data.op(equal_lo).input(0) == Some(lo1) {
            data.op(equal_lo).input(1)
        } else if data.op(equal_lo).input(1) == Some(lo1) {
            data.op(equal_lo).input(0)
        } else {
            continue;
        };
        let Some(lo2) = lo2 else { continue };
        // Ghidra `Equal2Form::replace`.
        let mut in_ = i.clone();
        let mut param2 = SplitVarnode::default();
        let hi2c = data.vn(hi2).is_constant();
        let lo2c = data.vn(lo2).is_constant();
        if hi2c && lo2c {
            let val = (data.vn(hi2).constant_value() << (8 * data.vn(lo1).size))
                | data.vn(lo2).constant_value();
            param2.init_partial_const(i.get_size(), val);
        } else if hi2c || lo2c {
            continue; // some kind of mixed form
        } else {
            param2.init_partial(i.get_size(), Some(lo2), Some(hi2));
        }
        if !SplitVarnode::prepare_bool_op(data, &mut in_, &mut param2, bool_and_or) {
            continue;
        }
        if param2.exceeds_const_precision() {
            continue;
        }
        SplitVarnode::replace_bool_op(data, bool_and_or, &mut in_, &mut param2, eq_code);
        return true;
    }
    false
}

/// Ghidra `Equal3Form::applyRule` (double.cc): `(hi & lo) == -1` tests both halves for all-ones at
/// once, so it is a whole-width comparison against -1.
fn equal3_form_apply_rule(
    data: &mut Funcdata,
    i: &SplitVarnode,
    op: OpId,
    workishi: bool,
) -> bool {
    if !workishi || !i.has_both_pieces() {
        return false;
    }
    let (hi, lo) = (i.hi.unwrap(), i.lo.unwrap());
    if data.op(op).code() != OpCode::IntAnd {
        return false;
    }
    let Some(hislot) = (0..data.op(op).num_inputs()).find(|&k| data.op(op).input(k) == Some(hi))
    else {
        return false;
    };
    if data.op(op).input(1 - hislot) != Some(lo) {
        return false; // hi and lo must be ANDed together
    }
    let Some(and_out) = data.op(op).output else { return false };
    let Some(compareop) = data.lone_descend(and_out) else { return false };
    let cc = data.op(compareop).code();
    if cc != OpCode::IntEqual && cc != OpCode::IntNotequal {
        return false;
    }
    let Some(smallc) = data.op(compareop).input(1) else { return false };
    if !data.vn(smallc).is_constant() {
        return false;
    }
    if data.vn(smallc).constant_value() != super::nzmask::calc_mask(data.vn(lo).size) {
        return false;
    }
    let mut in_ = i.clone();
    let mut in2 = SplitVarnode::from_constant(
        i.get_size(),
        super::nzmask::calc_mask(i.get_size()),
    ); // the -1 value
    if in2.exceeds_const_precision() {
        return false;
    }
    if !SplitVarnode::prepare_bool_op(data, &mut in_, &mut in2, compareop) {
        return false;
    }
    SplitVarnode::replace_bool_op(data, compareop, &mut in_, &mut in2, cc);
    true
}


/// What a shift Form recovers: the result pair, the shift amount, and the whole-width opcode.
struct ShiftMatch {
    reshi: VarnodeId,
    reslo: VarnodeId,
    salo: VarnodeId,
    opc: OpCode,
}

/// Ghidra `ShiftForm::verifyShiftAmount` (double.cc): the three shift amounts must be constants,
/// the low and high shifts equal, and the middle shift the complement within one half's width.
fn shift_form_verify_amount(
    data: &Funcdata,
    lo: VarnodeId,
    salo: VarnodeId,
    samid: VarnodeId,
    sahi: VarnodeId,
) -> bool {
    if !data.vn(salo).is_constant()
        || !data.vn(samid).is_constant()
        || !data.vn(sahi).is_constant()
    {
        return false;
    }
    let val = data.vn(salo).constant_value();
    if val != data.vn(sahi).constant_value() {
        return false;
    }
    let width = 8 * data.vn(lo).size as u64;
    if val >= width {
        return false; // so big we would not use this form
    }
    data.vn(samid).constant_value() == width - val
}

/// Ghidra `ShiftForm::mapLeft` (double.cc): from the result pair, recover the three shifts of a
/// double-precision LEFT shift — `reslo = lo << k`, `reshi = (hi << k) | (lo >> (w-k))`.
fn shift_form_map_left(
    data: &Funcdata,
    hi: VarnodeId,
    lo: VarnodeId,
    reshi: VarnodeId,
    reslo: VarnodeId,
) -> Option<ShiftMatch> {
    if !data.vn(reslo).is_written() || !data.vn(reshi).is_written() {
        return None;
    }
    let loshift = data.vn(reslo).def.unwrap();
    let opc = data.op(loshift).code();
    if opc != OpCode::IntLeft {
        return None;
    }
    let orop = data.vn(reshi).def.unwrap();
    if !matches!(data.op(orop).code(), OpCode::IntOr | OpCode::IntXor | OpCode::IntAdd) {
        return None;
    }
    let (mut midlo, mut midhi) = (data.op(orop).input(0)?, data.op(orop).input(1)?);
    if !data.vn(midlo).is_written() || !data.vn(midhi).is_written() {
        return None;
    }
    if data.op(data.vn(midhi).def.unwrap()).code() != OpCode::IntLeft {
        std::mem::swap(&mut midhi, &mut midlo);
    }
    let midshift = data.vn(midlo).def?;
    if data.op(midshift).code() != OpCode::IntRight {
        return None; // must be an UNSIGNED right shift
    }
    let hishift = data.vn(midhi).def?;
    if data.op(hishift).code() != OpCode::IntLeft {
        return None;
    }
    if data.op(loshift).input(0) != Some(lo)
        || data.op(hishift).input(0) != Some(hi)
        || data.op(midshift).input(0) != Some(lo)
    {
        return None;
    }
    let salo = data.op(loshift).input(1)?;
    let sahi = data.op(hishift).input(1)?;
    let samid = data.op(midshift).input(1)?;
    if !shift_form_verify_amount(data, lo, salo, samid, sahi) {
        return None;
    }
    Some(ShiftMatch { reshi, reslo, salo, opc })
}

/// Ghidra `ShiftForm::mapRight` (double.cc): the same for a RIGHT shift — `reshi = hi >> k`
/// (signed or unsigned), `reslo = (lo >> k) | (hi << (w-k))`.
fn shift_form_map_right(
    data: &Funcdata,
    hi: VarnodeId,
    lo: VarnodeId,
    reshi: VarnodeId,
    reslo: VarnodeId,
) -> Option<ShiftMatch> {
    if !data.vn(reslo).is_written() || !data.vn(reshi).is_written() {
        return None;
    }
    let hishift = data.vn(reshi).def.unwrap();
    let opc = data.op(hishift).code();
    if opc != OpCode::IntRight && opc != OpCode::IntSright {
        return None;
    }
    let orop = data.vn(reslo).def.unwrap();
    if !matches!(data.op(orop).code(), OpCode::IntOr | OpCode::IntXor | OpCode::IntAdd) {
        return None;
    }
    let (mut midlo, mut midhi) = (data.op(orop).input(0)?, data.op(orop).input(1)?);
    if !data.vn(midlo).is_written() || !data.vn(midhi).is_written() {
        return None;
    }
    if data.op(data.vn(midlo).def.unwrap()).code() != OpCode::IntRight {
        std::mem::swap(&mut midhi, &mut midlo);
    }
    let midshift = data.vn(midhi).def?;
    if data.op(midshift).code() != OpCode::IntLeft {
        return None;
    }
    let loshift = data.vn(midlo).def?;
    if data.op(loshift).code() != OpCode::IntRight {
        return None; // must be an UNSIGNED right shift
    }
    if data.op(loshift).input(0) != Some(lo)
        || data.op(hishift).input(0) != Some(hi)
        || data.op(midshift).input(0) != Some(hi)
    {
        return None;
    }
    let salo = data.op(loshift).input(1)?;
    let sahi = data.op(hishift).input(1)?;
    let samid = data.op(midshift).input(1)?;
    if !shift_form_verify_amount(data, lo, salo, samid, sahi) {
        return None;
    }
    Some(ShiftMatch { reshi, reslo, salo, opc })
}

/// Ghidra `ShiftForm::applyRuleLeft` / `applyRuleRight` (double.cc). The left form is driven from
/// the LOW half's shift, the right form from the HIGH half's — which is why they take opposite
/// `workishi` senses.
fn shift_form_apply_rule(
    data: &mut Funcdata,
    i: &SplitVarnode,
    op: OpId,
    workishi: bool,
    left: bool,
) -> bool {
    if workishi == left || !i.has_both_pieces() {
        return false;
    }
    let (hi, lo) = (i.hi.unwrap(), i.lo.unwrap());
    let start = if left { hi } else { lo };
    let want = if left { OpCode::IntLeft } else { OpCode::IntRight };
    let Some(res_from_op) = data.op(op).output else { return false };
    let mut found = None;
    'outer: for shift in data.vn(start).descend.clone() {
        if data.op(shift).code() != want {
            continue;
        }
        let Some(outvn) = data.op(shift).output else { continue };
        for midshift in data.vn(outvn).descend.clone() {
            let Some(tmpvn) = data.op(midshift).output else { continue };
            let m = if left {
                shift_form_map_left(data, hi, lo, tmpvn, res_from_op)
            } else {
                shift_form_map_right(data, hi, lo, res_from_op, tmpvn)
            };
            if let Some(m) = m {
                found = Some(m);
                break 'outer;
            }
        }
    }
    let Some(m) = found else { return false };
    let mut in_ = i.clone();
    let mut out = SplitVarnode::default();
    out.init_partial(in_.get_size(), Some(m.reslo), Some(m.reshi));
    let Some(existop) = SplitVarnode::prepare_shift_op(data, &mut out, &mut in_) else {
        return false;
    };
    SplitVarnode::create_shift_op(data, &mut out, &mut in_, m.salo, existop, m.opc);
    true
}


/// Ghidra `PhiForm::applyRule` (double.cc): two MULTIEQUALs in the same block merging the halves of
/// the same pairs, slot for slot, are one whole-width MULTIEQUAL.
fn phi_form_apply_rule(
    data: &mut Funcdata,
    i: &SplitVarnode,
    hphi: OpId,
    workishi: bool,
) -> bool {
    if !workishi || !i.has_both_pieces() {
        return false;
    }
    let (hibase, lobase) = (i.hi.unwrap(), i.lo.unwrap());
    let Some(inslot) =
        (0..data.op(hphi).num_inputs()).find(|&k| data.op(hphi).input(k) == Some(hibase))
    else {
        return false;
    };
    let Some(hi_out) = data.op(hphi).output else { return false };
    if data.vn(hi_out).descend.is_empty() {
        return false;
    }
    let blbase = data.op(hphi).parent;
    let mut lophi = None;
    for cand in data.vn(lobase).descend.clone() {
        if data.op(cand).code() != OpCode::Multiequal {
            continue;
        }
        if data.op(cand).parent != blbase {
            continue;
        }
        if data.op(cand).input(inslot) != Some(lobase) {
            continue;
        }
        lophi = Some(cand);
        break;
    }
    let Some(lophi) = lophi else { return false };
    let numin = data.op(hphi).num_inputs();
    if data.op(lophi).num_inputs() != numin {
        return false;
    }
    let mut inlist = Vec::with_capacity(numin);
    for j in 0..numin {
        let (Some(vhi), Some(vlo)) = (data.op(hphi).input(j), data.op(lophi).input(j)) else {
            return false;
        };
        inlist.push(SplitVarnode::from_pieces(data, vlo, vhi));
    }
    let Some(lo_out) = data.op(lophi).output else { return false };
    let mut outvn = SplitVarnode::default();
    outvn.init_partial(i.get_size(), Some(lo_out), Some(hi_out));
    let Some(existop) = SplitVarnode::prepare_phi_op(data, &mut outvn, &mut inlist) else {
        return false;
    };
    SplitVarnode::create_phi_op(data, &mut outvn, &mut inlist, existop);
    true
}

/// Ghidra `IndirectForm::applyRule` (double.cc): two INDIRECTs guarding the same affector, one per
/// half, are one whole-width INDIRECT. Neither result may live in a temporary, and if either is
/// address-tied both must be, in contiguous storage.
fn indirect_form_apply_rule(
    data: &mut Funcdata,
    i: &SplitVarnode,
    ind: OpId,
    workishi: bool,
) -> bool {
    if !workishi || !i.has_both_pieces() {
        return false;
    }
    let (_hi, lo) = (i.hi.unwrap(), i.lo.unwrap());
    let Some(affector) = data.op(ind).guarded_op() else { return false };
    if data.op(affector).is_dead() {
        return false;
    }
    let Some(reshi) = data.op(ind).output else { return false };
    let internal = |data: &Funcdata, v: VarnodeId| {
        data.spaces.get(data.vn(v).loc.space).kind == super::space::SpaceKind::Internal
    };
    if internal(data, reshi) {
        return false; // indirect must not be through a temporary
    }
    let mut reslo = None;
    for indlo in data.vn(lo).descend.clone() {
        if data.op(indlo).code() != OpCode::Indirect {
            continue;
        }
        if data.op(indlo).guarded_op() != Some(affector) {
            continue; // hi and lo must be affected by the same op
        }
        let Some(r) = data.op(indlo).output else { continue };
        if internal(data, r) {
            return false;
        }
        if data.vn(r).is_addrtied() || data.vn(reshi).is_addrtied() {
            // If one piece is address-tied the other must be too, contiguously.
            if is_addr_tied_contiguous(data, r, reshi).is_none() {
                return false;
            }
        }
        reslo = Some(r);
        break;
    }
    let Some(reslo) = reslo else { return false };
    let mut in_ = i.clone();
    let mut outvn = SplitVarnode::default();
    outvn.init_partial(i.get_size(), Some(reslo), Some(reshi));
    if !SplitVarnode::prepare_indirect_op(data, &mut in_, affector) {
        return false;
    }
    SplitVarnode::replace_indirect_op(data, &mut outvn, &mut in_, affector)
}


/// Ghidra `CopyForceForm::applyRule` (double.cc): two address-forced COPYs of the halves into
/// contiguous storage are one whole-width COPY. The return-form (a global held past a RETURN) adds
/// requirements: each half must have exactly one reader, and if the input whole is not already at
/// the output address, both halves must come from COPYs in one block.
fn copy_force_form_apply_rule(
    data: &mut Funcdata,
    i: &SplitVarnode,
    cpy: OpId,
    workishi: bool,
) -> bool {
    if !workishi || !i.has_both_pieces() {
        return false;
    }
    let (h, l) = (i.hi.unwrap(), i.lo.unwrap());
    let Some(w) = i.whole else { return false };
    if data.op(cpy).input(0) != Some(h) {
        return false;
    }
    let Some(reshi) = data.op(cpy).output else { return false };
    if !data.vn(reshi).is_addr_force() || !data.vn(reshi).descend.is_empty() {
        return false;
    }
    for copylo in data.vn(l).descend.clone() {
        if data.op(copylo).code() != OpCode::Copy
            || data.op(copylo).parent != data.op(cpy).parent
        {
            continue;
        }
        let Some(reslo) = data.op(copylo).output else { continue };
        if !data.vn(reslo).is_addr_force() || !data.vn(reslo).descend.is_empty() {
            continue;
        }
        // The output MUST be contiguous storage.
        let Some(addr_out) = is_addr_tied_contiguous(data, reslo, reshi) else { continue };
        if data.op(cpy).is_return_copy() {
            if data.lone_descend(h).is_none() || data.lone_descend(l).is_none() {
                continue;
            }
            if data.vn(w).loc != addr_out {
                // Unless there are additional COPYs from the same basic block.
                if !data.vn(h).is_written() || !data.vn(l).is_written() {
                    continue;
                }
                let other_lo = data.vn(l).def.unwrap();
                let other_hi = data.vn(h).def.unwrap();
                if data.op(other_lo).code() != OpCode::Copy
                    || data.op(other_hi).code() != OpCode::Copy
                {
                    continue;
                }
                if data.op(other_lo).parent != data.op(other_hi).parent {
                    continue;
                }
            }
        }
        SplitVarnode::replace_copy_force(data, addr_out, i, copylo, cpy);
        return true;
    }
    false
}

/// Ghidra `LessConstForm::applyRule` (double.cc): a comparison of the HIGH half against a constant
/// is a whole-width comparison against that constant extended with all-ones or all-zeros, depending
/// on which side the value is on and whether the test is `<` or `<=`.
///
/// Ghidra guards this with "only if it directly affects a branch", because applying it more widely
/// would interfere with the less/equal rules.
fn less_const_form_apply_rule(
    data: &mut Funcdata,
    i: &SplitVarnode,
    op: OpId,
    workishi: bool,
) -> bool {
    if !workishi {
        return false;
    }
    let Some(vn) = i.hi else { return false }; // the lo part is not necessarily needed
    let Some(inslot) = (0..data.op(op).num_inputs()).find(|&k| data.op(op).input(k) == Some(vn))
    else {
        return false;
    };
    let Some(cvn) = data.op(op).input(1 - inslot) else { return false };
    if !data.vn(cvn).is_constant() {
        return false;
    }
    let losize = i.get_size() - data.vn(vn).size;
    let opc = data.op(op).code();
    let hilessequalform = opc == OpCode::IntSlessequal || opc == OpCode::IntLessequal;
    let mut val = data.vn(cvn).constant_value() << (8 * losize);
    if hilessequalform != (inslot == 1) {
        val |= super::nzmask::calc_mask(losize);
    }
    // Only applied when it directly affects a branch.
    let Some(out) = data.op(op).output else { return false };
    let Some(desc) = data.lone_descend(out) else { return false };
    if data.op(desc).code() != OpCode::Cbranch {
        return false;
    }
    let mut constin = SplitVarnode::from_constant(i.get_size(), val);
    if constin.exceeds_const_precision() {
        return false;
    }
    let mut in_ = i.clone();
    if inslot == 0 {
        if SplitVarnode::prepare_bool_op(data, &mut in_, &mut constin, op) {
            SplitVarnode::replace_bool_op(data, op, &mut in_, &mut constin, opc);
            return true;
        }
    } else if SplitVarnode::prepare_bool_op(data, &mut constin, &mut in_, op) {
        SplitVarnode::replace_bool_op(data, op, &mut constin, &mut in_, opc);
        return true;
    }
    false
}


/// What `MultForm`'s mapping recovers.
struct MultMatch {
    hi2: Option<VarnodeId>,
    lo2: VarnodeId,
    reshi: VarnodeId,
    reslo: VarnodeId,
}

/// Ghidra `MultForm::zextOf` (double.cc:2870): `big` is some form of zero extension of `small` —
/// a real INT_ZEXT, an AND-mask of the whole `small` was truncated from, or equal constants.
fn mult_form_zext_of(data: &Funcdata, big: VarnodeId, small: VarnodeId) -> bool {
    if data.vn(small).is_constant() {
        return data.vn(big).is_constant()
            && data.vn(big).constant_value() == data.vn(small).constant_value();
    }
    if !data.vn(big).is_written() {
        return false;
    }
    let op = data.vn(big).def.unwrap();
    match data.op(op).code() {
        OpCode::IntZext => data.op(op).input(0) == Some(small),
        OpCode::IntAnd => {
            let Some(c) = data.op(op).input(1) else { return false };
            if !data.vn(c).is_constant()
                || data.vn(c).constant_value() != super::nzmask::calc_mask(data.vn(small).size)
            {
                return false;
            }
            let Some(whole) = data.op(op).input(0) else { return false };
            if !data.vn(small).is_written() {
                return false;
            }
            let sub = data.vn(small).def.unwrap();
            data.op(sub).code() == OpCode::Subpiece && data.op(sub).input(0) == Some(whole)
        }
        _ => false,
    }
}

/// The intermediate state `MultForm`'s `mapResHi` recovers.
struct MultHi {
    multhi1: OpId,
    multhi2: Option<OpId>,
    subhi: OpId,
    midtmp: VarnodeId,
    lo1zext: VarnodeId,
    lo2zext: VarnodeId,
}

/// Ghidra `MultForm::mapResHi` (double.cc): the high half of a double-precision multiply is
/// `hi1*lo2 + hi2*lo1 + (lo1*lo2 >> w)`. `small_const` is the variant where `hi2` is an implied
/// zero, so only `hi1*lo2` appears.
fn mult_form_map_res_hi(data: &Funcdata, rhi: VarnodeId, small_const: bool) -> Option<MultHi> {
    if !data.vn(rhi).is_written() {
        return None;
    }
    let add1 = data.vn(rhi).def.unwrap();
    if data.op(add1).code() != OpCode::IntAdd {
        return None;
    }
    let (ad1, ad2) = (data.op(add1).input(0)?, data.op(add1).input(1)?);
    if !data.vn(ad1).is_written() || !data.vn(ad2).is_written() {
        return None;
    }
    let (multhi1, multhi2, subhi);
    if small_const {
        let mut m1 = data.vn(ad1).def.unwrap();
        let sh;
        if data.op(m1).code() != OpCode::IntMult {
            sh = m1;
            m1 = data.vn(ad2).def.unwrap();
        } else {
            sh = data.vn(ad2).def.unwrap();
        }
        if data.op(m1).code() != OpCode::IntMult || data.op(sh).code() != OpCode::Subpiece {
            return None;
        }
        multhi1 = m1;
        multhi2 = None;
        subhi = sh;
    } else {
        let mut a1 = ad1;
        let mut a2 = ad2;
        let a3;
        let mut add2 = data.vn(a1).def.unwrap();
        if data.op(add2).code() == OpCode::IntAdd {
            a1 = data.op(add2).input(0)?;
            a3 = data.op(add2).input(1)?;
        } else {
            add2 = data.vn(a2).def.unwrap();
            if data.op(add2).code() != OpCode::IntAdd {
                return None;
            }
            a2 = data.op(add2).input(0)?;
            a3 = data.op(add2).input(1)?;
        }
        if !data.vn(a1).is_written() || !data.vn(a2).is_written() || !data.vn(a3).is_written() {
            return None;
        }
        let mut sh = data.vn(a1).def.unwrap();
        let (m1, m2);
        if data.op(sh).code() == OpCode::Subpiece {
            m1 = data.vn(a2).def.unwrap();
            m2 = data.vn(a3).def.unwrap();
        } else {
            sh = data.vn(a2).def.unwrap();
            if data.op(sh).code() == OpCode::Subpiece {
                m1 = data.vn(a1).def.unwrap();
                m2 = data.vn(a3).def.unwrap();
            } else {
                sh = data.vn(a3).def.unwrap();
                if data.op(sh).code() != OpCode::Subpiece {
                    return None;
                }
                m1 = data.vn(a1).def.unwrap();
                m2 = data.vn(a2).def.unwrap();
            }
        }
        if data.op(m1).code() != OpCode::IntMult || data.op(m2).code() != OpCode::IntMult {
            return None;
        }
        multhi1 = m1;
        multhi2 = Some(m2);
        subhi = sh;
    }
    let midtmp = data.op(subhi).input(0)?;
    if !data.vn(midtmp).is_written() {
        return None;
    }
    let multlo = data.vn(midtmp).def.unwrap();
    if data.op(multlo).code() != OpCode::IntMult {
        return None;
    }
    let lo1zext = data.op(multlo).input(0)?;
    let lo2zext = data.op(multlo).input(1)?;
    Some(MultHi { multhi1, multhi2, subhi, midtmp, lo1zext, lo2zext })
}

/// Ghidra `MultForm::findResLo` (double.cc): the low half is a zero-offset SUBPIECE of the
/// `lo1*lo2` product — or, when the compiler computed that product twice, a separate INT_MULT.
fn mult_form_find_res_lo(
    data: &Funcdata,
    m: &MultHi,
    lo1: VarnodeId,
    lo2: VarnodeId,
) -> Option<VarnodeId> {
    for op in data.vn(m.midtmp).descend.clone() {
        if data.op(op).code() != OpCode::Subpiece {
            continue;
        }
        if data.op(op).input(1).map(|v| data.vn(v).constant_value()) != Some(0) {
            continue; // must grab the low bytes
        }
        let Some(reslo) = data.op(op).output else { continue };
        if data.vn(reslo).size != data.vn(lo1).size {
            continue;
        }
        return Some(reslo);
    }
    // Separate multiplies of lo1*lo2 may have been used for reshi and reslo.
    for op in data.vn(lo1).descend.clone() {
        if data.op(op).code() != OpCode::IntMult {
            continue;
        }
        let (vn1, vn2) = (data.op(op).input(0)?, data.op(op).input(1)?);
        if data.vn(lo2).is_constant() {
            let want = data.vn(lo2).constant_value();
            let ok1 = data.vn(vn1).is_constant() && data.vn(vn1).constant_value() == want;
            let ok2 = data.vn(vn2).is_constant() && data.vn(vn2).constant_value() == want;
            if !ok1 && !ok2 {
                continue;
            }
        } else if vn1 != lo2 && vn2 != lo2 {
            continue;
        }
        return data.op(op).output;
    }
    None
}

/// Ghidra `MultForm::mapFromIn` / `mapFromInSmallConst` (double.cc).
fn mult_form_map_from_in(
    data: &Funcdata,
    hi1: VarnodeId,
    lo1: VarnodeId,
    rhi: VarnodeId,
    small_const: bool,
) -> Option<MultMatch> {
    let m = mult_form_map_res_hi(data, rhi, small_const)?;
    let (hi2, lo2);
    if small_const {
        // Ghidra `findLoFromInSmallConst`: multhi1 is hi1*lo2 with lo2 constant, hi2 implied zero.
        let (vn1, vn2) = (data.op(m.multhi1).input(0)?, data.op(m.multhi1).input(1)?);
        let l2 = if vn1 == hi1 {
            vn2
        } else if vn2 == hi1 {
            vn1
        } else {
            return None;
        };
        if !data.vn(l2).is_constant() {
            return None;
        }
        hi2 = None;
        lo2 = l2;
    } else {
        // Ghidra `findLoFromIn`: normalize so multhi1 contains lo1, then multhi2 holds hi1 and lo2.
        let mut multhi1 = m.multhi1;
        let mut multhi2 = m.multhi2?;
        let (mut vn1, mut vn2) = (data.op(multhi1).input(0)?, data.op(multhi1).input(1)?);
        if vn1 != lo1 && vn2 != lo1 {
            std::mem::swap(&mut multhi1, &mut multhi2);
            vn1 = data.op(multhi1).input(0)?;
            vn2 = data.op(multhi1).input(1)?;
        }
        let h2 = if vn1 == lo1 {
            vn2
        } else if vn2 == lo1 {
            vn1
        } else {
            return None;
        };
        let (w1, w2) = (data.op(multhi2).input(0)?, data.op(multhi2).input(1)?);
        let l2 = if w1 == hi1 {
            w2
        } else if w2 == hi1 {
            w1
        } else {
            return None;
        };
        hi2 = Some(h2);
        lo2 = l2;
    }
    // Ghidra `verifyLo`: midtmp must be the zero-extended low product.
    if data.op(m.subhi).input(1).map(|v| data.vn(v).constant_value())
        != Some(data.vn(lo1).size as u64)
    {
        return None;
    }
    let ok = (mult_form_zext_of(data, m.lo1zext, lo1) && mult_form_zext_of(data, m.lo2zext, lo2))
        || (mult_form_zext_of(data, m.lo1zext, lo2) && mult_form_zext_of(data, m.lo2zext, lo1));
    if !ok {
        return None;
    }
    let reslo = mult_form_find_res_lo(data, &m, lo1, lo2)?;
    Some(MultMatch { hi2, lo2, reshi: rhi, reslo })
}

/// Ghidra `MultForm::applyRule` (double.cc): the piece-wise 64-bit multiply — two or three partial
/// products summed with the carry out of the low product — is one whole-width INT_MULT.
fn mult_form_apply_rule(
    data: &mut Funcdata,
    i: &SplitVarnode,
    hop: OpId,
    workishi: bool,
) -> bool {
    if !workishi || !i.has_both_pieces() {
        return false;
    }
    let (hi1, lo1) = (i.hi.unwrap(), i.lo.unwrap());
    let Some(hop_out) = data.op(hop).output else { return false };
    let mut found = None;
    'outer: for add1 in data.vn(hop_out).descend.clone() {
        if data.op(add1).code() != OpCode::IntAdd {
            continue;
        }
        let Some(add1_out) = data.op(add1).output else { continue };
        for add2 in data.vn(add1_out).descend.clone() {
            if data.op(add2).code() != OpCode::IntAdd {
                continue;
            }
            let Some(add2_out) = data.op(add2).output else { continue };
            if let Some(m) = mult_form_map_from_in(data, hi1, lo1, add2_out, false) {
                found = Some(m);
                break 'outer;
            }
        }
        if let Some(m) = mult_form_map_from_in(data, hi1, lo1, add1_out, false) {
            found = Some(m);
            break;
        }
        if let Some(m) = mult_form_map_from_in(data, hi1, lo1, add1_out, true) {
            found = Some(m);
            break;
        }
    }
    let Some(m) = found else { return false };
    let mut in_ = i.clone();
    let mut outdoub = SplitVarnode::default();
    outdoub.init_partial(i.get_size(), Some(m.reslo), Some(m.reshi));
    let mut in2 = SplitVarnode::default();
    in2.init_partial(i.get_size(), Some(m.lo2), m.hi2);
    if in2.exceeds_const_precision() {
        return false;
    }
    let Some(existop) = SplitVarnode::prepare_binary_op(data, &mut outdoub, &mut in_, &mut in2)
    else {
        return false;
    };
    SplitVarnode::create_binary_op(data, &mut outdoub, &mut in_, &mut in2, existop, OpCode::IntMult);
    true
}


/// Ghidra `LessThreeWay` (double.cc): the THREE-WAY comparison a compiler emits for a
/// double-precision `<` — test the high halves, then (if equal) the low halves, across three basic
/// blocks. Recognizing it collapses all three branches into one whole-width comparison.
///
/// The state is large because each of the three tests can be spelled several ways (`<`/`<=`,
/// signed/unsigned, either operand order, constant or not), and the normalization steps rewrite all
/// of them into one canonical form before the shapes are compared.
#[derive(Default)]
struct LessThreeWay {
    hilessbl: Option<BlockId>,
    lolessbl: Option<BlockId>,
    hieqbl: Option<BlockId>,
    hilessbool: Option<OpId>,
    lolessbool: Option<OpId>,
    hieqbool: Option<OpId>,
    hiless: Option<OpId>,
    hiequal: Option<OpId>,
    loless: Option<OpId>,
    vnhil1: Option<VarnodeId>,
    vnhil2: Option<VarnodeId>,
    vnhie1: Option<VarnodeId>,
    vnhie2: Option<VarnodeId>,
    vnlo1: Option<VarnodeId>,
    vnlo2: Option<VarnodeId>,
    hi2: Option<VarnodeId>,
    lo2: Option<VarnodeId>,
    hislot: usize,
    hiflip: bool,
    equalflip: bool,
    loflip: bool,
    lolessiszerocomp: bool,
    lolessequalform: bool,
    hilessequalform: bool,
    signcompare: bool,
    midlessform: bool,
    midlessequal: bool,
    midsigncompare: bool,
    hiconstform: bool,
    midconstform: bool,
    loconstform: bool,
    hival: u64,
    midval: u64,
    loval: u64,
    /// Ghidra leaves `finalopc` uninitialized until `setOpCode`; INT_LESS is the natural
    /// placeholder since every path assigns it before use.
    finalopc: Option<OpCode>,
}

impl LessThreeWay {
    /// Ghidra `mapBlocksFromLow`: from the block holding the LOW test, walk back to the equality
    /// block and the HIGH test block.
    fn map_blocks_from_low(&mut self, data: &Funcdata, lobl: BlockId) -> bool {
        self.lolessbl = Some(lobl);
        if data.block(lobl).in_edges.len() != 1 || data.block(lobl).out_edges.len() != 2 {
            return false;
        }
        let hieqbl = data.block(lobl).in_edges[0];
        if data.block(hieqbl).in_edges.len() != 1 || data.block(hieqbl).out_edges.len() != 2 {
            return false;
        }
        let hilessbl = data.block(hieqbl).in_edges[0];
        if data.block(hilessbl).out_edges.len() != 2 {
            return false;
        }
        self.hieqbl = Some(hieqbl);
        self.hilessbl = Some(hilessbl);
        true
    }

    /// Ghidra `mapOpsFromBlocks`: each block must end in a CBRANCH; classify the three comparisons.
    fn map_ops_from_blocks(&mut self, data: &Funcdata) -> bool {
        let last = |bl: Option<BlockId>| bl.and_then(|b| data.block(b).ops.last().copied());
        let (Some(lolessbool), Some(hieqbool), Some(hilessbool)) =
            (last(self.lolessbl), last(self.hieqbl), last(self.hilessbl))
        else {
            return false;
        };
        for op in [lolessbool, hieqbool, hilessbool] {
            if data.op(op).code() != OpCode::Cbranch {
                return false;
            }
        }
        self.lolessbool = Some(lolessbool);
        self.hieqbool = Some(hieqbool);
        self.hilessbool = Some(hilessbool);
        self.hiflip = false;
        self.equalflip = false;
        self.loflip = false;
        self.midlessform = false;
        self.lolessiszerocomp = false;

        let cond = |op: OpId| -> Option<OpId> {
            let v = data.op(op).input(1)?;
            if !data.vn(v).is_written() {
                return None;
            }
            data.vn(v).def
        };
        let Some(hiequal) = cond(hieqbool) else { return false };
        match data.op(hiequal).code() {
            OpCode::IntEqual | OpCode::IntNotequal => self.midlessform = false,
            OpCode::IntLess => {
                self.midlessequal = false;
                self.midsigncompare = false;
                self.midlessform = true;
            }
            OpCode::IntLessequal => {
                self.midlessequal = true;
                self.midsigncompare = false;
                self.midlessform = true;
            }
            OpCode::IntSless => {
                self.midlessequal = false;
                self.midsigncompare = true;
                self.midlessform = true;
            }
            OpCode::IntSlessequal => {
                self.midlessequal = true;
                self.midsigncompare = true;
                self.midlessform = true;
            }
            _ => return false,
        }
        self.hiequal = Some(hiequal);

        let Some(loless) = cond(lolessbool) else { return false };
        match data.op(loless).code() {
            // Only unsigned forms.
            OpCode::IntLess => self.lolessequalform = false,
            OpCode::IntLessequal => self.lolessequalform = true,
            OpCode::IntEqual | OpCode::IntNotequal => {
                let Some(c) = data.op(loless).input(1) else { return false };
                if !data.vn(c).is_constant() || data.vn(c).constant_value() != 0 {
                    return false;
                }
                self.lolessiszerocomp = true;
                self.lolessequalform = data.op(loless).code() == OpCode::IntEqual;
            }
            _ => return false,
        }
        self.loless = Some(loless);

        let Some(hiless) = cond(hilessbool) else { return false };
        match data.op(hiless).code() {
            OpCode::IntLess => {
                self.hilessequalform = false;
                self.signcompare = false;
            }
            OpCode::IntLessequal => {
                self.hilessequalform = true;
                self.signcompare = false;
            }
            OpCode::IntSless => {
                self.hilessequalform = false;
                self.signcompare = true;
            }
            OpCode::IntSlessequal => {
                self.hilessequalform = true;
                self.signcompare = true;
            }
            _ => return false,
        }
        self.hiless = Some(hiless);
        true
    }

    /// Ghidra `checkSignedness`.
    fn check_signedness(&self) -> bool {
        !self.midlessform || self.midsigncompare == self.signcompare
    }

    /// Ghidra `normalizeHi`: put the constant on the right, make the false branch reach the equality
    /// block, and rewrite `<=` into `<`.
    fn normalize_hi(&mut self, data: &Funcdata, in_: &SplitVarnode) -> bool {
        let hiless = self.hiless.unwrap();
        let (Some(mut v1), Some(mut v2)) = (data.op(hiless).input(0), data.op(hiless).input(1))
        else {
            return false;
        };
        if data.vn(v1).is_constant() {
            self.hiflip = !self.hiflip;
            self.hilessequalform = !self.hilessequalform;
            std::mem::swap(&mut v1, &mut v2);
        }
        self.hiconstform = false;
        if data.vn(v2).is_constant() {
            if in_.get_size() > 8 {
                return false; // must have enough precision for the constant
            }
            self.hiconstform = true;
            self.hival = data.vn(v2).constant_value();
            let Some((_, hilessfalse)) =
                SplitVarnode::get_true_false(data, self.hilessbool.unwrap(), self.hiflip)
            else {
                return false;
            };
            let mut inc: i64 = 1;
            if Some(hilessfalse) != self.hieqbl {
                self.hiflip = !self.hiflip;
                self.hilessequalform = !self.hilessequalform;
                std::mem::swap(&mut v1, &mut v2);
                inc = -1;
            }
            if self.hilessequalform {
                self.hival = self.hival.wrapping_add(inc as u64)
                    & super::nzmask::calc_mask(in_.get_size());
                self.hilessequalform = false;
            }
            let Some(lo) = in_.lo else { return false };
            self.hival >>= data.vn(lo).size * 8;
        } else if self.hilessequalform {
            self.hilessequalform = false;
            self.hiflip = !self.hiflip;
            std::mem::swap(&mut v1, &mut v2);
        }
        self.vnhil1 = Some(v1);
        self.vnhil2 = Some(v2);
        true
    }

    /// Ghidra `normalizeMid`: normalize the equality test, folding a whole-width constant down to a
    /// high-half comparison and reconciling an off-by-one against the high test.
    fn normalize_mid(&mut self, data: &Funcdata, in_: &SplitVarnode) -> bool {
        let hiequal = self.hiequal.unwrap();
        let (Some(mut v1), Some(mut v2)) = (data.op(hiequal).input(0), data.op(hiequal).input(1))
        else {
            return false;
        };
        if data.vn(v1).is_constant() {
            std::mem::swap(&mut v1, &mut v2);
            if self.midlessform {
                self.equalflip = !self.equalflip;
                self.midlessequal = !self.midlessequal;
            }
        }
        self.midconstform = false;
        if data.vn(v2).is_constant() {
            if !self.hiconstform {
                return false; // if mid is constant, both mid and hi must be
            }
            let Some(lo) = in_.lo else { return false };
            let losize = data.vn(lo).size;
            self.midconstform = true;
            self.midval = data.vn(v2).constant_value();
            if data.vn(v2).size == in_.get_size() {
                // Convert to a comparison on the high part.
                let lopart = self.midval & super::nzmask::calc_mask(losize);
                self.midval >>= losize * 8;
                if self.midlessform {
                    if self.midlessequal {
                        if lopart != super::nzmask::calc_mask(losize) {
                            return false;
                        }
                    } else if lopart != 0 {
                        return false;
                    }
                } else {
                    return false; // the compare forces a restriction on the lo part
                }
            }
            if self.midval != self.hival {
                if !self.midlessform {
                    return false;
                }
                // We may just be one off.
                let delta: i64 = if self.midlessequal { 1 } else { -1 };
                self.midval =
                    self.midval.wrapping_add(delta as u64) & super::nzmask::calc_mask(losize);
                self.midlessequal = !self.midlessequal;
                if self.midval != self.hival {
                    return false; // last chance
                }
            }
        }
        if self.midlessform {
            if !self.midlessequal {
                self.equalflip = !self.equalflip;
            }
        } else if data.op(hiequal).code() == OpCode::IntNotequal {
            self.equalflip = !self.equalflip;
        }
        self.vnhie1 = Some(v1);
        self.vnhie2 = Some(v2);
        true
    }

    /// Ghidra `normalizeLo`: the low test, normalized the same way as the high one.
    fn normalize_lo(&mut self, data: &Funcdata) -> bool {
        let loless = self.loless.unwrap();
        let (Some(mut v1), Some(mut v2)) = (data.op(loless).input(0), data.op(loless).input(1))
        else {
            return false;
        };
        if self.lolessiszerocomp {
            self.loconstform = true;
            if self.lolessequalform {
                self.loval = 1; // as if we saw vnlo1 <= 0
                self.lolessequalform = false;
            } else {
                self.loflip = !self.loflip; // as if we saw 0 < vnlo1
                self.loval = 1;
            }
            self.vnlo1 = Some(v1);
            self.vnlo2 = Some(v2);
            return true;
        }
        if data.vn(v1).is_constant() {
            self.loflip = !self.loflip;
            self.lolessequalform = !self.lolessequalform;
            std::mem::swap(&mut v1, &mut v2);
        }
        self.loconstform = false;
        if data.vn(v2).is_constant() {
            self.loconstform = true;
            self.loval = data.vn(v2).constant_value();
            if self.lolessequalform {
                self.loval =
                    self.loval.wrapping_add(1) & super::nzmask::calc_mask(data.vn(v2).size);
                self.lolessequalform = false;
            }
        } else if self.lolessequalform {
            self.lolessequalform = false;
            self.loflip = !self.loflip;
            std::mem::swap(&mut v1, &mut v2);
        }
        self.vnlo1 = Some(v1);
        self.vnlo2 = Some(v2);
        true
    }

    /// Ghidra `checkOpForm`: the same values must appear in the high test and the equality test, and
    /// the pieces must sit on the same side of each comparison.
    fn check_op_form(&mut self, data: &Funcdata, in_: &SplitVarnode) -> bool {
        let (lo, hi) = (in_.lo, in_.hi);
        let (vnhil1, vnhil2) = (self.vnhil1, self.vnhil2);
        let (vnhie1, vnhie2) = (self.vnhie1, self.vnhie2);
        if self.midconstform {
            if !self.hiconstform {
                return false;
            }
            let Some(v2) = vnhie2 else { return false };
            if data.vn(v2).size == in_.get_size() {
                if vnhie1 != vnhil1 && vnhie1 != vnhil2 {
                    return false;
                }
            } else if vnhie1 != hi {
                return false;
            }
        } else {
            // hi and hi2 must appear as inputs in both hiless and hiequal.
            if vnhil1 != vnhie1 && vnhil1 != vnhie2 {
                return false;
            }
            if vnhil2 != vnhie1 && vnhil2 != vnhie2 {
                return false;
            }
        }
        if hi.is_some() && hi == vnhil1 {
            if self.hiconstform {
                return false;
            }
            self.hislot = 0;
            self.hi2 = vnhil2;
            if self.vnlo1 != lo {
                std::mem::swap(&mut self.vnlo1, &mut self.vnlo2);
                if self.vnlo1 != lo {
                    return false;
                }
                self.loflip = !self.loflip;
                self.lolessequalform = !self.lolessequalform;
            }
            self.lo2 = self.vnlo2;
        } else if hi.is_some() && hi == vnhil2 {
            if self.hiconstform {
                return false;
            }
            self.hislot = 1;
            self.hi2 = vnhil1;
            if self.vnlo2 != lo {
                std::mem::swap(&mut self.vnlo1, &mut self.vnlo2);
                if self.vnlo2 != lo {
                    return false;
                }
                self.loflip = !self.loflip;
                self.lolessequalform = !self.lolessequalform;
            }
            self.lo2 = self.vnlo1;
        } else if in_.whole.is_some() && in_.whole == vnhil1 {
            if !self.hiconstform || !self.loconstform || self.vnlo1 != lo {
                return false;
            }
            self.hislot = 0;
        } else if in_.whole.is_some() && in_.whole == vnhil2 {
            // The whole constant appears on the left.
            if !self.hiconstform || !self.loconstform {
                return false;
            }
            if self.vnlo2 != lo {
                self.loflip = !self.loflip;
                let Some(lo) = lo else { return false };
                self.loval =
                    self.loval.wrapping_sub(1) & super::nzmask::calc_mask(data.vn(lo).size);
                if self.vnlo1 != Some(lo) {
                    return false;
                }
            }
            self.hislot = 1;
        } else {
            return false;
        }
        true
    }

    /// Ghidra `checkBlockForm`: the three branches must be wired as the three-way comparison, and
    /// the two later blocks must contain nothing but their tests.
    fn check_block_form(&self, data: &Funcdata) -> bool {
        let Some((hilesstrue, hilessfalse)) =
            SplitVarnode::get_true_false(data, self.hilessbool.unwrap(), self.hiflip)
        else {
            return false;
        };
        let Some((lolesstrue, lolessfalse)) =
            SplitVarnode::get_true_false(data, self.lolessbool.unwrap(), self.loflip)
        else {
            return false;
        };
        let Some((hieqtrue, hieqfalse)) =
            SplitVarnode::get_true_false(data, self.hieqbool.unwrap(), self.equalflip)
        else {
            return false;
        };
        if hilesstrue == lolesstrue
            && hieqfalse == lolessfalse
            && Some(hilessfalse) == self.hieqbl
            && Some(hieqtrue) == self.lolessbl
        {
            return SplitVarnode::otherwise_empty(data, self.hieqbool.unwrap())
                && SplitVarnode::otherwise_empty(data, self.lolessbool.unwrap());
        }
        false
    }

    /// Ghidra `setOpCode`: which comparison the collapsed whole-width test uses.
    fn set_op_code(&mut self) {
        self.finalopc = Some(if self.lolessequalform != self.hiflip {
            if self.signcompare { OpCode::IntSlessequal } else { OpCode::IntLessequal }
        } else if self.signcompare {
            OpCode::IntSless
        } else {
            OpCode::IntLess
        });
        if self.hiflip {
            self.hislot = 1 - self.hislot;
            self.hiflip = false;
        }
    }
}

/// Ghidra `LessThreeWay::applyRule` (double.cc): collapse the three-way comparison into one
/// whole-width branch. The equality branch is made unconditional so it always reaches its original
/// FALSE block, which leaves the low-test block unreachable for dead-code removal to collect.
fn less_three_way_apply_rule(
    data: &mut Funcdata,
    i: &SplitVarnode,
    loop_: OpId,
    workishi: bool,
) -> bool {
    if workishi || i.lo.is_none() {
        return false; // does not necessarily need the hi
    }
    let mut f = LessThreeWay::default();
    // Ghidra `mapFromLow`.
    let Some(out) = data.op(loop_).output else { return false };
    let Some(branch) = data.lone_descend(out) else { return false };
    let Some(bl) = data.op(branch).parent else { return false };
    if !f.map_blocks_from_low(data, bl)
        || !f.map_ops_from_blocks(data)
        || !f.check_signedness()
        || !f.normalize_hi(data, i)
        || !f.normalize_mid(data, i)
        || !f.normalize_lo(data)
        || !f.check_op_form(data, i)
        || !f.check_block_form(data)
    {
        return false;
    }
    // Ghidra `testReplace`.
    f.set_op_code();
    let mut in_ = i.clone();
    let mut in2 = SplitVarnode::default();
    if f.hiconstform {
        let Some(lo) = i.lo else { return false };
        let val = (f.hival << (8 * data.vn(lo).size)) | f.loval;
        in2.init_partial_const(i.get_size(), val);
    } else {
        in2.init_partial(i.get_size(), f.lo2, f.hi2);
    }
    let hilessbool = f.hilessbool.unwrap();
    let ok = if f.hislot == 0 {
        SplitVarnode::prepare_bool_op(data, &mut in_, &mut in2, hilessbool)
    } else {
        SplitVarnode::prepare_bool_op(data, &mut in2, &mut in_, hilessbool)
    };
    if !ok || in2.exceeds_const_precision() {
        return false;
    }
    if f.hislot == 0 {
        SplitVarnode::create_bool_op(data, hilessbool, &mut in_, &mut in2, f.finalopc.unwrap());
    } else {
        SplitVarnode::create_bool_op(data, hilessbool, &mut in2, &mut in_, f.finalopc.unwrap());
    }
    // Make hieqbool always go to the original FALSE block; the lolessbool block becomes
    // unreachable and is removed later.
    let k = data.new_const(1, if f.equalflip { 1 } else { 0 });
    data.op_set_input(f.hieqbool.unwrap(), 1, k);
    true
}


impl SplitVarnode {
    /// Ghidra `SplitVarnode::applyRuleIn` (double.cc): for each half in hand, try every Form that
    /// matches the reading op's opcode. The first Form that fires wins, and Ghidra's order within
    /// each opcode is preserved — it matters, because the more specific recognizer is tried first
    /// (Equal3 before Logical on INT_AND; LessThreeWay before Equal1/Equal2 and before LessConst).
    pub fn apply_rule_in(data: &mut Funcdata, in_: &SplitVarnode) -> u32 {
        for i in 0..2 {
            let vn = if i == 0 { in_.hi } else { in_.lo };
            let Some(vn) = vn else { continue };
            let workishi = i == 0;
            for workop in data.vn(vn).descend.clone() {
                let fired = match data.op(workop).code() {
                    OpCode::IntAdd => {
                        add_sub_apply_rule(data, in_, workop, workishi, true)
                            || add_sub_apply_rule(data, in_, workop, workishi, false)
                    }
                    OpCode::IntAnd => {
                        equal3_form_apply_rule(data, in_, workop, workishi)
                            || logical_form_apply_rule(data, in_, workop, workishi)
                    }
                    OpCode::IntOr | OpCode::IntXor => {
                        logical_form_apply_rule(data, in_, workop, workishi)
                    }
                    OpCode::IntEqual | OpCode::IntNotequal => {
                        less_three_way_apply_rule(data, in_, workop, workishi)
                            || equal1_form_apply_rule(data, in_, workop, workishi)
                            || equal2_form_apply_rule(data, in_, workop, workishi)
                    }
                    OpCode::IntLess | OpCode::IntLessequal => {
                        less_three_way_apply_rule(data, in_, workop, workishi)
                            || less_const_form_apply_rule(data, in_, workop, workishi)
                    }
                    OpCode::IntSless | OpCode::IntSlessequal => {
                        less_const_form_apply_rule(data, in_, workop, workishi)
                    }
                    OpCode::IntLeft => shift_form_apply_rule(data, in_, workop, workishi, true),
                    OpCode::IntRight | OpCode::IntSright => {
                        shift_form_apply_rule(data, in_, workop, workishi, false)
                    }
                    OpCode::IntMult => mult_form_apply_rule(data, in_, workop, workishi),
                    OpCode::Multiequal => phi_form_apply_rule(data, in_, workop, workishi),
                    OpCode::Indirect => indirect_form_apply_rule(data, in_, workop, workishi),
                    OpCode::Copy => {
                        let forced =
                            data.op(workop).output.is_some_and(|o| data.vn(o).is_addr_force());
                        forced && copy_force_form_apply_rule(data, in_, workop, workishi)
                    }
                    _ => false,
                };
                if fired {
                    return 1;
                }
            }
        }
        0
    }
}

/// Ghidra `RuleDoubleIn` (double.cc, oppool1 slot :5645): the entry point of the double-precision
/// engine. A SUBPIECE marked as the low half of a logical whole is fed, with its companion, to
/// [`SplitVarnode::apply_rule_in`], which looks for arithmetic done on the pair and rewrites it as
/// one whole-width operation.
///
/// Before the halves are marked, the rule instead tries to mark them
/// ([`double_in_attempt_marking`]) — the SUBPIECE-side counterpart of `RuleDoubleOut`'s marking.
pub struct RuleDoubleIn;

impl Rule for RuleDoubleIn {
    fn name(&self) -> &str {
        "doublein"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(outvn) = data.op(op).output else { return 0 };
        if !data.vn(outvn).is_precis_lo() {
            if data.vn(outvn).is_precis_hi() {
                return 0;
            }
            return double_in_attempt_marking(data, outvn, op);
        }
        if data.has_unreachable_blocks() {
            return 0;
        }
        let Some(whole) = data.op(op).input(0) else { return 0 };
        let splitvec = SplitVarnode::whole_list(data, whole);
        if splitvec.is_empty() {
            return 0;
        }
        for in_ in splitvec {
            let res = SplitVarnode::apply_rule_in(data, &in_);
            if res != 0 {
                return res;
            }
        }
        0
    }
}

/// Ghidra `RuleDoubleIn::attemptMarking` (double.cc): a value truncated to exactly the upper half
/// of a whole that is itself produced (or type-locked) as a single arithmetic value, whose lower
/// half is also truncated out, is a double-precision pair.
fn double_in_attempt_marking(data: &mut Funcdata, vn: VarnodeId, subpiece_op: OpId) -> u32 {
    let Some(whole) = data.op(subpiece_op).input(0) else { return 0 };
    if data.vn(whole).is_typelock() && !data.vn(whole).get_type().is_primitive_whole() {
        return 0;
    }
    let Some(offvn) = data.op(subpiece_op).input(1) else { return 0 };
    let offset = data.vn(offvn).constant_value() as u32;
    if offset != data.vn(vn).size {
        return 0;
    }
    if offset * 2 != data.vn(whole).size {
        return 0; // truncate exactly half
    }
    if data.vn(whole).is_input() {
        if !data.vn(whole).is_typelock() {
            return 0;
        }
    } else if !data.vn(whole).is_written() {
        return 0;
    } else {
        // Categorize opcodes as "producing a logical whole".
        let def = data.vn(whole).def.unwrap();
        if !data.op(def).is_arithmetic_op() && !data.op(def).is_floatingpoint_op() {
            return 0;
        }
    }
    let mut vn_lo = None;
    for op in data.vn(whole).descend.clone() {
        if data.op(op).code() != OpCode::Subpiece {
            continue;
        }
        if data.op(op).input(1).map(|v| data.vn(v).constant_value()) != Some(0) {
            continue;
        }
        if let Some(out) = data.op(op).output {
            if data.vn(out).size == data.vn(vn).size {
                vn_lo = Some(out);
                break;
            }
        }
    }
    let Some(vn_lo) = vn_lo else { return 0 };
    data.vn_mut(vn_lo).set_precis_lo();
    data.vn_mut(vn).set_precis_hi();
    1
}


#[cfg(test)]
mod split_varnode_tests {
    use super::*;
    use crate::decompile::op::SeqNum;
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::BlockBasic;

    fn fd() -> (Funcdata, Address) {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        (Funcdata::new("t", Address::new(ram, 0), spaces), Address::new(ram, 0))
    }

    /// A marked double-precision pair: an 8-byte `whole` split into two marked 4-byte halves.
    /// Returns `(whole, hi, lo, ops)`.
    fn marked_pair(
        f: &mut Funcdata,
        ram: Address,
        whole_in: VarnodeId,
        uniq_base: u32,
    ) -> (VarnodeId, VarnodeId, Vec<OpId>) {
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let four = f.new_const(4, 4);
        let subhi = f.new_op(OpCode::Subpiece, seq(uniq_base), vec![whole_in, four]);
        let hi = f.new_output_unique(subhi, 4);
        let zero = f.new_const(4, 0);
        let sublo = f.new_op(OpCode::Subpiece, seq(uniq_base + 1), vec![whole_in, zero]);
        let lo = f.new_output_unique(sublo, 4);
        f.vn_mut(hi).set_precis_hi();
        f.vn_mut(lo).set_precis_lo();
        (hi, lo, vec![subhi, sublo])
    }

    #[test]
    fn whole_list_finds_the_marked_pair() {
        // SplitVarnode::wholeList recovers both halves off one whole.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let w = f.new_input(8, Address::new(reg, 0x10));
        let (hi, lo, ops) = marked_pair(&mut f, ram, w, 0);
        f.set_blocks(vec![BlockBasic { ops: ops.clone(), ..Default::default() }]);
        for op in ops {
            f.op_mut(op).parent = Some(BlockId(0));
        }
        let v = SplitVarnode::whole_list(&f, w);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].hi, Some(hi));
        assert_eq!(v[0].lo, Some(lo));
        assert_eq!(v[0].wholesize, 8);
    }

    #[test]
    fn add_form_rewrites_piecewise_add_as_one_whole_add() {
        // The 64-bit add idiom on 32-bit halves:
        //     reslo = lo1 + lo2
        //     reshi = hi1 + hi2 + ZEXT(CARRY(lo1, lo2))
        // becomes a single whole-width INT_ADD (double.cc AddForm).
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let w1 = f.new_input(8, Address::new(reg, 0x10));
        let (hi1, lo1, mut ops) = marked_pair(&mut f, ram, w1, 0);
        let w2 = f.new_input(8, Address::new(reg, 0x20));
        let (hi2, lo2, ops2) = marked_pair(&mut f, ram, w2, 2);
        ops.extend(ops2);
        // Low half.
        let loadd = f.new_op(OpCode::IntAdd, seq(10), vec![lo1, lo2]);
        f.new_output_unique(loadd, 4);
        // Carry into the high half.
        let carry = f.new_op(OpCode::IntCarry, seq(11), vec![lo1, lo2]);
        let carry_out = f.new_output_unique(carry, 1);
        let zext = f.new_op(OpCode::IntZext, seq(12), vec![carry_out]);
        let zext_out = f.new_output_unique(zext, 4);
        // High half: (hi1 + zext) + hi2.
        let hiadd1 = f.new_op(OpCode::IntAdd, seq(13), vec![hi1, zext_out]);
        let hiadd1_out = f.new_output_unique(hiadd1, 4);
        let hiadd2 = f.new_op(OpCode::IntAdd, seq(14), vec![hiadd1_out, hi2]);
        let reshi = f.new_output_unique(hiadd2, 4);
        // Something must read the result, and the halves must be recombinable.
        let piece = f.new_op(OpCode::Piece, seq(15), vec![reshi, f.op(loadd).output.unwrap()]);
        f.new_output_unique(piece, 8);
        ops.extend([loadd, carry, zext, hiadd1, hiadd2, piece]);
        f.set_blocks(vec![BlockBasic { ops: ops.clone(), ..Default::default() }]);
        for op in ops {
            f.op_mut(op).parent = Some(BlockId(0));
        }
        let splits = SplitVarnode::whole_list(&f, w1);
        assert_eq!(splits.len(), 1, "the pair is discovered");
        let fired = SplitVarnode::apply_rule_in(&mut f, &splits[0]);
        assert_eq!(fired, 1, "AddForm recognizes the piece-wise add");
        // The PIECE that recombined the halves is now the whole-width INT_ADD itself.
        assert_eq!(f.op(piece).code(), OpCode::IntAdd);
        let ins: Vec<_> = (0..2).map(|k| f.op(piece).input(k).unwrap()).collect();
        for v in ins {
            assert_eq!(f.vn(v).size, 8, "operands are whole-width");
        }
    }

    #[test]
    fn logical_form_rewrites_piecewise_and_as_one_whole_and() {
        // `reslo = lo1 & lo2` with `reshi = hi1 & hi2` is one whole-width INT_AND
        // (double.cc LogicalForm). This Form is driven from the LOW half.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let w1 = f.new_input(8, Address::new(reg, 0x10));
        let (hi1, lo1, mut ops) = marked_pair(&mut f, ram, w1, 0);
        let w2 = f.new_input(8, Address::new(reg, 0x20));
        let (hi2, lo2, ops2) = marked_pair(&mut f, ram, w2, 2);
        ops.extend(ops2);
        let loand = f.new_op(OpCode::IntAnd, seq(10), vec![lo1, lo2]);
        let reslo = f.new_output_unique(loand, 4);
        let hiand = f.new_op(OpCode::IntAnd, seq(11), vec![hi1, hi2]);
        let reshi = f.new_output_unique(hiand, 4);
        let piece = f.new_op(OpCode::Piece, seq(12), vec![reshi, reslo]);
        f.new_output_unique(piece, 8);
        ops.extend([loand, hiand, piece]);
        f.set_blocks(vec![BlockBasic { ops: ops.clone(), ..Default::default() }]);
        for op in ops {
            f.op_mut(op).parent = Some(BlockId(0));
        }
        let splits = SplitVarnode::whole_list(&f, w1);
        let fired = SplitVarnode::apply_rule_in(&mut f, &splits[0]);
        assert_eq!(fired, 1, "LogicalForm recognizes the piece-wise AND");
        assert_eq!(f.op(piece).code(), OpCode::IntAnd);
        assert_eq!(f.vn(f.op(piece).input(0).unwrap()).size, 8);
    }

    #[test]
    fn apply_rule_in_declines_unrelated_arithmetic() {
        // The halves are used, but not as a matching pair — nothing to collapse.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let w1 = f.new_input(8, Address::new(reg, 0x10));
        let (hi1, lo1, mut ops) = marked_pair(&mut f, ram, w1, 0);
        let other = f.new_input(4, Address::new(reg, 0x30));
        let a = f.new_op(OpCode::IntAdd, seq(10), vec![lo1, other]);
        f.new_output_unique(a, 4);
        let b = f.new_op(OpCode::IntMult, seq(11), vec![hi1, other]);
        f.new_output_unique(b, 4);
        ops.extend([a, b]);
        f.set_blocks(vec![BlockBasic { ops: ops.clone(), ..Default::default() }]);
        for op in ops {
            f.op_mut(op).parent = Some(BlockId(0));
        }
        let splits = SplitVarnode::whole_list(&f, w1);
        assert_eq!(SplitVarnode::apply_rule_in(&mut f, &splits[0]), 0);
    }

    #[test]
    fn double_in_marks_a_half_of_an_arithmetic_whole() {
        // RuleDoubleIn's marking arm: SUBPIECE of the upper half of an ADD result, with the lower
        // half also truncated out, marks the pair.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let a = f.new_input(8, Address::new(reg, 0x10));
        let b = f.new_input(8, Address::new(reg, 0x20));
        let add = f.new_op(OpCode::IntAdd, seq(0), vec![a, b]);
        let whole = f.new_output_unique(add, 8);
        let four = f.new_const(4, 4);
        let subhi = f.new_op(OpCode::Subpiece, seq(1), vec![whole, four]);
        let hi = f.new_output_unique(subhi, 4);
        let zero = f.new_const(4, 0);
        let sublo = f.new_op(OpCode::Subpiece, seq(2), vec![whole, zero]);
        let lo = f.new_output_unique(sublo, 4);
        let ops = vec![add, subhi, sublo];
        f.set_blocks(vec![BlockBasic { ops: ops.clone(), ..Default::default() }]);
        for op in ops {
            f.op_mut(op).parent = Some(BlockId(0));
        }
        assert_eq!(RuleDoubleIn.apply_op(subhi, &mut f), 1);
        assert!(f.vn(hi).is_precis_hi());
        assert!(f.vn(lo).is_precis_lo());
    }

    #[test]
    fn double_in_declines_marking_a_non_arithmetic_whole() {
        // The whole is produced by a LOAD, not arithmetic — Ghidra's "producing a logical whole"
        // test refuses it, so two adjacent truncations are not assumed to be a 64-bit value.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let ramspc = f.spaces.by_name("ram").unwrap();
        let sid = f.new_const(8, ramspc.0 as u64);
        let ptr = f.new_input(8, Address::new(reg, 0x10));
        let load = f.new_op(OpCode::Load, seq(0), vec![sid, ptr]);
        let whole = f.new_output_unique(load, 8);
        let four = f.new_const(4, 4);
        let subhi = f.new_op(OpCode::Subpiece, seq(1), vec![whole, four]);
        let hi = f.new_output_unique(subhi, 4);
        let zero = f.new_const(4, 0);
        let sublo = f.new_op(OpCode::Subpiece, seq(2), vec![whole, zero]);
        f.new_output_unique(sublo, 4);
        let ops = vec![load, subhi, sublo];
        f.set_blocks(vec![BlockBasic { ops: ops.clone(), ..Default::default() }]);
        for op in ops {
            f.op_mut(op).parent = Some(BlockId(0));
        }
        assert_eq!(RuleDoubleIn.apply_op(subhi, &mut f), 0);
        assert!(!f.vn(hi).is_precis_hi());
    }
}
