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
