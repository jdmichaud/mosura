//! A fixed varnode's offset wraps into its address space (Ghidra `SleighBuilder::generateLocation`,
//! sleigh.cc:152: `vn.space->wrapOffset(...)` for every space but const and unique). A 68000
//! absolute-short operand sign-extends its 16 bits into the offset, so `($C000).w` is
//! `ram:0xffffc000` in the 4-byte `ram` space, never a 64-bit `0xffffffffffffc000`.

use mosura_core::sleigh::{self, pcode::PArg};

#[test]
fn a_sign_extended_absolute_address_wraps_into_its_space() {
    // move.w #$1234,($C000).w ; move.w ($1234).w,d0
    let insns = sleigh::disassemble("68000:BE:32:default", &[0x31, 0xfc, 0x12, 0x34, 0xc0, 0x00, 0x30, 0x38, 0x12, 0x34], 0x1000).expect("68000 tables");
    let ram: Vec<u64> = insns
        .iter()
        .flat_map(|i| i.ops.iter())
        .flat_map(|op| op.out.iter().chain(op.ins.iter().filter_map(PArg::as_var)))
        .filter(|v| v.space == "ram")
        .map(|v| v.offset)
        .collect();
    assert_eq!(ram, [0xffff_c000, 0x1234], "{:#?}", insns.iter().map(|i| &i.pcode).collect::<Vec<_>>());
}
