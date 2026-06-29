//! A faithful port of Ghidra's decompiler (`Features/Decompiler/src/decompile/cpp`),
//! mirroring its file/class names. See `docs/port-plan.md`.
//!
//! This is the decompiler core, built on Ghidra's Varnode-graph data model and
//! (incrementally) its `Action`/`Rule` pipeline, validated against Ghidra's intermediate
//! IR. It replaced the original `src/decomp/` prototype, now removed. Status / phases:
//! `TODO.md`.

pub mod action;
pub mod alias;
pub mod block;
pub mod build;
pub mod cast;
pub mod cfg;
pub mod cover;
pub mod deadcode;
pub mod determinedbranch;
pub mod dominator;
pub mod fspec;
pub mod funcdata;
pub mod heritage;
pub mod jumptable;
pub mod merge;
pub mod op;
pub mod opcode;
pub mod pipeline;
pub mod recover;
pub mod divopt;
pub mod printc;
pub mod ptrarith;
pub mod rules;
pub mod scope;
pub mod space;
pub mod stackvars;
pub mod structure;
pub mod types;
pub mod infertypes;
pub mod varmap;
pub mod varnode;

pub use action::{Action, ActionGroup, ActionPool, ActionStart, Rule};
pub use block::{BlockBasic, BlockId};
pub use funcdata::Funcdata;
pub use op::{OpId, PcodeOp, SeqNum};
pub use opcode::OpCode;
pub use space::{Address, Space, SpaceId, SpaceKind, SpaceManager};
pub use varnode::{Varnode, VarnodeId};

#[cfg(test)]
mod tests {
    use super::*;

    /// Build `register r0x0:4 = INT_ADD register r0x4:4, #0x1:4` by hand and check the
    /// graph wiring (def/descend) and the raw dump.
    #[test]
    fn build_and_print_a_tiny_funcdata() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        let mut f = Funcdata::new("func", Address::new(ram, 0x1000), spaces);

        let a = f.new_input(4, Address::new(reg, 0x4));
        let one = f.new_const(4, 1);
        let seq = SeqNum { pc: Address::new(ram, 0x1000), uniq: 0 };
        let add = f.new_op(OpCode::IntAdd, seq, vec![a, one]);
        let out = f.new_output(add, 4, Address::new(reg, 0x0));

        // graph wiring: output's def is the op; the op is in both inputs' descend lists.
        assert_eq!(f.vn(out).def, Some(add));
        assert!(f.vn(out).is_written());
        assert_eq!(f.vn(a).descend, vec![add]);
        assert_eq!(f.vn(one).descend, vec![add]);
        assert!(f.vn(a).is_input());
        assert!(f.vn(one).is_constant());
        assert_eq!(f.op(add).code(), OpCode::IntAdd);

        let raw = f.print_raw();
        assert!(raw.contains("r0x0:4 = INT_ADD r0x4:4 #0x1:4"), "raw was:\n{raw}");
    }

    #[test]
    fn opcode_roundtrips_through_lifter_numbers() {
        for n in 1..=73u32 {
            if let Some(oc) = OpCode::from_u32(n) {
                assert_eq!(oc as u32, n, "{} round-trips", oc.name());
            }
        }
        assert!(OpCode::from_u32(45).is_none()); // Ghidra's unused slot
        assert_eq!(OpCode::from_u32(62), Some(OpCode::Piece));
        assert_eq!(OpCode::Subpiece.name(), "SUBPIECE");
    }
}
