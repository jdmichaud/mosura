//! Stage 0 spike (`docs/fid-port-plan.md` §0): the read-only FID fingerprint accessor.
//!
//! Verifies the four disassembly-level SLEIGH ingredients Ghidra's FID hasher
//! (`MessageDigestFidHasher`) consumes are surfaced structurally for a spread of x86
//! instructions: `getInstructionMask` (opcode bits set, operand value bytes zeroed),
//! `getOperandValueMask`, `getOpObjects` (scalar/register components), `getOperandType`
//! (scalar/address), and `getFlowType().isCall()`.
//!
//! Byte-exact agreement with Ghidra's own hasher is a *later* gate (Stage 1's
//! `FidHashDump` oracle); here we assert the ingredients are structurally faithful.
//! Every expectation is spelled out from the instruction encoding.

use mosura::lang;
use mosura::sleigh::{InstructionFingerprint, OpObject};

const LANG: &str = "x86:LE:32:default";

/// Disassemble one x86-32 instruction and return (byte length, fingerprint).
/// Skips (returns `None`) only when the SLEIGH tables are unavailable — the
/// `sleigh_canary` suite fails loudly if that ever happens in CI.
fn one(bytes: &[u8]) -> Option<(usize, InstructionFingerprint)> {
    let (spec, ctx) = lang::load_cached(LANG)?;
    let base = 0x1000u64;
    let ins = spec.disassemble_ctx(bytes, base, ctx);
    let fps = spec.disassemble_fingerprint(bytes, base, ctx);
    assert_eq!(ins.len(), fps.len(), "fingerprint count matches instruction count");
    let insn = ins.into_iter().next()?;
    let fp = fps.into_iter().next()?;
    Some((insn.bytes.len(), fp))
}

/// The instruction mask must be the same length as the instruction bytes, and no
/// operand-value bit may also be set in the instruction mask (Ghidra clears operand
/// bits out of the instruction mask via `clearBits`).
fn check_invariants(byte_len: usize, fp: &InstructionFingerprint) {
    assert_eq!(fp.instruction_mask.len(), byte_len, "mask length == instruction length");
    for op in &fp.operands {
        let vm = op.value_mask.as_ref().expect("well-formed instruction yields Some value mask");
        assert_eq!(vm.len(), byte_len, "operand value mask length == instruction length");
        for (m, v) in fp.instruction_mask.iter().zip(vm) {
            assert_eq!(m & v, 0, "operand value bits are excluded from the instruction mask");
        }
    }
}

/// reg-reg: `MOV EAX,ECX` = `89 C8` (opcode 0x89, ModRM 0xC8 = mod=11 reg=001 rm=000).
/// Both operands are registers → neither scalar nor address; the opcode byte and the
/// ModRM mod bits are opcode-fixed while the reg/rm selector fields are operand value
/// bits and are zeroed in the instruction mask. EAX offset 0, ECX offset 4.
#[test]
fn reg_reg_mov() {
    let Some((len, fp)) = one(&[0x89, 0xc8]) else { return };
    check_invariants(len, &fp);
    assert!(!fp.is_call);
    assert_eq!(fp.instruction_mask, vec![0xff, 0xc0], "0x89 fixed; ModRM mod bits fixed, reg/rm cleared");
    assert_eq!(fp.operands.len(), 2);
    // op0 = r/m = EAX (offset 0), op1 = reg = ECX (offset 4)
    assert_eq!(fp.operands[0].objects, vec![OpObject::Register { space_offset: 0 }]);
    assert_eq!(fp.operands[1].objects, vec![OpObject::Register { space_offset: 4 }]);
    for op in &fp.operands {
        assert!(!op.is_scalar && !op.is_address, "a register is neither scalar nor address");
    }
}

/// immediate scalar: `ADD EAX,0x10` = `83 C0 10` (opcode 0x83 /0, ModRM 0xC0, imm8=0x10).
/// The imm8 byte is an operand value → fully zeroed in the instruction mask; the scalar
/// operand surfaces `Scalar { 16 }` and is typed as a scalar.
#[test]
fn immediate_scalar() {
    let Some((len, fp)) = one(&[0x83, 0xc0, 0x10]) else { return };
    check_invariants(len, &fp);
    assert!(!fp.is_call);
    assert_eq!(fp.instruction_mask[2], 0x00, "imm8 byte is an operand value → zeroed");
    let imm = fp.operands.last().expect("ADD has an immediate operand");
    assert_eq!(imm.objects, vec![OpObject::Scalar { signed_value: 16 }]);
    assert!(imm.is_scalar && !imm.is_address, "a plain immediate is a scalar");
    assert_eq!(imm.value_mask.as_deref(), Some(&[0x00, 0x00, 0xff][..]), "imm8 value bits");
}

/// memory operand with displacement: `MOV EAX,dword ptr [EBX+0x10]` = `8B 43 10`
/// (opcode 0x8B, ModRM 0x43 = mod=01 reg=000 rm=011, disp8=0x10). The memory operand is
/// dynamic (neither scalar nor address at the operand level); its `getOpObjects`
/// components are the base register EBX (offset 12) and the displacement scalar 0x10.
/// The disp8 byte is an operand value → zeroed in the instruction mask.
#[test]
fn memory_with_displacement() {
    let Some((len, fp)) = one(&[0x8b, 0x43, 0x10]) else { return };
    check_invariants(len, &fp);
    assert!(!fp.is_call);
    assert_eq!(fp.instruction_mask[2], 0x00, "disp8 byte is an operand value → zeroed");
    assert_eq!(fp.operands.len(), 2);
    let mem = &fp.operands[1];
    assert!(!mem.is_scalar && !mem.is_address, "a [reg+disp] memory operand is dynamic");
    assert_eq!(
        mem.objects,
        vec![OpObject::Register { space_offset: 12 }, OpObject::Scalar { signed_value: 16 }],
        "memory operand components: base register EBX (offset 12) then displacement 0x10"
    );
    // op0 = destination register EAX
    assert_eq!(fp.operands[0].objects, vec![OpObject::Register { space_offset: 0 }]);
}

/// CALL: `CALL rel32` = `E8 FB FF FF FF` (target = inst_next + (-5)). A non-degenerate
/// near call lifts to a `CALL` p-code op, so `is_call` is true; the rel32 target operand
/// is typed as an address, and its 4 target bytes are operand value bits → zeroed.
#[test]
fn call_rel32() {
    let Some((len, fp)) = one(&[0xe8, 0xfb, 0xff, 0xff, 0xff]) else { return };
    check_invariants(len, &fp);
    assert!(fp.is_call, "a real near CALL classifies as a call");
    assert_eq!(fp.instruction_mask, vec![0xff, 0x00, 0x00, 0x00, 0x00], "0xE8 fixed; rel32 target zeroed");
    assert_eq!(fp.operands.len(), 1);
    assert!(fp.operands[0].is_address, "the call target is a code address");
    assert!(!fp.operands[0].is_scalar);
}

/// The degenerate `E8 00000000` (target = the next instruction, simm32=0) is modeled by
/// x86 SLEIGH as a `goto` (ia.sinc: `simm32=0 & rel32 { …; goto rel32; }`), so Ghidra's
/// own `getFlowType().isCall()` is false here too — the p-code-derived flow is faithful.
#[test]
fn call_to_next_is_not_a_call() {
    let Some((len, fp)) = one(&[0xe8, 0x00, 0x00, 0x00, 0x00]) else { return };
    check_invariants(len, &fp);
    assert!(!fp.is_call, "call-to-next is modeled as a jump, not a call");
}

/// RET: `C3` — a return, not a call; no operands; single opcode byte, fully fixed.
#[test]
fn ret() {
    let Some((len, fp)) = one(&[0xc3]) else { return };
    check_invariants(len, &fp);
    assert!(!fp.is_call, "RET is not a call");
    assert!(fp.operands.is_empty(), "RET has no printed operands");
    assert_eq!(fp.instruction_mask, vec![0xff], "the whole opcode byte is fixed");
}

/// multi-byte NOP: `0F 1F 40 00` (the canonical 4-byte NOP). It disassembles to a 4-byte
/// instruction with a full-length mask whose two escape-opcode bytes are fully fixed.
/// (NOPs are dropped by the X86 skipper before hashing — a Stage 1 concern — so only the
/// structural shape matters here.)
#[test]
fn multibyte_nop() {
    let Some((len, fp)) = one(&[0x0f, 0x1f, 0x40, 0x00]) else { return };
    check_invariants(len, &fp);
    assert_eq!(len, 4, "canonical 4-byte NOP");
    assert!(!fp.is_call);
    assert_eq!(fp.instruction_mask[0], 0xff, "0x0F escape byte fixed");
    assert_eq!(fp.instruction_mask[1], 0xff, "0x1F opcode byte fixed");
}
