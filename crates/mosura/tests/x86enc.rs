//! `recompile::x86enc` (review R3): every reader pinned on hand-assembled bytes — both operand
//! sizes, with prefixes, with a displacement before the immediate — and cross-checked against
//! SLEIGH's decode of the committed oracle fixtures on what both assert.
use mosura::recompile::x86enc::*;

#[test]
fn prefixes_in_any_order() {
    assert_eq!(prefixes(&[0x3d, 0x34, 0x12, 0, 0]).len, 0);
    let p = prefixes(&[0x66, 0x3d, 0x34, 0x12]);
    assert!(p.opsize16 && !p.rep && p.len == 1);
    let p = prefixes(&[0xf3, 0x66, 0xa5]);
    assert!(p.rep && p.opsize16 && p.len == 2);
    let p = prefixes(&[0x2e, 0x67, 0xf2, 0xae]);
    assert!(p.segment == Some(0x2e) && p.addrsize16 && p.repne && p.len == 3);
    assert_eq!(prefixes(&[]), Prefixes::default());
}

#[test]
fn modrm_fields() {
    let m = ModRm::of(0xec);
    assert_eq!((m.mod_, m.reg, m.rm), (3, 5, 4));
    assert!(m.is_register_direct());
    let m = ModRm::of(0x7d);
    assert_eq!((m.mod_, m.reg, m.rm), (1, 7, 5));
    assert!(!m.is_register_direct());
}

#[test]
fn conditional_jumps_short_and_near() {
    let j = jcc(&[0x74, 0x05]).unwrap();
    assert_eq!((j.cond, j.negated, j.near, j.rel), (Cond::Equal, false, false, 5));
    let j = jcc(&[0x75, 0xfb]).unwrap();
    assert_eq!((j.cond, j.negated, j.rel), (Cond::Equal, true, -5));
    assert_eq!(jcc(&[0x72, 0x10]).unwrap().cond, Cond::Below);
    assert_eq!(jcc(&[0x73, 0x10]).unwrap(), Jcc { cond: Cond::Below, negated: true, near: false, rel: 0x10 });
    assert_eq!(jcc(&[0x76, 0x00]).unwrap().cond, Cond::BelowOrEqual);
    assert!(jcc(&[0x77, 0x00]).unwrap().negated, "JA = not below-or-equal");
    assert_eq!(jcc(&[0x7c, 0x01]).unwrap().cond, Cond::Less);
    assert_eq!(jcc(&[0x7e, 0x01]).unwrap().cond, Cond::LessOrEqual);
    assert!(jcc(&[0x7f, 0x01]).unwrap().negated, "JG = not less-or-equal");
    assert!(Cond::Less.is_signed() && Cond::LessOrEqual.is_signed() && !Cond::Below.is_signed() && !Cond::Equal.is_signed());
    let j = jcc(&[0x0f, 0x82, 0x83, 0x00, 0x00, 0x00]).unwrap();
    assert_eq!((j.cond, j.negated, j.near, j.rel), (Cond::Below, false, true, 0x83));
    let j = jcc(&[0x0f, 0x8f, 0xf0, 0xff, 0xff, 0xff]).unwrap();
    assert_eq!((j.cond, j.negated, j.rel), (Cond::LessOrEqual, true, -16));
    assert_eq!(jcc(&[0x70, 0x00]).unwrap().cond, Cond::Overflow);
    assert_eq!(jcc(&[0x78, 0x00]).unwrap().cond, Cond::Sign);
    assert_eq!(jcc(&[0x7a, 0x00]).unwrap().cond, Cond::Parity);
    assert!(jcc(&[0xeb, 0x05]).is_none(), "JMP rel8 is not a Jcc");
    assert!(jcc(&[0x74]).is_none() && jcc(&[0x0f, 0x84, 0, 0]).is_none(), "truncated");
    assert!(jcc(&[0x66, 0x0f, 0x84, 0, 0]).is_none(), "a 16-bit near displacement is not decoded");
    assert!(jcc(&[0x2e, 0x74, 0x05]).is_none() && jcc(&[0x3e, 0x0f, 0x84, 0, 0, 0, 0]).is_none(), "a branch hint is a prefix: not decoded");
}

#[test]
fn alu_immediates_in_every_form() {
    // CMP AL, imm8 = 3C ib
    assert_eq!(alu_imm(&[0x3c, 0x05], 7), Some(Imm { value: 5, opsize: 8 }));
    // CMP EAX, imm32 = 3D id; CMP AX, imm16 = 66 3D iw
    assert_eq!(alu_imm(&[0x3d, 0x78, 0x56, 0x34, 0x12], 7), Some(Imm { value: 0x12345678, opsize: 32 }));
    assert_eq!(alu_imm(&[0x66, 0x3d, 0x34, 0x12], 7), Some(Imm { value: 0x1234, opsize: 16 }));
    // CMP r/m8, imm8 = 80 /7 ib (CMP CL,7: ModRM F9 = 11 111 001)
    assert_eq!(alu_imm(&[0x80, 0xf9, 0x07], 7), Some(Imm { value: 7, opsize: 8 }));
    // CMP r/m32, imm32 = 81 /7 id (CMP EDX,0x100: ModRM FA)
    assert_eq!(alu_imm(&[0x81, 0xfa, 0x00, 0x01, 0x00, 0x00], 7), Some(Imm { value: 0x100, opsize: 32 }));
    assert_eq!(alu_imm(&[0x66, 0x81, 0xfa, 0x00, 0x01], 7), Some(Imm { value: 0x100, opsize: 16 }));
    // CMP r/m32, imm8 = 83 /7 ib, sign-extended to the operand size
    assert_eq!(alu_imm(&[0x83, 0xf8, 0xff], 7), Some(Imm { value: 0xffff_ffff, opsize: 32 }));
    assert_eq!(alu_imm(&[0x66, 0x83, 0xf8, 0xff], 7), Some(Imm { value: 0xffff, opsize: 16 }));
    assert_eq!(alu_imm(&[0x83, 0xf8, 0x7f], 7), Some(Imm { value: 0x7f, opsize: 32 }));
    // the immediate is the LAST n bytes whatever the addressing form: disp8, disp32, SIB+disp32
    assert_eq!(alu_imm(&[0x83, 0x7d, 0xfc, 0x05], 7), Some(Imm { value: 5, opsize: 32 }), "CMP dword [EBP-4],5");
    assert_eq!(alu_imm(&[0x81, 0xbd, 0x30, 0xff, 0xff, 0xff, 0x34, 0x12, 0x00, 0x00], 7), Some(Imm { value: 0x1234, opsize: 32 }), "CMP dword [EBP-0xd0],0x1234");
    assert_eq!(alu_imm(&[0x66, 0x83, 0xbc, 0x85, 0x00, 0x01, 0x00, 0x00, 0xfe], 7), Some(Imm { value: 0xfffe, opsize: 16 }), "CMP word [EBP+EAX*4+0x100],-2 under 66");
    assert_eq!(alu_imm(&[0x80, 0x3d, 0x10, 0x20, 0x30, 0x00, 0x01], 7), Some(Imm { value: 1, opsize: 8 }), "CMP byte [0x302010],1");
    // another /reg is another operation: SUB EAX,0x10 = 83 E8 10 is /5, not /7
    assert_eq!(alu_imm(&[0x83, 0xe8, 0x10], 7), None);
    assert_eq!(alu_imm(&[0x83, 0xe8, 0x10], 5), Some(Imm { value: 0x10, opsize: 32 }));
    // ADD EAX, imm32 = 05 id; AND AL, imm8 = 24 ib
    assert_eq!(alu_imm(&[0x05, 0x01, 0x00, 0x00, 0x00], 0), Some(Imm { value: 1, opsize: 32 }));
    assert_eq!(alu_imm(&[0x24, 0x0f], 4), Some(Imm { value: 0xf, opsize: 8 }));
    // not an immediate form, or truncated
    assert_eq!(alu_imm(&[0x39, 0xc8], 7), None, "CMP r/m32, r32");
    assert_eq!(alu_imm(&[0x3d, 0x78, 0x56], 7), None, "truncated iz");
    assert_eq!(alu_imm(&[0x83, 0xf8], 7), None, "no ib");
    assert_eq!(alu_imm(&[], 7), None);
}

#[test]
fn test_register_against_itself() {
    assert_eq!(test_rr(&[0x85, 0xc0]), Some((0, 32)), "TEST EAX,EAX");
    assert_eq!(test_rr(&[0x84, 0xdb]), Some((3, 8)), "TEST BL,BL");
    assert_eq!(test_rr(&[0x66, 0x85, 0xd2]), Some((2, 16)), "TEST DX,DX");
    assert_eq!(test_rr(&[0x85, 0xc1]), None, "TEST ECX,EAX is two registers");
    assert_eq!(test_rr(&[0x85, 0x00]), None, "TEST [EAX],EAX is a memory operand");
    assert_eq!(test_rr(&[0xa9, 0x01, 0, 0, 0]), None, "TEST EAX, imm32");
    assert_eq!(test_rr(&[0x85]), None);
}

#[test]
fn shifts_by_immediate_and_by_one() {
    let s = shift_imm(&[0xc1, 0xf8, 0x02]).unwrap();
    assert!(s.kind == Shift::Sar && s.count == 2 && s.modrm.is_register_direct() && s.modrm.rm == 0 && s.opsize == 32, "SAR EAX,2");
    let s = shift_imm(&[0xd1, 0xf8]).unwrap();
    assert!(s.kind == Shift::Sar && s.count == 1 && s.opsize == 32, "SAR EAX,1");
    let s = shift_imm(&[0xc1, 0xe0, 0x03]).unwrap();
    assert!(s.kind == Shift::Shl && s.count == 3, "SHL EAX,3");
    let s = shift_imm(&[0xc1, 0x7d, 0xfc, 0x02]).unwrap();
    assert!(s.kind == Shift::Sar && s.count == 2 && !s.modrm.is_register_direct(), "SAR dword [EBP-4],2");
    let s = shift_imm(&[0xc0, 0xe9, 0x04]).unwrap();
    assert!(s.kind == Shift::Shr && s.opsize == 8, "SHR CL,4");
    let s = shift_imm(&[0xd0, 0xc0]).unwrap();
    assert!(s.kind == Shift::Rol && s.opsize == 8, "ROL AL,1");
    assert_eq!(shift_imm(&[0x66, 0xc1, 0xf8, 0x02]).unwrap().opsize, 16, "SAR AX,2");
    assert!(shift_imm(&[0xd3, 0xf8]).is_none(), "SAR EAX,CL has no immediate");
    assert!(shift_imm(&[0xc1, 0xf8]).is_none(), "truncated");
}

#[test]
fn sbb_register_forms() {
    assert!(is_sbb_rr(&[0x1b, 0xc2]), "SBB EAX,EDX");
    assert!(is_sbb_rr(&[0x19, 0xc0]), "SBB EAX,EAX");
    assert!(!is_sbb_rr(&[0x1a, 0xc2]), "the byte form is not the template's");
    assert!(!is_sbb_rr(&[0x66, 0x19, 0xc0]), "the word form is not the template's");
    assert!(!is_sbb_rr(&[0x2b, 0xc2]), "SUB");
    assert!(!is_sbb_rr(&[]));
}

#[test]
fn string_instructions_and_the_plain_movsd() {
    let plain = string_insn(&[0xa5]).unwrap();
    assert!(plain.op == StringOp::Movs && plain.elem == 4 && !plain.rep && !plain.repne && plain.prefixes.len == 0);
    let rep = string_insn(&[0xf3, 0xa5]).unwrap();
    assert!(rep.op == StringOp::Movs && rep.elem == 4 && rep.rep && !rep.repne && rep.prefixes.len == 1);
    assert_eq!(string_insn(&[0xf3, 0xa4]).unwrap().elem, 1);
    let w = string_insn(&[0x66, 0xf3, 0xa5]).unwrap();
    assert!(w.elem == 2 && w.rep && w.prefixes.opsize16 && w.prefixes.len == 2);
    let w = string_insn(&[0xf3, 0x66, 0xa5]).unwrap();
    assert!(w.op == StringOp::Movs && w.elem == 2 && w.rep && w.prefixes.len == 2);
    let ne = string_insn(&[0xf2, 0xae]).unwrap();
    assert!(ne.op == StringOp::Scas && ne.elem == 1 && !ne.rep && ne.repne);
    assert_eq!(string_insn(&[0xf3, 0xa6]).unwrap().op, StringOp::Cmps);
    let st = string_insn(&[0xab]).unwrap();
    assert!(st.op == StringOp::Stos && st.elem == 4 && !st.rep && !st.repne);
    assert_eq!(string_insn(&[0xac]).unwrap().op, StringOp::Lods);
    assert!(string_insn(&[0xa5, 0x90]).is_none(), "the opcode must be the last byte");
    assert!(string_insn(&[0x90]).is_none());
    assert!(is_plain_movsd(&[0xa5]));
    assert!(!is_plain_movsd(&[0xf3, 0xa5]) && !is_plain_movsd(&[0x66, 0xa5]) && !is_plain_movsd(&[0xa4]));
}

#[test]
fn push_and_the_prologue_frame() {
    assert_eq!(push_r32(&[0x55]), Some(5), "PUSH EBP");
    assert_eq!(push_r32(&[0x53]), Some(3));
    assert_eq!(push_r32(&[0x66, 0x55]), None, "PUSH BP");
    assert_eq!(push_r32(&[0xff, 0x35, 0, 0, 0, 0]), None, "PUSH m32");
    assert_eq!(sub_esp_imm(&[0x83, 0xec, 0x30]), Some(0x30));
    assert_eq!(sub_esp_imm(&[0x81, 0xec, 0xd0, 0x00, 0x00, 0x00]), Some(0xd0));
    assert_eq!(sub_esp_imm(&[0x81, 0xec, 0x00, 0x01, 0x00, 0x00]), Some(0x100));
    assert_eq!(sub_esp_imm(&[0x83, 0xc4, 0x30]), None, "ADD ESP");
    assert_eq!(sub_esp_imm(&[0x83, 0xe8, 0x30]), None, "SUB EAX");
    assert_eq!(sub_esp_imm(&[0x2b, 0xe0]), None, "SUB ESP,EAX");
    assert_eq!(sub_esp_imm(&[0x83, 0xec, 0x80]), Some(0xffff_ff80), "the imm8 is sign-extended like any other");
    assert_eq!(sub_esp_imm(&[0x66, 0x83, 0xec, 0x30]), None, "SUB SP,imm");
    assert_eq!(sub_esp_imm(&[0x2e, 0x83, 0xec, 0x30]), None, "a prefixed SUB is not the prologue's");
}

/// The readers against SLEIGH's decode of every committed oracle fixture, on what both assert:
/// the mnemonic, and the decoded immediate being one of `NormInsn::consts` (never the whole
/// constant list — SLEIGH's also carries the flag arithmetic's constants and displacements).
#[test]
fn readers_agree_with_sleigh_on_the_oracle_fixtures() {
    use mosura::recompile::insn::{normalize, NoReloc};
    const LANG: &str = "x86:LE:32:default";
    let dir = mosura::paths::oracle_fixtures_dir();
    let mut checked = 0usize;
    let mut disagreements: Vec<String> = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).collect();
    entries.sort();
    for path in entries {
        if path.extension().and_then(|e| e.to_str()) != Some("xml") {
            continue;
        }
        let dt = mosura::datatest::parse_file(&path).unwrap();
        if !dt.arch.starts_with("x86:LE:32") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        for chunk in &dt.chunks {
            let Ok(insns) = normalize(LANG, chunk.bytes.as_slice(), chunk.offset, &NoReloc) else { continue };
            for insn in &insns {
                let b = insn.bytes.as_slice();
                let m = insn.mnemonic.to_ascii_uppercase();
                let mut expect = |ok: bool, what: &str| {
                    checked += 1;
                    if !ok {
                        disagreements.push(format!("{name} {:#x} {} {:02x?}: {what}", insn.addr, insn.text, b));
                    }
                };
                if let Some(j) = jcc(b) {
                    expect(m.starts_with('J') && m != "JMP" && insn.is_branch, &format!("jcc {j:?} but SLEIGH says {m}"));
                }
                if let Some(i) = alu_imm(b, 7) {
                    expect(m == "CMP" && insn.consts.contains(&i.value), &format!("CMP imm {:#x} not in consts {:x?}", i.value, insn.consts));
                }
                if let Some(i) = alu_imm(b, 5) {
                    expect(m == "SUB" && insn.consts.contains(&i.value), &format!("SUB imm {:#x} not in consts {:x?}", i.value, insn.consts));
                }
                if test_rr(b).is_some() {
                    expect(m == "TEST", "test_rr but not TEST");
                }
                if let Some(sh) = shift_imm(b) {
                    let want = format!("{:?}", sh.kind).to_ascii_uppercase();
                    expect(m == want, &format!("shift {sh:?} but SLEIGH says {m}"));
                }
                if is_sbb_rr(b) {
                    expect(m == "SBB", "sbb_rr but not SBB");
                }
                if let Some(s) = string_insn(b) {
                    let want = format!("{:?}", s.op).to_ascii_uppercase();
                    expect(m.starts_with(&want), &format!("string op {s:?} but SLEIGH says {m}"));
                }
                if push_r32(b).is_some() {
                    expect(m == "PUSH", "push_r32 but not PUSH");
                }
                if let Some(n) = sub_esp_imm(b) {
                    expect(m == "SUB" && insn.consts.contains(&(n as u64)), &format!("SUB ESP,{n:#x} not in consts {:x?}", insn.consts));
                }
            }
        }
    }
    assert!(checked > 50, "the fixtures exercise the readers ({checked} checks)");
    assert!(disagreements.is_empty(), "{} disagreement(s) with SLEIGH:\n{}", disagreements.len(), disagreements.join("\n"));
}
