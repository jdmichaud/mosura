//! Recovering the BUILD, not just the code: which compiler options each function was compiled with.
//!
//! A byte-exact claim is a claim about a specific compiler invoked a specific way. Two of WAR2's
//! options are visible in its own bytes and change the emitted function completely — whether a BP
//! frame is built at all, and whether callee-saved registers are pushed before or after it — so
//! compiling every function one way guarantees a mismatch on most of them, however good the
//! decompilation is.
//!
//! The evidence is read from the ORIGINAL function's decoded instructions rather than from a byte
//! pattern. A frame prologue is "push the frame-pointer register, then copy the stack pointer into
//! it" — a statement about what the instructions do, which holds for every encoding of it and for
//! architectures whose spellings nobody here has seen. Matching hex, the way the WAR2-specific
//! script this replaces does, misses the second encoding of the same instruction: WAR2 contains
//! both `55 89 e5` and `55 8b ec`, and a scan written for one silently mis-flags 84 functions.
//!
//! What stays outside: which flags a *profile* maps evidence to is toolchain knowledge, and it
//! belongs in a profile rather than in the decompiler. And a project that has independent ground
//! truth about its build (a recovered makefile, per-file options) supplies it as an override —
//! this module consumes such an answer, never invents one.

use super::insn::{NormInsn, SemArg, SemOp};
use std::collections::HashMap;

/// What the original function's own code says about how it was compiled.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Evidence {
    /// The function builds a frame: the frame-pointer register is pushed, then the stack pointer
    /// is copied into it.
    pub frame_prologue: bool,
    /// Callee-saved registers are pushed BEFORE the frame is built.
    ///
    /// This separates the compiler's two prologue paths. Building the frame first requires
    /// restoring the stack pointer from it at the end (`lea esp,[ebp-N]`); saving first does not,
    /// and the epilogue is bare pops. A function whose original saves first was not compiled the
    /// other way, and compiling it that way costs at least three bytes no matter what the C says.
    pub saves_before_frame: bool,
    /// The body contains an in-place scaled LEA (`LEA EAX,[EAX*4]`-family — the destination is
    /// its own index register). Under `-5r` the code generator never selects this form: the
    /// CPU_586 arm of the LEA verifier (Open Watcom `i86ver.c`, `V_LEA_GOOD`/`OP_LSHIFT`,
    /// `op1 == result && _CPULevel( CPU_586 )`) rewrites in-place scaling to `SHL`. So its
    /// presence PROVES the function was compiled with pre-Pentium tuning; the evidence is
    /// one-sided — absence proves nothing, and the default stays the profile's `-5r`.
    ///
    /// Measured on WAR2 (docs/war2-toolchain-synthesis.md): exactly one contiguous module —
    /// 9 functions, 0x69fb0..0x6e6e0, 18 sites — carries the form inside an otherwise
    /// Pentium-tuned build. A per-module CFLAGS difference in the original Makefile, which is
    /// why the CPU digit is per-function evidence and not only a profile constant.
    pub in_place_scaled_lea: bool,
}

/// A rule mapping evidence to option changes, for one toolchain.
#[derive(Debug, Clone)]
pub struct Rule {
    pub when_frame_prologue: Option<bool>,
    pub when_saves_before_frame: Option<bool>,
    pub when_in_place_scaled_lea: Option<bool>,
    pub add: Vec<String>,
    pub remove: Vec<String>,
}

/// One toolchain's base options and evidence rules.
#[derive(Debug, Clone)]
pub struct Profile {
    pub name: String,
    pub base: Vec<String>,
    pub rules: Vec<Rule>,
}

impl Profile {
    /// Options for a function with this evidence.
    pub fn flags_for(&self, ev: &Evidence) -> Vec<String> {
        let mut out = self.base.clone();
        for r in &self.rules {
            if r.when_frame_prologue.is_some_and(|w| w != ev.frame_prologue) {
                continue;
            }
            if r.when_saves_before_frame.is_some_and(|w| w != ev.saves_before_frame) {
                continue;
            }
            if r.when_in_place_scaled_lea.is_some_and(|w| w != ev.in_place_scaled_lea) {
                continue;
            }
            out.retain(|f| !r.remove.contains(f));
            for a in &r.add {
                if !out.contains(a) {
                    out.push(a.clone());
                }
            }
        }
        out
    }
}

/// Decide the `local-width` axis for one function FROM THE ORIGINAL'S BYTES — no compiler, no
/// search. This is the field mechanism: an emission axis is a placeholder for a recovery
/// problem, and the evidence is in the subject (see byte-exact-status.md, "From searched axes
/// to RECOVERED choices").
///
/// TARGET-SPECIFIC BY CONSTRUCTION, which is why it lives here beside the Watcom profile and
/// not in `decompile::emit`: the signature it looks for is x86 code generated by this
/// compiler family — a value established in a narrow sub-register whose containing register
/// was just zeroed (`XOR EBX,EBX ; MOV BX,[m]`) means the ORIGINAL SOURCE held that value in
/// an int-width local, which is what `LocalWidth::Storage` renders. A value written narrow
/// with no widening (`MOV BL,[m]` alone) means the source's variable really was narrow.
///
/// `candidates` is the axis's own candidate set with each one's defining instruction address
/// ([`crate::decompile::printc::EmitReport`]); scoring the SAME set the rendering keys on is
/// what makes the rule calibratable against the searched arm.
pub fn local_width_from_evidence(
    candidates: &[(crate::decompile::varnode::VarnodeId, u64)],
    insns: &[NormInsn],
) -> crate::decompile::emit::LocalWidth {
    use crate::decompile::emit::LocalWidth;
    let (mut widened, mut narrow) = (0usize, 0usize);
    for &(_, pc) in candidates {
        let Some(i) = insns.iter().position(|x| x.addr == pc) else { continue };
        let Some(rest) = insns[i].text.strip_prefix("MOV ") else { continue };
        let dst = rest.split(',').next().unwrap_or("");
        let container = match dst {
            "AL" | "AH" | "AX" => "EAX",
            "BL" | "BH" | "BX" => "EBX",
            "CL" | "CH" | "CX" => "ECX",
            "DL" | "DH" | "DX" => "EDX",
            _ => continue,
        };
        // the widening the original performs at the def: the container zeroed just before
        let zero = format!("XOR {container},{container}");
        if i > 0 && insns[i - 1].text == zero {
            widened += 1;
        } else {
            narrow += 1;
        }
    }
    // Any widened candidate decides the function: the axis is per-function, and a function
    // that widens one narrow local at its def is a function whose source declared int locals.
    if widened > 0 && widened >= narrow {
        LocalWidth::Storage
    } else {
        LocalWidth::Recovered
    }
}

/// Watcom C/C++32 10.0a as WAR2 was built with it.
///
/// The base options are the register calling convention (`-4r`), inline 387 (`-fpi87`), no stack
/// checking (`-s`) and the measured optimization set (`-onatx`). The one evidence rule is `-d1+`:
/// line-number debug information, which is what makes this compiler emit a BP frame on the path
/// WAR2 was built with. Adding it to a frameless function adds four bytes that are not there, so
/// it is applied only where the original has a frame.
///
/// Deliberately NOT here: `-of`/`-of+`. Both force the other prologue path, and every WAR2
/// function that saves registers before its frame is evidence against them.
/// `-5r`, not `-4r`: the CPU digit is a TUNING level, not a convention change, and WAR2 was
/// tuned for Pentium. Measured 2026-08-18 (docs/war2-toolchain-synthesis.md): 10.0a's code
/// generator carries a CPU_586 gate that suppresses the in-place scaled-LEA selection
/// (`SHL EAX,2` instead of `LEA EAX,[EAX*4]` — the gate survives into Open Watcom source as
/// the `op1 == result && _CPULevel( CPU_586 )` arm of V_LEA_GOOD's OP_LSHIFT case). WAR2
/// uses the SHL form everywhere. Corpus-wide on sb43 sources: SHL>LEA divergence rows
/// 157 -> 12, EXACT 586 -> 591 (+6/-1). `-4r` had itself replaced `-3r` on the same kind of
/// evidence (V_GOOD_CLR needs CPU_486 — the warcraft2-re byte-zero-store finding).
pub fn watcom_10_0a() -> Profile {
    Profile {
        name: "watcom-10.0a".into(),
        base: ["-5r", "-fpi87", "-s", "-onatx"].iter().map(|s| s.to_string()).collect(),
        rules: vec![
            Rule {
                when_frame_prologue: Some(true),
                when_saves_before_frame: None,
                when_in_place_scaled_lea: None,
                add: vec!["-d1+".into()],
                remove: vec!["-of".into(), "-of+".into()],
            },
            // The per-function CPU-digit downgrade: see `Evidence::in_place_scaled_lea`.
            Rule {
                when_frame_prologue: None,
                when_saves_before_frame: None,
                when_in_place_scaled_lea: Some(true),
                add: vec!["-4r".into()],
                remove: vec!["-5r".into()],
            },
        ],
    }
}

/// Read the evidence out of a function's decoded prologue.
///
/// `sp` and `fp` are the stack- and frame-pointer registers as `(register-space offset, size)`;
/// the caller resolves them from the language rather than this module assuming an architecture.
pub fn detect(insns: &[NormInsn], sp: (u64, u32), fp: (u64, u32)) -> Evidence {
    let mut ev = Evidence::default();
    let mut pushes_before = 0usize;
    for (i, insn) in insns.iter().enumerate().take(PROLOGUE_WINDOW) {
        if is_frame_setup(insn, sp, fp) {
            ev.frame_prologue = true;
            // A push of the frame pointer itself is part of the frame setup, not a callee-saved
            // register save, so it does not count as saving first.
            ev.saves_before_frame = pushes_before > 0;
            break;
        }
        match push_of(insn, sp) {
            Some(reg) if reg != fp => pushes_before += 1,
            Some(_) => {}
            None => break, // anything else ends the prologue
        }
        let _ = i;
    }
    // Body evidence (whole function, not just the prologue): an in-place scaled LEA — the
    // destination register is its own index. `LEA EAX,[EAX*0x4 + 0x0]` matches;
    // `LEA EAX,[EDX*0x4 + 0x0]` (cross-register, legal at every CPU level) does not.
    for insn in insns {
        if let Some(rest) = insn.text.strip_prefix("LEA ") {
            if let Some((dest, addr)) = rest.split_once(',') {
                if addr.contains(&format!("[{dest}*0x")) {
                    ev.in_place_scaled_lea = true;
                    break;
                }
            }
        }
    }
    ev
}

/// How many instructions into the function a frame setup may appear. Registers are saved first on
/// one of the two paths, so the window has to cover a realistic save list.
const PROLOGUE_WINDOW: usize = 12;

/// `fp = sp`, however it is spelled: a single COPY of the stack pointer into the frame pointer.
fn is_frame_setup(insn: &NormInsn, sp: (u64, u32), fp: (u64, u32)) -> bool {
    matches!(
        insn.sem.as_slice(),
        [SemOp { opcode: CPUI_COPY, out: Some(SemArg::Reg(o, osz)), ins }]
            if (*o, *osz) == fp && matches!(ins.as_slice(), [SemArg::Reg(i, isz)] if (*i, *isz) == sp)
    )
}

/// A push: the stack pointer is decremented and a register is stored at the new top. Returns the
/// pushed register.
///
/// The stored value is a lifter TEMPORARY, not the register itself — `PUSH EBP` becomes
/// `t = COPY EBP ; ESP = INT_SUB ESP,4 ; STORE ram ESP t` — so the store's operand is resolved
/// back through the copies inside the instruction. Matching the register directly finds nothing,
/// which made this return `None` for every push and stop the prologue scan at its first
/// instruction.
fn push_of(insn: &NormInsn, sp: (u64, u32)) -> Option<(u64, u32)> {
    let mut decremented = false;
    let mut stored: Option<&SemArg> = None;
    // Temporary -> what was copied into it, within this instruction.
    let mut origin: Vec<(&SemArg, &SemArg)> = Vec::new();
    for op in &insn.sem {
        match op.opcode {
            CPUI_COPY => {
                if let (Some(out @ SemArg::Temp(..)), [src]) = (&op.out, op.ins.as_slice()) {
                    origin.push((out, src));
                }
            }
            CPUI_INT_SUB | CPUI_INT_ADD => {
                if matches!(&op.out, Some(SemArg::Reg(o, s)) if (*o, *s) == sp) {
                    decremented = true;
                }
            }
            CPUI_STORE => {
                if let [_, _, value] = op.ins.as_slice() {
                    stored = Some(value);
                }
            }
            _ => {}
        }
    }
    if !decremented {
        return None;
    }
    let mut value = stored?;
    for _ in 0..4 {
        match value {
            SemArg::Reg(r, s) => return Some((*r, *s)),
            _ => match origin.iter().find(|(t, _)| *t == value) {
                Some((_, src)) => value = src,
                None => return None,
            },
        }
    }
    None
}

const CPUI_COPY: u32 = 1;
const CPUI_STORE: u32 = 3;
const CPUI_INT_ADD: u32 = 19;
const CPUI_INT_SUB: u32 = 20;

/// Per-function options for a whole program.
#[derive(Debug, Default, Clone)]
pub struct BuildConfig {
    /// Keyed by function entry address.
    pub flags: HashMap<u64, Vec<String>>,
    pub profile: String,
}

impl BuildConfig {
    pub fn get(&self, entry: u64) -> Option<&Vec<String>> {
        self.flags.get(&entry)
    }
}

/// Recover per-function options for every function whose original instructions are supplied.
///
/// `overrides` carries independent ground truth about the build, keyed by entry address; where it
/// speaks, it wins, because it is evidence this module cannot derive. Everything else comes from
/// the profile's rules applied to the function's own prologue.
pub fn recover(
    profile: &Profile,
    functions: &[(u64, Vec<NormInsn>)],
    sp: (u64, u32),
    fp: (u64, u32),
    overrides: &HashMap<u64, Vec<String>>,
) -> BuildConfig {
    let mut flags = HashMap::with_capacity(functions.len());
    for (entry, insns) in functions {
        let ev = detect(insns, sp, fp);
        let mut f = match overrides.get(entry) {
            // An override states the build, not the evidence, so the evidence rules still apply on
            // top: the two answer different questions and the override does not know this
            // function's prologue.
            Some(o) => o.clone(),
            None => profile.base.clone(),
        };
        for r in &profile.rules {
            if r.when_frame_prologue.is_some_and(|w| w != ev.frame_prologue) {
                continue;
            }
            if r.when_saves_before_frame.is_some_and(|w| w != ev.saves_before_frame) {
                continue;
            }
            f.retain(|x| !r.remove.contains(x));
            for a in &r.add {
                if !f.contains(a) {
                    f.push(a.clone());
                }
            }
        }
        flags.insert(*entry, f);
    }
    BuildConfig { flags, profile: profile.name.clone() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recompile::insn::{NoReloc, normalize};

    const ESP: (u64, u32) = (0x10, 4);
    const EBP: (u64, u32) = (0x14, 4);

    fn lift(hex: &str) -> Vec<NormInsn> {
        let bytes: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        normalize("x86:LE:32:default", &bytes, 0x1000, &NoReloc).expect("language tables")
    }

    /// BOTH encodings of `mov ebp,esp` are a frame setup. The script this replaces matched hex, and
    /// WAR2 contains both spellings — 261 functions use one and 84 the other.
    #[test]
    fn a_frame_is_recognized_in_either_encoding() {
        for hex in ["5589e58b45085dc3", "558bec8b45085dc3"] {
            let ev = detect(&lift(hex), ESP, EBP);
            assert!(ev.frame_prologue, "{hex}");
            assert!(!ev.saves_before_frame, "{hex}");
        }
    }

    /// Registers pushed BEFORE the frame is the other prologue path, and the frame-pointer's own
    /// push does not count as one.
    #[test]
    fn saving_before_the_frame_is_distinguished() {
        // push edx; push ebp; mov ebp,esp; pop ebp; pop edx; ret
        let ev = detect(&lift("52558 9e55d5ac3".replace(' ', "").as_str()), ESP, EBP);
        assert!(ev.frame_prologue);
        assert!(ev.saves_before_frame);
    }

    /// A function with no frame at all reports neither.
    #[test]
    fn a_frameless_function_reports_no_frame() {
        // mov eax,edx; add eax,1; ret
        let ev = detect(&lift("89d083c001c3"), ESP, EBP);
        assert!(!ev.frame_prologue);
        assert!(!ev.saves_before_frame);
    }

    /// The Watcom profile adds the frame flag only where there is a frame — on a frameless
    /// function it would add four bytes the original does not have.
    #[test]
    fn the_frame_flag_is_applied_only_where_there_is_a_frame() {
        let p = watcom_10_0a();
        assert!(p
            .flags_for(&Evidence { frame_prologue: true, ..Evidence::default() })
            .contains(&"-d1+".to_string()));
        assert!(!p.flags_for(&Evidence::default()).contains(&"-d1+".to_string()));
    }

    /// An in-place scaled LEA in the body is proof of pre-Pentium tuning — `-5r` can never
    /// emit the form — so the profile downgrades that function's CPU digit to `-4r`.
    /// Cross-register scaled LEAs are legal at every level and must not trigger it.
    #[test]
    fn in_place_scaled_lea_downgrades_the_cpu_digit() {
        // lea eax,[eax*4+0]; ret  — the -4r signature (WAR2's 0x69fb0..0x6e6e0 module)
        let ev = detect(&lift("8d048500000000c3"), ESP, EBP);
        assert!(ev.in_place_scaled_lea);
        // lea eax,[edx*4+0]; ret  — cross-register, non-evidence
        let ev2 = detect(&lift("8d049500000000c3"), ESP, EBP);
        assert!(!ev2.in_place_scaled_lea);

        let p = watcom_10_0a();
        let f = p.flags_for(&ev);
        assert!(f.contains(&"-4r".to_string()) && !f.contains(&"-5r".to_string()));
        let f2 = p.flags_for(&ev2);
        assert!(f2.contains(&"-5r".to_string()) && !f2.contains(&"-4r".to_string()));
    }
}
