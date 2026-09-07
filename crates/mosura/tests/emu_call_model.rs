//! What a CALL does to the machine, and what the machine knows about its own bytes.
//!
//! These are the properties the differential-execution harness (`examples/equiv_check.rs`) rests
//! on. Each one was a real defect: a verdict is only as good as the state the two runs start each
//! instruction in, and a piece of state nobody models is a piece both sides agree about for free.

use mosura::sleigh::emu::{self, FlagReturn, FlagSource, RegReturn, RunConfig};
use std::collections::{HashMap, HashSet};

const LANG: &str = "x86:LE:32:default";
// x86 register-space offsets (Ghidra's `register` space).
const EAX: u64 = 0;
const ECX: u64 = 4;
const EDX: u64 = 8;
const EBX: u64 = 12;
const ESP: u64 = 16;
/// The arithmetic flags, one byte each from 0x200 (`ia.sinc:39`): CF PF AF ZF SF OF.
const CF: u64 = 0x200;
const ZF: u64 = 0x206;
const SF: u64 = 0x207;
const FLAGS: [(u64, u32); 6] = [(CF, 1), (0x202, 1), (0x204, 1), (ZF, 1), (SF, 1), (0x20b, 1)];

const BASE: u64 = 0x4000;
const STACK_TOP: u64 = 0x0f00_0000;

/// Run `bytes` at [`BASE`] the way the harness does, with `seed` driving unset memory.
fn run(seed: u64, bytes: &[u8], inputs: &[(&str, u64, u64, u32)]) -> emu::Machine {
    run_side(seed, bytes, inputs, &HashMap::new(), false)
}

/// The same, on one SIDE of a differential run of a program that calls a callee answering in a
/// flag: `in_register` is what tells the candidate's run to deliver the answer in a general
/// register as well (see [`emu::RunConfig::call_flag_returns`]).
fn run_side(
    seed: u64,
    bytes: &[u8],
    inputs: &[(&str, u64, u64, u32)],
    flag_returns: &HashMap<u64, FlagReturn>,
    in_register: bool,
) -> emu::Machine {
    run_full(seed, bytes, inputs, flag_returns, &HashMap::new(), &HashMap::new(), no_regs(), in_register)
}

/// The three REGISTER-contract channels, in the order `run_full` takes them: by target, by site,
/// by ordinal. `no_regs()` is "no register contract at all", which is what every flag test uses.
type RegChannels<'a> = (&'a HashMap<u64, RegReturn>, &'a HashMap<u64, RegReturn>, &'a HashMap<u64, RegReturn>);
static NO_REG_MAP: std::sync::LazyLock<HashMap<u64, RegReturn>> = std::sync::LazyLock::new(HashMap::new);
fn no_regs() -> RegChannels<'static> {
    (&NO_REG_MAP, &NO_REG_MAP, &NO_REG_MAP)
}

/// Every flag-contract channel at once, so the two one-sided ones can be exercised the way
/// `equiv_check` drives them: `by_target` to both runs, `by_site` to the ORIGINAL's only (a site is
/// an address in ITS text), `by_ordinal` to the CANDIDATE's only (what the original's sites
/// resolved to).
#[allow(clippy::too_many_arguments)]
fn run_full(
    seed: u64,
    bytes: &[u8],
    inputs: &[(&str, u64, u64, u32)],
    by_target: &HashMap<u64, FlagReturn>,
    by_site: &HashMap<u64, FlagReturn>,
    by_ordinal: &HashMap<u64, FlagReturn>,
    regs: RegChannels,
    in_register: bool,
) -> emu::Machine {
    let image = [(BASE, bytes)];
    let (spec, ctx) = mosura::lang::load_cached(LANG).expect("x86:LE:32:default language tables");
    let call_args: HashMap<u64, Vec<(u64, u32)>> = HashMap::new();
    let call_modifies: HashMap<u64, Vec<(u64, u32)>> = HashMap::new();
    let stack_targets: HashSet<u64> = HashSet::new();
    let default_args = [(EAX, 4u32), (EDX, 4), (EBX, 4), (ECX, 4)];
    let clobbers = [(EAX, 4u32), (ECX, 4), (EDX, 4), (EBX, 4)];
    let pool = [0u64, 1, 2, 0xffff_ffff];
    let cfg = RunConfig {
        seed,
        scratch: (STACK_TOP - 0x8000, STACK_TOP + 0x400),
        call_args: &call_args,
        default_args: &default_args,
        call_clobbers: &clobbers,
        call_modifies: &call_modifies,
        call_flag_clobbers: &FLAGS,
        call_flag_returns: by_target,
        site_flag_returns: by_site,
        ordinal_flag_returns: by_ordinal,
        call_reg_returns: regs.0,
        site_reg_returns: regs.1,
        ordinal_reg_returns: regs.2,
        is_candidate_run: in_register,
        stack_targets: &stack_targets,
        sp: (ESP, 4),
        image: &image,
        // Wide enough for a poll loop that runs until a one-in-256 byte comes up: the
        // `FlagSource::IsZero` control below is exactly that shape, and a budget that truncated it
        // would make the two sides agree by both being cut off.
        max_steps: 5_000_000,
        pool: &pool,
        max_effects: 100_000,
    };
    let mut vals = vec![("register", ESP, STACK_TOP, 4u32)];
    vals.extend_from_slice(inputs);
    emu::run_traced(spec, bytes, BASE, ctx, &vals, &cfg).0
}

/// A CALL is an event, not a descent — but the instruction's own p-code has already PUSHED the
/// return address by the time the CALL op is reached, and nothing pops it. `run_traced` gives that
/// word back, and it must do so for an INDIRECT call too.
///
/// This test exists because the opposite was reported: that `CALL dword ptr [mem]` lowered ESP by
/// four and never restored it, so `PUSH ECX ; CALL [ind] ; POP ECX` recovered fill instead of ECX.
/// It does not — the `ESP += 4` is on the shared `"CALL" | "CALLIND"` arm and covers both — and the
/// reported symptom on FUN_00004141 had a different cause (the original preserves its result
/// register across two calls through the stack, and the candidate did not). Keeping the property
/// under test is worth more than the argument.
#[test]
fn a_call_gives_back_the_word_its_push_took() {
    // PUSH ECX ; CALL dword ptr [0x45338] ; POP ECX  — and the direct-call twin. No `RET`: `RET`
    // pops its own return address, which is a real +4 that would hide the thing being measured.
    for bytes in [
        &[0x51u8, 0xff, 0x15, 0x38, 0x53, 0x04, 0x00, 0x59][..],
        &[0x51, 0xe8, 0x00, 0x10, 0x00, 0x00, 0x59][..],
    ] {
        let m = run(0x1234, bytes, &[("register", ECX, 0xdead_beef, 4)]);
        assert_eq!(m.read("register", ESP, 4), STACK_TOP, "ESP is balanced across the call");
        // ECX is in the clobber set, so what comes back is the pushed word, not the entry value:
        // the point is that the POP reads the slot the PUSH wrote rather than untouched fill.
        assert_eq!(m.read("register", ECX, 4), 0xdead_beef, "POP recovered the word PUSH stored");
    }
}

/// A call leaves the arithmetic flags UNDEFINED. Before this was modelled they survived a call
/// untouched, so `STC ; CALL f ; JC` took the same branch on both sides of every differential run
/// no matter what either program did — the CF-returning idiom this subject is full of was being
/// agreed with for free. The property is behavioural: over enough seeds the CF after the call must
/// sometimes be 0 even though the caller set it to 1.
#[test]
fn a_call_clobbers_the_arithmetic_flags() {
    // STC ; CALL rel32 ; RET
    let bytes = [0xf9u8, 0xe8, 0x00, 0x10, 0x00, 0x00, 0xc3];
    let mut zero = 0;
    let mut one = 0;
    for s in 0..64u64 {
        let m = run(0x5eed_0000 ^ s.wrapping_mul(0x9e37_79b9), &bytes, &[]);
        match m.read("register", CF, 1) {
            0 => zero += 1,
            1 => one += 1,
            v => panic!("a flag must hold 0 or 1, not {v:#x} — a byte of fill in a 1-bit register"),
        }
    }
    assert!(zero > 0, "CF survived the call on every seed: the callee's effect on it is not modelled");
    assert!(one > 0, "CF was never 1 either — the clobber is not a bit, it is a constant");
}

