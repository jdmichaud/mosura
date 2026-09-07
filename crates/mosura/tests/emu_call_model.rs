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

/// The bytes a function is made of are also memory. Without them in the machine's data space an
/// inline table or a self-referential load read the seeded fill instead of the byte that is there.
#[test]
fn a_function_can_read_its_own_bytes() {
    // MOV EAX,[0x4000] ; RET — the dword it loads is the instruction's own encoding.
    let bytes = [0xa1u8, 0x00, 0x40, 0x00, 0x00, 0xc3];
    let m = run(0x1234, &bytes, &[]);
    assert_eq!(m.read("register", EAX, 4), 0x0040_00a1, "the load must see the function's own bytes");
}

/// `BSR`/`BSF` scan for the highest/lowest set bit. Their SLEIGH semantics are a LOOP built out of
/// internal labels (`<start>`, `<done>` — ia.sinc:2765), and until `PcodeBuilder`'s label
/// resolution was ported the lifter emitted every one of those branches with NO operands: the loop
/// fell straight through and `BSR` answered 31 (16-bit: 15) and `BSF` answered 1 for EVERY input.
/// That is the worst shape of modelling bug — both sides of a differential run got the same wrong
/// answer, so a verdict on any bit-scanning function was hollow rather than failing.
///
/// The zero-source case is NOT a convention chosen here: x86 leaves the destination undefined, and
/// the language table decides. `ia.sinc` branches straight to `<done>` with the counter still at
/// its initial value, so `BSR 0` is 31 and `BSF 0` is 0 — this test pins what the table says.
#[test]
fn bit_scan_finds_the_bit_rather_than_a_constant() {
    for (bytes, name, cases) in [
        // BSR ECX,EDX ; RET
        (&[0x0fu8, 0xbd, 0xca, 0xc3][..], "BSR", &[(0x3a4u64, 9u64), (1, 0), (0x8000_0000, 31), (0xff, 7), (0, 31)][..]),
        // BSF ECX,EDX ; RET
        (&[0x0f, 0xbc, 0xca, 0xc3][..], "BSF", &[(0x3a4, 2), (1, 0), (0x8000_0000, 31), (0xff, 0), (0, 0)][..]),
    ] {
        for &(src, want) in cases {
            let m = run(0x1234, bytes, &[("register", EDX, src, 4)]);
            assert_eq!(m.read("register", ECX, 4), want, "{name}({src:#x})");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// A callee that answers in a FLAG.
//
// This subject's hand-written convention returns booleans in the carry flag — `STC`/`CLC` in the
// callee, `CALL` then `JC`/`JB`/`JAE` in the caller — and Watcom 10.0a has no spelling for it
// (`#pragma aux f value [cf]` is rejected) and C no construct that reads the flags a call left. So
// a candidate models such a callee as returning a VALUE, and the two runs read the callee's answer
// out of two different places. `RunConfig::call_flag_returns` makes those two places hold the SAME
// bit; these tests are what says it is the same bit, and that the branch is still a real test.

/// The callee both sides call, and the store both sides make. Far from [`BASE`] and from the
/// stack, so the store is an observable effect and the target is not inside either program.
const CALLEE: u64 = 0x1_0000;
const SLOT: u64 = 0x5000;

/// `CALL 0x10000 ; J<cc> +8 ; store 1 ; RET ; store 2 ; RET` — the ORIGINAL's shape: branch on the
/// flag the callee left. `cc` is `0x72` (`JB`, carry set) or `0x74` (`JE`, zero set); both jump to
/// the "store 2" arm when their flag is 1.
fn original_branching_on_flag(cc: u8) -> Vec<u8> {
    #[rustfmt::skip]
    let v = vec![
        0xe8, 0xfb, 0xbf, 0x00, 0x00,                   // 4000 call 0x10000
        cc, 0x08,                                       // 4005 jcc 0x400f
        0xc6, 0x05, 0x00, 0x50, 0x00, 0x00, 0x01,       // 4007 mov byte [0x5000],1
        0xc3,                                           // 400e ret
        0xc6, 0x05, 0x00, 0x50, 0x00, 0x00, 0x02,       // 400f mov byte [0x5000],2
        0xc3,                                           // 4016 ret
    ];
    v
}

/// `CALL 0x10000 ; TEST EAX,EAX ; J<cc> +8 ; store 1 ; RET ; store 2 ; RET` — what a compiler emits
/// for `if (f()) store 2; else store 1;` when `f` is declared `value [eax]`. `cc` is `0x75` (`JNE`,
/// the FAITHFUL candidate: take the "store 2" arm when the answer is true) or `0x74` (`JE`, the
/// same candidate with the condition inverted).
fn candidate_branching_on_eax(cc: u8) -> Vec<u8> {
    #[rustfmt::skip]
    let v = vec![
        0xe8, 0xfb, 0xbf, 0x00, 0x00,                   // 4000 call 0x10000
        0x85, 0xc0,                                     // 4005 test eax,eax
        cc, 0x08,                                       // 4007 jcc 0x4011
        0xc6, 0x05, 0x00, 0x50, 0x00, 0x00, 0x01,       // 4009 mov byte [0x5000],1
        0xc3,                                           // 4010 ret
        0xc6, 0x05, 0x00, 0x50, 0x00, 0x00, 0x02,       // 4011 mov byte [0x5000],2
        0xc3,                                           // 4018 ret
    ];
    v
}

fn flag_return(flag: u64) -> HashMap<u64, FlagReturn> {
    HashMap::from([(CALLEE, FlagReturn { flag: (flag, 1), reg: (EAX, 4), from: FlagSource::Bit })])
}

fn seed_of(s: u64) -> u64 {
    0x5eed_0000_0000_0000 ^ s.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

/// The bit the ORIGINAL reads out of the flag and the bit the CANDIDATE reads out of the register
/// are the same bit, and it is a BIT: 0 on some seeds and 1 on others.
///
/// This is the whole soundness argument in one property. If the two sides were handed the same
/// CONSTANT they would agree for free and the branch downstream would prove nothing; if they were
/// computed by two expressions they would be one edit away from that. They come from one
/// `call_flag_bit`, and the register is written only on the candidate's side.
#[test]
fn a_flag_returning_callee_answers_the_same_bit_to_both_sides() {
    // CALL 0x10000 ; RET — no branch: just what the call leaves behind.
    let bytes = [0xe8u8, 0xfb, 0xbf, 0x00, 0x00, 0xc3];
    let map = flag_return(CF);
    let (mut zero, mut one) = (0, 0);
    for s in 0..64u64 {
        let orig = run_side(seed_of(s), &bytes, &[], &map, false);
        let cand = run_side(seed_of(s), &bytes, &[], &map, true);
        let bit = orig.read("register", CF, 1);
        assert_eq!(bit, cand.read("register", EAX, 4), "the candidate's register holds the original's flag");
        // ...and the ORIGINAL's side is unchanged: nothing is delivered in the register there.
        assert_ne!(orig.read("register", EAX, 4), bit, "the original must still see a clobbered EAX");
        match bit {
            0 => zero += 1,
            1 => one += 1,
            v => panic!("a flag answer must be one bit, not {v:#x}"),
        }
    }
    assert!(zero > 0 && one > 0, "the answer must VARY with the seed ({zero} zero, {one} one) — a constant proves nothing");
}

/// The branch is a real test again: a candidate that uses the returned condition the way the
/// original does agrees on every seed, and one that INVERTS it or IGNORES it does not.
///
/// The negative controls are the point. Making both sides take the same arm is easy and worthless;
/// what has to be true is that taking the WRONG arm is still caught. Both flags this harness can
/// name are exercised — CF for the `CALL ; JB` idiom, ZF for the `CALL ; JNE` retry.
#[test]
fn a_candidate_that_branches_the_wrong_way_on_a_returned_flag_differs() {
    // Every flag the harness can name: CF for the `CALL ; JB` idiom, ZF for the `CALL ; JNE`
    // retry, SF for `FUN_000166c7`'s three `JNS` on the sign of a 64-bit dot product.
    for (flag, cc, name) in [(CF, 0x72u8, "cf"), (ZF, 0x74, "zf"), (SF, 0x78, "sf")] {
        let map = flag_return(flag);
        let orig = original_branching_on_flag(cc);
        let faithful = candidate_branching_on_eax(0x75); // JNE: take the arm the flag's 1 takes
        let inverted = candidate_branching_on_eax(0x74); // JE: the same source with `if (!f())`
        // ...and a candidate that never looks at the answer at all: CALL ; store 1 ; RET.
        let ignoring =
            vec![0xe8u8, 0xfb, 0xbf, 0x00, 0x00, 0xc6, 0x05, 0x00, 0x50, 0x00, 0x00, 0x01, 0xc3];
        let (mut agree, mut inv_agree, mut ign_agree) = (0, 0, 0);
        let (mut arm1, mut arm2) = (0, 0);
        for s in 0..64u64 {
            let seed = seed_of(s);
            let o = run_side(seed, &orig, &[], &map, false).effects;
            match o.last() {
                Some(emu::Effect::Store(_, SLOT, 1, 1)) => arm1 += 1,
                Some(emu::Effect::Store(_, SLOT, 1, 2)) => arm2 += 1,
                e => panic!("{name}: the original stored nothing recognisable: {e:?}"),
            }
            agree += usize::from(o == run_side(seed, &faithful, &[], &map, true).effects);
            inv_agree += usize::from(o == run_side(seed, &inverted, &[], &map, true).effects);
            ign_agree += usize::from(o == run_side(seed, &ignoring, &[], &map, true).effects);
        }
        assert!(arm1 > 0 && arm2 > 0, "{name}: the original must take BOTH arms across the seeds ({arm1}/{arm2})");
        assert_eq!(agree, 64, "{name}: the faithful candidate must agree on every seed");
        assert_eq!(inv_agree, 0, "{name}: a candidate that inverts the returned condition must DIFFER");
        assert!(ign_agree < 64, "{name}: a candidate that ignores the returned condition must DIFFER somewhere");
    }
}

/// A callee NOT declared as answering in a flag is treated exactly as before: clobbered, and
/// nothing delivered in a register. The feature is opt-in, so no verdict already recorded can
/// change under it.
#[test]
fn a_callee_without_a_flag_contract_is_unchanged() {
    let bytes = [0xe8u8, 0xfb, 0xbf, 0x00, 0x00, 0xc3];
    let empty = HashMap::new();
    for s in 0..16u64 {
        let plain = run_side(seed_of(s), &bytes, &[], &empty, false);
        let asked = run_side(seed_of(s), &bytes, &[], &empty, true);
        assert_eq!(plain.read("register", EAX, 4), asked.read("register", EAX, 4));
        assert_eq!(plain.read("register", CF, 1), asked.read("register", CF, 1));
        assert_eq!(plain.read("register", EAX, 4), run(seed_of(s), &bytes, &[]).read("register", EAX, 4));
    }
}

