//! What a CALL does to the machine, and what the machine knows about its own bytes.
//!
//! These are the properties the differential-execution instrument (`function.equiv`, api) rests
//! on. Each one was a real defect: a verdict is only as good as the state the two runs start each
//! instruction in, and a piece of state nobody models is a piece both sides agree about for free.

use mosura_core::sleigh::emu::{self, FlagReturn, FlagSource, RegReturn, RunConfig};
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
    let (spec, ctx) = mosura_core::lang::load_cached(LANG).expect("x86:LE:32:default language tables");
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

// ---------------------------------------------------------------------------------------------
// A flag returned by a call that has NO STATIC TARGET.
//
// `CALL dword ptr [0x45320] ; JAE` is the shape `FUN_000140f8` polls its mode-settle vector with,
// and no `callee <va>` contract can describe it: nothing writes 0x45320, so the interpreter fills
// it and the runtime target is a different word on every seed. The key is then the CALL SITE — and
// because a site is an address in the ORIGINAL's text, which the candidate's compiled code does
// not share, the original's run resolves its sites to call ORDINALS
// (`emu::Machine::flag_return_ordinals`) and the candidate's run is driven by those.

/// `CALL [0x45320] ; JB +8 ; store 1 ; RET ; store 2 ; RET` — the ORIGINAL, its call at [`BASE`].
#[rustfmt::skip]
fn original_indirect() -> Vec<u8> {
    vec![
        // 0x45320 is never written, so both runs read the same filled word there and so reach the
        // same (seed-dependent) callee — which is the whole difficulty: it is a DIFFERENT callee
        // on every seed, and no `callee <va>` line can name it.
        0xff, 0x15, 0x20, 0x53, 0x04, 0x00,             // 4000 call dword ptr [0x45320]
        0x72, 0x08,                                     // 4006 jb 0x4010
        0xc6, 0x05, 0x00, 0x50, 0x00, 0x00, 0x01,       // 4008 mov byte [0x5000],1
        0xc3,                                           // 400f ret
        0xc6, 0x05, 0x00, 0x50, 0x00, 0x00, 0x02,       // 4010 mov byte [0x5000],2
        0xc3,                                           // 4017 ret
    ]
}

/// The candidate for it — and its call is at BASE+1, NOT at the annotated site. That is the
/// property under test: a compiler lays the same program out differently, so nothing about the
/// candidate's own addresses may be relied on.
#[rustfmt::skip]
fn candidate_indirect(cc: u8) -> Vec<u8> {
    vec![
        0x90,                                           // 4000 nop
        0xff, 0x15, 0x20, 0x53, 0x04, 0x00,             // 4001 call dword ptr [0x45320]
        0x85, 0xc0,                                     // 4007 test eax,eax
        cc, 0x08,                                       // 4009 jcc 0x4013
        0xc6, 0x05, 0x00, 0x50, 0x00, 0x00, 0x01,       // 400b mov byte [0x5000],1
        0xc3,                                           // 4012 ret
        0xc6, 0x05, 0x00, 0x50, 0x00, 0x00, 0x02,       // 4013 mov byte [0x5000],2
        0xc3,                                           // 401a ret
    ]
}

/// A flag contract keyed by CALL SITE reaches an indirect call, and the branch it feeds is a real
/// test: the faithful candidate agrees on every seed, the inverted one on none, the one that
/// ignores the answer not on all of them — and the candidate run that is NOT given the ordinals
/// the site resolved to does not agree either.
///
/// That last count is the one that keeps this honest. The site key crosses between two programs
/// through exactly one channel, and if the channel were dead the faithful candidate would still be
/// branching on SOMETHING; `unwired` is that same candidate with the channel cut, and it must
/// fail. Without it this test would pass just as well against a model that delivered nothing at
/// all and let both sides read the same clobbered flag.
#[test]
fn a_flag_returned_by_an_indirect_call_is_reachable_by_call_site() {
    let fr = FlagReturn { flag: (CF, 1), reg: (EAX, 4), from: FlagSource::Bit };
    let by_site = HashMap::from([(BASE, fr)]);
    let none = HashMap::new();
    let orig = original_indirect();
    let faithful = candidate_indirect(0x75); // JNE: take the arm the carry's 1 takes
    let inverted = candidate_indirect(0x74); // JE:  the same source with `if (!f())`
    let ignoring = {
        let mut v = vec![0x90u8, 0xff, 0x15, 0x20, 0x53, 0x04, 0x00];
        v.extend_from_slice(&[0xc6, 0x05, 0x00, 0x50, 0x00, 0x00, 0x01, 0xc3]);
        v
    };
    let (mut arm1, mut arm2) = (0, 0);
    let (mut agree, mut inv_agree, mut ign_agree, mut unwired_agree) = (0, 0, 0, 0);
    for s in 0..64u64 {
        let seed = seed_of(s);
        let om = run_full(seed, &orig, &[], &none, &by_site, &none, no_regs(), false);
        // The site is the FIRST call this program makes, every time it runs.
        assert_eq!(om.flag_return_ordinals, vec![(1, fr)], "the site must resolve to the call it names");
        let by_ordinal: HashMap<u64, FlagReturn> = om.flag_return_ordinals.iter().copied().collect();
        match om.effects.last() {
            Some(emu::Effect::Store(_, SLOT, 1, 1)) => arm1 += 1,
            Some(emu::Effect::Store(_, SLOT, 1, 2)) => arm2 += 1,
            e => panic!("the original stored nothing recognisable: {e:?}"),
        }
        let cand = |b: &[u8], ord: &HashMap<u64, FlagReturn>| {
            run_full(seed, b, &[], &none, &none, ord, no_regs(), true).effects
        };
        agree += usize::from(om.effects == cand(&faithful, &by_ordinal));
        inv_agree += usize::from(om.effects == cand(&inverted, &by_ordinal));
        ign_agree += usize::from(om.effects == cand(&ignoring, &by_ordinal));
        unwired_agree += usize::from(om.effects == cand(&faithful, &none));
    }
    assert!(arm1 > 0 && arm2 > 0, "the original must take BOTH arms across the seeds ({arm1}/{arm2})");
    assert_eq!(agree, 64, "the faithful candidate must agree on every seed");
    assert_eq!(inv_agree, 0, "a candidate that inverts the returned condition must DIFFER");
    assert!(ign_agree < 64, "a candidate that ignores the returned condition must DIFFER somewhere");
    assert!(unwired_agree < 64, "the ordinal channel must be load-bearing: cutting it must break agreement");
}

/// A site is resolved to the ORDINAL of the call, so a site inside a LOOP names every pass — which
/// is the shape that matters, since `FUN_000140f8` polls its vector until it answers.
#[test]
fn a_site_inside_a_loop_names_every_pass() {
    let fr = FlagReturn { flag: (CF, 1), reg: (EAX, 4), from: FlagSource::Bit };
    let none = HashMap::new();
    // MOV ESI,3 ; L: CALL [VECTOR] ; DEC ESI ; JNZ L ; RET — ESI is not in the clobber set, so the
    // trip count is fixed and the ordinals are exactly 1, 2, 3.
    #[rustfmt::skip]
    let bytes = vec![
        0xbe, 0x03, 0x00, 0x00, 0x00,                   // 4000 mov esi,3
        0xff, 0x15, 0x20, 0x53, 0x04, 0x00,             // 4005 call dword ptr [0x45320]
        0x4e,                                           // 400b dec esi
        0x75, 0xf7,                                     // 400c jnz 0x4005
        0xc3,                                           // 400e ret
    ];
    let m = run_full(seed_of(1), &bytes, &[], &none, &HashMap::from([(0x4005, fr)]), &none, no_regs(), false);
    assert_eq!(m.flag_return_ordinals, vec![(1, fr), (2, fr), (3, fr)]);
    // ...and a site that is not the first call in the function gets the ordinal it really has.
    #[rustfmt::skip]
    let two = vec![
        0xe8, 0xfb, 0xbf, 0x00, 0x00,                   // 4000 call 0x10000
        0xff, 0x15, 0x20, 0x53, 0x04, 0x00,             // 4005 call dword ptr [0x45320]
        0xc3,                                           // 400b ret
    ];
    let m = run_full(seed_of(1), &two, &[], &none, &HashMap::from([(0x4005, fr)]), &none, no_regs(), false);
    assert_eq!(m.flag_return_ordinals, vec![(2, fr)]);
    // An address that no call is at names nothing, and the run is unchanged. (`equiv_check`
    // refuses such an annotation outright — this only pins that the interpreter cannot be made to
    // invent a delivery from one.)
    let m = run_full(seed_of(1), &two, &[], &none, &HashMap::from([(0x4006, fr)]), &none, no_regs(), false);
    assert!(m.flag_return_ordinals.is_empty());
}

// ---------------------------------------------------------------------------------------------
// A callee whose flag answer is a PREDICATE ON THE VALUE IT RETURNS.
//
// `FUN_0001025d` is the game's key-poll: it leaves the key in EAX and ends `TEST EAX,EAX ; RET`,
// so its ZF says "there was no key" — and its caller reads BOTH, `JE` for the flag and `CMP AL,0x1b`
// for the key. `FlagSource::Bit` cannot express that: it would have to put the flag in EAX and
// the key would be gone. `FlagSource::IsZero` computes the flag from the register instead, on both
// runs, and delivers nothing.

/// `CALL 0x10000 ; JNE -7 ; store 1 ; RET` — poll until the callee answers "zero", the shape of
/// `FUN_0001758f`'s key loop. The trip count is a property of the value the callee returns, so it
/// is the same on both sides only if the flag really is derived from that value.
#[rustfmt::skip]
fn original_polling_until_zero() -> Vec<u8> {
    vec![
        0xe8, 0xfb, 0xbf, 0x00, 0x00,                   // 4000 call 0x10000
        0x75, 0xf9,                                     // 4005 jnz 0x4000
        0xc6, 0x05, 0x00, 0x50, 0x00, 0x00, 0x01,       // 4007 mov byte [0x5000],1
        0xc3,                                           // 400e ret
    ]
}

/// The candidate: `k = f(); while (k != 0) k = f();` — it tests the returned VALUE itself.
#[rustfmt::skip]
fn candidate_polling_on_eax(cc: u8) -> Vec<u8> {
    vec![
        0xe8, 0xfb, 0xbf, 0x00, 0x00,                   // 4000 call 0x10000
        0x85, 0xc0,                                     // 4005 test eax,eax
        cc, 0xf7,                                       // 4007 jcc 0x4000
        0xc6, 0x05, 0x00, 0x50, 0x00, 0x00, 0x01,       // 4009 mov byte [0x5000],1
        0xc3,                                           // 4010 ret
    ]
}

/// A derived flag is COMPUTED from the register on both runs, and nothing is delivered: the
/// register still holds the callee's ordinary clobber, which is the point — the caller reads it.
#[test]
fn a_derived_flag_is_the_predicate_on_the_value_the_callee_returns() {
    let bytes = [0xe8u8, 0xfb, 0xbf, 0x00, 0x00, 0xc3]; // CALL 0x10000 ; RET
    let plain = HashMap::new();
    for (from, flag, name) in
        [(FlagSource::IsZero, ZF, "zf"), (FlagSource::IsNegative, SF, "sf")]
    {
        let map = HashMap::from([(CALLEE, FlagReturn { flag: (flag, 1), reg: (EAX, 4), from })]);
        let (mut zero, mut one) = (0, 0);
        for s in 0..4096u64 {
            let m = run_side(seed_of(s), &bytes, &[], &map, false);
            let eax = m.read("register", EAX, 4);
            let want = match from {
                FlagSource::IsZero => u64::from(eax == 0),
                _ => eax >> 31,
            };
            assert_eq!(m.read("register", flag, 1), want, "{name}: the flag must be the predicate on EAX");
            // NOTHING is delivered in the register: it is the ordinary clobber, the same value the
            // run would have had with no contract at all, and the same on the candidate's side.
            assert_eq!(eax, run(seed_of(s), &bytes, &[]).read("register", EAX, 4), "{name}: EAX untouched");
            assert_eq!(eax, run_side(seed_of(s), &bytes, &[], &map, true).read("register", EAX, 4));
            assert_eq!(run_side(seed_of(s), &bytes, &[], &plain, false).read("register", EAX, 4), eax);
            match want {
                0 => zero += 1,
                _ => one += 1,
            }
        }
        assert!(zero > 0 && one > 0, "{name}: the answer must VARY over the seeds ({zero}/{one})");
    }
}

/// The poll loop runs as often as the returned VALUE says, and a candidate that tests it the wrong
/// way round does not.
///
/// `unwired` is the control that matters here too: the same faithful candidate against an original
/// whose ZF is the independent clobber bit rather than the predicate. That original leaves the
/// loop after about two passes and the candidate after about two hundred and fifty, so it must
/// disagree — which is exactly the divergence `FUN_0001758f` was stuck on.
#[test]
fn a_candidate_that_tests_a_derived_flag_the_wrong_way_differs() {
    let map = HashMap::from([(CALLEE, FlagReturn { flag: (ZF, 1), reg: (EAX, 4), from: FlagSource::IsZero })]);
    let none = HashMap::new();
    let orig = original_polling_until_zero();
    let faithful = candidate_polling_on_eax(0x75); // JNE: poll again while the value is non-zero
    let inverted = candidate_polling_on_eax(0x74); // JE:  poll again while it is zero
    let ignoring = vec![0xe8u8, 0xfb, 0xbf, 0x00, 0x00, 0xc6, 0x05, 0x00, 0x50, 0x00, 0x00, 0x01, 0xc3];
    let (mut agree, mut inv_agree, mut ign_agree, mut unwired_agree) = (0, 0, 0, 0);
    let (mut passes, mut longest) = (0usize, 0usize);
    for s in 0..64u64 {
        let seed = seed_of(s);
        let o = run_side(seed, &orig, &[], &map, false).effects;
        let n = o.iter().filter(|e| matches!(e, emu::Effect::Call(..))).count();
        passes += n;
        longest = longest.max(n);
        agree += usize::from(o == run_side(seed, &faithful, &[], &map, true).effects);
        inv_agree += usize::from(o == run_side(seed, &inverted, &[], &map, true).effects);
        ign_agree += usize::from(o == run_side(seed, &ignoring, &[], &map, true).effects);
        let unwired = run_side(seed, &orig, &[], &none, false).effects;
        unwired_agree += usize::from(unwired == run_side(seed, &faithful, &[], &none, true).effects);
    }
    assert!(longest > 4 && passes > 64, "the poll loop must really loop ({passes} passes, longest {longest})");
    assert_eq!(agree, 64, "the faithful candidate must agree on every seed");
    assert!(inv_agree <= 2, "a candidate that inverts the derived test must DIFFER ({inv_agree}/64)");
    assert!(ign_agree <= 2, "a candidate that never loops must DIFFER ({ign_agree}/64)");
    assert!(unwired_agree < 32, "without the contract the flag is an independent coin and the two must part ({unwired_agree}/64)");
}

// ---------------------------------------------------------------------------------------------
// A callee that answers in a REGISTER THE CANDIDATE'S C CANNOT NAME.
//
// The other half of the indirect-call wall. `CALL CS:[EDI*4+0x20e42]` in `FUN_00020dba` reaches a
// boundary-push routine that hands the clipped point back as X in EAX and Y in EBX, and the caller
// publishes both with `XCHG mem,reg`. Watcom 10.0a honours no `#pragma aux` form on a function
// POINTER, so a `code *` call returns `int` in EAX and that is the ONLY register C can name at an
// indirect call; the X half is therefore expressible and the Y half is not. `RegReturn` delivers
// the ORIGINAL's EBX fill into the register a second channel — the EDX half of a
// `double (*)(void)` return under `-fpc` — puts it in on the CANDIDATE's side.
//
// These tests are what says that channel is a real one: the same value on both sides, computed
// once, varying with the seed, and load-bearing enough that reading the WRONG register still
// DIFFERS. Without the last part the model would be hollow.

/// `CALL [0x45320] ; MOV [0x5000],EBX ; RET` — the ORIGINAL: publish what the indirect callee left
/// in EBX. Its call is at [`BASE`], the address a `site` contract names.
#[rustfmt::skip]
fn original_publishing_ebx() -> Vec<u8> {
    vec![
        0xff, 0x15, 0x20, 0x53, 0x04, 0x00,             // 4000 call dword ptr [0x45320]
        0x89, 0x1d, 0x00, 0x50, 0x00, 0x00,             // 4006 mov [0x5000],ebx
        0xc3,                                           // 400c ret
    ]
}

/// The candidate for it, publishing whatever register `modrm` names — and its call is at BASE+1,
/// NOT at the annotated site, because a compiler lays the same program out differently and nothing
/// about the candidate's own addresses may be relied on.
///
/// `0x15` is EDX (what the second channel delivers into), `0x05` EAX (the ordinary `code *` return,
/// i.e. a candidate that read the WRONG half), `0x0d` ECX (a register nothing was delivered to).
#[rustfmt::skip]
fn candidate_publishing(modrm: u8) -> Vec<u8> {
    vec![
        0x90,                                           // 4000 nop
        0xff, 0x15, 0x20, 0x53, 0x04, 0x00,             // 4001 call dword ptr [0x45320]
        0x89, modrm, 0x00, 0x50, 0x00, 0x00,            // 4007 mov [0x5000],<reg>
        0xc3,                                           // 400d ret
    ]
}

/// The candidate's named register is handed the SAME value the original's named register gets, and
/// it is a VALUE: different on (almost) every seed, and different from what the candidate's own
/// register would otherwise have held.
///
/// This is the soundness argument in one property, and it is the register twin of
/// `a_flag_returning_callee_answers_the_same_bit_to_both_sides`. Both places come from ONE
/// `call_clobber_fill` at ONE offset — the SOURCE register's — so they cannot drift; and because
/// that fill depends on the offset, the delivered value is NOT what EDX would have held, which is
/// exactly why reading the wrong register is detectable.
#[test]
fn a_register_returning_callee_answers_the_same_value_to_both_sides() {
    let rr = RegReturn { src: (EBX, 4), dst: (EDX, 4) };
    let by_site = HashMap::from([(BASE, rr)]);
    let (nof, none): (HashMap<u64, FlagReturn>, HashMap<u64, RegReturn>) = (HashMap::new(), HashMap::new());
    let bytes = [0xffu8, 0x15, 0x20, 0x53, 0x04, 0x00, 0xc3]; // CALL [0x45320] ; RET
    let mut differed_from_own_fill = 0;
    for s in 0..64u64 {
        let seed = seed_of(s);
        let orig = run_full(seed, &bytes, &[], &nof, &nof, &nof, (&none, &by_site, &none), false);
        let ord: HashMap<u64, RegReturn> = orig.reg_return_ordinals.iter().copied().collect();
        assert_eq!(orig.reg_return_ordinals, vec![(1, rr)], "the site must resolve to the call it names");
        let cand = run_full(seed, &bytes, &[], &nof, &nof, &nof, (&none, &none, &ord), true);
        let answer = orig.read("register", EBX, 4);
        assert_eq!(answer, cand.read("register", EDX, 4), "the candidate's EDX holds the original's EBX");
        // ...and NOTHING is delivered on the original's side: its EDX is the ordinary clobber, the
        // same value it has with no contract at all.
        assert_eq!(
            orig.read("register", EDX, 4),
            run(seed, &bytes, &[]).read("register", EDX, 4),
            "the original's own EDX must be untouched"
        );
        // The delivery is not a no-op dressed up as one: EDX's own fill is a different value from
        // EBX's on essentially every seed, which is what makes the wrong-register control below
        // fail. (Both are replicated bytes, so a collision is a 1-in-256 event, not impossible.)
        differed_from_own_fill += usize::from(answer != orig.read("register", EDX, 4));
        assert_ne!(answer, 0, "a replicated-byte fill of zero would make the controls vacuous");
    }
    assert!(
        differed_from_own_fill > 55,
        "the delivered value must differ from the register's own fill ({differed_from_own_fill}/64)"
    );
}

/// THE NEGATIVE CONTROL. A candidate that publishes the register the delivery names agrees on every
/// seed; one that publishes the ordinary `code *` return instead, or a register nothing was
/// delivered to, does not — and neither does the faithful candidate with the ordinal channel cut.
///
/// `unwired` is the one that keeps this honest. The site key crosses between the two programs
/// through exactly one channel, and if that channel were dead the faithful candidate would still be
/// publishing SOMETHING; without this the test would pass just as well against a model that
/// delivered nothing at all.
#[test]
fn a_candidate_that_reads_the_wrong_register_after_a_call_differs() {
    let rr = RegReturn { src: (EBX, 4), dst: (EDX, 4) };
    let by_site = HashMap::from([(BASE, rr)]);
    let none = HashMap::new();
    let orig = original_publishing_ebx();
    let nof: HashMap<u64, FlagReturn> = HashMap::new();
    let (mut agree, mut wrong_eax, mut wrong_ecx, mut unwired) = (0, 0, 0, 0);
    for s in 0..64u64 {
        let seed = seed_of(s);
        let om = run_full(seed, &orig, &[], &nof, &nof, &nof, (&none, &by_site, &none), false);
        assert!(
            matches!(om.effects.last(), Some(emu::Effect::Store(_, SLOT, 4, _))),
            "the original must publish its EBX: {:?}",
            om.effects
        );
        let ord: HashMap<u64, RegReturn> = om.reg_return_ordinals.iter().copied().collect();
        let cand = |modrm: u8, o: &HashMap<u64, RegReturn>| {
            run_full(seed, &candidate_publishing(modrm), &[], &nof, &nof, &nof, (&none, &none, o), true).effects
        };
        agree += usize::from(om.effects == cand(0x15, &ord));
        wrong_eax += usize::from(om.effects == cand(0x05, &ord));
        wrong_ecx += usize::from(om.effects == cand(0x0d, &ord));
        unwired += usize::from(om.effects == cand(0x15, &none));
    }
    assert_eq!(agree, 64, "the faithful candidate must agree on every seed");
    assert!(wrong_eax <= 1, "a candidate that reads the call's ordinary EAX return must DIFFER ({wrong_eax}/64)");
    assert!(wrong_ecx <= 1, "a candidate that reads a register nothing was delivered to must DIFFER ({wrong_ecx}/64)");
    assert!(unwired <= 1, "the ordinal channel must be load-bearing: cutting it must break agreement ({unwired}/64)");
}

/// The same contract keyed by call TARGET, for a DIRECT call — and the ordinals a site resolves to
/// are recorded per call, so a site inside a loop names every pass.
#[test]
fn a_register_contract_can_be_keyed_by_callee_or_by_ordinal() {
    let rr = RegReturn { src: (EBX, 4), dst: (EDX, 4) };
    let (nof, none): (HashMap<u64, FlagReturn>, HashMap<u64, RegReturn>) = (HashMap::new(), HashMap::new());
    // CALL 0x10000 ; MOV [0x5000],EBX ; RET, and the candidate that publishes EDX instead.
    #[rustfmt::skip]
    let orig = vec![0xe8u8, 0xfb, 0xbf, 0x00, 0x00, 0x89, 0x1d, 0x00, 0x50, 0x00, 0x00, 0xc3];
    #[rustfmt::skip]
    let cand = vec![0xe8u8, 0xfb, 0xbf, 0x00, 0x00, 0x89, 0x15, 0x00, 0x50, 0x00, 0x00, 0xc3];
    let by_target = HashMap::from([(CALLEE, rr)]);
    for s in 0..32u64 {
        let seed = seed_of(s);
        let o = run_full(seed, &orig, &[], &nof, &nof, &nof, (&by_target, &none, &none), false);
        let c = run_full(seed, &cand, &[], &nof, &nof, &nof, (&by_target, &none, &none), true);
        assert_eq!(o.effects, c.effects, "a target-keyed register contract reaches a direct call");
        // ...and a target key records no ordinals: only a SITE has to cross between the two runs.
        assert!(o.reg_return_ordinals.is_empty());
    }
    // MOV ESI,3 ; L: CALL [VECTOR] ; DEC ESI ; JNZ L ; RET — ESI is not in the clobber set, so the
    // trip count is fixed and the ordinals are exactly 1, 2, 3.
    #[rustfmt::skip]
    let loop_bytes = vec![
        0xbe, 0x03, 0x00, 0x00, 0x00,                   // 4000 mov esi,3
        0xff, 0x15, 0x20, 0x53, 0x04, 0x00,             // 4005 call dword ptr [0x45320]
        0x4e,                                           // 400b dec esi
        0x75, 0xf7,                                     // 400c jnz 0x4005
        0xc3,                                           // 400e ret
    ];
    let sites = HashMap::from([(0x4005, rr)]);
    let m = run_full(seed_of(1), &loop_bytes, &[], &nof, &nof, &nof, (&none, &sites, &none), false);
    assert_eq!(m.reg_return_ordinals, vec![(1, rr), (2, rr), (3, rr)]);
    // An address no call is at names nothing. (`equiv_check` refuses such an annotation outright;
    // this only pins that the interpreter cannot be made to invent a delivery from one.)
    let sites = HashMap::from([(0x4006, rr)]);
    let m = run_full(seed_of(1), &loop_bytes, &[], &nof, &nof, &nof, (&none, &sites, &none), false);
    assert!(m.reg_return_ordinals.is_empty());
}

/// A call with NO register contract is treated exactly as before, on both sides. The feature is
/// opt-in, so no verdict already recorded can change under it — including every flag-model verdict,
/// whose runs now go through the same `call_clobber_fill` the delivery does.
#[test]
fn a_callee_without_a_register_contract_is_unchanged() {
    let bytes = [0xffu8, 0x15, 0x20, 0x53, 0x04, 0x00, 0xc3];
    let none: HashMap<u64, FlagReturn> = HashMap::new();
    for s in 0..32u64 {
        let plain = run(seed_of(s), &bytes, &[]);
        let asked = run_full(seed_of(s), &bytes, &[], &none, &none, &none, no_regs(), true);
        for &(off, name) in &[(EAX, "eax"), (ECX, "ecx"), (EDX, "edx"), (EBX, "ebx")] {
            assert_eq!(plain.read("register", off, 4), asked.read("register", off, 4), "{name}");
        }
    }
}

/// A flag contract and a register contract on the SAME call are independent channels: the flag
/// answer still reaches the flag on both runs and the candidate's flag register, and the register
/// answer still reaches the candidate's other register. (`equiv_check` refuses the one arrangement
/// that would make them collide — a register delivery into the flag's register.)
#[test]
fn a_flag_and_a_register_contract_can_share_one_call() {
    let fr = FlagReturn { flag: (CF, 1), reg: (EAX, 4), from: FlagSource::Bit };
    let rr = RegReturn { src: (EBX, 4), dst: (EDX, 4) };
    let (nof, none): (HashMap<u64, FlagReturn>, HashMap<u64, RegReturn>) = (HashMap::new(), HashMap::new());
    let regs = HashMap::from([(BASE, rr)]);
    let bytes = [0xffu8, 0x15, 0x20, 0x53, 0x04, 0x00, 0xc3];
    for s in 0..32u64 {
        let seed = seed_of(s);
        let o = run_full(seed, &bytes, &[], &nof, &HashMap::from([(BASE, fr)]), &nof, (&none, &regs, &none), false);
        let fo: HashMap<u64, FlagReturn> = o.flag_return_ordinals.iter().copied().collect();
        let ro: HashMap<u64, RegReturn> = o.reg_return_ordinals.iter().copied().collect();
        let c = run_full(seed, &bytes, &[], &nof, &nof, &fo, (&none, &none, &ro), true);
        assert_eq!(o.read("register", CF, 1), c.read("register", EAX, 4), "the flag answer still crosses");
        assert_eq!(o.read("register", EBX, 4), c.read("register", EDX, 4), "the register answer still crosses");
    }
}
