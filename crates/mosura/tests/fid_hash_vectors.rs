//! Stage 1 gate (`docs/fid-port-plan.md` §5): the FID hasher's building blocks and its
//! defining behaviours.
//!
//! Byte-exact agreement with Ghidra's own hasher is **Stage 3** — that gate looks mosura's
//! quads up in Ghidra's shipped databases. What is asserted here is everything that can be
//! pinned without Ghidra: the FNV-1a digest against *published* vectors (external truth, not
//! our own arithmetic replayed), the big-endian int feed, the skipper table, the relocation
//! narrowing, and the full-vs-specific hash split that the whole scheme rests on.
//!
//! Each test is written so it *can* fail: the full/specific tests contrast two bodies that
//! differ in exactly one way, and assert which digest moves and which does not.

use mosura::analysis::fid::hash::{
    CodeUnitInput, FidHasher, Fnv1a64, NoOperandReferences, NoRelocations, RelocationQuery,
    Skipper,
};
use mosura::lang;
use mosura::sleigh::InstructionFingerprint;

const LANG: &str = "x86:LE:32:default";

// ---------------------------------------------------------------------------------------
// FNV-1a 64 — published vectors
// ---------------------------------------------------------------------------------------

/// The canonical FNV-1a 64-bit test vectors (Landon Curt Noll's reference set). These are
/// external ground truth: if the basis, the prime, the xor-then-multiply order, or the
/// 64-bit wrapping were wrong, none of them would land.
#[test]
fn fnv1a64_published_vectors() {
    for (input, expected) in [
        ("", 0xcbf2_9ce4_8422_2325u64),
        ("a", 0xaf63_dc4c_8601_ec8c),
        ("b", 0xaf63_df4c_8601_f1a5),
        ("foobar", 0x8594_4171_f739_67e8),
    ] {
        let mut d = Fnv1a64::new();
        d.update_bytes(input.as_bytes());
        assert_eq!(d.digest_long(), expected, "FNV-1a 64 of {input:?}");
    }
}

/// `digestLong` returns the raw state **and re-initialises** — so the same digest object
/// reused gives the same answer, rather than continuing to accumulate.
#[test]
fn digest_long_resets_state() {
    let mut d = Fnv1a64::new();
    d.update_bytes(b"foobar");
    let first = d.digest_long();
    d.update_bytes(b"foobar");
    assert_eq!(d.digest_long(), first, "digestLong re-inits, so a reuse repeats");
}

/// `AbstractMessageDigest.update(int)` feeds bytes **MSB first**. Asserting equality with the
/// big-endian byte feed alone would pass for a symmetric value, so this also asserts the
/// little-endian feed differs — the mistake this test exists to catch.
#[test]
fn update_i32_is_big_endian() {
    let value: i32 = 0x1122_3344;

    let mut via_int = Fnv1a64::new();
    via_int.update_i32(value);

    let mut via_be = Fnv1a64::new();
    via_be.update_bytes(&[0x11, 0x22, 0x33, 0x44]);

    let mut via_le = Fnv1a64::new();
    via_le.update_bytes(&[0x44, 0x33, 0x22, 0x11]);

    let int_hash = via_int.digest_long();
    assert_eq!(int_hash, via_be.digest_long(), "update(int) is MSB-first");
    assert_ne!(int_hash, via_le.digest_long(), "and is NOT little-endian");
}

// ---------------------------------------------------------------------------------------
// The x86 skipper table
// ---------------------------------------------------------------------------------------

/// `X86InstructionSkipper.shouldSkip` requires the pattern to match the code unit's **whole
/// length**. Two chained one-byte NOPs are two skipped units; a single two-byte unit whose
/// bytes happen to start with 0x90 is not a match at all.
#[test]
fn x86_skipper_matches_whole_unit_only() {
    let s = Skipper::X86;

    assert!(s.should_skip(&[0x90]), "one-byte NOP");
    assert!(s.should_skip(&[0x8b, 0xc0]), "mov eax,eax NOP form");
    assert!(s.should_skip(&[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]), "9-byte NOP");

    assert!(!s.should_skip(&[0x90, 0x90]), "length must match the pattern exactly");
    assert!(!s.should_skip(&[0x8b, 0xc1]), "mov eax,ecx is a real move, not a NOP");
    assert!(!s.should_skip(&[0x0f, 0x1f]), "truncated pattern");
    assert!(!s.should_skip(&[]), "empty unit");
}

/// Skippers are selected by **processor**, and every processor except x86 has none
/// registered (`FidService.getHasher` falls back to an empty list).
#[test]
fn skipper_selected_by_processor() {
    assert_eq!(Skipper::for_language("x86:LE:32:default"), Skipper::X86);
    assert_eq!(Skipper::for_language("x86:LE:64:default"), Skipper::X86);
    assert_eq!(Skipper::for_language("AARCH64:LE:64:v8A"), Skipper::None);
    assert_eq!(Skipper::for_language("68000:BE:32:Coldfire"), Skipper::None);

    // A 0x90 byte on AArch64 is not a NOP-to-skip; nothing is skipped there.
    assert!(!Skipper::None.should_skip(&[0x90]));
}

// ---------------------------------------------------------------------------------------
// End-to-end over real disassembly
// ---------------------------------------------------------------------------------------

/// Disassemble one contiguous x86-32 body and hash it. Returns `None` when the SLEIGH tables
/// are unavailable (the `sleigh_canary` suite fails loudly if that happens in CI).
fn hash_body(bytes: &[u8], relocations: &dyn RelocationQuery) -> Option<mosura::analysis::fid::hash::FidHashQuad> {
    let (spec, ctx) = lang::load(LANG)?;
    let base = 0x1000u64;
    let insns = spec.disassemble_ctx(bytes, base, &ctx);
    let fps: Vec<InstructionFingerprint> = spec.disassemble_fingerprint(bytes, base, &ctx);
    assert_eq!(insns.len(), fps.len(), "one fingerprint per instruction");

    let units: Vec<CodeUnitInput> = insns
        .iter()
        .zip(&fps)
        .map(|(insn, fp)| CodeUnitInput {
            min_address: insn.address,
            max_address: insn.address + insn.bytes.len() as u64 - 1,
            bytes: &insn.bytes,
            fingerprint: Some(fp),
            is_call: None,
        })
        .collect();

    FidHasher::new(Skipper::X86).hash(&units, relocations, &NoOperandReferences)
}

/// A 4-instruction body: `push ebp; mov ebp,esp; add eax,imm8; ret`.
fn body_with_immediate(imm: u8) -> Vec<u8> {
    vec![0x55, 0x89, 0xe5, 0x83, 0xc0, imm, 0xc3]
}

/// **The defining property of the scheme.** Change only a scalar operand's *value* and the
/// full hash must not move (it masks the operand bits out and substitutes a placeholder),
/// while the specific hash must move (it folds the real small scalar in).
///
/// This is the test that fails if the masking, the placeholder substitution, or the
/// full/specific split is wrong in either direction.
#[test]
fn full_hash_ignores_scalar_value_specific_hash_does_not() {
    let Some(a) = hash_body(&body_with_immediate(0x10), &NoRelocations) else { return };
    let Some(b) = hash_body(&body_with_immediate(0x20), &NoRelocations) else { return };

    assert_eq!(a.full_hash, b.full_hash, "full hash masks the immediate's value");
    assert_ne!(a.specific_hash, b.specific_hash, "specific hash folds the real value in");

    assert_eq!(a.code_unit_size, 4, "four instructions, no calls");
    assert_eq!(a.code_unit_size, b.code_unit_size);
    assert_eq!(
        a.specific_hash_additional_size, b.specific_hash_additional_size,
        "the same number of scalars qualified in both"
    );
    assert!(
        a.specific_hash_additional_size >= 1,
        "the immediate is a small scalar, so it counts toward the specific size"
    );
}

/// Changing a *register* changes the full hash: registers are mixed into both digests
/// (`:171-177`), unlike scalars. `mov ebp,esp` vs `mov ebx,esp`.
#[test]
fn full_hash_tracks_register_choice() {
    let with_ebp = vec![0x55, 0x89, 0xe5, 0x83, 0xc0, 0x10, 0xc3];
    let with_ebx = vec![0x55, 0x89, 0xe3, 0x83, 0xc0, 0x10, 0xc3];

    let Some(a) = hash_body(&with_ebp, &NoRelocations) else { return };
    let Some(b) = hash_body(&with_ebx, &NoRelocations) else { return };

    assert_ne!(a.full_hash, b.full_hash, "a different register is a different function");
    assert_ne!(a.specific_hash, b.specific_hash);
}

/// `codeUnitSize = codeUnitIndex - callCount` — calls are hashed but subtracted from the
/// size, so a call-heavy body does not score as if it were large.
#[test]
fn calls_are_subtracted_from_code_unit_size() {
    // push ebp; mov ebp,esp; call rel32(+5); ret = 4 instructions, 1 of them a call.
    // The displacement must be non-zero — see `zero_displacement_call_is_not_a_call`.
    let with_call = vec![0x55, 0x89, 0xe5, 0xe8, 0x05, 0x00, 0x00, 0x00, 0xc3];
    let Some(q) = hash_body(&with_call, &NoRelocations) else { return };
    assert_eq!(q.code_unit_size, 3, "4 code units - 1 call");

    // Same shape with a non-call 5-byte instruction (mov eax,imm32) in place of the call.
    let no_call = vec![0x55, 0x89, 0xe5, 0xb8, 0x05, 0x00, 0x00, 0x00, 0xc3];
    let Some(q2) = hash_body(&no_call, &NoRelocations) else { return };
    assert_eq!(q2.code_unit_size, 4, "no call to subtract");
}

/// `E8` with a **zero** displacement — `call $+5`, the classic position-independent-code
/// idiom for reading EIP — is deliberately *not* a call in Ghidra's x86 spec. `ia.sinc:2964`
/// declares a separate, more specific constructor (`simm32=0 & rel32`) whose semantics are
/// `goto`, not `call`, so the flow type is a branch and FID does not subtract it from the
/// code-unit size.
///
/// This is asserted because it is surprising, and because the first version of the test above
/// used a zero displacement and measured the wrong thing.
#[test]
fn zero_displacement_call_is_not_a_call() {
    let call_next = vec![0x55, 0x89, 0xe5, 0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3];
    let Some(q) = hash_body(&call_next, &NoRelocations) else { return };
    assert_eq!(
        q.code_unit_size, 4,
        "`call $+5` lifts to `goto` (ia.sinc:2964), so there is no call to subtract"
    );
}

/// Below the short-hash floor of 4 code units the hasher declines to produce a quad —
/// checked on the raw extent before the walk, and again on the post-skip count after it.
#[test]
fn short_bodies_are_not_hashed() {
    // push ebp; mov ebp,esp; ret = 3 code units.
    assert!(hash_body(&[0x55, 0x89, 0xe5, 0xc3], &NoRelocations).is_none(), "3 units < 4");
    // One more instruction clears the floor.
    assert!(hash_body(&[0x55, 0x89, 0xe5, 0x40, 0xc3], &NoRelocations).is_some(), "4 units");
}

/// NOP padding is skipped entirely: neither hashed nor counted. A body padded with the
/// multi-byte NOP forms must hash identically to the same body without them — that is what
/// makes a signature survive a different alignment choice.
#[test]
fn nop_padding_does_not_change_the_hash() {
    let plain = vec![0x55, 0x89, 0xe5, 0x83, 0xc0, 0x10, 0xc3];
    let mut padded = plain.clone();
    padded.extend_from_slice(&[0x90]); // 1-byte NOP
    padded.extend_from_slice(&[0x66, 0x90]); // 2-byte NOP
    padded.extend_from_slice(&[0x0f, 0x1f, 0x00]); // 3-byte NOP

    let Some(a) = hash_body(&plain, &NoRelocations) else { return };
    let Some(b) = hash_body(&padded, &NoRelocations) else { return };

    assert_eq!(a.full_hash, b.full_hash, "skipped units are not hashed");
    assert_eq!(a.specific_hash, b.specific_hash);
    assert_eq!(a.code_unit_size, b.code_unit_size, "and are not counted");
}

// ---------------------------------------------------------------------------------------
// Relocation narrowing
// ---------------------------------------------------------------------------------------

/// A relocation table covering one inclusive offset range.
struct RelocRange(u64, u64);

impl RelocationQuery for RelocRange {
    fn any_in_range(&self, min_offset: u64, max_offset: u64) -> bool {
        min_offset <= self.1 && self.0 <= max_offset
    }
}

/// `hasRelocation` narrows the code unit's range to the span of the operand mask's non-zero
/// bytes before querying. A relocation **on the immediate's byte** must suppress the scalar
/// (it is part of an address the loader will patch), collapsing the specific hash onto the
/// value-independent one; a relocation on a byte the operand mask does not cover must not.
///
/// Both directions are asserted, so a `has_relocation` that always answered the same way —
/// or that skipped the narrowing and queried the whole instruction — fails.
#[test]
fn relocation_narrowing_gates_the_scalar() {
    // `add eax,0x10` sits at 0x1003..=0x1005; its imm8 is the last byte, 0x1005.
    let body = body_with_immediate(0x10);

    let Some(baseline) = hash_body(&body, &NoRelocations) else { return };
    let Some(on_immediate) = hash_body(&body, &RelocRange(0x1005, 0x1005)) else { return };
    let Some(off_immediate) = hash_body(&body, &RelocRange(0x1003, 0x1003)) else { return };

    assert_ne!(
        baseline.specific_hash, on_immediate.specific_hash,
        "a relocation on the immediate suppresses its value"
    );
    assert_eq!(
        baseline.specific_hash, off_immediate.specific_hash,
        "a relocation on the opcode byte is outside the operand mask's span"
    );

    assert_eq!(
        baseline.full_hash, on_immediate.full_hash,
        "the full hash never used the value, so relocations cannot move it"
    );

    // The suppressed scalar no longer counts toward the specific size.
    assert!(
        on_immediate.specific_hash_additional_size < baseline.specific_hash_additional_size,
        "a suppressed scalar stops counting: {} should be < {}",
        on_immediate.specific_hash_additional_size,
        baseline.specific_hash_additional_size
    );
}

/// With no relocation table — the normal case for the statically-linked libraries FID
/// identifies — nothing is suppressed.
#[test]
fn no_relocations_suppresses_nothing() {
    let body = body_with_immediate(0x10);
    let Some(a) = hash_body(&body, &NoRelocations) else { return };
    let Some(b) = hash_body(&body, &RelocRange(0xffff_0000, 0xffff_0000)) else { return };
    assert_eq!(a.specific_hash, b.specific_hash, "a far-away relocation changes nothing");
    assert_eq!(a.specific_hash_additional_size, b.specific_hash_additional_size);
}
