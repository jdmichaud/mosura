//! `ext-cast=hide-wide` is zc44's promotion-cast hide, ON AN AXIS.
//!
//! Until Order P the hide lived inside `extension_implied_at` — the port of Ghidra's
//! `CastStrategyC::isExtensionCastImplied` (cast.cc:249-297) — as an unconditional early
//! `return true` ahead of Ghidra's own two tests. The port therefore looked complete while being
//! suppressed: measured on the calibrated oracle sweep's clean residue, Ghidra spells the
//! promotion cast at 491 of 1,425 narrow arithmetic operands and we spelled 7 of 1,404, with 486
//! of those 491 (99 %) falling in the hide's opcode list. Being off every axis, it could neither
//! be switched off nor priced.
//!
//! These pin both halves of the repair: the default rendering is Ghidra's again, and the arm
//! reproduces the old behaviour when it is asked for.
//!
//! SELF-COMPILED fixture (examples/watcom_mve_fixtures.rs): `x86_watcom_dowhile_or`, whose body
//! scales a byte global into a table address — `(uint4)uRam00097510 * 10 + 0x87e92`, the
//! int-width value-insensitive shape the hide was built for (an INT_MULT consumer).
use mosura::decompile::emit::EmitChoices;
use mosura::decompile::funcdata::Funcdata;
use mosura::decompile::printc::{print_c, print_c_with};
use mosura::decompile::{build, pipeline};
use mosura::{datatest, paths};

fn decompiled() -> Funcdata {
    let path = paths::oracle_fixtures_dir().join("x86_watcom_dowhile_or.xml");
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id)
        .expect("the vendored x86 SLEIGH tables load (third_party/ghidra/Processors/x86)");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);
    f
}

fn wide_casts(c: &str) -> usize {
    ["(uint4)", "(int4)"].iter().map(|t| c.matches(t).count()).sum()
}

/// The regression this file exists for. `EmitChoices::default()` is the reference rendering — what
/// the oracle sweep and the datatests compare against — so it must be Ghidra's rule alone. With
/// the hide inside the port, this assertion failed on every one of the corpus's promotion sites.
#[test]
fn the_default_rendering_spells_ghidras_promotion_cast() {
    let c = print_c(&decompiled());
    assert!(
        c.contains("(uint4)uRam00097510 * 10"),
        "the byte global is promoted explicitly, as Ghidra prints it:\n{c}"
    );
}

#[test]
fn the_arm_hides_what_the_default_spells() {
    let f = decompiled();
    let reference = print_c(&f);
    let mut hide = EmitChoices::default();
    hide.set("ext-cast", "hide-wide").unwrap();
    let armed = print_c_with(&f, &hide);
    assert!(
        armed.contains("uRam00097510 * 10") && !armed.contains("(uint4)uRam00097510"),
        "the arm prints the bare operand and lets C's promotion widen it:\n{armed}"
    );
    assert!(wide_casts(&armed) < wide_casts(&reference), "the arm hides casts, it does not add them");
}

/// The arm is value-preserving by construction — it fires only at int width and only for consumers
/// whose result cannot depend on the extension — so the two renderings differ ONLY in cast tokens.
/// An arm that rewrote anything else would be a bug with a switch on it (see `emit`'s rule 1).
#[test]
fn the_arm_changes_nothing_but_the_casts() {
    let f = decompiled();
    let mut hide = EmitChoices::default();
    hide.set("ext-cast", "hide-wide").unwrap();
    let strip = |c: &str| c.replace("(uint4)", "").replace("(int4)", "").replace(' ', "");
    assert_eq!(
        strip(&print_c(&f)),
        strip(&print_c_with(&f, &hide)),
        "hiding a promotion cast rewrites nothing else"
    );
}

/// `ext-cast=promotion` — the corpus arm — never reaches either predicate: its zero-extension
/// branch returns the bare operand before the implied-cast test runs. So Order P's repair cannot
/// move the recompile corpus, and this pins that reading rather than leaving it to a round.
#[test]
fn the_promotion_arm_is_unaffected_by_either_predicate() {
    let f = decompiled();
    let mut promo = EmitChoices::default();
    promo.set("ext-cast", "promotion").unwrap();
    let mut hide = EmitChoices::default();
    hide.set("ext-cast", "hide-wide").unwrap();
    let c = print_c_with(&f, &promo);
    assert!(
        !c.contains("(uint4)uRam00097510"),
        "a zero-extension prints bare under `promotion`:\n{c}"
    );
    assert_eq!(
        c,
        print_c_with(&f, &promo),
        "and it is deterministic — the same choices render the same C"
    );
    assert_ne!(c, print_c(&f), "which is not the faithful rendering");
    let _ = hide;
}
