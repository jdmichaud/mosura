//! Ghidra `PrintC::pushConstant` prints a constant signed ONLY when its read-facing type is
//! `TYPE_INT` (`push_integer(…, sign=true)`); `TYPE_UINT`/`TYPE_UNKNOWN` print unsigned. mosura's
//! type-blind renderer printed every narrow high-bit constant as a negative, so a 1-byte unsigned
//! compare `cmp al,0xfe ; jb` became `-3 < param_1` — which C's integer promotion folds to
//! always-false: wrong code (60 sites / 20 the subject TUs, wc2src-reconcile). Now `0xfd < param_1`.
use mosura::decompile::printc::print_c;
use mosura::decompile::{build, pipeline};
use mosura::{datatest, paths};

#[test]
fn narrow_unsigned_compare_prints_unsigned_literal() {
    let path = paths::oracle_fixtures_dir().join("x86_uint_cmp_literal.xml");
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id).expect("x86 SLEIGH tables load");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);
    let c = print_c(&f);
    assert!(c.contains("0xfd < param_1") || c.contains("param_1 < 0xfe"), "unsigned literal:\n{c}");
    assert!(!c.contains("-3") && !c.contains("-2"), "no signed rendering of an unsigned byte literal:\n{c}");
}

#[test]
fn char_constant_stays_signed() {
    // `char` is TYPE_INT in Ghidra: the -1 added to a sign-extended byte prints signed, not 0xff.
    let path = paths::oracle_fixtures_dir().join("x86_char_add_neg.xml");
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id).expect("x86 SLEIGH tables load");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);
    let c = print_c(&f);
    assert!(!c.contains("0xff") && (c.contains("-1") || c.contains("- 1")), "signed char literal:\n{c}");
}
