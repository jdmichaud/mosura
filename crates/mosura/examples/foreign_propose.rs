//! Foreign-module proposer (`docs/foreign-scope-plan.md`, Phase 1). Reads a binary, proposes
//! locality-clustered anchor **bands** for a human to confirm as foreign or in-scope, and — given a
//! confirmation file — previews the resulting denominator.
//!
//! Read-only: it changes no measurement. It NEVER decides foreign-vs-game itself (a `foo.c` band
//! may be the game's own module); it proposes, the human confirms.
//!
//! ```text
//! cargo run --release --example foreign_propose -- <binary> [--native] [--confirm <file>]
//! ```
use mosura::analysis::{self, foreign};

fn main() {
    let mut args = std::env::args().skip(1);
    let mut path = None;
    let mut native = false;
    let mut confirm: Option<String> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--native" => native = true,
            "--confirm" => confirm = args.next(),
            _ => path = Some(a),
        }
    }
    let path = path.expect("usage: foreign_propose <binary> [--native] [--confirm <file>]");
    let p = std::path::Path::new(&path);
    let prog = if native {
        analysis::analyze_native_file(p).expect("analyze_native_file")
    } else {
        analysis::analyze_le_file(p).expect("analyze_le_file")
    };

    let facts = foreign::extract_facts(&prog);
    let n = facts.fns.len();
    let fid = facts.fns.iter().filter(|f| f.identified).count();
    let anchored = facts.fns.iter().filter(|f| f.anchor.is_some()).count();
    println!("== {path}");
    println!("   {n} functions   {fid} FID/loader-named   {anchored} anchored");

    // Phase 1: propose bands (gap 0x2000 = a page-plus, well above intra-module string spacing).
    let bands = foreign::propose_bands(&facts, 0x2000);
    println!("\n-- proposed module bands (confirm foreign? or reject as game's own):");
    println!(
        "   {:<22} {:<11} {:>5} {:>5} {:>5}  {:<20} example",
        "label", "class", "seeds", "span", "fFP%", "va-range"
    );
    for b in &bands {
        println!(
            "   {:<22} {:<11} {:>5} {:>5} {:>4.0}%  {:<20} {:?}",
            b.label,
            format!("{:?}", b.class),
            b.seeds.len(),
            b.span_fns,
            b.fp_agreement * 100.0,
            format!("{:#08x}..{:#08x}", b.lo, b.hi),
            b.example,
        );
    }

    // Phase 3 preview: classify with the given (or empty) confirmation.
    let conf = match &confirm {
        Some(f) => foreign::Confirmation::load(std::path::Path::new(f)).expect("read confirm file"),
        None => foreign::Confirmation::default(),
    };
    let cls = foreign::classify(&facts, &conf);
    let foreign = cls.foreign_count();
    let denom = n - foreign;
    println!(
        "\n-- classification ({}):",
        confirm.as_deref().unwrap_or("empty confirmation = FID/loader only, default-safe")
    );
    println!("   foreign (excluded): {foreign}   in-scope denominator: {denom}   held (surfaced, not dropped): {}", cls.held.len());
    if !cls.held.is_empty() {
        let show = cls.held.len().min(8);
        println!("   held examples:");
        for (va, why) in cls.held.iter().take(show) {
            println!("     {va:#08x}  {why}");
        }
        if cls.held.len() > show {
            println!("     ... and {} more", cls.held.len() - show);
        }
    }
}
