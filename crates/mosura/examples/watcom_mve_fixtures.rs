//! Generate the committed watcom fixtures from SELF-COMPILED minimal examples — no game bytes
//! (third-party policy; directive #6). Compiles each MVE with the in-house Watcom 10.0a via the
//! recompile toolchain, extracts the function's code from the OMF object, and prints the fixture
//! XML with the source embedded as a comment. Committed alongside the fixtures it generates, so provenance and regeneration stay in-repo.
//!
//! Usage: watcom_mve_fixtures <WATCOM-dir> <out-dir>
//!        watcom_mve_fixtures --check <WATCOM-dir>   — regenerate into a temp dir and diff against
//!        oracle/fixtures; exit 1 on any difference, on a missing product, or on an ORPHAN (a
//!        committed fixture carrying the generator's header that is not a product of this
//!        generator — nothing could regenerate it). On failure the temp dir is kept and its path
//!        printed. The manual pre-landing step for anything that touches a fixture (it needs the
//!        in-house wcc386, so it is not a unit test).
use mosura::recompile::candidate::load_object_function;
use mosura::recompile::toolchain::{spec, CompileUnit, CompilerDriver, DriverRole, Toolchain};


/// The first line of every product; `tests/fixture_provenance.rs` keys the generator-product bar on it.
const GENERATED_MARKER: &str = "<!-- SELF-COMPILED fixture: wcc386";


fn main() {
    const USAGE: &str = "usage: watcom_mve_fixtures <WATCOM-dir> <out-dir> | watcom_mve_fixtures --check <WATCOM-dir>";
    let (flags_only, positional): (Vec<String>, Vec<String>) = std::env::args().skip(1).partition(|a| a.starts_with("--"));
    let check = flags_only.iter().any(|a| a == "--check");
    let watcom = positional.first().cloned().expect(USAGE);
    let out = if check {
        std::env::temp_dir().join(format!("watcom_mve_check_{}", std::process::id()))
    } else {
        std::path::PathBuf::from(positional.get(1).expect(USAGE))
    };
    std::fs::create_dir_all(&out).unwrap();
    let work = out.join("work");
    // Through the generic driver. Role DEVELOPMENT-ASSISTANCE: this builds oracle fixtures
    // offline, which is the compiler helping us do the work rather than standing in for it.
    // Every unit below carries EXPLICIT flags, so the spec's profile fallback never fires and the
    // products are the same bytes as before the migration -- `--check` is the proof, not this note.
    let tc = CompilerDriver::new(
        spec::watcom_10_0a_dos(""),
        &watcom,
        &work,
        DriverRole::DevelopmentAssistance,
    )
    .expect("toolchain")
    .owning_work_dir();
    // The watcom_10_0a profile's own flag knowledge (buildconfig.rs): `-d1+` is what makes
    // 10.0a emit the BP frame on the subject's path — saves pushed BEFORE the frame (`52 55 89e5`),
    // which is the whole point of the callee-save fixture: the saved-EBP slot carves the
    // ownership hole BELOW the register save. `-of`/`-of+` force the other prologue path
    // (frame first) and are evidence-rejected for the subject.
    let flags: Vec<String> =
        ["-5r", "-fpi87", "-s", "-onatx", "-d1+", "-zq"].iter().map(|s| s.to_string()).collect();
    let mut products: Vec<&str> = Vec::new();
    for m in mosura::recompile::mve::MVES {
        let (key, sym, src, file, base) = (m.key, m.sym, m.source, m.fixture, m.base);
        let outp = tc.compile(&CompileUnit {
            key: key.into(),
            source: src.into(),
            flags: flags.clone(),
        });
        let obj = outp.object.unwrap_or_else(|| panic!("{key} failed:\n{}", outp.log));
        // Externs resolve INSIDE the fixture image: code symbols to a RET stub, data to a
        // plain address — an unresolvable (zero) call target aborts flow analysis and the
        // fixture decompiles to nothing.
        let stub = base + 0x1000;
        let data = base + 0x2000;
        // Every extern gets its OWN address (data 0x100 apart, code stubs 0x10 apart, in order
        // of first reference): two globals never alias (a struct copy between aliased globals
        // would be a self-copy) and two callees never merge (identical call bodies would
        // tail-merge into shared labels).
        let seen = std::rc::Rc::new(std::cell::RefCell::new(std::collections::HashMap::<String, u64>::new()));
        let seen_r = seen.clone();
        // The KIND of an extern comes from the MVE source itself — an `extern` declarator followed
        // by `(` is a function, anything else is data — never from its name (a `g`-prefix rule had
        // sent `getv` to the data area: a CALL with no RET stub behind it).
        let (code_names, data_names) = mosura::recompile::mve::extern_kinds(src);
        let unit = key.to_string();
        let resolver = move |sym: &str| {
            // Watcom's register convention: functions are `name_`, data `_name`
            let bare = sym.trim_start_matches('_').trim_end_matches('_');
            let is_data = data_names.contains(bare);
            if !is_data && !code_names.contains(bare) {
                eprintln!("{unit}: `{sym}` is not declared extern in the MVE source — placed as a callee stub");
            }
            let mut m = seen_r.borrow_mut();
            let n_data = m.values().filter(|&&a| a >= data).count() as u64;
            let n_code = m.values().filter(|&&a| a < data).count() as u64;
            Some(*m.entry(sym.to_string()).or_insert(if is_data { data + 0x100 * n_data } else { stub + 0x10 * n_code }))
        };
        let mut cand = load_object_function(&obj, sym, base, &resolver)
            .unwrap_or_else(|e| panic!("{key}: {e}\nlog:\n{}", outp.log));
        // A switch's jump table lives outside the function's extent (Watcom emits it at the front
        // of `_TEXT`): emit each table as its own chunk at `base + 0x800 + ..` and resolve the
        // function's reference to it, so the fixture carries a decodable BRANCHIND.
        let mut extra_chunks = String::new();
        if !cand.tables.is_empty() {
            let tables = cand.tables.clone();
            let mut addrs = Vec::new();
            let mut next = base + 0x800;
            for t in &tables {
                addrs.push(next);
                next += 4 * t.entries_fnrel.len() as u64;
            }
            let entries = |t: &mosura::recompile::candidate::CandTable| -> Vec<u8> {
                t.entries_fnrel.iter().flat_map(|k| ((base + k) as u32).to_le_bytes()).collect()
            };
            cand.resolve_tables(&|bytes| tables.iter().position(|t| entries(t) == bytes).map(|i| addrs[i]));
            for (i, t) in tables.iter().enumerate() {
                let hex: String = entries(t).iter().map(|b| format!("{b:02x}")).collect();
                extra_chunks += &format!("  <bytechunk space=\"ram\" offset=\"{:#x}\" readonly=\"true\">\n{hex}\n  </bytechunk>\n", addrs[i]);
            }
        }
        let hex: String = cand.relinked_bytes().iter().map(|b| format!("{b:02x}")).collect();
        // one RET stub per code extern referenced (plus the default one)
        let mut stubs: Vec<u64> = seen.borrow().values().copied().filter(|&a| a < data).collect();
        stubs.push(stub);
        stubs.sort_unstable();
        stubs.dedup();
        let stub_chunks: String = stubs.iter().map(|a| format!("  <bytechunk space=\"ram\" offset=\"{a:#x}\" readonly=\"true\">\nc3\n  </bytechunk>\n")).collect();
        let src_comment: String = src.trim().lines().map(|l| format!("  {l}\n")).collect();
        // the layout this object was built with — every extern the object references, by the
        // bare name, at the address the resolver assigned it, in ADDRESS order = the object's
        // RELOCATION order, not the source's (review R5 d: the twin build binds `func_0x..` and
        // the address-named globals to the MVE's externs through this line; nobody "fixes" the
        // order to the source's — it is the object's).
        let externs_line: String = {
            let mut v: Vec<(u64, String)> = seen
                .borrow()
                .iter()
                .map(|(s, &a)| (a, s.trim_start_matches('_').trim_end_matches('_').to_string()))
                .collect();
            v.sort();
            v.iter().map(|(a, n)| format!("{n}={a:#x}")).collect::<Vec<_>>().join(" ")
        };
        let xml = format!(
            "<!-- SELF-COMPILED fixture: wcc386 10.0a (in-house), flags {fl}. No third-party\n\
             \x20    bytes — the source is this comment; regenerate with examples/watcom_mve_fixtures.rs.\n\
             \x20    Externs: code from {stub:#x} (one RET stub per callee, 0x10 apart), data from {data:#x} (0x100 apart).\n\
             \x20    externs: {externs_line}\n\
             {src_comment}-->\n\
             <binaryimage arch=\"x86:LE:32:default:watcom\">\n\
             \x20 <bytechunk space=\"ram\" offset=\"{base:#x}\" readonly=\"true\">\n{hex}\n  </bytechunk>\n\
             {extra_chunks}\
             {stub_chunks}</binaryimage>\n",
            fl = flags.join(" "),
        );
        debug_assert!(xml.starts_with(GENERATED_MARKER), "the product header must carry the marker");
        std::fs::write(out.join(file), xml).unwrap();
        println!("{file}: {} bytes of {sym}", cand.bytes.len());
        products.push(file);
    }
    if check {
        // every product must match the committed fixture byte for byte ...
        let committed = mosura::paths::oracle_fixtures_dir();
        let mut problems: Vec<String> = Vec::new();
        for file in &products {
            let ours = std::fs::read(out.join(file)).unwrap();
            match std::fs::read(committed.join(file)) {
                Ok(theirs) if theirs == ours => println!("check: {file}: same"),
                Ok(_) => {
                    println!("check: {file}: DIFFERS");
                    problems.push(file.to_string());
                }
                Err(_) => {
                    println!("check: {file}: MISSING from {}", committed.display());
                    problems.push(file.to_string());
                }
            }
        }
        // ... and every committed fixture that carries the generator's header must be one of the
        // products: a file the generator once wrote and no longer does would otherwise pass
        // silently, with nothing left that can regenerate it.
        let mut marked = 0;
        let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(&committed).unwrap().map(|e| e.unwrap().path()).collect();
        entries.sort();
        for path in entries {
            if path.extension().and_then(|e| e.to_str()) != Some("xml") {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if !std::fs::read_to_string(&path).map(|s| s.starts_with(GENERATED_MARKER)).unwrap_or(false) {
                continue;
            }
            marked += 1;
            if !products.iter().any(|p| *p == name) {
                println!("check: {name}: ORPHAN (carries the generator header, but is not a product of this generator)");
                problems.push(name);
            }
        }
        drop(tc);
        if !problems.is_empty() {
            eprintln!(
                "--check: {} problem(s) against oracle/fixtures: {problems:?} — the regenerated products are kept in {}",
                problems.len(),
                out.display()
            );
            std::process::exit(1);
        }
        let _ = std::fs::remove_dir_all(&out);
        println!(
            "--check: all {} generator products match oracle/fixtures, and all {marked} generator-marked fixtures there are products (no orphans)",
            products.len()
        );
    }
}
