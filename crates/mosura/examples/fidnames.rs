//! Print the library functions FID identifies in a binary, one `<address> <name>` per line.
//!
//! The integration gates assert *specific* names on binaries whose contents are known; this is
//! the open-ended view for a binary whose contents are not — which of the committed databases
//! matched, how many functions were recovered, and what each one is called.
//!
//! ```text
//! cargo run --release --example fidnames -- <binary> [db-dir]
//! cargo run --release --example fidnames -- --le <bound-exe>     # native LE loader
//! cargo run --release --example fidnames -- --native <exe>       # whichever native loader claims it
//! ```
//!
//! `--le` selects [`analyze_le_file`](mosura::analysis::analyze_le_file) for a DOS/4GW-bound
//! executable. It matters more than it looks: the default container dispatch keeps a bound exe on
//! the Ghidra-parity MZ-stub path, which sees only the 16-bit stub — a few hundred functions of
//! loader, none of the 32-bit program — so FID quite correctly identifies nothing there.
//!
//! With no `db-dir`, every database the resource provider holds under `fid/` is
//! searched. Passing one narrows the search to a single database set, which is how to attribute a
//! name to the column it came from.
fn main() {
    let mut args = std::env::args().skip(1).peekable();
    let mut le = false;
    let mut native = false;
    while let Some(a) = args.peek() {
        match a.as_str() {
            "--le" => le = true,
            // `--native` picks whichever beyond-Ghidra loader claims the file (LE, X-32, ...)
            // via `analyze_native_file`, rather than naming one.
            "--native" => native = true,
            _ => break,
        }
        args.next();
    }
    let bin =
        std::path::PathBuf::from(args.next().expect("usage: fidnames [--le] <binary> [db-dir]"));
    let db_dir: Option<std::path::PathBuf> = args.next().map(std::path::PathBuf::from);

    let program = if native {
        mosura::analysis::analyze_native_file(&bin)
    } else if le {
        mosura::analysis::analyze_le_file(&bin)
    } else {
        mosura::analysis::analyze_file(&bin)
    }
    .expect("analyze the binary");

    let service = match &db_dir {
        Some(dir) => mosura::analysis::fid::query::FidQueryService::load_matching(
            dir,
            &program.language_id,
            &program.compiler_spec_id,
        ),
        None => mosura::analysis::fid::query::FidQueryService::load_matching_resources(
            &program.language_id,
            &program.compiler_spec_id,
        ),
    };
    eprintln!(
        "{} {} — {} functions, {} signature records",
        program.language_id,
        program.compiler_spec_id,
        program.function_manager.function_count(),
        service.function_count(),
    );

    let results = mosura::analysis::fid::analyzer::search_program(&program, &service);
    // A result whose `name` is `None` matched, but ambiguously: several records share the hash,
    // so it earns a plate comment rather than a rename. Only the named ones are listed.
    let mut named: Vec<(u64, String)> =
        results.into_iter().filter_map(|r| r.name.map(|n| (r.entry.offset, n))).collect();
    named.sort();
    println!("NAMED {}", named.len());
    for (address, name) in named {
        println!("{address:#x} {name}");
    }
}
