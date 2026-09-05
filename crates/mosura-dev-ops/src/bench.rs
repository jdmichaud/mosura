//! `dev.bench` — the perf harness: the faithful pipeline over the x86-64 datatests (no oracle
//! spawns), per-fixture wall time worst first, plus the phase totals. With `debug.topics=perf`
//! the per-action / per-rule accounting of `action::perf` is dumped to the log. (Was
//! `examples/perf_corpus.rs`.)

use std::time::Instant;

use mosura_api::ops::{Cache, Op, Progress, Tier};
use mosura_api::{Error, Options, Result, Session, Table, TableBuilder};
use mosura_core::decompile::{action, build, pipeline, printc};
use mosura_core::sleigh::engine::Spec;
use mosura_core::{datatest, paths};

use crate::keys;
use crate::schemas::BENCH as BENCH_SCHEMA;

pub static BENCH_OP_DOC: &str = "the perf harness: build/decompile/print wall time per x86-64 datatest fixture, worst first, then *total* and *spec-load* rows; dev.only = fixture stems; debug.topics=perf dumps the per-action accounting";

pub static BENCH: Op = Op { name: "dev.bench", doc: BENCH_OP_DOC, since: "0.1", tier: Tier::Dev, params: &[keys::DEV_ONLY], result: "bench", cache: Cache::Transient, run: bench };

fn bench(_s: &mut Session, o: &Options, p: &mut dyn Progress) -> Result<Table> {
    let only = crate::list(o, keys::DEV_ONLY)?;
    let sla = paths::language_dir("x86").join("x86-64.sla");
    let t0 = Instant::now();
    let bytes = std::fs::read(&sla).map_err(|e| Error::io(e, sla.clone()))?;
    let spec = Spec::from_sla(&bytes).map_err(|e| Error::Format(format!("{}: {e:?}", sla.display())))?;
    let spec_ms = t0.elapsed().as_secs_f64() * 1e3;
    let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
    let dir = paths::datatests_dir();
    let mut entries: Vec<_> = std::fs::read_dir(&dir).map_err(|e| Error::io(e, dir.clone()))?.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    entries.sort();
    let mut times: Vec<(String, f64, f64, f64)> = Vec::new();
    let total = entries.len() as u64;
    for (i, path) in entries.iter().enumerate() {
        if !p.report(BENCH.name, i as u64, total) {
            return Err(Error::Cancelled);
        }
        if path.extension().is_none_or(|e| e != "xml") {
            continue;
        }
        let name = path.file_stem().unwrap_or_default().to_string_lossy().to_string();
        if !only.is_empty() && !only.iter().any(|o| *o == name) {
            continue;
        }
        if !std::fs::read_to_string(path).unwrap_or_default().contains("x86:LE:64") {
            continue;
        }
        let Ok(dt) = datatest::parse_file(path) else { continue };
        if dt.chunks.is_empty() {
            continue;
        }
        let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
        let entry = dt.chunks[0].offset;
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let t0 = Instant::now();
            let mut f = build::raw_funcdata_flow_image_arch(&spec, "func", &image, entry, &ctx, &dt.arch);
            let t1 = Instant::now();
            pipeline::decompile(&mut f);
            let t2 = Instant::now();
            printc::print_c(&f);
            let t3 = Instant::now();
            ((t1 - t0).as_secs_f64() * 1e3, (t2 - t1).as_secs_f64() * 1e3, (t3 - t2).as_secs_f64() * 1e3)
        }));
        if let Ok((b, d, pr)) = r {
            times.push((name, b, d, pr));
        }
    }
    times.sort_by(|a, b| (b.1 + b.2 + b.3).partial_cmp(&(a.1 + a.2 + a.3)).unwrap_or(std::cmp::Ordering::Equal));
    let mut t = TableBuilder::new(&BENCH_SCHEMA);
    let (mut tb, mut td, mut tp) = (0.0, 0.0, 0.0);
    for (n, b, d, pr) in &times {
        tb += b;
        td += d;
        tp += pr;
        t.row().str(n).f64(b + d + pr).f64(*b).f64(*d).f64(*pr);
    }
    t.row().str("*total*").f64(tb + td + tp).f64(tb).f64(td).f64(tp);
    t.row().str("*spec-load*").f64(spec_ms).f64(0.0).f64(0.0).f64(0.0);
    if action::perf::enabled() {
        action::perf::dump();
    }
    Ok(t.finish(false))
}
