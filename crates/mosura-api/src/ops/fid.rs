//! `fid.identify`: the library functions FID recognises in an analyzed program, one row per
//! result — the address, the name to apply (empty when FID recognised the function but several
//! records share the hash: Ghidra declines to rename then and still records the finding as a
//! plate comment, so an empty name is a RESULT, not the absence of one), the score and the plate.
//! Every database the resource provider holds is searched, or one directory (`fid.db`), which is
//! how a name is attributed to the database it came from. (Was `examples/fidnames.rs`.)

use crate::error::Result;
use crate::options::{keys, Options};
use crate::ops::program::program_of;
use crate::ops::schemas::FID_NAMES;
use crate::ops::{Cache, Op, Progress, Tier};
use crate::session::Session;
use crate::table::builder::TableBuilder;
use crate::table::Table;
use mosura_core::analysis::fid::{analyzer, query::FidQueryService};

pub static IDENTIFY: Op = Op {
    name: "fid.identify",
    doc: "the library functions FID recognises in the current program (address, name or empty when ambiguous, score, plate comment); every embedded/override database for the program's language and spec, or the one directory fid.db",
    since: "0.1",
    tier: Tier::Product,
    params: &["program", keys::FID_DB],
    result: "fid_names",
    cache: Cache::Transient,
    run: identify,
};

fn identify(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let (_, program) = program_of(s, o)?;
    let db = o.get(keys::FID_DB)?;
    let service = if db.is_empty() { FidQueryService::load_matching_resources(&program.language_id, &program.compiler_spec_id) } else { FidQueryService::load_matching(std::path::Path::new(db), &program.language_id, &program.compiler_spec_id) };
    let mut results = analyzer::search_program(&program, &service);
    results.sort_by_key(|r| r.entry.offset);
    let mut b = TableBuilder::new(&FID_NAMES);
    for r in &results {
        b.row().u64(r.entry.offset).str(r.name.as_deref().unwrap_or("")).f64(f64::from(r.score)).str(&r.plate);
    }
    Ok(b.finish(true))
}
