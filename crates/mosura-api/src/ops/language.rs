//! Language facts as tables: the `.ldefs` catalogue (`languages`), a language's register file
//! (`registers`), and the emitter's axes and arms.

use crate::error::{Error, Result};
use crate::ops::schemas::{EMIT_ARMS, EMIT_AXES, LANGUAGES, REGISTERS};
use crate::table::builder::TableBuilder;
use crate::table::Table;
use mosura_core::decompile::emit::arms::registry::Recovered;
use mosura_core::decompile::emit::EmitChoices;

/// Every `<language>` of every processor `.ldefs` the resource provider serves (the same walk
/// `lang::resolve` performs: only an `.ldefs` directly in a `data/languages` directory counts —
/// Ghidra's own tree keeps a deprecated duplicate under `old/`). Sorted by id.
pub fn languages_table() -> Table {
    let res = mosura_core::resources::get();
    let mut rows: Vec<(String, String, String, u32, String, String, String, String)> = Vec::new();
    for name in res.list("ghidra/Processors/") {
        let Some(stem) = name.strip_suffix(".ldefs") else { continue };
        let Some((dir, _)) = stem.rsplit_once('/') else { continue };
        if !dir.ends_with("/data/languages") {
            continue;
        }
        let Some(text) = res.read_string(&name) else { continue };
        let Ok(doc) = roxmltree::Document::parse(&text) else { continue };
        for l in doc.descendants().filter(|n| n.tag_name().name() == "language") {
            let Some(id) = l.attribute("id") else { continue };
            let attr = |k: &str| l.attribute(k).unwrap_or("").to_string();
            let description = l.children().find(|c| c.tag_name().name() == "description").and_then(|d| d.text()).unwrap_or("").trim().to_string();
            let cspecs: Vec<&str> = l.children().filter(|c| c.tag_name().name() == "compiler").filter_map(|c| c.attribute("id")).collect();
            rows.push((id.to_string(), attr("processor"), attr("endian"), l.attribute("size").and_then(|s| s.parse().ok()).unwrap_or(0), attr("variant"), attr("version"), description, cspecs.join(",")));
        }
    }
    rows.sort();
    rows.dedup_by(|a, b| a.0 == b.0);
    let mut b = TableBuilder::new(&LANGUAGES);
    for (id, processor, endian, size, variant, version, description, cspecs) in &rows {
        b.row().str(id).str(processor).str(endian).u32(*size).str(variant).str(version).str(description).str(cspecs);
    }
    b.finish(true)
}

/// The register file of a language: name, space, offset, size — sorted by offset, wider first.
pub fn registers_table(lang_id: &str) -> Result<Table> {
    let (spec, _) = mosura_core::lang::load_cached(lang_id).ok_or_else(|| Error::NotFound(format!("language `{lang_id}` (tables unavailable)")))?;
    let mut regs: Vec<((u64, u32), String)> = spec.register_table();
    regs.sort_by(|a, b| (a.0 .0, std::cmp::Reverse(a.0 .1), &a.1).cmp(&(b.0 .0, std::cmp::Reverse(b.0 .1), &b.1)));
    let mut b = TableBuilder::new(&REGISTERS);
    for ((off, size), name) in &regs {
        b.row().str(name).str("register").u64(*off).u32(*size);
    }
    Ok(b.finish(false))
}

/// The emit axes (`EmitChoices::axes`): name, values, default, doc.
pub fn emit_axes_table() -> Table {
    let default = EmitChoices::default();
    let mut b = TableBuilder::new(&EMIT_AXES);
    for a in EmitChoices::axes() {
        b.row().str(a.name).str(&a.values.join("|")).str(default.get(a.name).unwrap_or("")).str(a.doc);
    }
    b.finish(false)
}

/// The emit arms (`Recovered::ARMS`): the names `emit.arms-off` accepts.
pub fn emit_arms_table() -> Table {
    let mut b = TableBuilder::new(&EMIT_ARMS);
    for a in Recovered::ARMS {
        b.row().str(a);
    }
    b.finish(false)
}
