//! The option registry: the hand-written keys of `keys.rs` plus the keys generated from the
//! core's own tables — `emit.<axis>` for every `EmitChoices::AXES` entry, `knobs.off` over
//! `Switch::ALL`, `emit.arms-off` over `Recovered::ARMS`, `debug.topics` over `Topic::ALL` — so a
//! new axis, switch, arm or topic appears here without an edit. Assembled once per process;
//! an extension (the dev tier) adds its keys at run time through `register`.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use super::{keys, Affects, OptType, OptionSpec};
use crate::error::{Error, Result};
use mosura_core::decompile::emit::arms::registry::Recovered;
use mosura_core::decompile::emit::EmitChoices;
use mosura_core::debug::Topic;
use mosura_core::switches::Switch;

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

/// The registry key of an emit axis: `emit.<axis>` (the axis names as `AXES` spells them,
/// `return-width`, `sum-order`, …).
pub fn emit_key(axis: &str) -> &'static str {
    static KEYS: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    let m = KEYS.get_or_init(|| EmitChoices::axes().iter().map(|a| (a.name, leak(format!("emit.{}", a.name)))).collect());
    m.get(axis).copied().unwrap_or_else(|| leak(format!("emit.{axis}")))
}

fn build() -> Vec<OptionSpec> {
    let mut specs = keys::hand_written();
    let d = EmitChoices::default();
    for axis in EmitChoices::axes() {
        specs.push(OptionSpec {
            key: emit_key(axis.name),
            ty: OptType::Enum(axis.values),
            default: d.get(axis.name).expect("every axis has a default"),
            doc: axis.doc,
            since: "0.1",
            affects: Affects::Result,
        });
    }
    let switch_names: &'static [&'static str] = Box::leak(Switch::ALL.iter().map(|s| s.name()).collect::<Vec<_>>().into_boxed_slice());
    specs.push(OptionSpec {
        key: keys::KNOBS_OFF,
        ty: OptType::List(switch_names),
        default: "",
        doc: "result-affecting switches to turn off, by name (the switch half of --arms-off); every one is stamped on the emit's arms line",
        since: "0.1",
        affects: Affects::Result,
    });
    let arm_names: &'static [&'static str] = Box::leak(Recovered::ARMS.to_vec().into_boxed_slice());
    specs.push(OptionSpec {
        key: keys::EMIT_ARMS_OFF,
        ty: OptType::List(arm_names),
        default: "",
        doc: "emit arms to switch off, by name (the arm half of --arms-off): their witnessed sites are cleared",
        since: "0.1",
        affects: Affects::Result,
    });
    let mut topics: Vec<&'static str> = Topic::ALL.iter().map(|t| t.name()).collect();
    topics.push("all");
    let topics: &'static [&'static str] = Box::leak(topics.into_boxed_slice());
    specs.push(OptionSpec {
        key: keys::DEBUG_TOPICS,
        ty: OptType::List(topics),
        default: "",
        doc: "diagnostic topics to print (or all)",
        since: "0.1",
        affects: Affects::Diagnostic,
    });
    specs.sort_by(|a, b| a.key.cmp(b.key));
    specs
}

/// The compiled registry (assembled once).
fn compiled() -> &'static [OptionSpec] {
    static REG: OnceLock<Vec<OptionSpec>> = OnceLock::new();
    REG.get_or_init(build)
}

fn compiled_lookup(key: &str) -> Option<&'static OptionSpec> {
    static INDEX: OnceLock<HashMap<&'static str, usize>> = OnceLock::new();
    let idx = INDEX.get_or_init(|| compiled().iter().enumerate().map(|(i, s)| (s.key, i)).collect());
    idx.get(key).map(|&i| &compiled()[i])
}

/// Keys registered at run time (an extension's; see `ops::register`), leaked once per process.
static EXTRA: RwLock<Vec<&'static OptionSpec>> = RwLock::new(Vec::new());

/// Add option keys at run time. A key already registered, not spelled dotted lower-case, or
/// without a doc line is `InvalidArg` (the same rules the compiled registry's test pins).
pub fn register(specs: Vec<OptionSpec>) -> Result<()> {
    let mut extra = EXTRA.write().unwrap_or_else(|e| e.into_inner());
    for s in specs {
        let spelled = !s.key.is_empty() && s.key.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-');
        if !spelled || s.doc.is_empty() {
            return Err(Error::InvalidArg(format!("option key `{}`: keys are dotted lower-case and carry a doc line", s.key)));
        }
        if compiled_lookup(s.key).is_some() || extra.iter().any(|x| x.key == s.key) {
            return Err(Error::InvalidArg(format!("option key `{}` is already registered", s.key)));
        }
        extra.push(Box::leak(Box::new(s)));
    }
    Ok(())
}

/// Every key — the compiled registry plus the registered extensions — sorted.
pub fn registry() -> Vec<&'static OptionSpec> {
    let mut all: Vec<&'static OptionSpec> = compiled().iter().collect();
    all.extend(EXTRA.read().unwrap_or_else(|e| e.into_inner()).iter().copied());
    all.sort_by(|a, b| a.key.cmp(b.key));
    all
}

pub fn lookup(key: &str) -> Option<&'static OptionSpec> {
    let key = key.trim();
    compiled_lookup(key).or_else(|| EXTRA.read().unwrap_or_else(|e| e.into_inner()).iter().copied().find(|s| s.key == key))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keys are unique, sorted, dotted lower-case; the generated families are present; the
    /// registry renders as rows a table can carry.
    #[test]
    fn registry_is_sorted_unique_and_complete() {
        let r = registry();
        assert!(r.windows(2).all(|w| w[0].key < w[1].key), "sorted, unique");
        for s in &r {
            assert!(s.key.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-'), "{}", s.key);
            assert!(!s.doc.is_empty(), "{} has a doc line", s.key);
        }
        // every `emit.<axis>` key IS an emit axis, so the family cannot drift from the arms
        // layer; `emit.arms-off` (the arm switches) is the one hand-written exception, named
        // here so a second one is a deliberate act.
        let hand_written_emit_keys = [keys::EMIT_ARMS_OFF];
        assert_eq!(
            r.iter().filter(|s| s.key.starts_with("emit.") && !hand_written_emit_keys.contains(&s.key)).count(),
            EmitChoices::axes().len()
        );
        assert!(matches!(lookup(keys::KNOBS_OFF).unwrap().ty, OptType::List(v) if v.len() == Switch::ALL.len()));
        assert!(matches!(lookup(keys::EMIT_ARMS_OFF).unwrap().ty, OptType::List(v) if v.len() == Recovered::ARMS.len()));
        assert!(matches!(lookup(keys::DEBUG_TOPICS).unwrap().ty, OptType::List(v) if v.len() == Topic::ALL.len() + 1));
        assert!(lookup(" load.loader ").is_some(), "trimmed");
        assert!(lookup("emit").is_none());
    }
}

/// The registry as a table: key, type, default, doc, since, affects (`mosura options registry`).
pub fn registry_table() -> crate::table::Table {
    let mut b = crate::table::builder::TableBuilder::new(&crate::ops::schemas::OPTION_REGISTRY);
    for s in registry() {
        b.row().str(s.key).str(&s.ty.name()).str(s.default).str(s.doc).str(s.since).str(s.affects.name());
    }
    b.finish(true)
}
