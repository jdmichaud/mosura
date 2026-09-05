//! The option registry: the hand-written keys of `keys.rs` plus the keys generated from the
//! core's own tables — `emit.<axis>` for every `EmitChoices::AXES` entry, `knobs.off` over
//! `Switch::ALL`, `emit.arms-off` over `Recovered::ARMS`, `debug.topics` over `Topic::ALL` — so a
//! new axis, switch, arm or topic appears here without an edit. Assembled once per process.

use std::collections::HashMap;
use std::sync::OnceLock;

use super::{keys, Affects, OptType, OptionSpec};
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

pub fn registry() -> &'static [OptionSpec] {
    static REG: OnceLock<Vec<OptionSpec>> = OnceLock::new();
    REG.get_or_init(build)
}

pub fn lookup(key: &str) -> Option<&'static OptionSpec> {
    static INDEX: OnceLock<HashMap<&'static str, usize>> = OnceLock::new();
    let idx = INDEX.get_or_init(|| registry().iter().enumerate().map(|(i, s)| (s.key, i)).collect());
    idx.get(key.trim()).map(|&i| &registry()[i])
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
        for s in r {
            assert!(s.key.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-'), "{}", s.key);
            assert!(!s.doc.is_empty(), "{} has a doc line", s.key);
        }
        assert_eq!(r.iter().filter(|s| s.key.starts_with("emit.") && s.key != keys::EMIT_ARMS_OFF).count(), EmitChoices::axes().len());
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
