//! Options — the ONLY way a knob reaches the library (`docs/product/architecture.md` §4.2). One
//! registry of dotted, lower-case keys replaces the environment variables: `Options::set` validates
//! against it and rejects unknown keys and ill-typed values loudly (the debug facility's
//! unknown-topic rule, generalized). Every key records what it `affects`: a `Result` key changes
//! what an operation computes and enters the cache key through [`Options::tag`]; a `Diagnostic` key
//! only changes what is printed; an `Environment` key only says where an external tool is; an
//! `Input` key names WHAT an operation runs on and enters the key as an input digest, never through
//! the tag (decision E6). The core's own value types stay what they are — `switches::Knobs`,
//! `debug::Config`, `emit::EmitChoices` — this module is the front door that VALIDATES and BUILDS
//! them, so a new emit axis appears in the registry without an edit here.

pub mod keys;
pub mod registry;

use std::collections::{BTreeMap, HashSet};

use crate::error::{Error, Result};
use mosura_core::decompile::emit::EmitChoices;
use mosura_core::switches::Knobs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Affects {
    Result,
    Diagnostic,
    Environment,
    Input,
}

impl Affects {
    pub fn name(self) -> &'static str {
        match self {
            Affects::Result => "result",
            Affects::Diagnostic => "diagnostic",
            Affects::Environment => "environment",
            Affects::Input => "input",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptType {
    Bool,
    U64,
    /// A hex number, with or without `0x`.
    Hex,
    Str,
    /// One of the listed values.
    Enum(&'static [&'static str]),
    /// A comma-separated list; each element one of the listed values (an empty list = free).
    List(&'static [&'static str]),
    /// `all`, `none`, or a comma-separated list of hex addresses (`decompile.proto-scope`).
    Scope,
}

impl OptType {
    pub fn name(self) -> String {
        match self {
            OptType::Bool => "bool".into(),
            OptType::U64 => "u64".into(),
            OptType::Hex => "hex".into(),
            OptType::Str => "str".into(),
            OptType::Enum(v) => format!("one of {}", v.join("|")),
            OptType::List(v) if v.is_empty() => "list".into(),
            OptType::List(v) => format!("list of {}", v.join("|")),
            OptType::Scope => "all|none|<hex,..>".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct OptionSpec {
    pub key: &'static str,
    pub ty: OptType,
    pub default: &'static str,
    pub doc: &'static str,
    /// The api version that introduced the key.
    pub since: &'static str,
    pub affects: Affects,
}

fn parse_bool(v: &str) -> Option<bool> {
    match v.trim() {
        "1" | "true" | "on" | "yes" => Some(true),
        "0" | "false" | "off" | "no" => Some(false),
        _ => None,
    }
}

pub fn parse_hex(v: &str) -> Option<u64> {
    let t = v.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    if t.is_empty() {
        return None;
    }
    u64::from_str_radix(t, 16).ok()
}

fn validate(spec: &OptionSpec, value: &str) -> std::result::Result<(), String> {
    match spec.ty {
        OptType::Bool => parse_bool(value).map(|_| ()).ok_or_else(|| format!("`{}` wants true/false, got `{value}`", spec.key)),
        OptType::U64 => value.trim().parse::<u64>().map(|_| ()).map_err(|_| format!("`{}` wants a decimal number, got `{value}`", spec.key)),
        OptType::Hex => {
            if value.is_empty() || parse_hex(value).is_some() {
                Ok(())
            } else {
                Err(format!("`{}` wants a hex value, got `{value}`", spec.key))
            }
        }
        OptType::Str => Ok(()),
        OptType::Enum(allowed) => {
            if allowed.contains(&value.trim()) {
                Ok(())
            } else {
                Err(format!("`{}` wants one of {}, got `{value}`", spec.key, allowed.join("|")))
            }
        }
        OptType::List(allowed) => {
            for tok in value.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                if !allowed.is_empty() && !allowed.contains(&tok) {
                    return Err(format!("`{}`: `{tok}` is not one of {}", spec.key, allowed.join("|")));
                }
            }
            Ok(())
        }
        OptType::Scope => {
            let t = value.trim();
            if t == "all" || t == "none" {
                return Ok(());
            }
            for tok in t.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                if parse_hex(tok).is_none() {
                    return Err(format!("`{}` wants all, none or hex addresses, got `{tok}`", spec.key));
                }
            }
            Ok(())
        }
    }
}

/// A validated set of explicit values; `get` falls back to the registry default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    values: BTreeMap<&'static str, String>,
}

/// The decompile-time settings the survey set on the program AFTER analysis — options, not program
/// state (design finding: `global_scope_all_loaded` and `proto_scope` are decided per run).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecompileSettings {
    pub global_scope_all_loaded: bool,
    /// `None` = consult every recovered prototype; `Some(set)` = only these callees.
    pub proto_scope: Option<HashSet<u64>>,
}

impl Options {
    pub fn new() -> Options {
        Options::default()
    }

    fn spec(key: &str) -> Result<&'static OptionSpec> {
        registry::lookup(key).ok_or_else(|| {
            Error::InvalidArg(format!("unknown option key `{key}` (see the registry: `mosura ops`, `mosura_options_registry`)"))
        })
    }

    /// Set a key; an unknown key or an ill-typed value is `InvalidArg` carrying the key's doc line.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        let spec = Self::spec(key)?;
        validate(spec, value).map_err(|m| Error::InvalidArg(format!("{m} — {}: {}", spec.key, spec.doc)))?;
        self.values.insert(spec.key, value.trim().to_string());
        Ok(())
    }

    pub fn unset(&mut self, key: &str) -> Result<()> {
        let spec = Self::spec(key)?;
        self.values.remove(spec.key);
        Ok(())
    }

    /// The effective value: explicit, else the default.
    pub fn get(&self, key: &str) -> Result<&str> {
        let spec = Self::spec(key)?;
        Ok(self.values.get(spec.key).map(String::as_str).unwrap_or(spec.default))
    }

    pub fn is_set(&self, key: &str) -> bool {
        registry::lookup(key).is_some_and(|s| self.values.contains_key(s.key))
    }

    /// Parse `key=value;key=value` (the `EmitChoices::assign` grammar, generalized); a bare key
    /// sets a Bool to true.
    pub fn assign(&mut self, spec: &str) -> Result<()> {
        for part in spec.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            match part.split_once('=') {
                Some((k, v)) => self.set(k.trim(), v)?,
                None => {
                    let s = Self::spec(part)?;
                    if s.ty != OptType::Bool {
                        return Err(Error::InvalidArg(format!("`{part}` needs a value ({})", s.ty.name())));
                    }
                    self.set(part, "true")?;
                }
            }
        }
        Ok(())
    }

    /// The canonical string of the RESULT-affecting explicit values that differ from their defaults:
    /// sorted `key=value` pairs joined by `;`, or `default`. This is the option digest of a cache
    /// key; diagnostics, tool locations and inputs never enter it.
    pub fn tag(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for (k, v) in &self.values {
            let spec = registry::lookup(k).expect("a set key is registered");
            if spec.affects == Affects::Result && v != spec.default {
                parts.push(format!("{k}={v}"));
            }
        }
        if parts.is_empty() { "default".to_string() } else { parts.join(";") }
    }

    /// Every explicit value, for `mosura config` and provenance.
    pub fn explicit(&self) -> impl Iterator<Item = (&'static str, &str)> + '_ {
        self.values.iter().map(|(k, v)| (*k, v.as_str()))
    }

    // ── the core's value types ──

    pub fn knobs(&self) -> Result<Knobs> {
        let mut k = Knobs::default();
        let cspec = self.get(keys::LOAD_CSPEC_X86_32)?;
        if !cspec.is_empty() {
            k = k.with_x86_32_cspec(Some(cspec));
        }
        let disable = self.get(keys::ANALYSIS_DISABLE)?;
        if !disable.is_empty() {
            k = k.with_disabled_analyzers(Some(disable));
        }
        if parse_bool(self.get(keys::ANALYSIS_SWITCH_TABLE_REFS)?) == Some(true) {
            k = k.with_switch_table_refs(true);
        }
        for name in self.get(keys::KNOBS_OFF)?.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            k.turn_off(name).map_err(Error::InvalidArg)?;
        }
        Ok(k)
    }

    pub fn emit_choices(&self) -> Result<EmitChoices> {
        let mut c = EmitChoices::default();
        for axis in EmitChoices::axes() {
            let key = registry::emit_key(axis.name);
            if let Some(v) = self.values.get(key) {
                c.set(axis.name, v).map_err(|e| Error::InvalidArg(format!("{key}: {e:?}")))?;
            }
        }
        Ok(c)
    }

    /// The emit arms switched off by name (`Recovered::switch_off`).
    pub fn arms_off(&self) -> Vec<String> {
        self.get(keys::EMIT_ARMS_OFF).map(|v| v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()).unwrap_or_default()
    }

    /// The diagnostics configuration — the same `Config` that `debug::parse_spec` builds from a
    /// `--debug` spec, key by key.
    pub fn debug_config(&self) -> Result<mosura_core::debug::Config> {
        use mosura_core::debug::{Config, Topic};
        let mut cfg = Config::default();
        for tok in self.get(keys::DEBUG_TOPICS)?.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if tok == "all" {
                cfg.enable_all();
            } else {
                cfg.enable(Topic::by_name(tok).ok_or_else(|| Error::InvalidArg(format!("unknown debug topic `{tok}`")))?);
            }
        }
        let hex = |key: &str| -> Result<Option<u64>> {
            let v = self.get(key)?;
            if v.is_empty() {
                return Ok(None);
            }
            parse_hex(v).map(Some).ok_or_else(|| Error::InvalidArg(format!("`{key}` wants a hex value, got `{v}`")))
        };
        cfg.watch_call = hex(keys::DEBUG_WATCH_CALL)?;
        cfg.merge_watch = hex(keys::DEBUG_MERGE_WATCH)?
            .map(|v| u32::try_from(v).map_err(|_| Error::InvalidArg(format!("`{}` wants a 32-bit id", keys::DEBUG_MERGE_WATCH))))
            .transpose()?;
        cfg.aou_pc = hex(keys::DEBUG_AOU_PC)?;
        let s = |key: &str| -> Result<Option<String>> {
            let v = self.get(key)?;
            Ok((!v.is_empty()).then(|| v.to_string()))
        };
        cfg.gt_raw = s(keys::DEBUG_GT_RAW)?;
        cfg.trace_func = s(keys::DEBUG_TRACE_FUNC)?;
        // `all` records every action (parse_spec's bare `opaction`); a name scopes the trace to it
        cfg.opaction = match self.get(keys::DEBUG_OPACTION)? {
            "" => None,
            "all" => Some(String::new()),
            v => Some(v.to_string()),
        };
        cfg.recover_fixpoint = parse_bool(self.get(keys::DEBUG_FIXPOINT)?).unwrap_or(false);
        Ok(cfg)
    }

    pub fn decompile_settings(&self) -> Result<DecompileSettings> {
        let global_scope_all_loaded = self.get(keys::DECOMPILE_GLOBAL_SCOPE)? == "application";
        let proto_scope = match self.get(keys::DECOMPILE_PROTO_SCOPE)? {
            "all" => None,
            "none" => Some(HashSet::new()),
            list => Some(list.split(',').map(str::trim).filter(|s| !s.is_empty()).filter_map(parse_hex).collect()),
        };
        Ok(DecompileSettings { global_scope_all_loaded, proto_scope })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unknown keys and ill-typed values are refused with the key's doc line; a valid value is
    /// read back; `unset` restores the default; `assign` speaks the `k=v;k=v` grammar and bare bools.
    #[test]
    fn unknown_key_and_value_rejected_with_doc() {
        let mut o = Options::new();
        assert!(matches!(o.set("no.such", "1"), Err(Error::InvalidArg(m)) if m.contains("unknown option key")));
        let e = o.set(keys::LOAD_LOADER, "sideways").unwrap_err().to_string();
        assert!(e.contains("one of default|native|le|x32|com|raw|xml") && e.contains("load.loader:"), "{e}");
        assert!(o.set(keys::ANALYSIS_DISABLE, "Function Start Search,Stack").is_ok(), "a free list");
        assert!(o.set(keys::KNOBS_OFF, "ret-split,nope").unwrap_err().to_string().contains("`nope` is not one of"));
        assert!(o.set(keys::DEBUG_WATCH_CALL, "zz").unwrap_err().to_string().contains("hex"));
        assert!(o.set(keys::DECOMPILE_PROTO_SCOPE, "0x1000,abc").is_ok());
        assert!(o.set(keys::DECOMPILE_PROTO_SCOPE, "0x1000,xyz").is_err());
        o.set(keys::LOAD_LOADER, "le").unwrap();
        assert_eq!(o.get(keys::LOAD_LOADER).unwrap(), "le");
        o.unset(keys::LOAD_LOADER).unwrap();
        assert_eq!(o.get(keys::LOAD_LOADER).unwrap(), "default");
        o.assign("emit.return-width=storage; debug.fixpoint; knobs.off=frame-agg").unwrap();
        assert_eq!(o.get("emit.return-width").unwrap(), "storage");
        assert_eq!(o.get(keys::DEBUG_FIXPOINT).unwrap(), "true");
        assert!(o.assign("load.loader").unwrap_err().to_string().contains("needs a value"));
        assert!(o.get("emit.no-such-axis").is_err());
    }

    /// The tag is the sorted Result subset that differs from the defaults, `default` when none;
    /// diagnostics and inputs never enter it; order of setting does not matter; a value equal to
    /// its default is not a deviation.
    #[test]
    fn tag_is_canonical_and_order_free() {
        let mut a = Options::new();
        assert_eq!(a.tag(), "default");
        a.set(keys::DEBUG_TOPICS, "types").unwrap();
        a.set("input", "subject").unwrap();
        a.set("entry", "0x1000").unwrap();
        assert_eq!(a.tag(), "default", "diagnostic and input keys never enter the tag");
        a.set(keys::KNOBS_OFF, "frame-agg").unwrap();
        a.set("emit.sum-order", "original").unwrap();
        a.set(keys::LOAD_LOADER, "default").unwrap();
        let mut b = Options::new();
        b.set("emit.sum-order", "original").unwrap();
        b.set(keys::KNOBS_OFF, "frame-agg").unwrap();
        assert_eq!(a.tag(), b.tag());
        assert_eq!(a.tag(), "emit.sum-order=original;knobs.off=frame-agg");
    }

    /// Every axis of `EmitChoices::AXES` is a registered `emit.<axis>` key whose enum is the axis's
    /// value list and whose default is the default choice; setting each value builds the same
    /// `EmitChoices` as `set` on the core type.
    #[test]
    fn emit_keys_cover_every_axis_and_value() {
        let d = EmitChoices::default();
        for axis in EmitChoices::axes() {
            let key = registry::emit_key(axis.name);
            let spec = registry::lookup(key).unwrap_or_else(|| panic!("{key} registered"));
            assert_eq!(spec.ty, OptType::Enum(axis.values));
            assert_eq!(Some(spec.default), d.get(axis.name), "{key} default");
            assert_eq!(spec.affects, Affects::Result);
            for v in axis.values {
                let mut o = Options::new();
                o.set(key, v).unwrap();
                let mut want = EmitChoices::default();
                want.set(axis.name, v).unwrap();
                assert_eq!(o.emit_choices().unwrap(), want, "{key}={v}");
            }
        }
        assert_eq!(Options::new().emit_choices().unwrap(), d);
    }

    /// `knobs.off` accepts every switch name and builds the same `Knobs` as `turn_off`; the cspec
    /// and analyzer-ablation keys fill their fields.
    #[test]
    fn knobs_off_covers_switch_all() {
        use mosura_core::switches::Switch;
        for s in Switch::ALL {
            let mut o = Options::new();
            o.set(keys::KNOBS_OFF, s.name()).unwrap();
            let k = o.knobs().unwrap();
            assert!(!k.on(*s), "{} off", s.name());
            assert!(Switch::ALL.iter().filter(|x| *x != s).all(|x| k.on(*x)));
        }
        let mut o = Options::new();
        o.set(keys::LOAD_CSPEC_X86_32, "watcom").unwrap();
        o.set(keys::ANALYSIS_DISABLE, "Function Start Search").unwrap();
        let k = o.knobs().unwrap();
        assert_eq!(k.x86_32_cspec.as_deref(), Some("watcom"));
        assert_eq!(k.disabled_analyzers.as_deref(), Some("Function Start Search"));
        assert_eq!(Options::new().knobs().unwrap(), Knobs::default());
    }

    /// The `debug.*` keys build the same `Config` as `debug::parse_spec` does from the equivalent
    /// `--debug` spec, field by field.
    #[test]
    fn debug_keys_match_parse_spec() {
        use mosura_core::debug::parse_spec;
        let mut o = Options::new();
        o.set(keys::DEBUG_TOPICS, "types,structure").unwrap();
        o.set(keys::DEBUG_WATCH_CALL, "0x1234").unwrap();
        o.set(keys::DEBUG_MERGE_WATCH, "7f").unwrap();
        o.set(keys::DEBUG_AOU_PC, "0x5000").unwrap();
        o.set(keys::DEBUG_GT_RAW, "main").unwrap();
        o.set(keys::DEBUG_OPACTION, "all").unwrap();
        o.set(keys::DEBUG_TRACE_FUNC, "FUN_00001000").unwrap();
        o.set(keys::DEBUG_FIXPOINT, "true").unwrap();
        let ours = o.debug_config().unwrap();
        let theirs = parse_spec("topics=types,structure;watch-call=0x1234;merge-watch=7f;aou-pc=0x5000;gt-raw=main;opaction;trace-func=FUN_00001000;fixpoint").unwrap();
        assert_eq!(ours.topics(), theirs.topics());
        assert_eq!(ours.watch_call, theirs.watch_call);
        assert_eq!(ours.merge_watch, theirs.merge_watch);
        assert_eq!(ours.aou_pc, theirs.aou_pc);
        assert_eq!(ours.gt_raw, theirs.gt_raw);
        assert_eq!(ours.opaction, theirs.opaction);
        assert_eq!(ours.trace_func, theirs.trace_func);
        assert_eq!(ours.recover_fixpoint, theirs.recover_fixpoint);
        let empty = Options::new().debug_config().unwrap();
        assert!(empty.topics().is_empty() && empty.watch_call.is_none() && empty.opaction.is_none() && !empty.recover_fixpoint);
        assert!(Options::new().set(keys::DEBUG_TOPICS, "nope").is_err());
    }

    /// Input keys are registered as `Input` and never tag; the scope key decodes to the program's
    /// decompile-time settings.
    #[test]
    fn input_keys_never_enter_tag_and_scope_decodes() {
        for k in ["input", "program", "entry", "table", "addr", "len", "lang", "bytes", "base", "ctx", "format"] {
            assert_eq!(registry::lookup(k).unwrap_or_else(|| panic!("{k}")).affects, Affects::Input, "{k}");
        }
        let mut o = Options::new();
        assert_eq!(o.decompile_settings().unwrap(), DecompileSettings { global_scope_all_loaded: true, proto_scope: None });
        o.set(keys::DECOMPILE_GLOBAL_SCOPE, "standalone").unwrap();
        o.set(keys::DECOMPILE_PROTO_SCOPE, "none").unwrap();
        assert_eq!(o.decompile_settings().unwrap(), DecompileSettings { global_scope_all_loaded: false, proto_scope: Some(HashSet::new()) });
        o.set(keys::DECOMPILE_PROTO_SCOPE, "0x1000, 2000").unwrap();
        assert_eq!(o.decompile_settings().unwrap().proto_scope, Some([0x1000u64, 0x2000].into_iter().collect()));
        assert_eq!(o.tag(), "decompile.global-scope=standalone;decompile.proto-scope=0x1000, 2000");
    }
}
