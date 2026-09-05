//! The library context (`mosura_ctx` in the C header): the resource provider with the caller's
//! override directories, the diagnostics configuration, the panic policy, and the build identity.
//! `Context::new` installs the two process-wide seams the core still has (`resources::set`,
//! `debug::configure`), so there is ONE context per process in P1: a second `new` with an identical
//! configuration is a no-op, with a different one an error (a per-context provider comes with the
//! wasm/serve work of phase 5).

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use crate::error::{Error, Result};
use crate::fingerprint::{build_id, fp, Stage};
use mosura_core::debug::Config;
use mosura_core::resources::{self, Resources};

#[derive(Clone, Default)]
pub struct ContextConfig {
    /// Override directories, resolved before the embedded data; the LAST one first.
    pub data_dirs: Vec<PathBuf>,
    /// The diagnostics: topics, watches, the sink. A copy is installed process-wide.
    pub debug: Config,
    /// Development aid: let an internal panic propagate (the process dies with its backtrace)
    /// instead of catching it at the boundary into `Error::Internal`.
    pub abort_on_panic: bool,
}

impl ContextConfig {
    /// What decides "the same configuration": the override directories and the panic policy (the
    /// diagnostics may be reconfigured freely — they change no result).
    fn identity(&self) -> String {
        let mut s = String::new();
        for d in &self.data_dirs {
            s.push_str(&d.display().to_string());
            s.push('\u{1f}');
        }
        s.push_str(if self.abort_on_panic { "abort" } else { "catch" });
        s
    }
}

/// The build identity a session manifest records.
#[derive(Debug, Clone)]
pub struct BuildInfo {
    pub version: &'static str,
    pub build_id: &'static str,
    pub fingerprints: [(Stage, [u8; 32]); 4],
}

pub struct Context {
    pub resources: Arc<Resources>,
    pub debug: Config,
    pub abort_on_panic: bool,
    pub build: BuildInfo,
}

static INSTALLED: OnceLock<String> = OnceLock::new();

impl Context {
    pub fn new(cfg: ContextConfig) -> Result<Context> {
        let id = cfg.identity();
        match INSTALLED.get() {
            Some(prev) if *prev != id => {
                return Err(Error::Unsupported(format!(
                    "one context per process in this version: a context with override directories {:?} is already installed",
                    prev.split('\u{1f}').filter(|s| !s.is_empty()).collect::<Vec<_>>()
                )));
            }
            Some(_) => {}
            None => {
                for d in &cfg.data_dirs {
                    if !d.is_dir() {
                        return Err(Error::io(std::io::Error::new(std::io::ErrorKind::NotFound, "not a directory"), d));
                    }
                }
                let mut r = resources::default_for_process();
                for d in &cfg.data_dirs {
                    r = r.with_override_first(d);
                }
                resources::set(r);
                let _ = INSTALLED.set(id);
            }
        }
        mosura_core::debug::configure(cfg.debug.clone());
        Ok(Context {
            resources: resources::get(),
            debug: cfg.debug,
            abort_on_panic: cfg.abort_on_panic,
            build: BuildInfo {
                version: env!("CARGO_PKG_VERSION"),
                build_id: build_id(),
                fingerprints: [Stage::Analysis, Stage::Decompile, Stage::Emit, Stage::Recompile].map(|s| (s, fp(s))),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A context installs the provider and the diagnostics; a second identical one is a no-op; a
    /// missing override directory is refused before anything is installed.
    #[test]
    fn one_context_per_process() {
        let bad = ContextConfig { data_dirs: vec![PathBuf::from("/nonexistent/mosura-data")], ..Default::default() };
        assert!(matches!(Context::new(bad), Err(Error::Io(..))));
        let c = Context::new(ContextConfig::default()).expect("the default context");
        assert!(c.resources.exists("ghidra/Processors/x86/data/languages/x86.sla"));
        assert_eq!(c.build.build_id, build_id());
        assert_eq!(c.build.fingerprints[0].1, fp(Stage::Analysis));
        let again = Context::new(ContextConfig::default()).expect("the same configuration again");
        assert_eq!(again.build.build_id, c.build.build_id);
    }
}
