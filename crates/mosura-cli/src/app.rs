//! The plumbing every command shares: the context, the session, the merged options and their
//! projection onto one operation, the current program, function-name resolution, rendering.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use mosura::{Ctx, CtxConfig, Format, Options, Session, Status, Table};

/// Exit codes: 0 ok · 1 a gate or verdict failed · 2 usage or config · 3 library error · 4 internal.
pub struct Fail {
    pub code: i32,
    pub message: String,
}

impl From<mosura::Error> for Fail {
    fn from(e: mosura::Error) -> Fail {
        Fail { code: if e.status == Status::MOSURA_ERR_INTERNAL { 4 } else { 3 }, message: e.to_string() }
    }
}

pub fn usage(msg: impl Into<String>) -> Fail {
    Fail { code: 2, message: msg.into() }
}

pub type Res<T> = Result<T, Fail>;

pub struct App {
    pub ctx: Ctx,
    pub format: Format,
    pub progress: bool,
    /// `-o key=value` and the typed sugar, validated against the registry.
    pub opts: Options,
    /// The keys the user set explicitly (`-o KEY=VALUE`), so a key an operation does not accept
    /// is reported rather than silently dropped by the projection (a `round run
    /// -o passes.pass-through-return=recovered` measured nothing for exactly that reason).
    pub explicit: std::collections::BTreeSet<String>,
    /// Operation name → its parameter list (from the `ops` table), for projecting `opts`.
    op_params: BTreeMap<String, Vec<String>>,
    diagnostic_keys: BTreeSet<String>,
    session_dir: Option<PathBuf>,
    session: Option<Session>,
    /// `toolchains.<name>.install` from the machine config — where each named toolchain lives here.
    pub toolchain_installs: BTreeMap<String, String>,
    /// The machine config file `toolchain add` writes to.
    pub machine_config: Option<PathBuf>,
    opened: BTreeSet<String>,
}

impl App {
    pub fn new(data_dirs: Vec<PathBuf>, abort_on_panic: bool, format: Format, progress: bool, session: &Path) -> Res<App> {
        let ctx = Ctx::new(CtxConfig { spec_dirs: data_dirs, abort_on_panic, ..Default::default() })?;
        let opts = ctx.options()?;
        let ops = ctx.ops(true)?;
        let mut op_params = BTreeMap::new();
        for r in 0..ops.rows() {
            let params: Vec<String> = ops.str(r, 4)?.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect();
            op_params.insert(ops.str(r, 0)?.to_string(), params);
        }
        let reg = ctx.options_registry()?;
        let mut diagnostic_keys = BTreeSet::new();
        for r in 0..reg.rows() {
            if reg.str(r, 5)? == "diagnostic" {
                diagnostic_keys.insert(reg.str(r, 0)?.to_string());
            }
        }
        let session_dir = match session.to_str() {
            Some("-") | Some("mem") => None,
            _ => Some(session.to_path_buf()),
        };
        Ok(App { ctx, format, progress, opts, op_params, diagnostic_keys, session_dir, session: None, toolchain_installs: BTreeMap::new(), machine_config: None, opened: BTreeSet::new(), explicit: BTreeSet::new() })
    }

    /// Apply the machine config: only `Environment` keys may live there (none in this version).
    pub fn apply_machine_config(&mut self, cfg: &BTreeMap<String, String>) -> Res<()> {
        let reg = self.ctx.options_registry()?;
        let mut affects = BTreeMap::new();
        for r in 0..reg.rows() {
            affects.insert(reg.str(r, 0)?.to_string(), reg.str(r, 5)?.to_string());
        }
        for (k, v) in cfg {
            // the CLI's own keys: where each named toolchain is installed on this machine
            if let Some(name) = k.strip_prefix("toolchains.").and_then(|r| r.strip_suffix(".install")) {
                self.toolchain_installs.insert(name.to_string(), v.clone());
                continue;
            }
            match affects.get(k).map(String::as_str) {
                Some("environment") => self.opts.set(k, v)?,
                Some(_) => return Err(usage(format!("machine config: `{k}` affects results and belongs in the session config (`mosura config set {k}={v}`)"))),
                None => return Err(usage(format!("machine config: unknown key `{k}`"))),
            }
        }
        Ok(())
    }

    pub fn session(&mut self) -> Res<&mut Session> {
        if self.session.is_none() {
            let s = Session::open(&self.ctx, self.session_dir.as_deref(), None)?;
            self.session = Some(s);
        }
        Ok(self.session.as_mut().expect("just opened"))
    }

    /// The options `op` accepts, out of the merged set plus `extra` (a typed command's own keys).
    /// An operation the registry does not list gets `extra` alone and the library's answer (not
    /// found, or "not built in" for a `dev.*` name in a release build).
    pub fn params_for(&self, op: &str, extra: &[(&str, &str)]) -> Res<Options> {
        let mut o = self.ctx.options()?;
        let Some(params) = self.op_params.get(op) else {
            for (k, v) in extra {
                o.set(k, v)?;
            }
            return Ok(o);
        };
        let emit_ok = params.iter().any(|p| p == "emit.*");
        let reg = self.ctx.options_registry()?;
        for r in 0..reg.rows() {
            let k = reg.str(r, 0)?;
            let accepted = params.iter().any(|p| p == k) || self.diagnostic_keys.contains(k) || (emit_ok && k.starts_with("emit.") && k != "emit.arms-off");
            if !accepted {
                if self.explicit.contains(k) {
                    eprintln!("warning: -o {k} is not an option of {op} and was ignored (`mosura ops` lists what each operation accepts)");
                }
                continue;
            }
            let v = self.opts.get(k)?;
            if v != reg.str(r, 2)? {
                o.set(k, &v)?;
            }
        }
        for (k, v) in extra {
            o.set(k, v)?;
        }
        Ok(o)
    }

    /// Run an operation through the plumbing (`mosura call`).
    pub fn call(&mut self, op: &str, extra: &[(&str, &str)]) -> Res<Table> {
        let params = self.params_for(op, extra)?;
        let progress = self.progress;
        let s = self.session()?;
        let mut report = |stage: &str, done: u64, total: u64| -> bool {
            if progress {
                eprintln!("[{stage}] {done}/{total}");
            }
            true
        };
        Ok(s.call(op, Some(&params), if progress { Some(&mut report) } else { None })?)
    }

    /// The session config as a map (the `session.config` table).
    pub fn session_config(&mut self) -> Res<BTreeMap<String, String>> {
        let t = self.call("session.config", &[])?;
        let mut m = BTreeMap::new();
        for r in 0..t.rows() {
            m.insert(t.str(r, 0)?.to_string(), t.str(r, 1)?.to_string());
        }
        Ok(m)
    }

    /// Open the named toolchain in the session (once per process): its spec from `--spec` or the
    /// session config (`toolchains.<name>.spec`, written by `toolchain add`), its install from
    /// `--install` or the machine config (`toolchains.<name>.install`).
    pub fn open_toolchain(&mut self, name: &str, spec: Option<&str>, install: Option<&str>) -> Res<()> {
        if self.opened.contains(name) {
            return Ok(());
        }
        let cfg = self.session_config()?;
        let spec = match spec {
            Some(s) => s.to_string(),
            None => cfg.get(&format!("toolchains.{name}.spec")).cloned().ok_or_else(|| usage(format!("toolchain `{name}` has no spec: `mosura toolchain add {name} --spec <spec> --install <dir>` (see `mosura toolchain specs`)")))?,
        };
        let install = match install {
            Some(i) => i.to_string(),
            None => self.toolchain_installs.get(name).cloned().ok_or_else(|| usage(format!("toolchain `{name}`: no install location on this machine — `mosura toolchain add {name} --spec {spec} --install <dir>` writes it to the machine config, or pass --install")))?,
        };
        self.call("toolchain.open", &[("toolchain", name), ("toolchain.spec", &spec), ("toolchain.install", &install)])?;
        self.opened.insert(name.to_string());
        Ok(())
    }

    /// Remember the current program in the session config (the default `program` of every op).
    pub fn set_current_program(&mut self, key: &str) -> Res<()> {
        self.call("session.config.set", &[("key", "program"), ("value", key)])?;
        Ok(())
    }

    /// `0x<va>`, a decimal address, or a function name from the functions table.
    pub fn resolve_function(&mut self, name: &str) -> Res<u64> {
        let t = name.trim();
        if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            return u64::from_str_radix(h, 16).map_err(|_| usage(format!("`{name}` is not an address")));
        }
        if t.chars().all(|c| c.is_ascii_digit()) && !t.is_empty() {
            return t.parse().map_err(|_| usage(format!("`{name}` is not an address")));
        }
        let fns = self.call("program.tables", &[("table", "functions")])?;
        for r in 0..fns.rows() {
            if fns.str(r, 2)? == t {
                return fns.u64(r, 1).map_err(Fail::from);
            }
        }
        Err(Fail { code: 3, message: format!("no function named `{name}` (see `mosura functions`)") })
    }

    /// Every function entry of the current program, in table order.
    pub fn entries(&mut self) -> Res<Vec<u64>> {
        let fns = self.call("program.tables", &[("table", "functions")])?;
        (0..fns.rows()).map(|r| fns.u64(r, 1).map_err(Fail::from)).collect()
    }

    pub fn render(&self, t: &Table) -> Res<String> {
        Ok(t.render(self.format)?)
    }

    /// Print a table in the chosen format.
    pub fn show(&self, t: &Table) -> Res<()> {
        print!("{}", self.render(t)?);
        Ok(())
    }
}

/// Split `--arms-off a,b` into the arm half (`emit.arms-off`) and the switch half (`knobs.off`),
/// by the arms table; arm names accept dashes.
pub fn split_arms_off(ctx: &Ctx, list: &str) -> Res<(String, String)> {
    let arms = ctx.emit_arms()?;
    let known: BTreeSet<String> = (0..arms.rows()).map(|r| arms.str(r, 0).map(str::to_string)).collect::<Result<_, _>>()?;
    let (mut a, mut k) = (Vec::new(), Vec::new());
    for name in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let underscored = name.replace('-', "_");
        if known.contains(&underscored) { a.push(underscored) } else { k.push(name.to_string()) }
    }
    Ok((a.join(","), k.join(",")))
}
