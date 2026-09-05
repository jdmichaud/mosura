//! `mosura` — the command line (`docs/product/architecture.md` §6). Porcelain over the `mosura`
//! binding; every leaf is an operation, and `mosura call <op>` reaches the rest. The CLI owns
//! interaction and no state: sessions are directories the library owns. It reads no environment
//! variable except `HOME`, to locate the machine config (config.rs).

mod app;
mod config;

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use mosura::Format;

use app::{split_arms_off, usage, App, Res};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum FormatArg {
    Text,
    Tsv,
    Json,
}

#[derive(Parser, Debug)]
#[command(name = "mosura", version, about = "mosura — decompile, emit and recompile through the mosura library", long_about = None)]
struct Cli {
    /// The session directory (`-` or `mem` = an in-memory session for one-shot commands)
    #[arg(short = 'S', long, global = true, default_value = ".mosura", value_name = "DIR")]
    session: PathBuf,
    /// The machine config file (default: <home>/.config/mosura/config.toml; Environment keys only)
    #[arg(long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,
    /// How tables print
    #[arg(long, global = true, value_enum, default_value_t = FormatArg::Text)]
    format: FormatArg,
    /// Diagnostic topics (`debug.topics`), comma-separated
    #[arg(long, global = true, value_name = "TOPICS")]
    debug: Option<String>,
    /// An override directory for spec/FID data (repeatable; searched before the embedded data)
    #[arg(long = "data-dir", global = true, value_name = "DIR")]
    data_dirs: Vec<PathBuf>,
    /// The session input a command runs on (label or digest; the only one when omitted)
    #[arg(long, global = true, value_name = "LABEL")]
    input: Option<String>,
    /// An option key (`mosura ops`, `mosura schema option_registry`)
    #[arg(short = 'o', long = "set", global = true, value_name = "KEY=VALUE")]
    set: Vec<String>,
    /// Let an internal panic propagate with its backtrace instead of reporting MOSURA_ERR_INTERNAL
    #[arg(long, global = true)]
    abort_on_panic: bool,
    /// Report operation progress on stderr
    #[arg(long, global = true)]
    progress: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// What a file is: container, loaders, compiler evidence, language, cspec, FID
    Identify { bin: PathBuf },
    /// Create the session directory
    Init,
    /// Add an input binary to the session
    Add {
        bin: PathBuf,
        #[arg(long)]
        label: Option<String>,
    },
    /// The session's inputs
    Inputs,
    /// Load an input (adds it first when a path is given); becomes the current program
    Load {
        bin: Option<PathBuf>,
        #[arg(long, value_name = "default|native|le|x32|com|raw|xml")]
        loader: Option<String>,
        #[arg(long, value_name = "ID")]
        language: Option<String>,
        #[arg(long, value_name = "ADDR")]
        base: Option<String>,
        #[arg(long, value_name = "ID")]
        cspec: Option<String>,
    },
    /// Auto-analyze the current input (loads it first); becomes the current program
    Analyze {
        #[arg(long, value_name = "A,B")]
        disable: Option<String>,
        #[arg(long, value_name = "default|native|le|x32|com|raw|xml")]
        loader: Option<String>,
        #[arg(long, value_name = "ID")]
        language: Option<String>,
        #[arg(long, value_name = "ADDR")]
        base: Option<String>,
        #[arg(long, value_name = "ID")]
        cspec: Option<String>,
    },
    /// The whole-program passes that feed emission (prototypes, marks, evidence)
    Passes,
    Functions,
    Symbols,
    Refs,
    Blocks,
    Listing,
    Relocs,
    Entries,
    Comments,
    Protos,
    Facts,
    /// A program table by name (`mosura table` lists them)
    Table { name: Option<String> },
    /// Bytes of the loaded image
    Read { addr: String, len: u64 },
    /// Disassemble a range of the current program, or raw bytes (`--bytes HEX --language ID`)
    Disasm {
        addr: Option<String>,
        len: Option<u64>,
        #[arg(long, value_name = "HEX")]
        bytes: Option<String>,
        #[arg(long, value_name = "ID")]
        language: Option<String>,
        #[arg(long, value_name = "ADDR")]
        base: Option<String>,
        #[arg(long, value_name = "NAME=V;..")]
        ctx: Option<String>,
    },
    /// Lift raw bytes to p-code
    Lift {
        bytes: String,
        #[arg(long, value_name = "ID", default_value = "x86:LE:32:default")]
        language: String,
        #[arg(long, value_name = "ADDR")]
        base: Option<String>,
        #[arg(long, value_name = "NAME=V;..")]
        ctx: Option<String>,
    },
    /// Decompile a function (`0x<va>` or a name) or every function
    Decompile {
        func: Option<String>,
        #[arg(long)]
        all: bool,
        /// c (default), raw, or table:<prototype|jumptables|calls>
        #[arg(long = "as", value_name = "c|raw|table:NAME", default_value = "c")]
        as_: String,
    },
    /// The recovered translation unit of a function, or of every function into --out (Watcom x86-32)
    Emit {
        func: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long, value_name = "DIR")]
        out: Option<PathBuf>,
        /// Arms and switches to turn off (one name space)
        #[arg(long = "arms-off", value_name = "A,B")]
        arms_off: Option<String>,
        /// The emit report instead of the TU
        #[arg(long)]
        report: bool,
    },
    /// The analysis snapshot (the golden format)
    Snapshot,
    /// The language catalogue
    Languages,
    /// A language's registers
    Registers {
        #[arg(long, value_name = "ID")]
        language: String,
    },
    /// The emit axes
    Axes,
    /// The emit arms
    Arms,
    /// The embedded data: export an override directory, or list what is in effect
    Data {
        #[command(subcommand)]
        what: DataCmd,
    },
    /// The operation registry
    Ops {
        #[arg(long)]
        dev: bool,
    },
    /// A table schema
    Schema { name: String },
    /// Any operation by name: `mosura call <op> key=value ...`
    Call {
        op: String,
        #[arg(value_name = "KEY=VALUE")]
        args: Vec<String>,
    },
    /// The session config (`mosura config set key=value`)
    Config {
        #[command(subcommand)]
        sub: Option<ConfigCmd>,
    },
    /// The store: explain a key, list the sets
    Cache {
        #[command(subcommand)]
        sub: CacheCmd,
    },
    /// Library and ABI versions
    Version,
}

#[derive(Subcommand, Debug)]
enum DataCmd {
    Export {
        dir: PathBuf,
        #[arg(long)]
        overwrite: bool,
        #[arg(long, default_value = "all", value_name = "all|specs|fid")]
        what: String,
    },
    List,
}

#[derive(Subcommand, Debug)]
enum ConfigCmd {
    Set { kv: String },
}

#[derive(Subcommand, Debug)]
enum CacheCmd {
    Explain { key: String },
    Gc,
}

fn main() {
    let cli = Cli::parse();
    let code = match run(cli) {
        Ok(()) => 0,
        Err(f) => {
            eprintln!("mosura: {}", f.message);
            f.code
        }
    };
    std::process::exit(code);
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn run(cli: Cli) -> Res<()> {
    let format = match cli.format {
        FormatArg::Text => Format::MOSURA_FMT_TEXT,
        FormatArg::Tsv => Format::MOSURA_FMT_TSV,
        FormatArg::Json => Format::MOSURA_FMT_JSON,
    };
    let mut app = App::new(cli.data_dirs.clone(), cli.abort_on_panic, format, cli.progress, &cli.session)?;
    let machine = config::load(cli.config.as_deref()).map_err(usage)?;
    app.apply_machine_config(&machine)?;
    for kv in &cli.set {
        let (k, v) = kv.split_once('=').ok_or_else(|| usage(format!("`-o {kv}`: expected KEY=VALUE")))?;
        app.opts.set(k.trim(), v.trim())?;
    }
    if let Some(topics) = &cli.debug {
        app.opts.set("debug.topics", topics)?;
    }
    if let Some(input) = &cli.input {
        app.opts.set("input", input)?;
    }
    match cli.cmd {
        Cmd::Identify { bin } => {
            let data = std::fs::read(&bin).map_err(|e| usage(format!("{}: {e}", bin.display())))?;
            let t = app.ctx.identify(&data)?;
            app.show(&t)
        }
        Cmd::Init => {
            app.session()?;
            println!("session: {}", cli.session.display());
            Ok(())
        }
        Cmd::Add { bin, label } => {
            let data = std::fs::read(&bin).map_err(|e| usage(format!("{}: {e}", bin.display())))?;
            let label = label.unwrap_or_else(|| bin.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "input".into()));
            let digest = app.session()?.add_input(&data, &label)?;
            println!("{digest}\t{label}");
            Ok(())
        }
        Cmd::Inputs => {
            let t = app.session()?.inputs()?;
            app.show(&t)
        }
        Cmd::Load { bin, loader, language, base, cspec } => load_or_analyze(&mut app, bin, loader, language, base, cspec, None, false),
        Cmd::Analyze { disable, loader, language, base, cspec } => load_or_analyze(&mut app, None, loader, language, base, cspec, disable, true),
        Cmd::Passes => {
            let t = app.call("program.passes", &[])?;
            app.show(&t)
        }
        Cmd::Functions => table(&mut app, "functions"),
        Cmd::Symbols => table(&mut app, "symbols"),
        Cmd::Refs => table(&mut app, "references"),
        Cmd::Blocks => table(&mut app, "blocks"),
        Cmd::Listing => table(&mut app, "listing"),
        Cmd::Relocs => table(&mut app, "relocations"),
        Cmd::Entries => table(&mut app, "entry_points"),
        Cmd::Comments => table(&mut app, "comments"),
        Cmd::Protos => table(&mut app, "protos"),
        Cmd::Facts => table(&mut app, "facts"),
        Cmd::Table { name } => table(&mut app, name.as_deref().unwrap_or("")),
        Cmd::Read { addr, len } => {
            let a = app.resolve_function(&addr)?;
            let t = app.call("program.read", &[("addr", &format!("{a:#x}")), ("len", &len.to_string())])?;
            println!("{}", hex_of(t.bytes(0, 1)?));
            Ok(())
        }
        Cmd::Disasm { addr, len, bytes, language, base, ctx } => {
            if let Some(hex) = bytes {
                let lang = language.unwrap_or_else(|| "x86:LE:32:default".to_string());
                let mut extra = vec![("lang", lang.as_str()), ("bytes", hex.as_str())];
                let b = base.clone().unwrap_or_default();
                if !b.is_empty() {
                    extra.push(("base", b.as_str()));
                }
                let c = ctx.clone().unwrap_or_default();
                if !c.is_empty() {
                    extra.push(("ctx", c.as_str()));
                }
                let t = app.call("sleigh.disassemble", &extra)?;
                return app.show(&t);
            }
            let addr = addr.ok_or_else(|| usage("disasm needs <addr> <len>, or --bytes HEX"))?;
            let a = app.resolve_function(&addr)?;
            let t = match len {
                Some(n) => app.call("program.disassemble", &[("addr", &format!("{a:#x}")), ("len", &n.to_string())])?,
                None => app.call("program.disassemble", &[("entry", &format!("{a:#x}"))])?,
            };
            app.show(&t)
        }
        Cmd::Lift { bytes, language, base, ctx } => {
            let mut extra = vec![("lang", language.as_str()), ("bytes", bytes.as_str())];
            let b = base.clone().unwrap_or_default();
            if !b.is_empty() {
                extra.push(("base", b.as_str()));
            }
            let c = ctx.clone().unwrap_or_default();
            if !c.is_empty() {
                extra.push(("ctx", c.as_str()));
            }
            let t = app.call("sleigh.lift", &extra)?;
            app.show(&t)
        }
        Cmd::Decompile { func, all, as_ } => {
            let entries = targets(&mut app, func, all)?;
            let mut failed = 0usize;
            for (i, e) in entries.iter().enumerate() {
                if entries.len() > 1 {
                    if i > 0 {
                        println!();
                    }
                    println!("/* ===== {e:#010x} ===== */");
                }
                match app.call("function.decompile", &[("entry", &format!("{e:#x}")), ("format", &as_)]) {
                    Ok(t) => app.show(&t)?,
                    // over a whole program a function the pipeline declines is reported in place,
                    // as the survey's DECOMPILE_FAIL row is, and the run goes on
                    Err(f) if all && f.code == 4 => {
                        println!("/* decompile failed: {} */", f.message);
                        failed += 1;
                    }
                    Err(f) => return Err(f),
                }
            }
            if all && failed > 0 {
                eprintln!("decompile: {failed} of {} function(s) failed", entries.len());
            }
            Ok(())
        }
        Cmd::Emit { func, all, out, arms_off, report } => {
            if let Some(list) = &arms_off {
                let (arms, switches) = split_arms_off(&app.ctx, list)?;
                if !arms.is_empty() {
                    app.opts.set("emit.arms-off", &arms)?;
                }
                if !switches.is_empty() {
                    app.opts.set("knobs.off", &switches)?;
                }
            }
            let entries = targets(&mut app, func, all)?;
            if let Some(dir) = &out {
                std::fs::create_dir_all(dir).map_err(|e| usage(format!("{}: {e}", dir.display())))?;
            }
            let (mut ok, mut failed) = (0usize, 0usize);
            for e in &entries {
                let entry = format!("{e:#x}");
                let fmt = if report { "table:report" } else { "tu" };
                let t = match app.call("function.emit", &[("entry", &entry), ("format", fmt)]) {
                    Ok(t) => t,
                    Err(f) if out.is_some() && f.code == 4 => {
                        eprintln!("{entry}: {}", f.message);
                        failed += 1;
                        continue;
                    }
                    Err(f) => return Err(f),
                };
                match &out {
                    None => app.show(&t)?,
                    Some(dir) => {
                        // the survey's file names: the emit index of the function, five digits
                        let rep = app.call("function.emit", &[("entry", &entry), ("format", "table:report")])?;
                        let idx = (0..rep.rows()).find(|&r| rep.str(r, 0).map(|k| k == "idx").unwrap_or(false)).map(|r| rep.str(r, 1).unwrap_or("0").to_string()).unwrap_or_else(|| "0".into());
                        let idx: usize = idx.parse().unwrap_or(0);
                        let text = t.render(Format::MOSURA_FMT_TEXT)?;
                        std::fs::write(dir.join(format!("{idx:05}.c")), text).map_err(|e| usage(format!("{}: {e}", dir.display())))?;
                        ok += 1;
                    }
                }
            }
            if let Some(dir) = &out {
                eprintln!("emit: {ok} written to {}, {failed} failed", dir.display());
            }
            Ok(())
        }
        Cmd::Snapshot => {
            let t = app.call("program.tables", &[("table", "snapshot")])?;
            print!("{}", t.render(Format::MOSURA_FMT_TEXT)?);
            Ok(())
        }
        Cmd::Languages => {
            let t = app.ctx.languages()?;
            app.show(&t)
        }
        Cmd::Registers { language } => {
            let t = app.ctx.language(&language)?.registers()?;
            app.show(&t)
        }
        Cmd::Axes => {
            let t = app.ctx.emit_axes()?;
            app.show(&t)
        }
        Cmd::Arms => {
            let t = app.ctx.emit_arms()?;
            app.show(&t)
        }
        Cmd::Data { what } => match what {
            DataCmd::Export { dir, overwrite, what } => {
                let t = app.ctx.export_data(&dir, &what, overwrite)?;
                eprintln!("data export: {} file(s) -> {}", t.rows(), dir.display());
                app.show(&t)
            }
            DataCmd::List => {
                let t = app.ctx.data_list()?;
                app.show(&t)
            }
        },
        Cmd::Ops { dev } => {
            let t = app.ctx.ops(dev)?;
            app.show(&t)
        }
        Cmd::Schema { name } => {
            let t = app.ctx.schema(&name)?;
            app.show(&t)
        }
        Cmd::Call { op, args } => {
            let mut pairs: Vec<(String, String)> = Vec::new();
            for a in &args {
                let a = a.trim_start_matches("--");
                let (k, v) = a.split_once('=').ok_or_else(|| usage(format!("`{a}`: expected KEY=VALUE")))?;
                pairs.push((k.trim().to_string(), v.trim().to_string()));
            }
            let extra: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let t = app.call(&op, &extra)?;
            app.show(&t)
        }
        Cmd::Config { sub } => match sub {
            None => {
                let t = app.call("session.config", &[])?;
                app.show(&t)
            }
            Some(ConfigCmd::Set { kv }) => {
                let (k, v) = kv.split_once('=').ok_or_else(|| usage(format!("`{kv}`: expected KEY=VALUE")))?;
                let t = app.call("session.config.set", &[("key", k.trim()), ("value", v.trim())])?;
                app.show(&t)
            }
        },
        Cmd::Cache { sub } => match sub {
            CacheCmd::Explain { key } => {
                let t = app.session()?.explain(&key)?;
                app.show(&t)
            }
            CacheCmd::Gc => {
                let t = app.session()?.gc(true)?;
                app.show(&t)
            }
        },
        Cmd::Version => {
            println!("mosura {} (abi {}.{})", mosura::version(), mosura::abi_version() >> 16, mosura::abi_version() & 0xffff);
            Ok(())
        }
    }
}

fn table(app: &mut App, name: &str) -> Res<()> {
    let t = app.call("program.tables", &[("table", name)])?;
    app.show(&t)
}

/// The functions a `decompile`/`emit` command targets.
fn targets(app: &mut App, func: Option<String>, all: bool) -> Res<Vec<u64>> {
    match (func, all) {
        (Some(f), false) => Ok(vec![app.resolve_function(&f)?]),
        (None, true) => app.entries(),
        (Some(_), true) => Err(usage("give a function or --all, not both")),
        (None, false) => Err(usage("which function? give `0x<va>`, a name, or --all")),
    }
}

/// `load` / `analyze`: the typed sugar into option keys, the program opened (and analyzed) through
/// the binding's handle, its key remembered as the session's current program.
#[allow(clippy::too_many_arguments)]
fn load_or_analyze(app: &mut App, bin: Option<PathBuf>, loader: Option<String>, language: Option<String>, base: Option<String>, cspec: Option<String>, disable: Option<String>, analyze: bool) -> Res<()> {
    if let Some(bin) = &bin {
        let data = std::fs::read(bin).map_err(|e| usage(format!("{}: {e}", bin.display())))?;
        let label = bin.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "input".into());
        app.session()?.add_input(&data, &label)?;
        app.opts.set("input", &label)?;
    }
    for (k, v) in [("load.loader", loader), ("load.language", language), ("load.base", base), ("load.cspec-x86-32", cspec), ("analysis.disable", disable)] {
        if let Some(v) = v {
            app.opts.set(k, &v)?;
        }
    }
    let load_opts = app.params_for("program.load", &[])?;
    let input = if app.opts.get("input")?.is_empty() { None } else { Some(app.opts.get("input")?) };
    let progress = app.progress;
    let mut p = app.session()?.program_open(input.as_deref(), Some(&load_opts))?;
    if analyze {
        let analyze_opts = app.params_for("program.analyze", &[])?;
        let mut report = |stage: &str, done: u64, total: u64| -> bool {
            if progress {
                eprintln!("[{stage}] {done}/{total}");
            }
            true
        };
        p.analyze(Some(&analyze_opts), if progress { Some(&mut report) } else { None })?;
    }
    let key = p.key()?;
    app.set_current_program(&key)?;
    let summary = app.call(if analyze { "program.analyze" } else { "program.load" }, &[])?;
    app.show(&summary)
}
