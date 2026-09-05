//! The dev tier's option keys (`dev.*`), registered with the operations. `Input` keys name what
//! an operation reads or writes; dev operations are transient, so nothing here enters a cache key.

use mosura_api::{Affects, OptType, OptionSpec};

pub const DEV_PATH: &str = "dev.path";
pub const DEV_SYMBOL: &str = "dev.symbol";
pub const DEV_OUT: &str = "dev.out";
pub const DEV_ONLY: &str = "dev.only";
pub const DEV_LIMIT: &str = "dev.limit";
pub const DEV_CHECK: &str = "dev.check";
pub const DEV_M32: &str = "dev.m32";
pub const DEV_ARMS: &str = "dev.arms";
pub const DEV_FIXTURE: &str = "dev.fixture";
pub const DEV_PROGRAMS: &str = "dev.programs";

const SINCE: &str = "0.1";

macro_rules! spec {
    ($key:expr, $ty:expr, $default:expr, $doc:expr) => {
        OptionSpec { key: $key, ty: $ty, default: $default, doc: $doc, since: SINCE, affects: Affects::Input }
    };
}

pub fn all() -> Vec<OptionSpec> {
    vec![
        spec!(DEV_PATH, OptType::Str, "", "a file the dev operation reads (dev.omf.dump: the object file)"),
        spec!(DEV_SYMBOL, OptType::Str, "", "a symbol name (dev.omf.dump: extract this function from the object as the verifier would, at `base`)"),
        spec!(DEV_OUT, OptType::Str, "", "an output directory (dev.oracle.sweep: the work dir, default <session>/dev/sweep; dev.groundtruth.recompile: the report dir, default <workspace>/build/gt-recompile; dev.mve.fixtures: where the fixtures are written)"),
        spec!(DEV_ONLY, OptType::List(&[]), "", "restrict the run to these items (dev.oracle.sweep: emit indices or hex addresses; dev.bench: fixture stems)"),
        spec!(DEV_LIMIT, OptType::U64, "", "stop after this many items (dev.oracle.sweep)"),
        spec!(DEV_CHECK, OptType::Bool, "false", "check mode (dev.mve.fixtures: regenerate into a temp dir and compare against the committed fixtures instead of writing them)"),
        spec!(DEV_M32, OptType::Bool, "false", "dev.groundtruth.recompile: the 32-bit column (gcc -m32) instead of x86-64"),
        spec!(DEV_ARMS, OptType::Bool, "false", "dev.groundtruth.recompile: emit under the survey's measured arm set (canonical arms + per-function recovery) instead of the plain plan"),
        spec!(DEV_FIXTURE, OptType::Str, "", "dev.groundtruth.recompile: also write every function's original bytes as a datatest fixture into this directory"),
        spec!(DEV_PROGRAMS, OptType::List(&[]), "", "dev.groundtruth.recompile: the ground-truth programs to run, by file stem (all when empty)"),
    ]
}
