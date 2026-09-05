//! The dev tier's option keys (`dev.*`), registered with the operations. `Input` keys name what
//! an operation reads; dev operations are transient, so nothing here enters a cache key.

use mosura_api::{Affects, OptType, OptionSpec};

pub const DEV_PATH: &str = "dev.path";
pub const DEV_SYMBOL: &str = "dev.symbol";

const SINCE: &str = "0.1";

pub fn all() -> Vec<OptionSpec> {
    vec![
        OptionSpec { key: DEV_PATH, ty: OptType::Str, default: "", doc: "a file the dev operation reads (dev.omf.dump: the object file)", since: SINCE, affects: Affects::Input },
        OptionSpec { key: DEV_SYMBOL, ty: OptType::Str, default: "", doc: "a symbol name (dev.omf.dump: extract this function from the object as the verifier would, at `base`)", since: SINCE, affects: Affects::Input },
    ]
}
