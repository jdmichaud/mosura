//! The session's own operations: its config table (the defaults every operation run in the
//! session gets for the keys it accepts — a front-end keeps its "current program" there).

use crate::error::{Error, Result};
use crate::ops::{Cache, Op, Progress, Tier};
use crate::options::Options;
use crate::session::Session;
use crate::table::Table;

pub static CONFIG: Op = Op { name: "session.config", doc: "the session config table (key, value): option defaults for every operation run in this session", since: "0.1", tier: Tier::Product, params: &[], result: "config", cache: Cache::Transient, run: |s, _o, _p| Ok(s.config_table()) };
pub static CONFIG_SET: Op = Op { name: "session.config.set", doc: "set a session config key (an empty value removes it); answers the config table", since: "0.1", tier: Tier::Product, params: &["key", "value"], result: "config", cache: Cache::Transient, run: config_set };

fn config_set(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let key = o.get("key")?;
    if key.is_empty() {
        return Err(Error::InvalidArg("`key` is required".into()));
    }
    // a Result-affecting default must be a registered key with a valid value; Input keys (the
    // current program) and unregistered front-end keys are stored as given
    if let Some(spec) = crate::options::registry::lookup(key) {
        let value = o.get("value")?;
        if !value.is_empty() {
            Options::new().set(spec.key, value)?;
        }
    }
    s.config_set(key, o.get("value")?)?;
    Ok(s.config_table())
}
