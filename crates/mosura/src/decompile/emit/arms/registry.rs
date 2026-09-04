//! The arms' evidence registry: what every arm reports on the report pass and what the
//! recovered pass renders — relocated out of printc.rs so the port holds two opaque fields
//! (`report`, `recovered`) and learns no arm's name.

/// Every arm's report candidates, one sub-struct per arm (review F1, 2026-09-04): the printer holds this
/// registry as ONE opaque field and never spells an arm's vocabulary; an arm touches its own
/// module and one line here. `port` is the R2b backlog — renderings still in printc.rs.
#[derive(Debug, Default, Clone)]
pub struct Report {
    pub port: super::port::Report,
    pub array_index: super::array_index::Report,
    pub cmp_order: super::cmp_order::Report,
    pub cmp_sign: super::cmp_sign::Report,
    pub complement_cmp: super::complement_cmp::Report,
    pub counted_loop: super::counted_loop::Report,
    pub ext_cast: super::ext_cast::Report,
    pub join_narrow: super::join_narrow::Report,
    pub load_hoist: super::load_hoist::Report,
    pub mask_cast: super::mask_cast::Report,
    pub nested_conds: super::nested_conds::Report,
    pub ptr_offset: super::ptr_offset::Report,
    pub return_split: super::return_split::Report,
    pub sdiv_pow2: super::sdiv_pow2::Report,
    pub snapshot: super::snapshot::Report,
    pub store_forward: super::store_forward::Report,
    pub string_ops: super::string_ops::Report,
    pub testmem: super::testmem::Report,
    pub unsigned_cmp: super::unsigned_cmp::Report,
}

/// Every arm's witnessed decisions, one sub-struct per arm (review F1, 2026-09-04): the printer holds this
/// registry as ONE opaque field and never spells an arm's vocabulary; an arm touches its own
/// module and one line here. `port` is the R2b backlog — renderings still in printc.rs.
#[derive(Debug, Default, Clone)]
pub struct Recovered {
    pub port: super::port::Sites,
    pub array_index: super::array_index::Sites,
    pub cmp_order: super::cmp_order::Sites,
    pub cmp_sign: super::cmp_sign::Sites,
    pub complement_cmp: super::complement_cmp::Sites,
    pub counted_loop: super::counted_loop::Sites,
    pub ext_cast: super::ext_cast::Sites,
    pub frame_fill: super::frame_fill::Sites,
    pub join_narrow: super::join_narrow::Sites,
    pub load_hoist: super::load_hoist::Sites,
    pub mask_cast: super::mask_cast::Sites,
    pub nested_conds: super::nested_conds::Sites,
    pub ptr_offset: super::ptr_offset::Sites,
    pub return_split: super::return_split::Sites,
    pub return_widen: super::return_widen::Sites,
    pub sdiv_pow2: super::sdiv_pow2::Sites,
    pub snapshot: super::snapshot::Sites,
    pub sparse_switch: super::sparse_switch::Sites,
    pub store_forward: super::store_forward::Sites,
    pub string_ops: super::string_ops::Sites,
    pub struct_copy: super::struct_copy::Sites,
    pub testmem: super::testmem::Sites,
    pub unsigned_cmp: super::unsigned_cmp::Sites,
}

/// What "off" means for one arm's witnessed decisions: the arm owns the answer (review F2,
/// 2026-09-04). The default — every decision dropped, `Default::default()` — is right for a
/// render-time arm (an empty witness set IS the port's own rendering) and for a block whose
/// declaration effects travel with their renderings: `port` (the R2b backlog) is switched as
/// one unit, so a widened declaration is never emitted without the rendering that consumes it.
/// An arm that needs a finer answer overrides `off`.
pub trait Off: Default {
    fn off(&mut self) {
        *self = Self::default();
    }
}
impl Off for super::port::Sites {}
impl Off for super::array_index::Sites {}
impl Off for super::cmp_order::Sites {}
impl Off for super::cmp_sign::Sites {}
impl Off for super::complement_cmp::Sites {}
impl Off for super::counted_loop::Sites {}
impl Off for super::ext_cast::Sites {}
impl Off for super::frame_fill::Sites {}
impl Off for super::join_narrow::Sites {}
impl Off for super::load_hoist::Sites {}
impl Off for super::mask_cast::Sites {}
impl Off for super::nested_conds::Sites {}
impl Off for super::ptr_offset::Sites {}
impl Off for super::return_split::Sites {}
impl Off for super::return_widen::Sites {}
impl Off for super::sdiv_pow2::Sites {}
impl Off for super::snapshot::Sites {}
impl Off for super::sparse_switch::Sites {}
impl Off for super::store_forward::Sites {}
impl Off for super::string_ops::Sites {}
impl Off for super::struct_copy::Sites {}
impl Off for super::testmem::Sites {}
impl Off for super::unsigned_cmp::Sites {}

impl Recovered {
    /// The switchable arm names (the registry's fields; `-` and `_` both accepted).
    pub const ARMS: [&'static str; 23] = ["port", "array_index", "cmp_order", "cmp_sign", "complement_cmp", "counted_loop", "ext_cast", "frame_fill", "join_narrow", "load_hoist", "mask_cast", "nested_conds", "ptr_offset", "return_split", "return_widen", "sdiv_pow2", "snapshot", "sparse_switch", "store_forward", "string_ops", "struct_copy", "testmem", "unsigned_cmp"];

    /// Switch one arm's witnessed decisions off — the port then prints that arm's sites as it
    /// prints everything else — or `Err` with the unknown name. A tree emitted with an arm off
    /// must say so: the caller stamps the manifest's `arms:` line (`war2_survey --arms-off`).
    pub fn switch_off(&mut self, arm: &str) -> Result<(), String> {
        match arm.replace('-', "_").as_str() {
            "port" => self.port.off(),
            "array_index" => self.array_index.off(),
            "cmp_order" => self.cmp_order.off(),
            "cmp_sign" => self.cmp_sign.off(),
            "complement_cmp" => self.complement_cmp.off(),
            "counted_loop" => self.counted_loop.off(),
            "ext_cast" => self.ext_cast.off(),
            "frame_fill" => self.frame_fill.off(),
            "join_narrow" => self.join_narrow.off(),
            "load_hoist" => self.load_hoist.off(),
            "mask_cast" => self.mask_cast.off(),
            "nested_conds" => self.nested_conds.off(),
            "ptr_offset" => self.ptr_offset.off(),
            "return_split" => self.return_split.off(),
            "return_widen" => self.return_widen.off(),
            "sdiv_pow2" => self.sdiv_pow2.off(),
            "snapshot" => self.snapshot.off(),
            "sparse_switch" => self.sparse_switch.off(),
            "store_forward" => self.store_forward.off(),
            "string_ops" => self.string_ops.off(),
            "struct_copy" => self.struct_copy.off(),
            "testmem" => self.testmem.off(),
            "unsigned_cmp" => self.unsigned_cmp.off(),
            other => return Err(format!("unknown arm `{other}` (switchable: {})", Self::ARMS.join(", "))),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every registry arm switches off by name (either spelling), an unknown name is refused
    /// with the switchable list, and the R2b block goes off as one unit — a widened
    /// declaration never survives without the rendering that consumes it.
    #[test]
    fn switch_off_is_by_name_and_atomic_per_arm() {
        let mut r = Recovered::default();
        r.port.widen_local_reps.insert(3);
        r.port.tier2_sites.insert(crate::decompile::varnode::VarnodeId(0));
        r.port.narrow_return = true;
        r.cmp_sign.sites.insert(0x1000);
        assert!(r.switch_off("cmp-sign").is_ok());
        assert!(r.cmp_sign.sites.is_empty() && !r.port.widen_local_reps.is_empty());
        assert!(r.switch_off("port").is_ok());
        assert!(r.port.widen_local_reps.is_empty() && r.port.tier2_sites.is_empty() && !r.port.narrow_return);
        let err = r.switch_off("no-such-arm").unwrap_err();
        assert!(err.contains("unknown arm") && err.contains("cmp_sign"));
        for a in Recovered::ARMS {
            assert!(Recovered::default().switch_off(a).is_ok(), "{a}");
        }
    }
}
