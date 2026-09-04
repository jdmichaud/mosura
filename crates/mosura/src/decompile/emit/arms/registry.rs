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
    pub inline_call: super::inline_call::Report,
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
    pub inline_call: super::inline_call::Sites,
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
impl Off for super::inline_call::Sites {}
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
    pub const ARMS: [&'static str; 24] = ["port", "array_index", "cmp_order", "cmp_sign", "complement_cmp", "counted_loop", "ext_cast", "frame_fill", "inline_call", "join_narrow", "load_hoist", "mask_cast", "nested_conds", "ptr_offset", "return_split", "return_widen", "sdiv_pow2", "snapshot", "sparse_switch", "store_forward", "string_ops", "struct_copy", "testmem", "unsigned_cmp"];

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
            "inline_call" => self.inline_call.off(),
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

/// The decisions this registry has that `prev` does not — a site, key or flag a further render
/// INTRODUCED (review F3's fixpoint check; finding 3: each arm compares its own `Sites`, and
/// `Recovered::grown_over` destructures the registry WITHOUT `..`, so a new arm is a compile
/// error until it is compared — a check that quietly narrows is worse than no check). Growth
/// only: a decision whose candidate the render consumed vanishes by design. The widening
/// compares its decided candidates' ADDRESSES (`port::Sites::widen_local_pcs`), never the
/// representative indices a re-render can renumber.
pub trait Grown {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str>;
}
impl Grown for super::port::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.narrow_return && self.narrow_return_width != prev.narrow_return_width {
            out.push("narrow_return_width");
        }
        if self.narrow_return && !prev.narrow_return {
            out.push("narrow_return");
        }
        if self.narrow_return_signed && !prev.narrow_return_signed {
            out.push("narrow_return_signed");
        }
        if self.widen_local_pcs.iter().any(|x| !prev.widen_local_pcs.contains(x)) {
            out.push("widen_local_pcs");
        }
        if self.tier2_sites.iter().any(|x| !prev.tier2_sites.contains(x)) {
            out.push("tier2_sites");
        }
        if self.store_orders.keys().any(|k| !prev.store_orders.contains_key(k)) {
            out.push("store_orders");
        }
        if self.call_arg_orders.keys().any(|k| !prev.call_arg_orders.contains_key(k)) {
            out.push("call_arg_orders");
        }
        if self.arm_swap_sites.iter().any(|x| !prev.arm_swap_sites.contains(x)) {
            out.push("arm_swap_sites");
        }
        if self.ilv_orders.keys().any(|k| !prev.ilv_orders.contains_key(k)) {
            out.push("ilv_orders");
        }
        out
    }
}
impl Grown for super::complement_cmp::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.sites.iter().any(|x| !prev.sites.contains(x)) {
            out.push("sites");
        }
        out
    }
}
impl Grown for super::cmp_order::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.sites.iter().any(|x| !prev.sites.contains(x)) {
            out.push("sites");
        }
        out
    }
}
impl Grown for super::ext_cast::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.sites.iter().any(|x| !prev.sites.contains(x)) {
            out.push("sites");
        }
        out
    }
}
impl Grown for super::mask_cast::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.sites.keys().any(|k| !prev.sites.contains_key(k)) {
            out.push("sites");
        }
        out
    }
}
impl Grown for super::unsigned_cmp::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.sites.iter().any(|x| !prev.sites.contains(x)) {
            out.push("sites");
        }
        out
    }
}
impl Grown for super::return_split::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.split.iter().any(|x| !prev.split.contains(x)) {
            out.push("split");
        }
        if self.const_phi.iter().any(|x| !prev.const_phi.contains(x)) {
            out.push("const_phi");
        }
        if self.early_return.iter().any(|x| !prev.early_return.contains(x)) {
            out.push("early_return");
        }
        if self.branch_return.iter().any(|x| !prev.branch_return.contains(x)) {
            out.push("branch_return");
        }
        out
    }
}
impl Grown for super::counted_loop::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.sites.iter().any(|x| !prev.sites.contains(x)) {
            out.push("sites");
        }
        out
    }
}
impl Grown for super::store_forward::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.sites.iter().any(|x| !prev.sites.contains(x)) {
            out.push("sites");
        }
        out
    }
}
impl Grown for super::cmp_sign::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.sites.iter().any(|x| !prev.sites.contains(x)) {
            out.push("sites");
        }
        if self.globals.iter().any(|x| !prev.globals.contains(x)) {
            out.push("globals");
        }
        out
    }
}
impl Grown for super::ptr_offset::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.sites.iter().any(|x| !prev.sites.contains(x)) {
            out.push("sites");
        }
        out
    }
}
impl Grown for super::inline_call::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.sites.iter().any(|x| !prev.sites.contains(x)) {
            out.push("sites");
        }
        out
    }
}
impl Grown for super::load_hoist::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.sites.iter().any(|x| !prev.sites.contains(x)) {
            out.push("sites");
        }
        out
    }
}
impl Grown for super::return_widen::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.zero_widened && !prev.zero_widened {
            out.push("zero_widened");
        }
        out
    }
}
impl Grown for super::nested_conds::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.sites.iter().any(|x| !prev.sites.contains(x)) {
            out.push("sites");
        }
        out
    }
}
impl Grown for super::snapshot::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.sites.keys().any(|k| !prev.sites.contains_key(k)) {
            out.push("sites");
        }
        out
    }
}
impl Grown for super::testmem::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.sites.iter().any(|x| !prev.sites.contains(x)) {
            out.push("sites");
        }
        out
    }
}
impl Grown for super::array_index::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.sites.iter().any(|x| !prev.sites.contains(x)) {
            out.push("sites");
        }
        out
    }
}
impl Grown for super::join_narrow::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.sites.iter().any(|x| !prev.sites.contains(x)) {
            out.push("sites");
        }
        out
    }
}
impl Grown for super::string_ops::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.sites.iter().any(|x| !prev.sites.contains(x)) {
            out.push("sites");
        }
        out
    }
}
impl Grown for super::sdiv_pow2::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.sites.iter().any(|x| !prev.sites.contains(x)) {
            out.push("sites");
        }
        out
    }
}
impl Grown for super::frame_fill::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.frame.is_some() && self.frame != prev.frame {
            out.push("frame");
        }
        out
    }
}
impl Grown for super::sparse_switch::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.sites.keys().any(|k| !prev.sites.contains_key(k)) {
            out.push("sites");
        }
        out
    }
}
impl Grown for super::struct_copy::Sites {
    fn grown_over(&self, prev: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.runs.keys().any(|k| !prev.runs.contains_key(k)) {
            out.push("runs");
        }
        out
    }
}

impl Recovered {
    /// The decisions of `self` that `prev` lacks, as `arm.field` names.
    pub fn grown_over(&self, prev: &Recovered) -> Vec<String> {
        let Recovered { port, complement_cmp, cmp_order, ext_cast, mask_cast, unsigned_cmp, return_split, counted_loop, store_forward, cmp_sign, ptr_offset, load_hoist, inline_call, return_widen, nested_conds, snapshot, testmem, array_index, join_narrow, string_ops, sdiv_pow2, frame_fill, sparse_switch, struct_copy } = self;
        let mut out = Vec::new();
        for f in port.grown_over(&prev.port) {
            out.push(format!("port.{f}"));
        }
        for f in complement_cmp.grown_over(&prev.complement_cmp) {
            out.push(format!("complement_cmp.{f}"));
        }
        for f in cmp_order.grown_over(&prev.cmp_order) {
            out.push(format!("cmp_order.{f}"));
        }
        for f in ext_cast.grown_over(&prev.ext_cast) {
            out.push(format!("ext_cast.{f}"));
        }
        for f in mask_cast.grown_over(&prev.mask_cast) {
            out.push(format!("mask_cast.{f}"));
        }
        for f in unsigned_cmp.grown_over(&prev.unsigned_cmp) {
            out.push(format!("unsigned_cmp.{f}"));
        }
        for f in return_split.grown_over(&prev.return_split) {
            out.push(format!("return_split.{f}"));
        }
        for f in counted_loop.grown_over(&prev.counted_loop) {
            out.push(format!("counted_loop.{f}"));
        }
        for f in store_forward.grown_over(&prev.store_forward) {
            out.push(format!("store_forward.{f}"));
        }
        for f in cmp_sign.grown_over(&prev.cmp_sign) {
            out.push(format!("cmp_sign.{f}"));
        }
        for f in ptr_offset.grown_over(&prev.ptr_offset) {
            out.push(format!("ptr_offset.{f}"));
        }
        for f in load_hoist.grown_over(&prev.load_hoist) {
            out.push(format!("load_hoist.{f}"));
        }
        for f in inline_call.grown_over(&prev.inline_call) {
            out.push(format!("inline_call.{f}"));
        }
        for f in return_widen.grown_over(&prev.return_widen) {
            out.push(format!("return_widen.{f}"));
        }
        for f in nested_conds.grown_over(&prev.nested_conds) {
            out.push(format!("nested_conds.{f}"));
        }
        for f in snapshot.grown_over(&prev.snapshot) {
            out.push(format!("snapshot.{f}"));
        }
        for f in testmem.grown_over(&prev.testmem) {
            out.push(format!("testmem.{f}"));
        }
        for f in array_index.grown_over(&prev.array_index) {
            out.push(format!("array_index.{f}"));
        }
        for f in join_narrow.grown_over(&prev.join_narrow) {
            out.push(format!("join_narrow.{f}"));
        }
        for f in string_ops.grown_over(&prev.string_ops) {
            out.push(format!("string_ops.{f}"));
        }
        for f in sdiv_pow2.grown_over(&prev.sdiv_pow2) {
            out.push(format!("sdiv_pow2.{f}"));
        }
        for f in frame_fill.grown_over(&prev.frame_fill) {
            out.push(format!("frame_fill.{f}"));
        }
        for f in sparse_switch.grown_over(&prev.sparse_switch) {
            out.push(format!("sparse_switch.{f}"));
        }
        for f in struct_copy.grown_over(&prev.struct_copy) {
            out.push(format!("struct_copy.{f}"));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every registry arm switches off by name (either spelling), an unknown name is refused
    /// with the switchable list, and the R2b block goes off as one unit — a widened
    /// declaration never survives without the rendering that consumes it.
    /// Every registry arm is switchable and compared: destructured WITHOUT `..`, so a new arm
    /// sub-struct fails to compile here until it is in `ARMS` (loud) — the guarantee F2 exists
    /// to give, enforced by the compiler instead of a hand list.
    #[test]
    fn every_registry_arm_is_in_arms() {
        let Recovered { port, complement_cmp, cmp_order, ext_cast, mask_cast, unsigned_cmp, return_split, counted_loop, store_forward, cmp_sign, ptr_offset, load_hoist, inline_call, return_widen, nested_conds, snapshot, testmem, array_index, join_narrow, string_ops, sdiv_pow2, frame_fill, sparse_switch, struct_copy } = Recovered::default();
        let names = ["port", "complement_cmp", "cmp_order", "ext_cast", "mask_cast", "unsigned_cmp", "return_split", "counted_loop", "store_forward", "cmp_sign", "ptr_offset", "load_hoist", "inline_call", "return_widen", "nested_conds", "snapshot", "testmem", "array_index", "join_narrow", "string_ops", "sdiv_pow2", "frame_fill", "sparse_switch", "struct_copy"];
        let _ = (&port, &complement_cmp, &cmp_order, &ext_cast, &mask_cast, &unsigned_cmp, &return_split, &counted_loop, &store_forward, &cmp_sign, &ptr_offset, &load_hoist, &inline_call, &return_widen, &nested_conds, &snapshot, &testmem, &array_index, &join_narrow, &string_ops, &sdiv_pow2, &frame_fill, &sparse_switch, &struct_copy);
        assert_eq!(names.len(), Recovered::ARMS.len());
        for n in names {
            assert!(Recovered::ARMS.contains(&n), "{n} is a registry arm but not switchable");
        }
    }

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
