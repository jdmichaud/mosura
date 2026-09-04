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
