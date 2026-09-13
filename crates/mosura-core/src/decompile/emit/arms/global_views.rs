//! Typed lvalues for partial and overlapping global Symbol accesses.
//!
//! The reference printer retains Ghidra's partial-field and mismatch notation.
//! This arm uses the linked Symbol and the Varnode's actual type to render the
//! access through the same storage. Recovery witnesses its memory range in the
//! original instructions; a declaration's width never substitutes for an
//! individual access width.
use std::collections::HashSet;

use crate::decompile::emit::{EmitChoices, GlobalViews};
use crate::decompile::printc::PrintC;
use crate::decompile::scope::Symbol;
use crate::decompile::space::Address;
use crate::decompile::varnode::VarnodeId;

#[derive(Debug, Default)]
pub(crate) struct State { typed: bool }

impl State {
    pub(crate) fn new(choices: &EmitChoices) -> Self {
        Self { typed: choices.global_views == GlobalViews::Typed }
    }
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub v: VarnodeId,
    pub space: String,
    pub address: u64,
    pub size: u32,
    pub resolved: Vec<crate::decompile::funcdata::ResolvedMemoryAccess>,
}

#[derive(Debug, Default, Clone)]
pub struct Report { pub candidates: Vec<Candidate> }

#[derive(Debug, Default, Clone)]
pub struct Sites {
    pub sites: HashSet<VarnodeId>,
    /// Qualifiers supplied by the output profile, also used by TU declarations.
    pub volatile: HashSet<u64>,
}

pub(crate) fn render(p: &mut PrintC<'_>, v: VarnodeId, address: Address,
    symbol: &Symbol, offset: u64) -> Option<(String, u8)>
{
    let ty = p.type_of(v);
    if offset == 0 && ty == symbol.datatype { return None; }
    let size = p.f.vn(v).size;
    let resolved = p.f.resolved_memory_accesses.iter().filter(|m| {
        m.storage.space == address.space && size <= m.size
            && address.offset.checked_sub(m.storage.offset)
                .is_some_and(|off| off <= u64::from(m.size - size))
    }).cloned().collect();
    p.report.global_views.candidates.push(Candidate {
        v, space: p.f.spaces.get(address.space).name.clone(),
        address: address.offset, size, resolved,
    });
    if !p.arms.global_views.typed || !p.recovered.global_views.sites.contains(&v) { return None; }
    let qualifier = if p.recovered.global_views.volatile.contains(&address.offset)
        || p.recovered.global_views.volatile.contains(&(address.offset - offset)) { "volatile " } else { "" };
    let pointer = if offset == 0 { format!("&{}", symbol.name) }
        else { format!("((char *)&{} + {offset})", symbol.name) };
    Some((format!("(*({qualifier}{} *){pointer})", ty.name()), 20))
}
