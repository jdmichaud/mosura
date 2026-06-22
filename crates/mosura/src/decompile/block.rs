//! Basic blocks and the control-flow graph — a port of Ghidra's `BlockBasic`/`BlockGraph`
//! (`block.hh`/`block.cc`).
//!
//! P0 stub: the [`BlockId`] handle and a minimal [`BlockBasic`]. The CFG construction and
//! the structured-block hierarchy (`BlockGraph::collapse`) are P7.

use super::op::OpId;

/// A handle to a [`BlockBasic`] — an index into the `Funcdata` block list.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct BlockId(pub u32);

/// A maximal straight-line run of ops (one entry, one exit). Edges index other blocks.
#[derive(Clone, Debug, Default)]
pub struct BlockBasic {
    /// Ops in execution order.
    pub ops: Vec<OpId>,
    /// Predecessor blocks.
    pub in_edges: Vec<BlockId>,
    /// Successor blocks (CBRANCH: `[fallthrough, taken]`).
    pub out_edges: Vec<BlockId>,
}
