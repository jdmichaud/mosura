//! Decompiler D2: simplification over SSA — starting with dead-code elimination
//! (Ghidra `ActionDeadCode`). A def with no uses and no side effect is dead;
//! removing it can make its inputs dead, so we mark-sweep to a fixed point.
//!
//! This is the coverage-driven part of the pipeline: more value-propagation rules
//! (constant folding, copy propagation, `MULTIEQUAL`/`COPY` collapse) slot in here
//! as the datatests demand them.

use super::cfg::Funcdata;
use super::ssa::{heritaged, Def, Ssa};

/// Which ops / phis survive dead-code elimination.
pub struct Liveness {
    pub live_ops: Vec<bool>,
    pub live_phis: Vec<bool>,
}

impl Liveness {
    pub fn live_op_count(&self) -> usize {
        self.live_ops.iter().filter(|&&l| l).count()
    }
}

/// Opcodes with a side effect (must be kept even if their output is unused).
fn side_effect(oc: u32) -> bool {
    // STORE, BRANCH, CBRANCH, BRANCHIND, CALL, CALLIND, CALLOTHER, RETURN
    matches!(oc, 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10)
}

enum Item {
    Op(usize),
    Phi(usize),
}

impl Funcdata {
    /// An op is eligible for removal-when-unused iff it has a heritaged output and
    /// no side effect.
    fn removable(&self, i: usize) -> bool {
        let op = &self.ops[i].op;
        op.out.as_ref().is_some_and(|o| heritaged(&o.space)) && !side_effect(op.opcode)
    }

    /// Mark-sweep dead-code elimination over the SSA.
    pub fn dead_code(&self, ssa: &Ssa) -> Liveness {
        let n_ops = self.ops.len();
        let n_phis = ssa.phis.len();

        // Count uses of every definition.
        let mut op_uses = vec![0u32; n_ops];
        let mut phi_uses = vec![0u32; n_phis];
        let mut bump = |d: Def| match d {
            Def::Op(i) => op_uses[i] += 1,
            Def::Phi(p) => phi_uses[p] += 1,
            Def::Live => {}
        };
        for d in ssa.uses.values() {
            bump(*d);
        }
        for ph in &ssa.phis {
            for a in &ph.args {
                bump(*a);
            }
        }

        // Seed the worklist with dead defs.
        let mut live_ops = vec![true; n_ops];
        let mut live_phis = vec![true; n_phis];
        let mut work: Vec<Item> = Vec::new();
        for i in 0..n_ops {
            if self.removable(i) && op_uses[i] == 0 {
                live_ops[i] = false;
                work.push(Item::Op(i));
            }
        }
        for p in 0..n_phis {
            if phi_uses[p] == 0 {
                live_phis[p] = false;
                work.push(Item::Phi(p));
            }
        }

        // Propagate: a removed def releases the uses it made of its inputs.
        while let Some(it) = work.pop() {
            let inputs: Vec<Def> = match it {
                Item::Op(i) => (0..self.ops[i].op.ins.len())
                    .filter_map(|pos| ssa.uses.get(&(i, pos)).copied())
                    .collect(),
                Item::Phi(p) => ssa.phis[p].args.clone(),
            };
            for d in inputs {
                match d {
                    Def::Op(j) if live_ops[j] => {
                        op_uses[j] -= 1;
                        if op_uses[j] == 0 && self.removable(j) {
                            live_ops[j] = false;
                            work.push(Item::Op(j));
                        }
                    }
                    Def::Phi(q) if live_phis[q] => {
                        phi_uses[q] -= 1;
                        if phi_uses[q] == 0 {
                            live_phis[q] = false;
                            work.push(Item::Phi(q));
                        }
                    }
                    _ => {}
                }
            }
        }

        Liveness { live_ops, live_phis }
    }
}
