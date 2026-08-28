//! Ghidra `ActionRestrictLocal` (`coreaction.cc:1957`, mainloop slot `:5502`, "Do before dead code
//! removed").
//!
//! The saved-register loop: for every register the calling convention does NOT kill, find its
//! input Varnode and mark the stack storage that value is SAVED to as *not mapped*. That storage
//! is not a local variable — it is the callee-save slot — so it is removed from `ScopeLocal`'s
//! window and no Symbol may be built over it.
//!
//! Why the marking has to happen HERE and not at `restructureVarnode` time: `ActionDirectWrite`
//! strips `addrforce` from the save chain (the saved register is not a legitimate function input),
//! so the following `ActionDeadCode` deletes the COPY and the slot's Varnode goes free. Ghidra
//! runs this action BEFORE that deadcode and the carve-out persists in the Scope. mosura measured
//! the consequence of not doing it: FUN_0005118c's 16-byte buffer at `[ebp-0x10]` recovered as a
//! 20-byte array running to the frame base, because the open range was sized to the artificial
//! endpoint with nothing occupying the saved-EBP slot at -4 — and Open Watcom then emitted
//! `sub esp,0x14` against the original's `sub esp,0x10`.
//!
//! DELIBERATE OMISSION: Ghidra's FIRST loop marks the outgoing stack-parameter area of every
//! input-locked call (`fc->getSpacebaseOffset()`, `markNotMapped(..., parameter=true)`), which
//! also maintains `minParamOffset`/`maxParamOffset`. mosura does not model a per-call locked
//! prototype with a resolved spacebase offset, and `Heritage::guardCalls` already keeps outgoing
//! argument slots out of the local window by other means. Only the saved-register loop is ported.

use super::action::Action;
use super::fspec::effect;
use super::funcdata::Funcdata;
use super::opcode::OpCode;
use super::space::SpaceKind;
use super::varnode::VarnodeId;

/// Ghidra `ActionRestrictLocal` (`coreaction.hh`).
pub struct ActionRestrictLocal;

impl Action for ActionRestrictLocal {
    fn name(&self) -> &str {
        "restrictlocal"
    }

    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        let Some(stack) = data.spaces.by_name("stack") else { return 0 };
        // Iterate through saved registers (`effectBegin`..`effectEnd`, skipping killedbycall).
        let saved: Vec<(u64, u32)> = data
            .proto_model
            .effectlist
            .iter()
            .filter(|e| e.effect != effect::KILLEDBYCALL)
            .map(|e| (e.offset, e.size))
            .collect();
        let mut marks: Vec<(u64, u32)> = Vec::new();
        for (offset, size) in saved {
            // Ghidra `Funcdata::findVarnodeInput(size, addr)`: the function-input Varnode at
            // exactly this storage.
            let input = (0..data.num_varnodes() as u32).map(VarnodeId).find(|&v| {
                let vn = data.vn(v);
                vn.is_input()
                    && vn.size == size
                    && vn.loc.offset == offset
                    && data.spaces.get(vn.loc.space).kind == SpaceKind::Processor
            });
            let Some(input) = input else { continue };
            if !data.vn(input).is_unaffected() {
                continue;
            }
            for &op in &data.vn(input).descend {
                if data.op(op).code() != OpCode::Copy {
                    continue;
                }
                let Some(outvn) = data.op(op).output else { continue };
                // `ScopeLocal::isUnaffectedStorage` (varmap.hh:244) — is this where unaffected
                // values get saved: the Varnode lives in the Scope's own (stack) space.
                if data.vn(outvn).loc.space != stack {
                    continue;
                }
                marks.push((data.vn(outvn).loc.offset, data.vn(outvn).size));
            }
        }
        for (off, sz) in marks {
            debug!(crate::debug::Topic::Varmap,
                    "marknotmapped [{}] off={} size={}",
                    data.name,
                    super::varmap::sx32(off),
                    sz
                );
            data.mark_not_mapped(stack, off, sz);
        }
        // Ghidra returns 0: this is scope maintenance, never a change that should drive a
        // rule_repeatapply fixpoint.
        0
    }
}
