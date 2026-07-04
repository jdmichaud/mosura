//! C emission — Ghidra's `PrintC` (`printc.cc`). Walks the structured-block tree
//! ([`structure`](super::structure)), renders each op as a C expression (inlining
//! single-use values, naming the [`merge`](super::merge) HighVariables), and emits
//! statements + control flow.
//!
//! This increment handles expressions, variable naming, the function signature, and the
//! linear case (basic blocks / lists). Structured control flow (`if`/`while`) emission,
//! casts, and faithful types are the next increments. The return value is located
//! heuristically (the last write to a return register) until P6 ActionReturnRecovery wires
//! it to RETURN.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use super::block::BlockId;
use super::cast::cast_standard;
use super::funcdata::Funcdata;
use super::infertypes::infer;
use super::merge::{merge, HighVariables};
use super::op::OpId;
use super::opcode::OpCode;
use super::space::Address;
use super::structure::{structure, FlowKind, Structured};
use super::types::{type_order, Datatype};
use super::varnode::VarnodeId;

/// Collect the basic blocks under a structured block (its loop body, etc.).
fn basic_blocks_of(s: &Structured, idx: usize, acc: &mut Vec<BlockId>) {
    match &s.blocks[idx].kind {
        FlowKind::Basic(b) => acc.push(*b),
        _ => {
            for &c in &s.blocks[idx].components {
                basic_blocks_of(s, c, acc);
            }
        }
    }
}

/// The exit basic block of a structured block (where its terminating CBRANCH lives).
fn exit_basic(s: &Structured, idx: usize) -> Option<BlockId> {
    match &s.blocks[idx].kind {
        FlowKind::Basic(b) => Some(*b),
        _ => exit_basic(s, *s.blocks[idx].components.last()?),
    }
}

/// The entry basic block of a structured block (where a case/label starts).
fn entry_basic(s: &Structured, idx: usize) -> Option<BlockId> {
    match &s.blocks[idx].kind {
        FlowKind::Basic(b) => Some(*b),
        _ => entry_basic(s, *s.blocks[idx].components.first()?),
    }
}

/// Ghidra's C name for an N-byte IEEE float.
fn float_name(size: u32) -> String {
    match size {
        4 => "float".to_string(),
        8 => "double".to_string(),
        10 | 16 => "longdouble".to_string(),
        n => format!("float{n}"),
    }
}

/// Ghidra's one-letter type prefix for a variable/global name.
fn type_prefix(t: &Datatype) -> &'static str {
    match t {
        Datatype::Int(_) => "i",
        Datatype::Uint(_) => "u",
        Datatype::Bool => "b",
        Datatype::Float(_) => "f",
        Datatype::Pointer(..) => "p",
        _ => "x",
    }
}

/// The 64-bit name of an x86-64 integer register by offset (for `extraout_*` etc.).
fn reg64_name(offset: u64) -> Option<&'static str> {
    Some(match offset {
        0x0 => "RAX",
        0x38 => "RDI",
        0x30 => "RSI",
        0x10 => "RDX",
        0x08 => "RCX",
        0x80 => "R8",
        0x88 => "R9",
        _ => return None,
    })
}

struct PrintC<'a> {
    f: &'a Funcdata,
    h: HighVariables,
    names: HashMap<u32, String>,
    reg_space: Option<super::space::SpaceId>,
    ram_space: Option<super::space::SpaceId>,
    stack_space: Option<super::space::SpaceId>,
    var_counter: u32,
    ret_val: Option<VarnodeId>,
    types: HashMap<VarnodeId, Datatype>,
    /// WhileDo block index → (initializer value, iterator op, loop variable) for `for`-loops.
    for_loops: HashMap<usize, (Option<VarnodeId>, OpId, VarnodeId)>,
    /// Ops emitted in a `for` header (initializer/iterator) — suppressed in their block.
    suppressed: HashSet<OpId>,
    /// Pointer base → element size, for bases accessed uniformly as an array (so the access
    /// renders `base[i]`). Non-uniform bases (struct-like) are absent and stay `*(base+k)`.
    array_elem: HashMap<VarnodeId, u32>,
    /// Goto edges cut for irreducible regions: source block → (target, negated condition).
    gotos: HashMap<BlockId, (BlockId, bool)>,
    /// Basic blocks that are goto targets (emitted with a label).
    labels: HashSet<BlockId>,
    /// Local variable declarations `(name, type, stack_offset)`, collected as names are assigned and
    /// emitted at the top of the body in Ghidra's declaration order. Ghidra `emitScopeVarDecls`
    /// (printc.cc:2265) walks the ScopeLocal symbol map, which is keyed by storage Address, so stack
    /// locals declare in ascending-address order (most-negative frame offset first). `stack_offset`
    /// is the signed frame offset for a `stack` local, `None` for a register/temp local; the emit
    /// sort orders stack locals by it. (No corpus fixture mixes register and stack locals in one
    /// decl block, so register-vs-stack precedence is unexercised; register temps keep first-use
    /// order via the stable sort.)
    decls: Vec<(String, Datatype, Option<i64>)>,
    /// Per-varnode: is this a register value written into an addrtied stack slot across a call (the
    /// input of an INDIRECT whose output is the slot)? Such a value is *explicit* — Ghidra renders
    /// the write to the addrtied variable even though the value is computed in a register merged
    /// into the slot (the memory-increment `iStack_NN = iStack_NN + 1`).
    slot_write: Vec<bool>,
    /// HighVariable representative → the frame offset of its `stack` member, so every member of the
    /// HighVariable (including merged register versions) is named `xStack_NN` by that offset.
    high_stack_off: HashMap<u32, u64>,
    /// Signed frame offset → type prefix of the `stack` slot living there, so an address-of-local
    /// `&<prefix>Stack_NN` carries the slot's prefix (`&iStack_28`); defaults to `x` (xunknown).
    stack_prefix: HashMap<i64, &'static str>,
    /// Varnodes forced explicit (named, not inlined) regardless of use count — the recovered
    /// stack-array base varnodes, so a single-use base still renders by its array name (`axStack_98`)
    /// instead of via its address-computation (`&xStack_98`).
    force_explicit: HashSet<VarnodeId>,
    /// Recovered-parameter storage → 1-based parameter index, from the faithful prototype recovery
    /// (`fspec::recover_input_params`, Ghidra `ActionInputPrototype`/`fillinMap`). An input Varnode
    /// at one of these locations names `param_N`. This is XMM-aware (a `float8` in `XMM0` is a real
    /// parameter), unlike the old GP-only register table, and carries the convention's ordering.
    param_index: HashMap<Address, u32>,
}

impl PrintC<'_> {
    fn type_of(&self, v: VarnodeId) -> Datatype {
        // A varnode's type is its inferred HighVariable type — the same value Ghidra's prototype
        // recovery reads (`FuncProto::updateInputTypes`/`updateOutputTypes`, fspec.cc:4076/4159:
        // `vn->getHigh()->getType()`) and the C printer declares for the symbol. Ghidra applies no
        // downgrade to `undefined` for stripped binaries — an int/uint that inference recovers stays
        // int/uint (naming a variable `iVar`/`uVar`, and avoiding the spurious `(int4)` cast that a
        // `undefined`-typed symbol would need when widened). Absent inference gives `undefined<N>`.
        self.types.get(&v).cloned().unwrap_or_else(|| Datatype::default_for(self.f.vn(v).size))
    }

    /// The variable's effective (type) width: the highest byte index any use reads — Ghidra's
    /// type-width that `ActionInferTypes::propagateOneType` derives from consumed bytes. A
    /// `SUBPIECE` use reads `[offset, offset+out_size)`; any other use reads the whole varnode.
    /// A truncating SUBPIECE renders as a cast exactly when this exceeds its output size (the
    /// value is genuinely wider than the slice), which distinguishes an int8 used at 4 bytes
    /// (`(int4)x`) from an int4 used at its width (plain `x`).
    fn effective_width(&self, x: VarnodeId) -> u32 {
        let full = self.f.vn(x).size;
        let mut w = 0;
        for &u in &self.f.vn(x).descend {
            let o = self.f.op(u);
            for (slot, &iv) in o.inrefs.iter().enumerate() {
                if iv != x {
                    continue;
                }
                let top = if o.code() == OpCode::Subpiece && slot == 0 {
                    let off = o
                        .input(1)
                        .and_then(|v| self.f.vn(v).is_constant().then(|| self.f.vn(v).constant_value()))
                        .unwrap_or(0) as u32;
                    off + o.output.map(|out| self.f.vn(out).size).unwrap_or(full)
                } else {
                    full
                };
                w = w.max(top);
            }
        }
        w
    }
}

impl<'a> PrintC<'a> {
    /// Whether a varnode is printed as its own named variable (vs inlined into its use).
    fn is_explicit(&self, v: VarnodeId) -> bool {
        let vn = self.f.vn(v);
        if vn.is_constant() {
            return false;
        }
        // a recovered stack-array base is always named (even single-use) so it renders `axStack_98`
        if self.force_explicit.contains(&v) {
            return true;
        }
        // A register value written into an addrtied stack slot across a call — Ghidra materializes
        // the write to the addrtied variable, so the producing op renders as `xStack_NN = …` at its
        // natural position, even when the value is computed in a register merged into the slot (the
        // memory-increment `iStack_NN = iStack_NN + 1`).
        if self.slot_write[v.0 as usize] {
            return true;
        }
        if vn.is_input() {
            return true;
        }
        if !vn.is_written() {
            return true;
        }
        if let Some(def) = vn.def {
            // a phi is a merged variable, and an INDIRECT (a value clobbered by a call) is an
            // opaque `extraout_*` — both are always named, never inlined raw. A CALL's return value
            // is likewise always named (Ghidra `ActionMarkExplicit::baseExplicit`, coreaction.cc:3015
            // `def->isCall()` ⇒ explicit) — a call result is `xVar = func(…)`, not folded into its use.
            if matches!(
                self.f.op(def).code(),
                OpCode::Multiequal | OpCode::Indirect | OpCode::Call | OpCode::Callind
            ) {
                return true;
            }
            // PTRADD/PTRSUB are address sub-expressions Ghidra recomputes inline at every use (an
            // `arr[i]` / `p->field` is re-rendered, never spilled to a pointer temp), so they stay
            // implied even with multiple uses — unless one of those uses is a phi.
            if matches!(self.f.op(def).code(), OpCode::Ptradd | OpCode::Ptrsub) {
                return vn.descend.iter().any(|&u| self.f.op(u).code() == OpCode::Multiequal);
            }
        }
        if vn.descend.len() != 1 {
            return true; // 0 or >1 uses: named
        }
        // single use: inline, unless it feeds a marker that stands for the *same* variable, in
        // which case it must be materialized as an assignment to that variable:
        //  - a phi (the loop increment `i = i + 1`, the init `i = 0`); or
        //  - an across-call INDIRECT carrying the same addrtied stack slot — the value is the write
        //    to that slot (`xStack_NN = …`); Ghidra renders the store, the INDIRECT is invisible.
        let user = vn.descend[0];
        match self.f.op(user).code() {
            OpCode::Multiequal => true,
            OpCode::Indirect => self
                .f
                .op(user)
                .output
                .is_some_and(|uout| self.f.vn(uout).loc == vn.loc && self.f.vn(uout).size == vn.size),
            _ => false,
        }
    }

    /// The name of `v`'s variable, assigning one on first use.
    fn name_of(&mut self, v: VarnodeId) -> String {
        let vn = self.f.vn(v);
        let is_reg = Some(vn.loc.space) == self.reg_space;
        if vn.is_input() {
            if let Some(&n) = self.param_index.get(&vn.loc) {
                return format!("param_{n}");
            }
        }
        // a direct global — a constant-address access in `ram` — is named by its address,
        // like Ghidra's `<typeprefix>Ram<addr>` (e.g. `iRam0000000000101000`)
        if Some(vn.loc.space) == self.ram_space {
            let (off, prefix) = (vn.loc.offset, type_prefix(&self.type_of(v)));
            return format!("{prefix}Ram{off:016x}");
        }
        // a value left in a caller-saved register by a call (an INDIRECT def) is Ghidra's
        // `extraout_<reg>`
        if is_reg {
            if let Some(def) = vn.def {
                if self.f.op(def).code() == OpCode::Indirect {
                    if let Some(r) = reg64_name(vn.loc.offset) {
                        return format!("extraout_{r}");
                    }
                }
            }
        }
        let id = self.h.high(v);
        if let Some(n) = self.names.get(&id) {
            return n.clone();
        }
        // Ghidra names a local by its type prefix (`xVar`/`iVar`/`uVar`/`fVar`/`pVar`); a local in
        // the recovered `stack` space is named by its frame offset (`xStack_28`) instead of a
        // running counter.
        let ty = self.type_of(v);
        let prefix = type_prefix(&ty);
        // Name by the frame offset when this varnode is (or is merged with) a `stack` slot, so a
        // register version merged into the slot shares the slot's `xStack_NN` name.
        let stack_off = self
            .high_stack_off
            .get(&id)
            .copied()
            .or_else(|| (Some(vn.loc.space) == self.stack_space).then_some(vn.loc.offset));
        let n = if let Some(off) = stack_off {
            format!("{prefix}Stack_{:x}", (off as i64).unsigned_abs())
        } else {
            self.var_counter += 1;
            format!("{prefix}Var{}", self.var_counter)
        };
        self.names.insert(id, n.clone());
        // a genuine local — declared at the body top, keyed by stack offset for the decl-order sort
        self.decls.push((n.clone(), ty, stack_off.map(|o| o as i64)));
        n
    }

    /// Render a varnode as a C expression with its operator precedence (16 = atomic).
    fn render_var(&mut self, v: VarnodeId) -> (String, u8) {
        let vn = self.f.vn(v);
        if vn.is_constant() {
            return (render_const(vn.constant_value(), vn.size), 16);
        }
        if self.is_explicit(v) {
            return (self.name_of(v), 16);
        }
        match vn.def {
            Some(def) => self.render_op(def),
            None => (self.name_of(v), 16),
        }
    }

    /// Render `v` as an operand of an operator of precedence `parent`, parenthesizing when
    /// the sub-expression binds looser (`right` operands also parenthesize at equal
    /// precedence, for left-associativity).
    fn operand(&mut self, v: VarnodeId, parent: u8, right: bool) -> String {
        let (s, p) = self.render_var(v);
        if p < parent || (right && p == parent) {
            format!("({s})")
        } else {
            s
        }
    }

    /// The cast an op requires of its input `slot` (Ghidra `TypeOp::getInputCast` → `castStandard`),
    /// or `None` if the operand's type already satisfies the op. Only the comparisons are wired:
    /// the signed/unsigned ones force a signedness cast (`care_uint_int`), which is what renders
    /// Ghidra's `(int4)param_1 < 10`; equality reconciles silently. Other ops (arithmetic, logic)
    /// use Ghidra's lenient default and effectively never cast in the primitive lattice, so they
    /// are left transparent here.
    fn get_input_cast(&self, op: OpId, slot: usize) -> Option<Datatype> {
        let o = self.f.op(op);
        let in_vn = o.input(slot)?;
        let cur = self.type_of(in_vn);
        let sz = self.f.vn(in_vn).size;
        match o.code() {
            OpCode::IntSless | OpCode::IntSlessequal => {
                cast_standard(&Datatype::Int(sz), &cur, true, true)
            }
            OpCode::IntLess | OpCode::IntLessequal => {
                cast_standard(&Datatype::Uint(sz), &cur, true, false)
            }
            // SEXT requires a signed input of the *input* width (Ghidra `TypeOpIntSext::
            // getInputCast`, care_uint_int=true): `(int8)(int4)param` when param is undefined.
            OpCode::IntSext => cast_standard(&Datatype::Int(sz), &cur, true, false),
            // signed/unsigned divide and remainder force their operand's signedness
            // (Ghidra `TypeOpIntSdiv`/`Srem`/`Div`/`Rem::getInputCast`, care_uint_int=true)
            OpCode::IntSdiv | OpCode::IntSrem => cast_standard(&Datatype::Int(sz), &cur, true, true),
            OpCode::IntDiv | OpCode::IntRem => cast_standard(&Datatype::Uint(sz), &cur, true, true),
            OpCode::IntEqual | OpCode::IntNotequal => {
                // reqtype is the more-specific of the two operand types (Ghidra
                // `TypeOpEqual::getInputCast`); equality does not care about signedness.
                let t0 = self.type_of(o.input(0)?);
                let t1 = self.type_of(o.input(1)?);
                let req = if type_order(&t1, &t0) == std::cmp::Ordering::Less { t1 } else { t0 };
                cast_standard(&req, &cur, false, false)
            }
            _ => None,
        }
        // NOTE: the `checkIntPromotionForCompare` gate (cast.cc) is omitted; it is exactly
        // NO_PROMOTION (→ defer to castStandard) for operands ≥ 4 bytes, which is every operand
        // here. Sub-4-byte promotion-forced casts are conservatively skipped.
    }

    /// Whether constant input `slot` should print with an explicit `U` suffix (Ghidra's
    /// `CastStrategy::markExplicitUnsigned`): the op inherits sign, the constant reads as
    /// unsigned/undefined and non-negative, and neither the other operand nor the consuming op
    /// already forces the unsignedness.
    fn mark_explicit_unsigned(&self, op: OpId, slot: usize) -> bool {
        let o = self.f.op(op);
        let code = o.code();
        if !inherits_sign(code) {
            return false;
        }
        let first_only = inherits_sign_first_only(code);
        if slot == 1 && first_only {
            return false;
        }
        let v = o.input(slot).unwrap();
        let vn = self.f.vn(v);
        if !vn.is_constant() {
            return false;
        }
        // A constant that renders as a small negative is signed in Ghidra (typed INT, rendered
        // `-N`) and never prints unsigned — guard the sign directly at the print, independent of
        // whatever unsigned type inference may have left on a negative literal.
        if render_const(vn.constant_value(), vn.size).starts_with('-') {
            return false;
        }
        // the constant's effective (read-facing) type — the type the op forces on it, else its
        // inferred type (constants now carry one, Ghidra `getHighTypeReadFacing`)
        let dt = self.get_input_cast(op, slot).unwrap_or_else(|| self.type_of(v));
        if !matches!(dt, Datatype::Uint(_) | Datatype::Unknown(_)) {
            return false;
        }
        if o.num_inputs() == 2 && !first_only {
            let other = o.input(1 - slot).unwrap();
            let om = self.get_input_cast(op, 1 - slot).unwrap_or_else(|| self.type_of(other));
            if matches!(om, Datatype::Uint(_) | Datatype::Unknown(_)) {
                return false; // the other side already forces the unsigned interpretation
            }
        }
        if let Some(out) = o.output {
            if self.is_explicit(out) {
                return false;
            }
            let desc = &self.f.vn(out).descend;
            if desc.len() == 1 && !inherits_sign(self.f.op(desc[0]).code()) {
                return false; // the consuming op would force the type anyway
            }
        }
        true
    }

    /// Render input `slot` of `op`, wrapping it in the cast the op requires ([`get_input_cast`]).
    /// A constant operand is never wrapped — like Ghidra's `castInput`, the literal simply adopts
    /// the required type (so a signed compare prints `(int4)x < 10`, not `< (int4)10`) — but may
    /// take an explicit `U` suffix ([`mark_explicit_unsigned`]).
    fn cast_operand(&mut self, op: OpId, slot: usize, prec: u8, right: bool) -> String {
        let v = self.f.op(op).input(slot).unwrap();
        if !self.f.vn(v).is_constant() {
            if let Some(ty) = self.get_input_cast(op, slot) {
                return format!("({}){}", ty.name(), self.operand(v, 14, false));
            }
        } else if self.mark_explicit_unsigned(op, slot) {
            let vn = self.f.vn(v);
            return render_const_unsigned(vn.constant_value(), vn.size);
        }
        self.operand(v, prec, right)
    }

    /// The signed frame offset if `(base, off)` is a stack-pointer-relative address (the stack/frame
    /// pointer RSP 0x20 / RBP 0x28 plus a constant). Shared by `stack_addr` (rendering) and
    /// `is_explicit` (an address-of-local is recomputed inline at every use, like a PTRSUB).
    fn stack_addr_off(&self, base: VarnodeId, off: VarnodeId) -> Option<i64> {
        let bvn = self.f.vn(base);
        let is_fp = Some(bvn.loc.space) == self.reg_space && matches!(bvn.loc.offset, 0x20 | 0x28);
        if !is_fp || !self.f.vn(off).is_constant() {
            return None;
        }
        Some(self.f.vn(off).constant_value() as i64)
    }

    /// If `base` is the stack/frame pointer and `off` a constant, this is the address of a stack
    /// local taken as a value — render `&<prefix>Stack_<offset>` (Ghidra names a stack local by its
    /// frame offset, with a type prefix; the address is an `&` of that name).
    fn stack_addr(&self, base: VarnodeId, off: VarnodeId) -> Option<String> {
        let c = self.stack_addr_off(base, off)?;
        Some(format!("&{}", self.stack_slot_name(c)))
    }

    /// Ghidra names a stack local `<prefix>Stack_<offset>` by its frame offset and the type of the
    /// slot there. The prefix comes from a `stack` slot at this offset when one exists, else `x`.
    fn stack_slot_name(&self, off: i64) -> String {
        let prefix = self.stack_prefix.get(&off).copied().unwrap_or("x");
        format!("{prefix}Stack_{:x}", off.unsigned_abs())
    }

    /// If `off` is `idx * size` (a scaled array index), return `idx`.
    fn scaled_index(&self, off: VarnodeId, size: u32) -> Option<VarnodeId> {
        let def = self.f.vn(off).def?;
        let o = self.f.op(def);
        if o.code() == OpCode::IntMult && o.num_inputs() == 2 {
            let c = o.input(1)?;
            if self.f.vn(c).is_constant() && self.f.vn(c).constant_value() == size as u64 {
                return o.input(0);
            }
        }
        None
    }

    /// Decompose a load/store address into `(base, index-fits-an-array-of `size`)`. The base
    /// is the pointer; the bool is whether the offset is a clean array index (a constant
    /// multiple of `size`, or a variable scaled by `size`, or zero).
    fn addr_base(&self, addr: VarnodeId, size: u32) -> (VarnodeId, bool) {
        if let Some(def) = self.f.vn(addr).def {
            let o = self.f.op(def);
            if o.code() == OpCode::IntAdd && o.num_inputs() == 2 {
                let (base, off) = (o.input(0).unwrap(), o.input(1).unwrap());
                let ok = (self.f.vn(off).is_constant()
                    && size > 0
                    && self.f.vn(off).constant_value() % size as u64 == 0)
                    || self.scaled_index(off, size).is_some();
                return (base, ok);
            }
        }
        (addr, true) // direct deref — element 0
    }

    /// Infer which pointer bases are accessed uniformly as an array (Ghidra's pointee
    /// inference, from the access pattern): a base qualifies only if every access through it
    /// uses the same element size and lands on a clean array index. Struct-like bases (mixed
    /// sizes/offsets) are excluded and keep `*(base + k)`.
    fn detect_arrays(&self) -> HashMap<VarnodeId, u32> {
        let mut info: HashMap<VarnodeId, Option<u32>> = HashMap::new();
        for op in self.f.op_ids() {
            let o = self.f.op(op);
            let (addr, size) = match o.code() {
                OpCode::Load => (o.input(1), o.output.map(|v| self.f.vn(v).size)),
                OpCode::Store => (o.input(1), o.input(2).map(|v| self.f.vn(v).size)),
                _ => continue,
            };
            let (Some(addr), Some(size)) = (addr, size) else { continue };
            if size == 0 {
                continue;
            }
            let (base, ok) = self.addr_base(addr, size);
            // Ghidra renders `base[i]` only when the base is genuinely *array*-typed; a plain
            // pointer prints `*(T *)(base + off)`. (Array typing comes from pointer-arithmetic
            // inference, #2/#10 — not yet produced, so this currently yields the pointer form.)
            if !matches!(self.type_of(base), Datatype::Array(..)) {
                continue;
            }
            let e = info.entry(base).or_insert(Some(size));
            if !(ok && *e == Some(size)) {
                *e = None; // mixed element size or non-array offset — disqualify
            }
        }
        info.into_iter().filter_map(|(b, s)| s.map(|sz| (b, sz))).collect()
    }

    /// Item C — anchor frame addresses on the recovered ScopeLocal stack symbols
    /// (`varmap::recover_scope`). A varnode that is the address of the START of a recovered ARRAY
    /// symbol (an INT_ADD on the stack pointer) is named by the array (`axStack_NN`), declared, has
    /// its address-computation assignment suppressed, and its element size registered. The array
    /// then decays to a pointer at a call (`func(axStack_NN)`) and an indexed access renders
    /// `axStack_NN[i]`, the way Ghidra renders a recovered stack array.
    fn anchor_stack_arrays(&mut self) {
        let syms = super::varmap::recover_scope(self.f);
        // the offsets of direct `stack`-space varnodes — a slot accessed as a scalar value, not
        // through a base+index. When one falls inside a recovered array we cannot cleanly render the
        // array (Ghidra would unify the scalar into `arr[0]`, which we do not model yet), so skip it.
        let scalar_offs: Vec<i64> = match self.stack_space {
            Some(stk) => (0..self.f.num_varnodes() as u32)
                .map(VarnodeId)
                .filter(|&v| self.f.vn(v).loc.space == stk)
                .map(|v| self.f.vn(v).loc.offset as i64)
                .collect(),
            None => Vec::new(),
        };
        for sym in &syms {
            let Datatype::Array(elem, _) = &sym.ty else { continue };
            let elem_sz = elem.align_size();
            if elem_sz == 0 {
                continue;
            }
            let range = sym.start..(sym.start + sym.size as i64);
            if scalar_offs.iter().any(|o| range.contains(o)) {
                continue; // a direct scalar access overlaps this array — leave it un-anchored
            }
            let aname =
                format!("a{}Stack_{:x}", type_prefix(elem), sym.start.unsigned_abs());
            let mut matched = false;
            for i in 0..self.f.num_varnodes() as u32 {
                let v = VarnodeId(i);
                let Some(def) = self.f.vn(v).def else { continue };
                let o = self.f.op(def);
                if o.code() != OpCode::IntAdd || o.num_inputs() != 2 {
                    continue;
                }
                let (b, off) = (o.input(0).unwrap(), o.input(1).unwrap());
                if self.stack_addr_off(b, off) != Some(sym.start) {
                    continue;
                }
                let id = self.h.high(v);
                self.names.entry(id).or_insert_with(|| aname.clone());
                self.array_elem.insert(v, elem_sz);
                self.suppressed.insert(def); // the array address is implicit, not an assignment
                self.force_explicit.insert(v); // render the array name even if the base is single-use
                matched = true;
            }
            if matched {
                self.decls.push((aname.clone(), sym.ty.clone(), Some(sym.start)));
            }
        }
    }

    /// Render a memory access `*addr` of `size` bytes holding a value of type `vty` — `base[i]`
    /// for a detected array base (non-zero index), else `*addr`, with a `(vty *)` cast on the
    /// address when it is not already a pointer to a value of the right size (Ghidra's
    /// `TypeOpLoad`/`TypeOpStore::getInputCast` on the pointer operand → `*(xunknown4 *)(addr)`).
    fn render_mem(&mut self, addr: VarnodeId, size: u32, vty: &Datatype) -> (String, u8) {
        if let Some(def) = self.f.vn(addr).def {
            let o = self.f.op(def).clone();
            // A LOAD/STORE through a PTRADD/PTRSUB is array/field access (Ghidra `opLoad`/`opStore`
            // → `checkArrayDeref` → the subscript/member token absorbs the dereference) — but only
            // when the access width matches the element. A sub/over-element access (e.g. a 1-byte
            // store through an `xunknown8 *`) keeps the pointer form with a cast, which Ghidra gets
            // from the `force_pointer` mod / the ActionSetCasts CAST on the LOAD/STORE pointer.
            if o.code() == OpCode::Ptradd {
                let elemsize = o.input(2).map(|v| self.f.vn(v).constant_value()).unwrap_or(0);
                if elemsize == size as u64 {
                    let (base, index) = (o.input(0).unwrap(), o.input(1).unwrap());
                    let b = self.operand(base, 16, false);
                    let i = self.render_var(index).0;
                    return (format!("{b}[{i}]"), 16);
                }
                return (format!("*({} *){}", vty.name(), self.operand(addr, 14, false)), 15);
            }
            if o.code() == OpCode::Ptrsub {
                return (self.render_ptrsub(def, true), 16);
            }
            if o.code() == OpCode::IntAdd && o.num_inputs() == 2 {
                let (base, off) = (o.input(0).unwrap(), o.input(1).unwrap());
                if let Some(&elem) = self.array_elem.get(&base) {
                    if self.f.vn(off).is_constant() && elem > 0 {
                        let c = self.f.vn(off).constant_value();
                        if c != 0 && c % elem as u64 == 0 {
                            let b = self.operand(base, 16, false);
                            return (format!("{b}[{}]", c / elem as u64), 16);
                        }
                    } else if let Some(idx) = self.scaled_index(off, elem) {
                        let b = self.operand(base, 16, false);
                        let i = self.render_var(idx).0;
                        return (format!("{b}[{i}]"), 16);
                    }
                }
            }
        }
        // A deref of an address that is genuinely a pointer to a value of the right size prints
        // `*addr`; otherwise Ghidra casts the address to `(vty *)` first. An address produced by
        // integer arithmetic is int-natured (Ghidra's `arithmeticOutputStandard`) and always
        // casts, even though type propagation back through the LOAD leaves a pointer temp-type on
        // it — mosura's `type_of` would otherwise see that pointer and wrongly skip the cast.
        let arithmetic_addr = self
            .f
            .vn(addr)
            .def
            .map(|d| {
                use OpCode::*;
                matches!(
                    self.f.op(d).code(),
                    IntAdd | IntSub | IntMult | IntAnd | IntOr | IntXor | IntLeft | IntRight | IntSright
                )
            })
            .unwrap_or(false);
        let addr_is_ptr = !arithmetic_addr
            && matches!(&self.type_of(addr), Datatype::Pointer(_, p) if p.size() == size);
        if addr_is_ptr {
            (format!("*{}", self.operand(addr, 15, false)), 15)
        } else {
            // cast the address to the access type (Ghidra `*(int4 *)`, or `*(xunknown4 *)` when
            // inference recovered no type for the access).
            (format!("*({} *){}", vty.name(), self.operand(addr, 14, false)), 15)
        }
    }

    /// Render a `PTRSUB(base, off)` as a member/element access (Ghidra `opPtrsub`). The result has
    /// no leading `&`/`*`: the deref (LOAD/STORE) context uses it as the field value (`base->f`),
    /// the value context prepends `&` (`&base->f`). Pointer-to-struct ⇒ `base->field_0x<off>`
    /// (Ghidra's default recovered field name); pointer-to-array ⇒ element 0.
    fn render_ptrsub(&mut self, op: OpId, _deref: bool) -> String {
        let base = self.f.op(op).input(0).unwrap();
        let off = self.f.op(op).input(1).map(|v| self.f.vn(v).constant_value()).unwrap_or(0);
        let b = self.operand(base, 16, false);
        match self.type_of(base).ptr_to() {
            Some(Datatype::Array(..)) => format!("{b}[0]"),
            Some(_) => format!("{b}->field_0x{off:x}"),
            None => format!("*{b}"),
        }
    }

    /// Render an op as a C expression with its precedence.
    fn render_op(&mut self, op: super::op::OpId) -> (String, u8) {
        let o = self.f.op(op);
        let a = |i: usize| o.input(i).unwrap();
        let bin = |s: &mut Self, sym: &str, prec: u8| {
            // route operands through the cast rule so a signed compare prints `(int4)x` etc.;
            // ops with no required cast (most) fall through to a plain operand
            let l = s.cast_operand(op, 0, prec, false);
            let r = s.cast_operand(op, 1, prec, true);
            (format!("{l} {sym} {r}"), prec)
        };
        match o.code() {
            // COPY and ZEXT (the implicit x86 32→64 zero-extension) stay transparent
            OpCode::Copy | OpCode::IntZext => self.render_var(a(0)),
            // SUBPIECE: a truncation at offset 0 of a value wider than the slice is a C cast
            // (Ghidra's `opSubpiece`/`isSubpieceCast`); when the value's type-width equals the
            // slice it is the natural read and stays transparent
            OpCode::Subpiece => {
                let in0 = a(0);
                let off = self.f.vn(a(1)).is_constant().then(|| self.f.vn(a(1)).constant_value());
                let out_size = self.f.vn(o.output.unwrap()).size;
                if off == Some(0) && self.effective_width(in0) > out_size {
                    let ty = self.type_of(o.output.unwrap()).name();
                    (format!("({ty}){}", self.operand(in0, 14, false)), 14)
                } else {
                    self.render_var(in0)
                }
            }
            OpCode::IntSext => {
                let n = self.f.vn(o.output.unwrap()).size;
                // the widening renders `(int{n})`; the input itself may also need a `(int{m})`
                // cast (e.g. from undefined), giving Ghidra's `(int8)(int4)x`
                (format!("(int{n}){}", self.cast_operand(op, 0, 14, false)), 14)
            }
            OpCode::IntMult => bin(self, "*", 13),
            OpCode::IntDiv | OpCode::IntSdiv => bin(self, "/", 13),
            OpCode::IntRem | OpCode::IntSrem => bin(self, "%", 13),
            OpCode::IntAdd => {
                // a frame-pointer-relative address taken as a value is `&Stack_<offset>`
                let (i0, i1) = (a(0), a(1));
                match self.stack_addr(i0, i1) {
                    Some(s) => (s, 15),
                    None => bin(self, "+", 12),
                }
            }
            OpCode::IntSub => bin(self, "-", 12),
            OpCode::IntLeft => bin(self, "<<", 11),
            OpCode::IntRight | OpCode::IntSright => bin(self, ">>", 11),
            OpCode::IntLess | OpCode::IntSless => bin(self, "<", 10),
            OpCode::IntLessequal | OpCode::IntSlessequal => bin(self, "<=", 10),
            OpCode::IntEqual => bin(self, "==", 9),
            OpCode::IntNotequal => bin(self, "!=", 9),
            OpCode::IntAnd => bin(self, "&", 8),
            OpCode::IntXor | OpCode::BoolXor => bin(self, "^", 7),
            OpCode::IntOr => bin(self, "|", 6),
            OpCode::BoolAnd => bin(self, "&&", 5),
            OpCode::BoolOr => bin(self, "||", 4),
            OpCode::IntNegate => (format!("~{}", self.operand(a(0), 15, false)), 15),
            OpCode::Int2comp => (format!("-{}", self.operand(a(0), 15, false)), 15),
            OpCode::BoolNegate => (format!("!{}", self.operand(a(0), 15, false)), 15),
            // floating point: arithmetic and comparisons as operators
            OpCode::FloatAdd => bin(self, "+", 12),
            OpCode::FloatSub => bin(self, "-", 12),
            OpCode::FloatMult => bin(self, "*", 13),
            OpCode::FloatDiv => bin(self, "/", 13),
            OpCode::FloatLess => bin(self, "<", 10),
            OpCode::FloatLessequal => bin(self, "<=", 10),
            OpCode::FloatEqual => bin(self, "==", 9),
            OpCode::FloatNotequal => bin(self, "!=", 9),
            OpCode::FloatNeg => (format!("-{}", self.operand(a(0), 15, false)), 15),
            // float intrinsics Ghidra prints as named calls
            OpCode::FloatNan => (format!("NAN({})", self.render_var(a(0)).0), 16),
            OpCode::FloatAbs => (format!("ABS({})", self.render_var(a(0)).0), 16),
            OpCode::FloatSqrt => (format!("SQRT({})", self.render_var(a(0)).0), 16),
            OpCode::FloatCeil => (format!("ceil({})", self.render_var(a(0)).0), 16),
            OpCode::FloatFloor => (format!("floor({})", self.render_var(a(0)).0), 16),
            OpCode::FloatRound => (format!("round({})", self.render_var(a(0)).0), 16),
            // conversions render as casts (to the output float/int width)
            OpCode::FloatInt2float | OpCode::FloatFloat2float => {
                let ty = float_name(self.f.vn(o.output.unwrap()).size);
                let in0 = a(0);
                (format!("({ty}){}", self.operand(in0, 14, false)), 14)
            }
            OpCode::FloatTrunc => {
                let n = self.f.vn(o.output.unwrap()).size;
                let in0 = a(0);
                (format!("(int{n}){}", self.operand(in0, 14, false)), 14)
            }
            OpCode::Load => {
                let (addr, sz) = (a(1), self.f.vn(o.output.unwrap()).size);
                let vty = self.type_of(o.output.unwrap());
                self.render_mem(addr, sz, &vty)
            }
            // PTRADD/PTRSUB used as a value (not a LOAD/STORE pointer): C pointer arithmetic
            // scales by the element implicitly, so `base + index` (Ghidra `opPtradd` non-value
            // case → `binary_plus`); PTRSUB takes the address of the sub-component.
            OpCode::Ptradd => {
                let (base, index) = (a(0), a(1));
                let l = self.operand(base, 12, false);
                let r = self.operand(index, 12, true);
                (format!("{l} + {r}"), 12)
            }
            OpCode::Ptrsub => (format!("&{}", self.render_ptrsub(op, false)), 15),
            OpCode::Call => {
                // input 0 is the (constant) call target — name it func_0x<addr>, like Ghidra
                let name = match o.input(0) {
                    Some(t) => format!("func_0x{:08x}", self.f.vn(t).loc.offset),
                    None => "func".to_string(),
                };
                let args: Vec<String> = (1..o.num_inputs()).map(|i| self.render_var(a(i)).0).collect();
                (format!("{name}({})", args.join(", ")), 16)
            }
            OpCode::Callind => {
                // indirect call through a computed target — Ghidra casts it to a code pointer
                let tgt = self.operand(a(0), 16, false);
                let args: Vec<String> = (1..o.num_inputs()).map(|i| self.render_var(a(i)).0).collect();
                (format!("(*(code *){tgt})({})", args.join(", ")), 16)
            }
            // PIECE (CONCAT) — heritage refinement / Ghidra's `guard` rejoin two pieces; printed
            // functionally as `CONCAT<s0><s1>(hi, lo)` (`TypeOpPiece::getOperatorName`, `typeop.cc`).
            OpCode::Piece => {
                let (s0, s1) = (self.f.vn(a(0)).size, self.f.vn(a(1)).size);
                let hi = self.render_var(a(0)).0;
                let lo = self.render_var(a(1)).0;
                (format!("CONCAT{s0}{s1}({hi},{lo})"), 16)
            }
            other => (format!("{}(...)", other.name()), 16),
        }
    }

    /// The function's return value: the value wired into a RETURN by return recovery (its
    /// second input), or `None` for a void function.
    fn return_value(&self) -> Option<VarnodeId> {
        self.f
            .op_ids()
            .find(|&op| self.f.op(op).code() == OpCode::Return && self.f.op(op).num_inputs() > 1)
            .and_then(|op| self.f.op(op).input(1))
    }

    /// Render an assignment statement body (`lhs = rhs`, no terminator) for an op.
    fn render_assign(&mut self, op: OpId) -> String {
        let outv = self.f.op(op).output.unwrap();
        let lhs = self.name_of(outv);
        let rhs = self.render_op(op).0;
        format!("{lhs} = {rhs}")
    }

    /// Walk back (≤4 levels, Ghidra's `findLoopVariable`) from the condition variable to a
    /// MULTIEQUAL defined in the loop header `head`.
    fn find_loop_phi(&self, cond_var: VarnodeId, head: BlockId) -> Option<OpId> {
        let mut stack = vec![(cond_var, 0u32)];
        let mut seen: HashSet<OpId> = HashSet::new();
        while let Some((v, depth)) = stack.pop() {
            let Some(def) = self.f.vn(v).def else { continue };
            if !seen.insert(def) {
                continue;
            }
            let o = self.f.op(def);
            if o.code() == OpCode::Multiequal {
                if o.parent == Some(head) {
                    return Some(def);
                }
                continue; // don't trace through a phi
            }
            if depth >= 4 || matches!(o.code(), OpCode::Call | OpCode::Callind) {
                continue;
            }
            for &inp in &o.inrefs.clone() {
                stack.push((inp, depth + 1));
            }
        }
        None
    }

    /// If the WhileDo with header `cond_idx` and body `body_idx` is a `for`-loop, return its
    /// `(initializer, iterator)` ops (Ghidra `findLoopVariable`/`findInitializer`): the
    /// condition variable's loop-header phi has one input defined in the body (the iterator)
    /// and one defined before the loop (the initializer).
    fn for_parts(
        &self,
        s: &Structured,
        cond_idx: usize,
        body_idx: usize,
    ) -> Option<(Option<VarnodeId>, OpId, VarnodeId)> {
        let head = exit_basic(s, cond_idx)?;
        let cbranch = self
            .f
            .block(head)
            .ops
            .iter()
            .rev()
            .copied()
            .find(|&op| self.f.op(op).code() == OpCode::Cbranch)?;
        let cond_var = self.f.op(cbranch).input(1)?;
        let phi = self.find_loop_phi(cond_var, head)?;
        let phi_out = self.f.op(phi).output?;

        let mut body_blocks = Vec::new();
        basic_blocks_of(s, body_idx, &mut body_blocks);

        // the phi's body-defined input is the iterator; its other input is the initializer
        // value (often a folded constant, so carry the varnode rather than a defining op)
        let (mut iterate, mut init_var) = (None, None);
        for &inp in &self.f.op(phi).inrefs {
            let in_body = match self.f.vn(inp).def {
                Some(d) => {
                    self.f.op(d).parent.is_some_and(|pb| body_blocks.contains(&pb))
                        && !self.f.op(d).is_marker()
                }
                None => false,
            };
            if in_body {
                iterate = self.f.vn(inp).def;
            } else {
                init_var = Some(inp);
            }
        }
        iterate.map(|it| (init_var, it, phi_out))
    }

    /// Find all `for`-loops in the structure tree and record their parts.
    fn detect_for_loops(&mut self, s: &Structured, idx: usize) {
        if let FlowKind::WhileDo = s.blocks[idx].kind {
            let comps = s.blocks[idx].components.clone();
            if let Some((init_var, iterate, phi_out)) = self.for_parts(s, comps[0], comps[1]) {
                self.for_loops.insert(idx, (init_var, iterate, phi_out));
                self.suppressed.insert(iterate);
                // a non-constant initializer is a real op in the pre-loop block — suppress it
                if let Some(d) = init_var.and_then(|iv| self.f.vn(iv).def) {
                    self.suppressed.insert(d);
                }
            }
        }
        for &c in &s.blocks[idx].components.clone() {
            self.detect_for_loops(s, c);
        }
    }

    /// The boolean tested by a condition block — the CBRANCH operand for a basic block, or
    /// the joined operands of a short-circuit `&&`/`||`.
    /// Render a (possibly short-circuit) condition, pushing a pending negation inward via
    /// De Morgan (Ghidra's print-time negation): `!(a && b)` → `!a || !b`, `!(a || b)` →
    /// `!a && !b`, recursing so the leading `!` never survives on a compound condition.
    fn render_cond_expr(&mut self, s: &Structured, idx: usize, neg: bool) -> String {
        let comps = s.blocks[idx].components.clone();
        match s.blocks[idx].kind {
            FlowKind::CondAnd | FlowKind::CondOr => {
                let is_and = matches!(s.blocks[idx].kind, FlowKind::CondAnd);
                // De Morgan swaps the connective under negation
                let conn = if is_and == !neg { "&&" } else { "||" };
                let a = self.render_cond_operand(s, comps[0], neg);
                let b = self.render_cond_operand(s, comps[1], neg);
                format!("{a} {conn} {b}")
            }
            _ => {
                let cvar = exit_basic(s, idx)
                    .and_then(|bid| {
                        self.f.block(bid).ops.iter().rev().copied().find(|&op| self.f.op(op).code() == OpCode::Cbranch)
                    })
                    .and_then(|cbr| self.f.op(cbr).input(1));
                match cvar {
                    Some(v) if neg => self.render_negated(v),
                    Some(v) => self.render_var(v).0,
                    None => if neg { "!(1)".into() } else { "1".into() },
                }
            }
        }
    }

    /// A short-circuit operand, parenthesized (Ghidra's `(a) && (b)` style).
    fn render_cond_operand(&mut self, s: &Structured, idx: usize, neg: bool) -> String {
        format!("({})", self.render_cond_expr(s, idx, neg))
    }

    /// The condition of an `if`/`while`, negated when the body is on the false edge. The
    /// negation is pushed into the expression (Ghidra's print-time boolean negation) rather
    /// than wrapped in `!(...)`: `!(!x)` cancels, `==`/`!=` flip, `&&`/`||` De Morgan.
    fn render_condition(&mut self, s: &Structured, cond_idx: usize, negated: bool) -> String {
        self.render_cond_expr(s, cond_idx, negated)
    }

    /// Render the logical negation of boolean `v`, folding double negation and flipping
    /// equality (Ghidra's print-time negation); falls back to `!(...)`.
    fn render_negated(&mut self, v: VarnodeId) -> String {
        if let Some(def) = self.f.vn(v).def {
            let code = self.f.op(def).code();
            match code {
                OpCode::BoolNegate => {
                    let inner = self.f.op(def).input(0).unwrap();
                    return self.render_var(inner).0; // !(!x) => x
                }
                // operands route through `cast_operand` so a flipped signed compare keeps its
                // `(int4)` cast (`!(9 s< x)` => `(int4)x < 10`), matching the un-negated path
                OpCode::IntEqual | OpCode::IntNotequal => {
                    let sym = if code == OpCode::IntEqual { "!=" } else { "==" };
                    let l = self.cast_operand(def, 0, 9, false);
                    let r = self.cast_operand(def, 1, 9, true);
                    return format!("{l} {sym} {r}");
                }
                // !(a <= b) => b < a
                OpCode::IntLessequal | OpCode::IntSlessequal => {
                    let l = self.cast_operand(def, 1, 9, false);
                    let r = self.cast_operand(def, 0, 9, true);
                    return format!("{l} < {r}");
                }
                // !(a < b) => b <= a; but when a is a constant c, Ghidra keeps the strict form
                // by incrementing the constant (`b < c+1`), unless c+1 overflows the width
                OpCode::IntLess | OpCode::IntSless => {
                    let i0 = self.f.op(def).input(0).unwrap();
                    let vn0 = self.f.vn(i0);
                    if vn0.is_constant() {
                        if let Some(cp1) = incr_in_width(vn0.constant_value(), vn0.size, code == OpCode::IntSless) {
                            let l = self.cast_operand(def, 1, 9, false);
                            return format!("{l} < {}", render_const(cp1, vn0.size));
                        }
                    }
                    let l = self.cast_operand(def, 1, 9, false);
                    let r = self.cast_operand(def, 0, 9, true);
                    return format!("{l} <= {r}");
                }
                // De Morgan: `!(a && b)` => `!a || !b`, `!(a || b)` => `!a && !b`, pushing the
                // negation into each operand. This is the print-time analogue of Ghidra's
                // `ActionNormalizeBranches` (blockaction.cc:2117), which flips a CBRANCH condition
                // in place — but ONLY when `opFlipInPlaceTest` reports the flip *normalizes* (return
                // 0), i.e. every operand is a lone-descended, flippable boolean. We apply the same
                // gate: distribute only when normalizing, otherwise keep the compact `!(...)`. So
                // `BOOL_AND(a!=10, b!=0x14)` prints as `a==10 || b==0x14` (orcompare), while a
                // condition that reuses a shared sub-boolean stays `!(...)` (pointerrel).
                OpCode::BoolAnd | OpCode::BoolOr if op_flip_normalizes(self.f, def) == 0 => {
                    let conn = if code == OpCode::BoolAnd { "||" } else { "&&" };
                    let l = self.f.op(def).input(0).unwrap();
                    let r = self.f.op(def).input(1).unwrap();
                    let ls = self.render_negated_demorgan(l);
                    let rs = self.render_negated_demorgan(r);
                    return format!("{ls} {conn} {rs}");
                }
                _ => {}
            }
        }
        format!("!{}", self.operand(v, 15, false))
    }

    /// A De-Morgan operand for [`render_negated`]: the negation of `v`, parenthesized only when it
    /// is itself a compound boolean (`BOOL_AND`/`BOOL_OR`) so the nested connective keeps its
    /// grouping. Simple comparisons (the common case) print bare — `a == 10 || b == 0x14`.
    fn render_negated_demorgan(&mut self, v: VarnodeId) -> String {
        let s = self.render_negated(v);
        let compound = self
            .f
            .vn(v)
            .def
            .is_some_and(|d| matches!(self.f.op(d).code(), OpCode::BoolAnd | OpCode::BoolOr));
        if compound {
            format!("({s})")
        } else {
            s
        }
    }

    /// Emit a structured block (and its children) as C.
    fn emit_structured(&mut self, s: &Structured, idx: usize, indent: usize, out: &mut String) {
        let pad = "  ".repeat(indent);
        let fb = &s.blocks[idx];
        let (kind, comps, negated) = (fb.kind.clone(), fb.components.clone(), fb.negated);
        match kind {
            FlowKind::Basic(bid) => self.emit_basic(bid, indent, out),
            // a short-circuit condition: its operands are inlined by render_condition; emit
            // only any side-effecting statements they carry (rare)
            FlowKind::CondAnd | FlowKind::CondOr => {
                for c in comps {
                    self.emit_structured(s, c, indent, out);
                }
            }
            FlowKind::Switch => {
                let head = exit_basic(s, comps[0]);
                let head_pc = head.and_then(|b| {
                    self.f.block(b).ops.iter().rev().copied().find(|&op| self.f.op(op).code() == OpCode::Branchind).map(|op| self.f.op(op).seqnum.pc.offset)
                });
                let idx = head
                    .and_then(|b| self.switch_index(b))
                    .map(|v| self.render_var(v).0)
                    .unwrap_or_else(|| "switchD".to_string());
                // emit the switch-head block's statements first (Ghidra `emitBlockSwitch`:
                // `getSwitchBlock()->emit` with `no_branch`) — the head may carry statements that
                // collapsed into it (e.g. the entry block once its bounds guard is folded away);
                // the BRANCHIND and the inlined index computation are skipped by `emit_basic`.
                self.emit_structured(s, comps[0], indent, out);
                // the entry addresses of the case blocks, so a recovered target can be matched to
                // the case block it enters (Ghidra `getIndexByBlock`) even when the block start
                // shifted past the target (leading case instructions optimized away)
                let case_addrs: Vec<u64> = comps[1..]
                    .iter()
                    .filter_map(|&c| entry_basic(s, c))
                    .filter_map(|cb| self.f.block_range(cb).map(|(a, _)| a))
                    .collect();
                let _ = writeln!(out, "{pad}switch ({idx}) {{");
                for &case in &comps[1..] {
                    if let (Some(pc), Some(cb)) = (head_pc, entry_basic(s, case)) {
                        let addr = self.f.block_range(cb).map(|(a, _)| a).unwrap_or(0);
                        // the folded-in out-of-range target prints as `default:` (Ghidra
                        // `BlockSwitch` CaseOrder.isdefault), never a case value
                        if self.f.switch_defaults.get(&pc) == Some(&addr) {
                            let _ = writeln!(out, "{pad}default:");
                        } else {
                            for v in self.case_labels(pc, addr, &case_addrs) {
                                let _ = writeln!(out, "{pad}case {v}:");
                            }
                        }
                    }
                    self.emit_structured(s, case, indent + 1, out);
                    // a case that breaks to the switch's merge ends with `break;`; one that
                    // returns is already terminal
                    let terminal = exit_basic(s, case)
                        .and_then(|eb| self.f.block(eb).ops.last().map(|&o| self.f.op(o).code()))
                        .map(|c| c == OpCode::Return)
                        .unwrap_or(false);
                    if !terminal {
                        let _ = writeln!(out, "{}break;", "  ".repeat(indent + 1));
                    }
                }
                let _ = writeln!(out, "{pad}}}");
            }
            FlowKind::List => {
                for c in comps {
                    self.emit_structured(s, c, indent, out);
                }
            }
            FlowKind::If => {
                self.emit_structured(s, comps[0], indent, out);
                let cond = self.render_condition(s, comps[0], negated);
                let _ = writeln!(out, "{pad}if ({cond}) {{");
                self.emit_structured(s, comps[1], indent + 1, out);
                let _ = writeln!(out, "{pad}}}");
            }
            FlowKind::IfElse => {
                self.emit_structured(s, comps[0], indent, out);
                let cond = self.render_condition(s, comps[0], negated);
                let _ = writeln!(out, "{pad}if ({cond}) {{");
                self.emit_structured(s, comps[1], indent + 1, out);
                let _ = writeln!(out, "{pad}}}");
                let _ = writeln!(out, "{pad}else {{");
                self.emit_structured(s, comps[2], indent + 1, out);
                let _ = writeln!(out, "{pad}}}");
            }
            FlowKind::WhileDo => {
                self.emit_structured(s, comps[0], indent, out);
                if let Some((init_var, iterate, phi_out)) = self.for_loops.get(&idx).copied() {
                    let init_s = match init_var {
                        Some(iv) => {
                            let lhs = self.name_of(phi_out);
                            let rhs = match self.f.vn(iv).def {
                                Some(d) => self.render_op(d).0, // the initializer's expression
                                None => self.render_var(iv).0,  // a folded constant / input
                            };
                            format!("{lhs} = {rhs}")
                        }
                        None => String::new(),
                    };
                    let cond = self.render_condition(s, comps[0], negated);
                    let iter_s = self.render_assign(iterate);
                    let _ = writeln!(out, "{pad}for ({init_s}; {cond}; {iter_s}) {{");
                    self.emit_structured(s, comps[1], indent + 1, out);
                    let _ = writeln!(out, "{pad}}}");
                } else {
                    let cond = self.render_condition(s, comps[0], negated);
                    let _ = writeln!(out, "{pad}while ({cond}) {{");
                    self.emit_structured(s, comps[1], indent + 1, out);
                    let _ = writeln!(out, "{pad}}}");
                }
            }
            FlowKind::DoWhile => {
                let _ = writeln!(out, "{pad}do {{");
                self.emit_structured(s, comps[0], indent + 1, out);
                let cond = self.render_condition(s, comps[0], negated);
                let _ = writeln!(out, "{pad}}} while ({cond});");
            }
        }
    }

    /// Emit one basic block's statements (skipping control-flow and inlined ops).
    fn emit_basic(&mut self, b: super::block::BlockId, indent: usize, out: &mut String) {
        let pad = "  ".repeat(indent);
        if self.labels.contains(&b) {
            let _ = writeln!(out, "{}{}:", "  ".repeat(indent.saturating_sub(1)), self.lab_name(b));
        }
        for op in self.f.block(b).ops.clone() {
            if self.suppressed.contains(&op) {
                continue; // emitted in a for-loop header (initializer / iterator)
            }
            let o = self.f.op(op);
            match o.code() {
                OpCode::Cbranch | OpCode::Branch | OpCode::Branchind | OpCode::Multiequal | OpCode::Indirect => {}
                OpCode::Return => match o.input(1) {
                    Some(v) => {
                        let e = self.render_var(v).0; // wired return value (inlined when single-use)
                        let _ = writeln!(out, "{pad}return {e};");
                    }
                    None => {
                        let _ = writeln!(out, "{pad}return;");
                    }
                },
                OpCode::Store => {
                    let (addr, vv) = (o.input(1).unwrap(), o.input(2).unwrap());
                    let sz = self.f.vn(vv).size;
                    let vty = self.type_of(vv);
                    let lhs = self.render_mem(addr, sz, &vty).0;
                    let val = self.render_var(vv).0;
                    let _ = writeln!(out, "{pad}{lhs} = {val};");
                }
                OpCode::Call | OpCode::Callind => {
                    // a call is a statement (it has a side effect). Its return value is always a
                    // named variable (Ghidra `baseExplicit`: a CALL output is explicit) — emit
                    // `xVar = func(…)` whenever the result is used; a void/unused call is a bare
                    // `func(…);`.
                    let out_vn = o.output;
                    let uses = out_vn.map(|v| self.f.vn(v).descend.len());
                    match (out_vn, uses) {
                        (Some(outv), Some(n)) if n >= 1 => {
                            let lhs = self.name_of(outv);
                            let rhs = self.render_op(op).0;
                            let _ = writeln!(out, "{pad}{lhs} = {rhs};");
                        }
                        _ => {
                            let e = self.render_op(op).0;
                            let _ = writeln!(out, "{pad}{e};");
                        }
                    }
                }
                _ => {
                    if let Some(outv) = o.output {
                        if self.is_explicit(outv) {
                            let lhs = self.name_of(outv);
                            let rhs = self.render_op(op).0;
                            let _ = writeln!(out, "{pad}{lhs} = {rhs};");
                        }
                    }
                }
            }
        }
        // a goto edge cut from this block for an irreducible region
        if let Some(&(target, negated)) = self.gotos.get(&b) {
            let lab = self.lab_name(target);
            let cbr = self
                .f
                .block(b)
                .ops
                .iter()
                .rev()
                .copied()
                .find(|&op| self.f.op(op).code() == OpCode::Cbranch);
            match cbr.and_then(|op| self.f.op(op).input(1)) {
                Some(cond) => {
                    let c = if negated { self.render_negated(cond) } else { self.render_var(cond).0 };
                    let _ = writeln!(out, "{pad}if ({c}) goto {lab};");
                }
                None => {
                    let _ = writeln!(out, "{pad}goto {lab};");
                }
            }
        }
    }

    /// The index variable of a switch head: trace the BRANCHIND through the table lookup if
    /// the lookup survived, else fall back to the dominating bound check `index <(=) count`.
    fn switch_index(&self, head: BlockId) -> Option<VarnodeId> {
        let bi = self.f.block(head).ops.iter().rev().copied().find(|&op| self.f.op(op).code() == OpCode::Branchind)?;
        if let Some(v) = self.trace_table_index(self.f.op(bi).input(0)?) {
            return Some(v);
        }
        // fallback: the range check guarding the switch — `index <= count-1` / `index < count`
        let pc = self.f.op(bi).seqnum.pc.offset;
        let num_cases = self.f.switch_targets.get(&pc).map(|t| t.len())?;
        for i in 0..self.f.num_ops() as u32 {
            let o = self.f.op(OpId(i));
            let c = match o.input(1) {
                Some(b) if self.f.vn(b).is_constant() => self.f.vn(b).constant_value() as usize,
                _ => continue,
            };
            let hit = (o.code() == OpCode::IntLessequal && c + 1 == num_cases) || (o.code() == OpCode::IntLess && c == num_cases);
            if hit {
                return o.input(0);
            }
        }
        None
    }

    /// Trace `RAX = base + ext(load(base + index*scale))` ⇒ `index`, when the lookup survives.
    fn trace_table_index(&self, mut v: VarnodeId) -> Option<VarnodeId> {
        for _ in 0..10 {
            let def = self.f.vn(v).def?;
            let o = self.f.op(def);
            match o.code() {
                OpCode::Load => {
                    let addr = o.input(1)?;
                    if let Some(ad) = self.f.vn(addr).def {
                        if self.f.op(ad).code() == OpCode::IntAdd {
                            for k in 0..self.f.op(ad).num_inputs() {
                                if let Some(pd) = self.f.op(ad).input(k).and_then(|p| self.f.vn(p).def) {
                                    if self.f.op(pd).code() == OpCode::IntMult {
                                        return self.f.op(pd).input(0);
                                    }
                                }
                            }
                        }
                    }
                    return Some(addr);
                }
                OpCode::IntAdd => {
                    v = (0..o.num_inputs()).filter_map(|k| o.input(k)).find(|&iv| self.f.vn(iv).def.is_some())?;
                }
                OpCode::IntSext | OpCode::IntZext | OpCode::Subpiece | OpCode::Copy => v = o.input(0)?,
                _ => return None,
            }
        }
        None
    }

    /// The case values that dispatch to the case block at `case_addr` (Ghidra
    /// `getLabelByIndex(getIndexByBlock(block,j))`). Each recovered target is attributed to the
    /// case block it enters — the first case block at or after the target address, since a case
    /// block can start a few bytes past its recovered target (leading instructions get CSE'd /
    /// hoisted out). For the canonical 0-based switch the index is the label; this is exact for a
    /// dense table and recovers the labels a strict `target == block-start` match dropped after a
    /// block shift.
    fn case_labels(&self, head_pc: u64, case_addr: u64, case_addrs: &[u64]) -> Vec<usize> {
        let Some(targets) = self.f.switch_targets.get(&head_pc) else { return Vec::new() };
        targets
            .iter()
            .enumerate()
            .filter_map(|(i, &t)| {
                let owner = case_addrs.iter().copied().filter(|&a| a >= t).min()?;
                (owner == case_addr).then_some(i)
            })
            .collect()
    }

    /// A label name for a goto target basic block, by its entry address.
    fn lab_name(&self, b: BlockId) -> String {
        let addr = self.f.block_range(b).map(|(a, _)| a).unwrap_or(0);
        format!("LAB_{addr:08x}")
    }
}

/// Render a constant: small negatives as signed decimal (Ghidra prints `0xff..fb` as `-5`),
/// otherwise decimal for small values and hex for the rest.
/// Faithful port of Ghidra's `Funcdata::opFlipInPlaceTest` (funcdata_op.cc:1221): trace a boolean
/// to the set of ops that would need flipping to negate it, and report whether the flip
/// *normalizes*. Returns 0 if it normalizes (a net win — flip), 1 if ambivalent, 2 if it does not
/// normalize (leave alone). We use it as the gate for print-time De Morgan distribution in
/// [`PrintC::render_negated`] (the analogue of `ActionNormalizeBranches`); a BOOL_AND/BOOL_OR is
/// distributed only when this returns 0. A non-lone-descended or non-flippable operand (e.g. a
/// shared sub-boolean, or a FLOAT_LESS that has no in-place complement) yields 2.
fn op_flip_normalizes(f: &Funcdata, op: OpId) -> i32 {
    let lone = |vn: VarnodeId| -> bool {
        let d = &f.vn(vn).descend;
        d.len() == 1 && d[0] == op
    };
    match f.op(op).code() {
        OpCode::IntEqual | OpCode::FloatEqual => 1,
        OpCode::BoolNegate | OpCode::IntNotequal | OpCode::FloatNotequal => 0,
        OpCode::IntSless | OpCode::IntLess => {
            let vn = f.op(op).input(0).unwrap();
            if !f.vn(vn).is_constant() {
                1
            } else {
                0
            }
        }
        OpCode::IntSlessequal | OpCode::IntLessequal => {
            let vn = f.op(op).input(1).unwrap();
            if f.vn(vn).is_constant() {
                1
            } else {
                0
            }
        }
        OpCode::BoolOr | OpCode::BoolAnd => {
            let vn0 = f.op(op).input(0).unwrap();
            if !lone(vn0) || !f.vn(vn0).is_written() {
                return 2;
            }
            let subtest1 = op_flip_normalizes(f, f.vn(vn0).def.unwrap());
            if subtest1 == 2 {
                return 2;
            }
            let vn1 = f.op(op).input(1).unwrap();
            if !lone(vn1) || !f.vn(vn1).is_written() {
                return 2;
            }
            let subtest2 = op_flip_normalizes(f, f.vn(vn1).def.unwrap());
            if subtest2 == 2 {
                return 2;
            }
            subtest1 // the front of AND/OR must be normalizing
        }
        _ => 2,
    }
}

/// `c + 1` masked to a comparison's width, or `None` if it would overflow the maximum value
/// for the signedness — so the strict-`<` rewrite `x <= c` ⇒ `x < c+1` stays exact.
fn incr_in_width(c: u64, size: u32, signed: bool) -> Option<u64> {
    let bits = (size * 8).clamp(1, 64);
    let full = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
    let cm = c & full;
    let max = if !signed {
        full
    } else if bits >= 64 {
        i64::MAX as u64
    } else {
        (1u64 << (bits - 1)) - 1
    };
    (cm != max).then(|| (cm + 1) & full)
}

/// Ops whose constant operands inherit the operation's signedness (Ghidra's `inherits_sign`):
/// an untyped/unsigned constant here prints with a `U` suffix unless the other side forces it.
fn inherits_sign(c: OpCode) -> bool {
    use OpCode::*;
    matches!(
        c,
        IntEqual | IntNotequal | IntSless | IntSlessequal | IntLess | IntLessequal | IntAdd | IntSub
            | Int2comp | IntMult | IntDiv | IntSdiv | IntRem | IntSrem | IntNegate | IntXor | IntAnd
            | IntOr | IntLeft | IntRight | IntSright
    )
}

/// Ops where only the first parameter inherits the sign (Ghidra's `inherits_sign_zero`): the
/// shift amount and the modulus second operand never take a `U`.
fn inherits_sign_first_only(c: OpCode) -> bool {
    use OpCode::*;
    matches!(c, IntLeft | IntRight | IntSright | IntRem | IntSrem)
}

/// Render a constant with an explicit unsigned `U` suffix (Ghidra's `setUnsignedPrint`).
fn render_const_unsigned(val: u64, size: u32) -> String {
    let masked = if size == 0 || size >= 8 { val } else { val & ((1u64 << (8 * size)) - 1) };
    if masked < 10 {
        format!("{masked}U")
    } else {
        format!("0x{masked:x}U")
    }
}

/// Ghidra's `PrintLanguage::mostNaturalBase` — pick base 10 for "round" numbers (a run of
/// trailing 0s or 9s in decimal), base 16 otherwise. Decides how a constant above the small-decimal
/// threshold prints.
fn most_natural_base(val: u64) -> u32 {
    if val == 0 {
        return 10;
    }
    let setdig = val % 10;
    let mut countdec = 0;
    let mut tmp = val;
    if setdig == 0 || setdig == 9 {
        countdec = 1;
        tmp /= 10;
        while tmp != 0 && tmp % 10 == setdig {
            countdec += 1;
            tmp /= 10;
        }
    }
    match countdec {
        0 => 16,
        1 => {
            if tmp > 1 || setdig == 9 {
                16
            } else {
                10
            }
        }
        2 => {
            if tmp > 10 {
                16
            } else {
                10
            }
        }
        3 => {
            if tmp > 100 {
                16
            } else {
                10
            }
        }
        _ => 10,
    }
}

fn render_const(val: u64, size: u32) -> String {
    let signed = if size == 0 || size >= 8 {
        val as i64
    } else {
        let sh = 64 - 8 * size;
        ((val << sh) as i64) >> sh
    };
    if signed < 0 && signed > -0x10000 {
        return format!("{signed}");
    }
    // Ghidra `push_integer`: small values (≤10) always decimal, otherwise the most natural base.
    if val <= 10 || most_natural_base(val) == 10 {
        format!("{val}")
    } else {
        format!("0x{val:x}")
    }
}

/// Decompile `f` to C text.
pub fn print_c(f: &Funcdata) -> String {
    let reg_space = f.spaces.by_name("register");

    // Parameters: the recovered function prototype (Ghidra `ActionInputPrototype` →
    // `FuncProto::deriveInputMap` → `ParamListStandard::fillinMap`, ported as
    // `fspec::recover_input_params`). This walks the calling convention's resource list — the float
    // registers `XMM0..7` then the integer registers `RDI..R9` then the stack overflow area — and
    // keeps the storage locations the convention deems used, *in convention order*. Slot `i` is
    // `param_{i+1}`. Replaces the former GP-only register table, which ignored XMM float parameters
    // and so mis-numbered the integer parameters that follow them.
    //
    // A slot is rendered only when backed by a *used* input Varnode (one with descendants). The
    // unreferenced "hole" slots that `fillinMap` synthesizes ahead of a used resource have no
    // backing Varnode at print time — Ghidra's `ActionInputPrototype` materializes them with
    // `newVarnode`/`setInputVarnode`, but this print-time recovery does not — so they are skipped,
    // keeping spurious leading params out of the signature when the body never reads them. The
    // param *number* stays the slot's convention position, so a lone used `RDX` still prints
    // `param_3`.
    let proto = super::fspec::recover_func_proto(f);
    let find_used_input = |addr: Address, size: u32| -> Option<VarnodeId> {
        let mut fallback = None;
        for i in 0..f.num_varnodes() as u32 {
            let v = VarnodeId(i);
            let vn = f.vn(v);
            if vn.is_input() && !vn.descend.is_empty() && vn.loc == addr {
                if vn.size as u32 == size {
                    return Some(v);
                }
                fallback.get_or_insert(v);
            }
        }
        fallback
    };
    let mut param_index: HashMap<Address, u32> = HashMap::new();
    let mut sig_params: Vec<(u32, VarnodeId)> = Vec::new();
    for (i, slot) in proto.params.iter().enumerate() {
        if let Some(v) = find_used_input(slot.addr, slot.size) {
            let n = i as u32 + 1;
            param_index.insert(slot.addr, n);
            sig_params.push((n, v));
        }
    }

    // Parameter type-locks: Ghidra's ActionPrototypeTypes recovers a parameter's type from
    // consistent usage (e.g. `int8 *` for modulo), and only keeps it undefined when usage is
    // inconsistent (divopt). Forcing all parameters to undefined is unfaithful — it regresses the
    // pointer-typed cases — so until that recovery is ported (pointee-consistency), no locks are
    // applied and parameters are typed by inference. The typelock machinery in infer() stands
    // ready for the recovered locks.
    let locks: HashMap<VarnodeId, Datatype> = HashMap::new();

    // Pre-compute the addrtied-HighVariable info. `slot_write` marks a register value that is written
    // into an addrtied stack slot across a call — it is the input of an INDIRECT whose output is the
    // slot (the memory-increment `iStack_NN = iStack_NN + 1` whose value lives in a register). Such a
    // value is *explicit* and named like the slot, the way Ghidra renders the write to an addrtied
    // variable. This is the precise across-call-slot-write pattern, not every member of a stack
    // HighVariable (which would spill intermediate register arithmetic into stray statements).
    // `high_stack_off` names the merged HighVariable by its stack frame offset.
    let t0 = std::time::Instant::now();
    let types = infer(f, &locks);
    if super::action::perf::enabled() {
        super::action::perf::record("print", "infer", t0.elapsed());
    }
    let t0 = std::time::Instant::now();
    let mut h = merge(f);
    if super::action::perf::enabled() {
        super::action::perf::record("print", "merge", t0.elapsed());
    }
    let mut high_stack_off: HashMap<u32, u64> = HashMap::new();
    let mut slot_write = vec![false; f.num_varnodes()];
    // The type prefix of each `stack` slot, keyed by its signed frame offset, so an address-of-local
    // `&<prefix>Stack_NN` carries the slot's prefix (Ghidra `&iStack_28`).
    let mut stack_prefix: HashMap<i64, &'static str> = HashMap::new();
    if let Some(stk) = f.spaces.by_name("stack") {
        for i in 0..f.num_varnodes() as u32 {
            let v = VarnodeId(i);
            if f.vn(v).loc.space == stk {
                high_stack_off.entry(h.high(v)).or_insert(f.vn(v).loc.offset);
                if let Some(t) = types.get(&v) {
                    stack_prefix.entry(f.vn(v).loc.offset as i64).or_insert(type_prefix(t));
                }
            }
        }
        for op in f.op_ids() {
            if f.op(op).code() == OpCode::Indirect {
                if let (Some(out), Some(inp)) = (f.op(op).output, f.op(op).input(0)) {
                    if f.vn(out).loc.space == stk && f.vn(inp).loc.space != stk {
                        slot_write[inp.0 as usize] = true;
                    }
                }
            }
        }
    }
    

    let mut p = PrintC {
        f,
        h,
        names: HashMap::new(),
        reg_space,
        ram_space: f.spaces.by_name("ram"),
        stack_space: f.spaces.by_name("stack"),
        var_counter: 0,
        ret_val: None,
        types,
        for_loops: HashMap::new(),
        suppressed: HashSet::new(),
        array_elem: HashMap::new(),
        gotos: HashMap::new(),
        labels: HashSet::new(),
        decls: Vec::new(),
        slot_write,
        high_stack_off,
        stack_prefix,
        force_explicit: HashSet::new(),
        param_index,
    };
    let t0 = std::time::Instant::now();
    p.array_elem = p.detect_arrays();
    p.anchor_stack_arrays();
    p.ret_val = p.return_value();
    if super::action::perf::enabled() {
        super::action::perf::record("print", "detect_arrays+anchor", t0.elapsed());
    }

    let ret = p.return_value();
    // Return type: the returned Varnode's inferred HighVariable type — Ghidra's
    // `ActionOutputPrototype` → `FuncProto::updateOutputTypes` (fspec.cc:4159), which sets the output
    // type to `triallist[0]->getHigh()->getType()` when the prototype is not output-locked (the
    // stripped-binary case). No downgrade to `undefined`; `void` when there is no returned value.
    let ret_ty = ret.map_or("void".to_string(), |v| p.type_of(v).name());
    // Signature parameters in convention order, each typed from its backing input Varnode.
    let plist: Vec<String> =
        sig_params.iter().map(|&(n, v)| format!("{} param_{}", p.type_of(v).name(), n)).collect();

    let t0 = std::time::Instant::now();
    let s = structure(f);
    if super::action::perf::enabled() {
        super::action::perf::record("print", "structure", t0.elapsed());
    }
    p.gotos = s.gotos.clone();
    p.labels = s.labels.clone();
    p.detect_for_loops(&s, s.root);
    // emit the body first so every local has been named (and recorded in `p.decls`), then assemble
    // signature + declarations + body, as Ghidra does.
    let t0 = std::time::Instant::now();
    let mut body = String::new();
    p.emit_structured(&s, s.root, 1, &mut body);
    if super::action::perf::enabled() {
        super::action::perf::record("print", "emit", t0.elapsed());
    }
    let mut out = String::new();
    // An empty parameter list renders `(void)`, not `()` — Ghidra `PrintC::emitPrototypeInputs`
    // (printc.cc:2227): when `numParams() == 0` it prints the `void` keyword.
    let params = if plist.is_empty() { "void".to_string() } else { plist.join(", ") };
    let _ = writeln!(out, "{ret_ty} {}({})", f.name, params);
    out.push_str("{\n");
    // Ghidra emits local declarations in storage-Address order (`emitScopeVarDecls`); for stack
    // locals that is ascending frame address — most-negative offset first. A stable sort orders the
    // stack locals by offset and leaves register/temp locals (no offset) in first-use order.
    p.decls.sort_by(|a, b| match (a.2, b.2) {
        (Some(oa), Some(ob)) => oa.cmp(&ob),
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    for (name, ty, _) in &p.decls {
        match ty {
            // a recovered stack array declares the element type then the subscript: `T name [N];`
            // (Ghidra `xunknown4 axStack_98 [36]`) — the element type is its inferred type.
            Datatype::Array(elem, count) => {
                let _ = writeln!(out, "  {} {} [{}];", elem.name(), name, count);
            }
            _ => {
                let _ = writeln!(out, "  {} {};", ty.name(), name);
            }
        }
    }
    if !p.decls.is_empty() {
        out.push('\n');
    }
    out.push_str(&body);
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::build::raw_funcdata_flow;
    use crate::decompile::pipeline;
    use crate::sleigh::engine::Spec;
    use crate::{datatest, paths};

    #[test]
    fn emits_c_for_a_straight_line_function() {
        let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
        if !sla.exists() {
            return;
        }
        let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).unwrap();
        let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
        let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_sem.xml")).unwrap();
        let mut f = raw_funcdata_flow(&spec, "func", &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);
        pipeline::decompile(&mut f);

        let c = print_c(&f);
        // well-formed: a signature line, balanced braces, and a return statement
        assert!(c.contains("func("), "has a signature:\n{c}");
        assert_eq!(c.matches('{').count(), c.matches('}').count(), "balanced braces:\n{c}");
        assert!(c.contains("return"), "has a return:\n{c}");
        // the body exactly matches Ghidra (modulo type names)
        assert!(c.contains("return param_1 * 3 + -5 + (param_2 >> 2);"), "body:\n{c}");
    }

    #[test]
    fn emits_structured_control_flow() {
        let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
        if !sla.exists() {
            return;
        }
        let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).unwrap();
        let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
        let dt = datatest::parse_file(&paths::datatests_dir().join("threedim.xml")).unwrap();
        let mut f = raw_funcdata_flow(&spec, "func", &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);
        pipeline::decompile(&mut f);
        let c = print_c(&f);
        // threedim has a loop — the structurer recovers a for/while, well-nested
        assert!(c.contains("while (") || c.contains("for ("), "structured loop expected:\n{c}");
        assert_eq!(c.matches('{').count(), c.matches('}').count(), "balanced braces:\n{c}");
    }
}
