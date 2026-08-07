//! The FID hasher — a faithful port of Ghidra's
//! `feature/fid/hash/MessageDigestFidHasher.java`, `FunctionBodyFunctionExtentGenerator.java`,
//! `FidHashQuadImpl.java`, `generic/hash/FNV1a64MessageDigest.java` (+ `AbstractMessageDigest`),
//! and the x86 skipper `Processors/x86/…/feature/fid/hash/X86InstructionSkipper.java`.
//!
//! Given a function body, produce a [`FidHashQuad`]: two 64-bit FNV-1a digests over the
//! instruction bytes with operand bits masked out, plus the code-unit counts that scoring
//! uses. The **full** hash substitutes a placeholder for every scalar and address, so the
//! same code hashes identically wherever it is linked; the **specific** hash folds in real
//! small scalar values, so it can tell near-identical bodies apart.
//!
//! Every constant and every branch here is Ghidra's. See `docs/fid-port-plan.md` §5 Stage 1
//! and §9 for the constants appendix.

use crate::sleigh::{InstructionFingerprint, OpObject};

/// `FNV1a64MessageDigest.FNV_64_OFFSET_BASIS` (`:21`).
pub const FNV_64_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
/// `FNV1a64MessageDigest.FNV_64_PRIME` (`:22`, decimal `1099511628211`).
pub const FNV_64_PRIME: u64 = 0x0000_0100_0000_01b3;

/// `FidService.SHORT_HASH_CODE_UNIT_LENGTH` (`:45`) — a body shorter than this is not
/// hashed at all.
pub const SHORT_HASH_CODE_UNIT_LENGTH: usize = 4;

/// Placeholder mixed in wherever a scalar or address is *present but its value is not used*
/// (`MessageDigestFidHasher.java:149,153,161,169,180,181`).
///
/// **Signedness matters.** In Java `0xfeeddead` is an `int` literal, i.e. `-17958739`, and
/// `long val = 0xfeeddead` widens *that* — it is not `4276215469`. Every arithmetic use below
/// is 32-bit wrapping, exactly as Java's `int` arithmetic.
const SCALAR_PLACEHOLDER: i32 = 0xfeed_deadu32 as i32;

/// Fill byte used when the instruction mask is unavailable and the whole code unit must be
/// made constant (`MessageDigestFidHasher.java:195`).
const MASK_FAILURE_FILL: u8 = 0xa5;

/// `MessageDigestFidHasher.java:105` — `codeUnitIndex >= Short.MAX_VALUE - 1` ends the walk.
const CODE_UNIT_INDEX_LIMIT: i32 = i16::MAX as i32 - 1;

// ---------------------------------------------------------------------------------------
// FNV-1a 64 (generic/hash/FNV1a64MessageDigest.java + AbstractMessageDigest)
// ---------------------------------------------------------------------------------------

/// Ghidra's `FNV1a64MessageDigest`. Despite the `MessageDigest` name this is **not** a
/// cryptographic digest: it is plain FNV-1a with 64-bit wrapping multiplication.
#[derive(Debug, Clone)]
pub struct Fnv1a64 {
    hashvalue: u64,
}

impl Default for Fnv1a64 {
    fn default() -> Self {
        Fnv1a64::new()
    }
}

impl Fnv1a64 {
    pub fn new() -> Fnv1a64 {
        Fnv1a64 { hashvalue: FNV_64_OFFSET_BASIS }
    }

    /// `update(byte)` (`:60-63`).
    pub fn update_byte(&mut self, input: u8) {
        self.hashvalue ^= u64::from(input);
        self.hashvalue = self.hashvalue.wrapping_mul(FNV_64_PRIME);
    }

    /// `update(byte[], int, int)` (`:41-46`).
    pub fn update_bytes(&mut self, input: &[u8]) {
        for &b in input {
            self.update_byte(b);
        }
    }

    /// `AbstractMessageDigest.update(int)` (`:64-69`) — the four bytes fed
    /// **big-endian, most-significant first**. This is the byte order that makes the
    /// operand sub-hashes reproducible; feeding little-endian silently changes every hash.
    pub fn update_i32(&mut self, input: i32) {
        let v = input as u32;
        self.update_byte((v >> 24) as u8);
        self.update_byte((v >> 16) as u8);
        self.update_byte((v >> 8) as u8);
        self.update_byte(v as u8);
    }

    /// `digestLong()` (`:100-104`) — returns the **raw internal state**, then re-initialises.
    /// There is no truncation or finalisation step.
    pub fn digest_long(&mut self) -> u64 {
        let result = self.hashvalue;
        self.reset();
        result
    }

    /// `reset()` (`:107-109`).
    pub fn reset(&mut self) {
        self.hashvalue = FNV_64_OFFSET_BASIS;
    }
}

// ---------------------------------------------------------------------------------------
// FidHashQuad (hash/FidHashQuadImpl.java)
// ---------------------------------------------------------------------------------------

/// The four values that identify a function body (`FidHashQuadImpl.java:21-39`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FidHashQuad {
    /// `codeUnitIndex - callCount`, as a Java `short`.
    pub code_unit_size: i16,
    /// The digest with every operand value masked out and scalars replaced by a placeholder.
    pub full_hash: u64,
    /// How many real scalar values the specific hash folded in, capped at 127 (Java `byte`).
    pub specific_hash_additional_size: i8,
    /// The digest that folds in qualifying real scalar values.
    pub specific_hash: u64,
}

// ---------------------------------------------------------------------------------------
// Instruction skippers (Processors/x86/…/X86InstructionSkipper.java)
// ---------------------------------------------------------------------------------------

/// The multi-byte NOP encodings Visual Studio (and gcc) lay down for dynamic code patching
/// (`X86InstructionSkipper.java:33-71`). A skipped code unit is neither hashed nor counted,
/// so a body padded differently still hashes the same.
///
/// Ghidra's own warning sits on this table: changing it requires incrementing
/// `LibrariesTable.VERSION` and rebuilding every database.
const X86_SKIP_PATTERNS: &[&[u8]] = &[
    &[0x90],
    &[0x8b, 0xc0],
    &[0x8b, 0xc9],
    &[0x8b, 0xd2],
    &[0x8b, 0xdb],
    &[0x8b, 0xe4],
    &[0x8b, 0xed],
    &[0x8b, 0xf6],
    &[0x8b, 0xff],
    &[0x66, 0x90],
    &[0x0f, 0x1f, 0x00],
    &[0x0f, 0x1f, 0x40, 0x00],
    &[0x0f, 0x1f, 0x44, 0x00, 0x00],
    &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00],
    &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00],
    &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
];

/// Which processor's skipper list applies. `FidService.getHasher` (`:145-152`) looks the
/// skippers up by `program.getLanguage().getProcessor()` and uses an **empty list** when the
/// processor has none — so every non-x86 language skips nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skipper {
    /// No skippers registered for this processor (every language except x86).
    None,
    /// `X86InstructionSkipper` — registered for processor `x86` (so x86-16/32/64 alike).
    X86,
}

impl Skipper {
    /// Pick the skipper list the way `FidService` does: by **processor**, which is the first
    /// field of a Ghidra language id (`x86:LE:32:default` → `x86`).
    pub fn for_language(lang_id: &str) -> Skipper {
        match lang_id.split(':').next() {
            Some("x86") => Skipper::X86,
            _ => Skipper::None,
        }
    }

    /// `InstructionSkipper.shouldSkip(buffer, size)` (`X86InstructionSkipper.java:66-77`).
    /// The pattern must match the code unit's **whole length** and every byte exactly.
    pub fn should_skip(self, bytes: &[u8]) -> bool {
        match self {
            Skipper::None => false,
            Skipper::X86 => X86_SKIP_PATTERNS.contains(&bytes),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------------------

/// A range query over the program's relocation table, as
/// `RelocationTable.getRelocations(AddressSet)` provides
/// (`MessageDigestFidHasher.java:74`). Both bounds are **inclusive**.
pub trait RelocationQuery {
    fn any_in_range(&self, min_offset: u64, max_offset: u64) -> bool;
}

/// A program with no relocations — the common case for the statically-linked libraries FID
/// exists to identify, and the correct behaviour for a loader that populates no table.
pub struct NoRelocations;

impl RelocationQuery for NoRelocations {
    fn any_in_range(&self, _min_offset: u64, _max_offset: u64) -> bool {
        false
    }
}

/// One code unit of the extent, as the hasher consumes it.
///
/// `FunctionBodyFunctionExtentGenerator` (`:45-48`) yields `listing.getInstructions(body, true)`
/// — **instructions only**, ascending, taken from the function's recorded body (not re-derived
/// by following flow). Data units therefore never appear in practice, but Ghidra's hasher still
/// branches on `codeUnit instanceof Instruction`, so the branch is preserved here via
/// [`Self::fingerprint`] being `None`.
pub struct CodeUnitInput<'a> {
    /// `codeUnit.getMinAddress()` — offset within its space.
    pub min_address: u64,
    /// `codeUnit.getMaxAddress()` — **inclusive**, i.e. `min_address + length - 1`.
    pub max_address: u64,
    /// The raw bytes read from memory (`memory.getBytes`, `codeUnit.getLength()` of them).
    pub bytes: &'a [u8],
    /// The disassembly-level ingredients, or `None` for a code unit that is not an
    /// instruction — or whose prototype could not yield a mask, which is Ghidra's
    /// `NullPointerException` path (`:190-197`, fill the unit with `0xa5`).
    pub fingerprint: Option<&'a InstructionFingerprint>,
}

// ---------------------------------------------------------------------------------------
// The hasher (hash/MessageDigestFidHasher.java)
// ---------------------------------------------------------------------------------------

/// `MessageDigestFidHasher`.
#[derive(Debug, Clone)]
pub struct FidHasher {
    short_code_unit_limit: usize,
    skipper: Skipper,
}

impl FidHasher {
    /// Build the hasher the way `FidService.getHasher` does: the short-hash floor plus the
    /// skipper list for the program's processor.
    pub fn new(skipper: Skipper) -> FidHasher {
        FidHasher { short_code_unit_limit: SHORT_HASH_CODE_UNIT_LENGTH, skipper }
    }

    /// `hash(Function)` (`:82-219`).
    ///
    /// `extent` is the function body's code units in ascending address order. Returns `None`
    /// exactly where Ghidra returns `null`: a body below the short-hash floor, either before
    /// the walk (on the raw extent size) or after it (on the post-skip count).
    pub fn hash(
        &self,
        extent: &[CodeUnitInput<'_>],
        relocations: &dyn RelocationQuery,
    ) -> Option<FidHashQuad> {
        // `:86-88` — not enough code units.
        if extent.len() < self.short_code_unit_limit {
            return None;
        }

        let mut full_digest = Fnv1a64::new();
        let mut specific_digest = Fnv1a64::new();

        let mut specific_count: i32 = 0;
        let mut call_count: i32 = 0;
        // `:98` — starts at -1 and is pre-incremented, so it indexes the current unit.
        let mut code_unit_index: i32 = -1;

        // Ghidra hashes out of a scratch buffer it masks in place; we mask a copy of the
        // unit's bytes, which is the same thing without the shared 110000-byte buffer.
        let mut buffer: Vec<u8> = Vec::new();

        for unit in extent {
            code_unit_index += 1;
            // `:105-107`
            if code_unit_index >= CODE_UNIT_INDEX_LIMIT {
                break;
            }

            let actual_number_read = unit.bytes.len();
            buffer.clear();
            buffer.extend_from_slice(unit.bytes);

            if let Some(fp) = unit.fingerprint {
                // `:114-124` — a skipped unit is not counted and not hashed.
                if self.skipper.should_skip(&buffer[..actual_number_read]) {
                    code_unit_index -= 1;
                    continue;
                }

                // `:126-128`
                if fp.is_call {
                    call_count += 1;
                }

                // `:134-186` — one sub-hash per operand, mixed into both digests.
                for (ii, operand) in fp.operands.iter().enumerate() {
                    // `:135-138` — a null operand mask contributes nothing at all.
                    let Some(_operand_mask) = operand.value_mask.as_deref() else { continue };
                    let operand_mask = _operand_mask;

                    // `:140-141` — the seed makes the sub-hash operand-order dependent while
                    // the opObjects within one operand combine commutatively.
                    let mut specific_update: i32 = (ii as i32 + 1).wrapping_mul(7777);
                    let mut full_update: i32 = specific_update;

                    for obj in &operand.objects {
                        match obj {
                            OpObject::Scalar { signed_value } => {
                                // `:143-170`. Note the comparisons below are on the full
                                // 64-bit value; only the mix truncates to `int`.
                                let mut val: i64 = *signed_value;
                                if has_relocation(
                                    operand_mask,
                                    unit.min_address,
                                    unit.max_address,
                                    relocations,
                                ) {
                                    // Part of an address the loader will relocate — the value
                                    // is not ours to hash.
                                    val = i64::from(SCALAR_PLACEHOLDER);
                                } else if operand.is_scalar {
                                    // The whole operand is the scalar.
                                    if operand.is_address {
                                        val = i64::from(SCALAR_PLACEHOLDER);
                                    } else {
                                        specific_count += 1;
                                    }
                                } else {
                                    // Only part of the operand — keep it only if it is small.
                                    if val >= 256 || val <= -256 {
                                        val = i64::from(SCALAR_PLACEHOLDER);
                                    } else {
                                        specific_count += 1;
                                    }
                                }
                                // `:168-169`
                                specific_update = specific_update.wrapping_add(
                                    (val as i32).wrapping_add(1234567).wrapping_mul(67999),
                                );
                                full_update = full_update.wrapping_add(SCALAR_PLACEHOLDER);
                            }
                            OpObject::Register { space_offset } => {
                                // `:171-177` — registers go into both digests, with a
                                // different mixing function so a register cannot collide
                                // with a scalar of the same numeric value.
                                let val = (*space_offset as i32)
                                    .wrapping_add(7654321)
                                    .wrapping_mul(98777);
                                full_update = full_update.wrapping_add(val);
                                specific_update = specific_update.wrapping_add(val);
                            }
                            OpObject::Address { .. } => {
                                // `:178-182` — the address value is never hashed, only its
                                // presence.
                                specific_update = specific_update.wrapping_add(
                                    SCALAR_PLACEHOLDER.wrapping_add(1234567).wrapping_mul(67999),
                                );
                                full_update = full_update.wrapping_add(SCALAR_PLACEHOLDER);
                            }
                        }
                    }

                    // `:184-185`
                    full_digest.update_i32(full_update);
                    specific_digest.update_i32(specific_update);
                }

                // `:187-201` — zero the operand bits so only opcode/addressing-mode structure
                // reaches the digests. `applyMask` touches exactly `mask.length` bytes and
                // leaves any tail untouched (`MaskImpl.java:93-102`).
                apply_mask(&mut buffer, &fp.instruction_mask);
            } else if unit.is_instruction_without_mask() {
                // `:190-197` — the prototype could not tell us the mask, so the whole code
                // unit is made constant rather than hashed unreliably.
                buffer[..actual_number_read].fill(MASK_FAILURE_FILL);
            }

            // `:203-204` — every code unit reaches both digests, instruction or not.
            full_digest.update_bytes(&buffer[..actual_number_read]);
            specific_digest.update_bytes(&buffer[..actual_number_read]);
        }

        // `:207-212` — the index becomes a length.
        code_unit_index += 1;
        if (code_unit_index as usize) < self.short_code_unit_limit {
            return None;
        }

        // `:214-218`
        let code_unit_size = (code_unit_index - call_count) as i16;
        let specific_hash_additional_size = specific_count.min(i8::MAX as i32) as i8;

        Some(FidHashQuad {
            code_unit_size,
            full_hash: full_digest.digest_long(),
            specific_hash_additional_size,
            specific_hash: specific_digest.digest_long(),
        })
    }
}

impl CodeUnitInput<'_> {
    /// Whether this unit is an instruction whose mask could not be derived — Ghidra's
    /// `NullPointerException` branch.
    ///
    /// mosura's accessor cannot currently produce this: `disassemble_fingerprint` either
    /// resolves an instruction (and always returns a mask of its byte length) or stops. The
    /// branch is kept because it is Ghidra's, and an adapter that cannot fingerprint an
    /// instruction the listing already recorded should route here rather than treat the
    /// bytes as data.
    fn is_instruction_without_mask(&self) -> bool {
        false
    }
}

/// `MaskImpl.applyMask(cde, cdeOffset, results, resultsOffset)` (`:93-102`) — AND exactly
/// `mask.len()` bytes; anything past the mask is left as-is.
fn apply_mask(buffer: &mut [u8], mask: &[u8]) {
    for (b, m) in buffer.iter_mut().zip(mask) {
        *b &= *m;
    }
}

/// `MessageDigestFidHasher.hasRelocation` (`:58-80`).
///
/// Narrows the code unit's address range to the span of the operand mask's **non-zero**
/// bytes — the bytes this operand's value actually occupies — then asks whether any
/// relocation lands in it. An all-zero mask narrows the range away entirely (min passes max),
/// which correctly reports no relocation.
fn has_relocation(
    mask: &[u8],
    min_address: u64,
    max_address: u64,
    relocations: &dyn RelocationQuery,
) -> bool {
    let mut min = min_address;
    let mut max = max_address;

    for &b in mask {
        if b != 0 {
            break;
        }
        min = min.wrapping_add(1);
    }
    for &b in mask.iter().rev() {
        if b != 0 {
            break;
        }
        max = max.wrapping_sub(1);
    }

    if min <= max {
        relocations.any_in_range(min, max)
    } else {
        false
    }
}
