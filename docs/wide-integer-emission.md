# Narrow consumers of wide integer arithmetic

The reference printer retains Ghidra's integer extension rules. In particular, a four-byte
pointer does not imply that eight-byte arithmetic can be replaced by four-byte arithmetic.
The mapped C++ oracle keeps the casts on both x86 modes for `widened_product.S` and
`widened_dividend.S`. The former caught missing casts after its IR value checks passed;
the latter catches the resulting compiler representation gap.

The `wide-int` emission axis defaults to `ghidra`. The Watcom-32 output configuration
selects `split32`, whose primitives are defined in that compiler's TU prelude. Input compiler
inference and pointer width do not select the arm. The IR is unchanged. Switching the arm
off restores the reference expressions, including their unrepresentable widths.

The arm answers the existing `ValueSite::OpRoot` seam for narrow SUBPIECE consumers of
implicit arithmetic. It follows same-width casts/copies and constant logical right shifts.
Supported roots are a product of equally extended words, or unsigned division/remainder
by a zero-extended word. A dividend may be a complete unsigned product, a pair of words,
a constant, or a zero-extended word shifted left by one word. Recovery checks that each
required arithmetic operation exists with an eight-byte result in the native instruction's
p-code at the corresponding IR provenance address. No address whitelist or mnemonic guess
is involved. Explicit wide objects, mixed signed/unsigned variable products and other
unhandled arithmetic remain visible to the representability contract.

The primitives preserve the complete arithmetic:

- A product slice selects the low word after a logical shift of the full signed or unsigned
  product. Counts are between zero and 63. A low product alone can use ordinary unsigned
  multiplication modulo one word.
- For a dividend `high * 2^32 + low` and nonzero divisor `d`, first divide `high` by `d`.
  Then divide `(high % d) * 2^32 + low` by `d`. The second quotient is the low word of the
  full quotient, and its remainder is the full remainder. Its high input is less than `d`,
  so the second native division cannot overflow. This remains correct when a single native
  division would overflow its word-sized quotient.
- A product quotient/remainder first computes both product words and uses that same division
  construction. Every C argument is evaluated once. The inline sequences balance their stack
  and declare their EAX/EDX clobbers; the count/divisor register is preserved.

GCC ground-truth emission uses independent native-wide expressions for the primitive meanings.
The Watcom implementation uses inline register primitives, so no floating-point stand-in or
impossible integer typedef is introduced. The existing incomplete-width tripwire remains.

The two source-built regressions pass 196 product and 1,776 dividend
IR value cases across the two x86 modes. The dividend emitter gate covers all six functions
on i386, including witness absence and arm disablement. A separate development execution
check of the Watcom-compiled primitive wrappers passes 19,736 cases: both product signs,
all shift counts, boundary/random words, and unsigned divisions whose full quotient exceeds
one word. The division source MVE checks the native instruction's non-faulting domain;
the primitive check additionally verifies truncation beyond that domain. These checks do not
claim that the emitter models native divide faults or arbitrary wide arithmetic. The eight
emitted source functions, compiled under Watcom with the production prelude, pass 14,257 further
native execution cases. The opt-in GCC source-value gate passes 15,420 cases; run it with
`cargo test -p mosura-core --test ground_truth_parity widened_word_emission -- --ignored`.

The all-function rounds `wide-words-all` and `wide-words-repeat` both cover 751 functions and
pass all eight gates. All 19 EXACT functions remain unchanged; the verdict comparison has
eight COMPILE_FAIL-to-MISMATCH changes and no new failures. The final census is 19 EXACT,
one SAME_CODE, 16 SAME_SHAPE, 556 MISMATCH and 159 COMPILE_FAIL. The repeat reuses all
751 compiled units with unchanged verdicts. The 12 failures first exposed by faithful casts
are resolved. The arm oracle preserves all 14 plain-passing programs in its 28-program
population; the remaining baseline failures are not claimed as passing.

Final workspace: `cargo test --workspace --no-fail-fast` exits zero with 1321/1321 tests
passing and 24 ignored. IR parity is 9/9, ground truth 43/43 (two ignored), disassembly
golden 1/1, and every repository guard passes. The final guard-registration update changes
0/751 emitted TUs; `wide-words-final` passes all eight gates with 751/751 cached units.
