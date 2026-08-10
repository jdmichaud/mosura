---
name: pspec-key-differs-from-java-field
description: "Ghidra's pspec property STRING never matches the Java field or variable name — grepping the code name finds nothing and reads as 'no language sets it'."
metadata:
  type: reference
---

Ghidra language properties have **three different names** for the same thing, and only the
third one appears in a `.pspec`:

| layer | name |
|---|---|
| analyzer field | `assumeContiguousFunctions` |
| key constant | `GhidraLanguagePropertyKeys.ENABLE_ASSUME_CONTIGUOUS_FUNCTIONS_ONLY` |
| **the actual pspec string** | **`enableContiguousFunctionsOnly`** |

Grepping the pspec tree for the field or the constant returns **nothing**, which reads as
"no language overrides this" — a false negative. Always resolve the constant to its string
first (`GhidraLanguagePropertyKeys.java`), then grep for the string.

## The worked example (2026-08-10, the `1d74e` regression)

The agent suspected `assume_contiguous_functions: true` was an unfaithful hardcode of the
[[hardcoded-x86-64-vs-cspec-class]] shape, recalling Ghidra's default as `false`.
`SharedReturnAnalyzer.java` settles both halves:

```java
:58  OPTION_DEFAULT_ASSUME_CONTIGUOUS_FUNCTIONS_ENABLED = true;   // default IS true
:95  // If the language (in the .pspec file) overrides this setting, use that value
:96  boolean contiguousFunctionsEnabled = language.getPropertyAsBoolean(
:97      GhidraLanguagePropertyKeys.ENABLE_ASSUME_CONTIGUOUS_FUNCTIONS_ONLY, assumeContiguousFunctions);
```

Resolved to the string, only **ARM** pspecs set it (`ARMt`, `ARM_v45`, `ARMCortex`, …).
**x86 does not**, and no vendored pspec does. So `true` is correct for x86 by two independent
routes, and the flag was **not** the regression's cause.

**The reusable half is the shape of the answer, not the value.** A hardcode can be
simultaneously (a) *correct today* for the one language under test and (b) *unfaithful in
form* — it would be wrong the instant anyone analyses ARM. Recording it as "fine" loses the
second half; recording it as "the bug" burns the diagnosis on the wrong target. Log it as a
latent portability defect and keep hunting the real mechanism —
see [[gate-what-you-measured-not-what-you-guessed]].
