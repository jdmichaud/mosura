//! Decompiler D5: a structural similarity metric between two C functions — mosura's
//! output and Ghidra's (captured via `oracle/capture --c`).
//!
//! An exact AST match is the wrong tool: the two decompilers make different but
//! semantically-equivalent choices (`a + 0xfffffffb` vs `a - 5`, `for` vs `while`,
//! `(int4)x` casts, placeholder `xunknown4` vs `int` types, `xStack_c` vs `var_0`
//! names). So we normalize away the cosmetic axes — types, identifiers, numeric
//! literals, and grouping/punctuation — and compare the resulting token skeletons
//! with a longest-common-subsequence ratio. 1.0 means structurally identical modulo
//! names/types; high values mean the recovered control flow and operators agree.

/// C type keywords (incl. Ghidra's placeholder/undefined families) → erased to `T`.
const TYPES: &[&str] = &[
    "int", "uint", "long", "ulong", "char", "uchar", "short", "ushort", "bool", "void", "float", "double", "byte",
    "int1", "int2", "int4", "int8", "uint1", "uint2", "uint4", "uint8", "undefined", "undefined1", "undefined2",
    "undefined4", "undefined8", "xunknown1", "xunknown2", "xunknown4", "xunknown8", "code", "unkbyte", "unkuint",
];

/// Control-flow keywords kept verbatim (the structural skeleton).
const KEYWORDS: &[&str] = &["return", "while", "for", "if", "else", "do", "switch", "case", "break", "goto", "default"];

/// Normalize a C function into a token skeleton: types → `T`, identifiers → `ID`,
/// numbers → `N`, control keywords kept, operators kept; grouping punctuation
/// (`(){};,`) and the leading `*`/`&` of a declaration are dropped as noise.
pub fn normalize(c: &str) -> Vec<String> {
    let mut toks = Vec::new();
    let bytes: Vec<char> = c.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        let ch = bytes[i];
        if ch.is_whitespace() {
            i += 1;
        } else if ch.is_alphabetic() || ch == '_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_alphanumeric() || bytes[i] == '_') {
                i += 1;
            }
            let word: String = bytes[start..i].iter().collect();
            if TYPES.contains(&word.as_str()) {
                toks.push("T".to_string());
            } else if KEYWORDS.contains(&word.as_str()) {
                toks.push(word);
            } else {
                toks.push("ID".to_string());
            }
        } else if ch.is_ascii_digit() {
            while i < bytes.len() && (bytes[i].is_alphanumeric() || bytes[i] == 'x') {
                i += 1;
            }
            toks.push("N".to_string());
        } else if "(){};,".contains(ch) {
            i += 1; // grouping noise
        } else {
            // an operator run (==, <=, >>, etc.) or a single-char operator
            let start = i;
            while i < bytes.len() && "+-*/%<>=!&|^~?:.".contains(bytes[i]) {
                i += 1;
            }
            if i > start {
                toks.push(bytes[start..i].iter().collect());
            } else {
                i += 1;
            }
        }
    }
    toks
}

/// Length of the longest common subsequence of two token slices.
fn lcs(a: &[String], b: &[String]) -> usize {
    let mut prev = vec![0usize; b.len() + 1];
    let mut cur = vec![0usize; b.len() + 1];
    for x in a {
        for (j, y) in b.iter().enumerate() {
            cur[j + 1] = if x == y { prev[j] + 1 } else { cur[j].max(prev[j + 1]) };
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Structural similarity of two C functions in `[0, 1]`: `2·LCS / (|a| + |b|)` over
/// the normalized token skeletons. 1.0 = identical modulo names/types/grouping.
pub fn similarity(a: &str, b: &str) -> f64 {
    let (ta, tb) = (normalize(a), normalize(b));
    if ta.is_empty() && tb.is_empty() {
        return 1.0;
    }
    2.0 * lcs(&ta, &tb) as f64 / (ta.len() + tb.len()) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_modulo_names_and_types() {
        let a = "int func(int param_1) { return param_1 + 1; }";
        let b = "xunknown4 func(xunknown4 iVar1) { return iVar1 + 1; }";
        assert_eq!(similarity(a, b), 1.0);
    }

    #[test]
    fn structurally_different_scores_lower() {
        let a = "int f(int x) { return x + 1; }";
        let b = "int f(int x) { while (x < 10) { x = x + 1; } return x; }";
        assert!(similarity(a, b) < 0.7, "different structure must score lower");
    }
}
