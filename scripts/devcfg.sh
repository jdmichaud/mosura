# devcfg.sh — the shell side of the DEVELOPER CONFIG (`<workspace>/dev-config.toml`; every key and
# its default in `dev-config.example.toml`). Source it from a script in scripts/, then:
#
#   devcfg <section.key> [<default>]        e.g.  GHIDRA_SRC="$(devcfg ghidra_src "$WORKSPACE/ghidra")"
#
# Reads the same TOML subset `crates/mosura/src/devcfg.rs` reads (`[section]`, `key = "string"`,
# `key = true|false`, `#` comments; `[[subject]]` blocks are skipped — use `cargo xtask devcfg` for
# those), expands a leading `~/` to $HOME, and prints the default when the file or the key is absent.
# It replaces the `${GHIDRA_SRC:-…}` / `${MOSURA_*_EXE:-…}` environment parameters the scripts used
# to take (2026-09-05, WP4): one file, read by the tests and the scripts alike.
devcfg() {
  local key="$1" default="${2:-}" file val
  file="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/dev-config.toml"
  val=$(awk -v key="$key" '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    /^[[:space:]]*\[\[/ { section = "[["; next }
    /^[[:space:]]*\[/ { s = $0; sub(/^[[:space:]]*\[/, "", s); sub(/\][[:space:]]*$/, "", s); section = s; next }
    /=/ {
      if (section == "[[") next
      k = $0; sub(/[[:space:]]*=.*$/, "", k); sub(/^[[:space:]]*/, "", k)
      full = (section == "") ? k : section "." k
      if (full == key) {
        v = $0; sub(/^[^=]*=[[:space:]]*/, "", v)
        if (v ~ /^"/) { sub(/^"/, "", v); sub(/".*$/, "", v) }
        print v; exit
      }
    }' "$file" 2>/dev/null || true)
  case "$val" in "~/"*) val="$HOME/${val#~/}" ;; esac
  if [ -n "$val" ]; then printf '%s\n' "$val"; else printf '%s\n' "$default"; fi
}
