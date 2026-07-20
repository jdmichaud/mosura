#!/usr/bin/env bash
#
# setup-ghidra.sh — fetch, pin, and prepare mosura's ONE mandatory build/test dependency:
# the Ghidra processor source, pinned to the exact commit the port targets.
#
# `cargo test` needs two things from Ghidra and nothing else (docs/dependencies.md, BUILD/TEST
# tier): (1) the pinned processor source (.slaspec/.pspec/.cspec/.ldefs/.opinion + the
# decompiler datatests), and (2) the compiled .sla — a build artifact a fresh Ghidra clone does
# NOT ship (git-ignored). This script produces both from nothing:
#
#   1. clones github.com/NationalSecurityAgency/ghidra at the pinned tag (shallow) into
#      $GHIDRA_SRC, then VERIFIES the checkout is exactly the pinned commit (the checksum);
#   2. compiles every processor .slaspec -> .sla once (delegates to setup-oracle.sh --sla-only).
#
# Why a fetch script and not a git submodule: the checkout is a sibling *outside* this repo
# (paths.rs default `<workspace>/../ghidra`), Ghidra's full history would bloat every clone,
# and a fresh source clone needs the post-fetch sleigh compile a submodule can't provide anyway.
#
# Idempotent: an existing checkout already at the pin is reused (never re-cloned or clobbered).
#
# Usage:  scripts/setup-ghidra.sh [--verify-only] [--no-sla]
#           --verify-only   only check an existing $GHIDRA_SRC is at the pin (no clone/compile)
#           --no-sla        fetch + verify the source, but skip the .sla compile
# Env:    GHIDRA_SRC   where the pinned checkout lives (default: <workspace>/../ghidra),
#                      the same override paths.rs and setup-oracle.sh honor.
#
set -euo pipefail

# --- the pin (keep in lockstep with docs/dependencies.md + setup-oracle.sh) ---
GHIDRA_TAG="Ghidra_12.0.3_build"
GHIDRA_COMMIT="09f14c92d3da6e5d5f6b7dea115409719db3cce1"
GHIDRA_REPO="https://github.com/NationalSecurityAgency/ghidra.git"

# --- resolve paths relative to this script (portable; no absolute paths) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOSURA_DIR="$(dirname "$SCRIPT_DIR")"
WORKSPACE="$(dirname "$MOSURA_DIR")"
GHIDRA_SRC="${GHIDRA_SRC:-$WORKSPACE/ghidra}"

log() { printf '\033[1;34m[ghidra]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[ghidra:error]\033[0m %s\n' "$*" >&2; }
die() { err "$*"; exit 1; }

VERIFY_ONLY=0; NO_SLA=0
for a in "$@"; do
  case "$a" in
    --verify-only) VERIFY_ONLY=1 ;;
    --no-sla)      NO_SLA=1 ;;
    -h|--help)     grep '^#' "$0" | sed 's/^#\? \?//'; exit 0 ;;
    *)             die "unknown arg: $a (try --help)" ;;
  esac
done

# HEAD commit of the checkout (empty if not a git repo).
head_commit() { git -C "$GHIDRA_SRC" rev-parse HEAD 2>/dev/null || true; }

verify_pin() {
  # The commit id IS the checksum: a git commit hash covers its whole tree + history, so
  # HEAD == $GHIDRA_COMMIT proves the source is byte-for-byte the pinned Ghidra.
  local cpp="$GHIDRA_SRC/Ghidra/Features/Decompiler/src/decompile/cpp"
  [ -d "$cpp" ] || die "no Ghidra source at $GHIDRA_SRC (expected $cpp). Run without --verify-only to fetch it."
  if [ -e "$GHIDRA_SRC/.git" ]; then
    local h; h="$(head_commit)"
    if [ "$h" != "$GHIDRA_COMMIT" ]; then
      err "GHIDRA_SRC is at commit ${h:-<none>}, expected the pin $GHIDRA_COMMIT ($GHIDRA_TAG)."
      err "Fix:  git -C \"$GHIDRA_SRC\" fetch --depth 1 origin $GHIDRA_TAG && git -C \"$GHIDRA_SRC\" checkout $GHIDRA_COMMIT"
      die "Ghidra checkout does not match the pin"
    fi
    log "pin OK: $GHIDRA_TAG @ $GHIDRA_COMMIT ($GHIDRA_SRC)"
  else
    log "note: $GHIDRA_SRC is present but not a git checkout — cannot verify the $GHIDRA_COMMIT pin"
  fi
}

fetch() {
  if [ -e "$GHIDRA_SRC" ]; then
    # Already present (dir or symlink) — reuse; a pin mismatch is a hard error, never a
    # silent re-clone over the user's tree.
    log "reusing existing checkout at $GHIDRA_SRC"
    verify_pin
    return 0
  fi
  command -v git >/dev/null || die "git not found (needed to fetch the pinned Ghidra source)"
  log "cloning $GHIDRA_REPO @ $GHIDRA_TAG (shallow) -> $GHIDRA_SRC"
  git clone --depth 1 --branch "$GHIDRA_TAG" "$GHIDRA_REPO" "$GHIDRA_SRC"
  local h; h="$(head_commit)"
  [ "$h" = "$GHIDRA_COMMIT" ] \
    || die "cloned $GHIDRA_TAG resolved to $h, not the pinned $GHIDRA_COMMIT — refusing (supply-chain check)"
  log "fetched + verified: $GHIDRA_TAG @ $GHIDRA_COMMIT"
}

compile_sla() {
  # A fresh Ghidra clone ships no compiled .sla (git-ignored). Build sleigh_opt + compile the
  # specs — the minimal BUILD/TEST step (setup-oracle.sh owns the compile logic).
  if find "$GHIDRA_SRC/Ghidra/Processors" -name '*.sla' -print -quit 2>/dev/null | grep -q .; then
    log ".sla already present — skipping compile (delete them + re-run to force)"
    return 0
  fi
  log "compiling SLEIGH specs (.slaspec -> .sla), one-time"
  GHIDRA_SRC="$GHIDRA_SRC" "$SCRIPT_DIR/setup-oracle.sh" --sla-only
}

if [ "$VERIFY_ONLY" -eq 1 ]; then verify_pin; exit 0; fi
fetch
if [ "$NO_SLA" -eq 1 ]; then
  log "done (--no-sla): source pinned; run setup-oracle.sh to compile .sla"
  exit 0
fi
compile_sla
log "done — pinned Ghidra ready at $GHIDRA_SRC; 'cargo test' is now self-contained"
