#!/usr/bin/env bash
# Build the ORACLE ROOT: the directory `oracle/capture` and `decomp_dbg` are pointed at
# (SLEIGHHOME / GHIDRA_SRC) so that Ghidra decompiles WAR2 under *mosura's own* Watcom compiler
# spec — the same file the decompiler reads.
#
# WHY THIS EXISTS (2026-08-31). An oracle capture takes its calling convention from the compiler
# spec the ROOT resolves, and a compiler id that the root's `.ldefs` does not register falls back
# to the language default SILENTLY, with no error:
#
#   root whose Processors are third_party/ (no watcom entry):  arch=…:watcom -> __fastcall  (x86win!)
#   root whose Processors are a dist that registers watcom:    arch=…:watcom -> no keyword   (watcall)
#
# Every WAR2 capture taken before this script existed used the first kind of root, so Ghidra was
# decompiling under Visual Studio's convention while mosura used watcall; four investigative
# findings had to be withdrawn. This root removes the failure class rather than detecting it: the
# spec it installs IS `specs/x86-32-watcom.cspec`, so the oracle and the decompiler provably read
# one file, and nothing depends on a Ghidra distribution happening to carry a watcom spec.
#
# usage: scripts/make-oracle-root.sh [<root-dir>]     (default: <workspace>/build/oracle-root)
#        PROCESSORS=<dir>  override the Processors tree (default: third_party/ghidra/Processors)
#
# Then: GHIDRA_SRC=<root-dir> (oracle/capture, war2_oracle_sweep) or SLEIGHHOME=<root-dir> (decomp_dbg).
#
# CALIBRATION, which callers must still perform (a root can be right and the CACHE wrong): a watcom
# capture prints NO convention keyword on a default-model function. `__fastcall` or `__regparm3`
# means the wrong spec was resolved — and note `build/oracle-cache` is keyed on the resolved root,
# so a root change invalidates it; entries written before that key existed must be cleared by hand.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
root=${1:-$here/build/oracle-root}
procs=${PROCESSORS:-$here/third_party/ghidra/Processors}
spec=$here/specs/x86-32-watcom.cspec

[ -d "$procs" ] || { echo "no Processors tree at $procs" >&2; exit 1; }
[ -f "$spec" ]  || { echo "no watcom cspec at $spec" >&2; exit 1; }
[ -f "$procs/x86/data/languages/x86.sla" ] || {
  echo "the Processors tree has no compiled x86.sla — sleigh must be built first" >&2; exit 1; }

rm -rf "$root"
mkdir -p "$root/Ghidra/Processors"
# every processor but x86 is the vendored tree verbatim
for p in "$procs"/*; do
  name=$(basename "$p")
  [ "$name" = x86 ] && continue
  ln -s "$p" "$root/Ghidra/Processors/$name"
done
# x86: everything verbatim except the two files that decide which spec `:watcom` resolves to
mkdir -p "$root/Ghidra/Processors/x86/data/languages"
for d in "$procs"/x86/*; do
  [ "$(basename "$d")" = data ] && continue
  ln -s "$d" "$root/Ghidra/Processors/x86/$(basename "$d")"
done
for d in "$procs"/x86/data/*; do
  [ "$(basename "$d")" = languages ] && continue
  ln -s "$d" "$root/Ghidra/Processors/x86/data/$(basename "$d")"
done
for f in "$procs"/x86/data/languages/*; do
  case $(basename "$f") in x86.ldefs|x86-32-watcom.cspec) continue;; esac
  ln -s "$f" "$root/Ghidra/Processors/x86/data/languages/$(basename "$f")"
done
# OUR spec, installed (not linked) so the root is self-describing if the worktree moves.
# It is transliterated to ASCII on the way in: Ghidra's own XML scanner cannot read a non-ASCII
# byte, INCLUDING INSIDE A COMMENT, on any platform where `char` is signed. getxmlchar does
# `char c; ... lookahead[pos] = c;` into an int4 (xml.y:58,70-81), so a byte >= 0x80 sign-extends
# negative, isChar's `val>=0x20` test fails (xml.y:415-417), and scanComment breaks out
# mid-comment (xml.y:341-353) -- the only symptom being "XML error ... syntax error". The class
# doc at xml.y:35 claims extended UTF-8 is legal in comments; the implementation disagrees.
# So the prose survives, the bytes get folded, and a character with no mapping is a hard error
# rather than a silent drop.
python3 - "$spec" "$root/Ghidra/Processors/x86/data/languages/x86-32-watcom.cspec" <<'PYSPEC'
import re, sys
s = open(sys.argv[1], encoding='utf-8').read()
# NB: an em dash must NOT become "--", which is illegal inside an XML comment.
for k, v in {'—': ' - ', '…': '...', '⚠': '(!)', '️': ''}.items():
    s = s.replace(k, v)
bad = sorted(set(c for c in s if ord(c) > 127))
if bad:
    sys.exit('cspec carries non-ASCII characters with no transliteration: %r -- '
             "Ghidra's XML scanner cannot read them; add a mapping here" % bad)
for m in re.finditer(r'<!--(.*?)-->', s, flags=re.S):
    if '--' in m.group(1):
        sys.exit('transliteration produced "--" inside an XML comment (illegal XML): %r'
                 % m.group(1)[:60])
open(sys.argv[2], 'w').write(s)
PYSPEC
# the .ldefs with a watcom <compiler> registered inside x86:LE:32:default
python3 - "$procs/x86/data/languages/x86.ldefs" "$root/Ghidra/Processors/x86/data/languages/x86.ldefs" <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src).read()
entry = '    <compiler name="watcom" spec="x86-32-watcom.cspec" id="watcom"/>\n'
def add(m):
    body = m.group(0)
    if 'id="watcom"' in body:
        return body
    return body.replace('</language>', entry + '  </language>')
out = re.sub(r'<language[^>]*id="x86:LE:32:default".*?</language>', add, s, flags=re.S)
if 'id="watcom"' not in out:
    sys.exit('could not register the watcom compiler in x86.ldefs')
open(dst, 'w').write(out)
PY
echo "oracle root: $root"
echo "  Processors: $procs"
echo "  watcom spec: $spec (copied in)"
echo "  use: GHIDRA_SRC=$root  (or SLEIGHHOME=$root for decomp_dbg)"
