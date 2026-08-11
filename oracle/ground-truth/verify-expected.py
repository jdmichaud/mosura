#!/usr/bin/env python3
"""Prove each `expected/*.c` really recompiles to the bytes of the function it claims.

THE POINT, in the byte-exact campaign: from the BYTES, the decompiler must produce source that —
recompiled with the right compiler and flags — reproduces those bytes. The compiler cannot live
in the test chain, so it lives HERE: this establishes ONCE, at build time, that a reference
source is byte-faithful. `ground_truth_parity` then only has to compare mosura's output against
that reference, and needs no toolchain.

A reference that stops matching its function fails the build, rather than quietly degrading into
a statement of intent.

Each expected/<prog>.<symbol>.c carries its own recipe in comment lines:
    func:  <symbol in the committed binary>      (defaults to the filename's <symbol>)
    flags: <wcc386 flags, minus -bt/-fo>
    decl:  <a declaration the snippet needs>     (repeatable)

Comparison is modulo relocated operands: the reference is an unlinked object, so a call or data
displacement reads zero where the binary holds a resolved address. Those fields are masked on
both sides — the same argument that makes RELOC_EXACT legitimate in the survey.
"""
import os, re, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, "/home/jd/projects/warcraft2-re/tools/wardiff")
WAT = os.environ.get("GT_WATCOM", os.path.expanduser("~/tools/open-watcom"))
PRE = ("typedef int code(); typedef unsigned int uint4; typedef unsigned int xunknown4; "
       "typedef unsigned char uint1; typedef int int4;")


def directives(text):
    out = {"decl": []}
    for k in ("func", "flags"):
        m = re.search(rf"^\s*\*\s*{k}:\s*(.+)$", text, re.M)
        if m:
            out[k] = m.group(1).strip()
    out["decl"] = [m.group(1).strip() for m in re.finditer(r"^\s*\*\s*decl:\s*(.+)$", text, re.M)]
    return out


def mask(h):
    """Zero out relocated 4-byte operands so an unlinked object compares to a linked image."""
    h = re.sub(r"(?<=ff15)[0-9a-f]{8}", "R" * 8, h)
    h = re.sub(r"(?<=e8)[0-9a-f]{8}", "R" * 8, h)
    h = re.sub(r"(?<=a1)[0-9a-f]{8}", "R" * 8, h)
    # `mov <reg>,DWORD PTR [abs32]` — the modrm form of the `a1` accumulator shortcut, emitted
    # whenever the destination is not EAX (8b1d = EBX). Its displacement is a relocation exactly as
    # a1's is, so it masks on the same argument.
    h = re.sub(r"(?<=8b1d)[0-9a-f]{8}", "R" * 8, h)
    return h


def ref_bytes(path, decls, flags):
    import wardiff
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "e.c")
        with open(src, "w") as f:
            f.write(PRE + "\n" + "\n".join(decls) + "\n" + open(path).read())
        env = dict(os.environ, WATCOM=WAT, INCLUDE=f"{WAT}/lh", PATH=f"{WAT}/binl:" + os.environ["PATH"])
        subprocess.run(["wcc386", "e.c", "-bt=linux", *flags.split(), "-fo=e.obj"],
                       cwd=td, env=env, capture_output=True)
        obj = os.path.join(td, "e.obj")
        if not os.path.exists(obj):
            return None
        o = wardiff.OMFObject(obj)
        pubs = [p for p in o.publics if not p.name.startswith("_")]
        if not pubs:
            return None
        p = pubs[0]
        b = bytes(o.segments[p.seg_idx - 1].bytes[p.offset:])
        while b and b[-1] in (0, 0x90, 0xCC):
            b = b[:-1]
        return b.hex()


def bin_bytes(prog, sym):
    truth = open(f"{HERE}/{prog}.watcom-x86-32.truth").read()
    addr = [l.split()[1] for l in truth.splitlines()
            if l.startswith("func ") and sym in l.split()[2:]]
    if not addr:
        return None
    a = int(addr[0], 16)
    out = subprocess.run(["objdump", "-d", "--start-address", hex(a), "-M", "intel",
                          f"{HERE}/{prog}.watcom-x86-32"], capture_output=True, text=True).stdout
    by = []
    for l in out.splitlines():
        if ":\t" not in l:
            continue
        parts = l.split("\t")
        if len(parts) < 3:
            continue
        by.append(parts[1].strip().replace(" ", ""))
        if parts[2].strip().startswith("ret"):
            break
    return "".join(by) if by else None


def main():
    d = f"{HERE}/expected"
    if not os.path.isdir(d):
        return 0
    if not os.path.exists(f"{WAT}/binl/wcc386"):
        print("skip verify-expected: wcc386 absent")
        return 0
    bad = 0
    for name in sorted(os.listdir(d)):
        if not name.endswith(".c"):
            continue
        base = name[:-2]
        prog, _, symdefault = base.partition(".")
        text = open(f"{d}/{name}").read()
        dr = directives(text)
        sym = dr.get("func", symdefault)
        got = ref_bytes(f"{d}/{name}", dr["decl"], dr.get("flags", "-s -onatx"))
        want = bin_bytes(prog, sym)
        if not got or not want:
            print(f"  {base}: could not extract bytes (ref={got!r} bin={want!r})")
            bad = 1
        elif mask(got) == mask(want):
            print(f"  {base}: reference reproduces {sym} ({len(want)//2}b)")
        else:
            print(f"  {base}: MISMATCH\n     reference -> {got}\n     binary    -> {want}")
            bad = 1
    return bad


if __name__ == "__main__":
    sys.exit(main())
