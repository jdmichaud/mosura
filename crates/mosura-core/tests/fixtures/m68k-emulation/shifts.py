"""The shift and rotate oracle ROMs' sources (see generate.py). Each ROM stores, per case, the
result long, the low byte of SR and a pad byte from $FF0000, then $DEAD at $FFFF00.

- shift-OP-SIZE: `OP.SIZE d1,d0` for every value in VALUES, every count 0-69 in d1 (a register count
  is taken modulo 64) and both condition-code inputs.
- shift-OP-imm: `OP.SIZE #n,d0` for n 1-8, every size, value and condition-code input.
- shift-memory: `OP.w (a0)` (a shift by one) for every OP, the low word of every value and both
  condition-code inputs; the long stored is the word, zero-extended.
"""
OPS = ["asl", "asr", "lsl", "lsr", "rol", "ror", "roxl", "roxr"]
VALUES = [0, 1, 0x80, 0x81, 0x7F, 0xFF, 0x8000, 0x7FFF, 0xFFFF, 0x80000000, 0x7FFFFFFF, 0xFFFFFFFF,
          0x12345678, 0x87654321, 0xA5A5A5A5, 0x40000001, 0xC0000040, 0x3F, 0x0FF0, 0x60000000]
COUNTS = list(range(0, 70))
CCRS = [0x0F, 0x10]   # X clear with N Z V C set; X set alone
HEAD = """	org 0
	dc.l $00FFFE00, start
	dcb.l 62, start
	org $100
	dc.b "SEGA MEGA DRIVE "
	dcb.b $100-16, $20
start:
	move.w #$2700,sr
	lea $FF0000,a2
"""
TAIL = """	move.w #$DEAD,$FFFF00
done:
	bra done
"""
def store():
    return "\tmove sr,d2\n\tmove.l d0,(a2)+\n\tmove.b d2,(a2)+\n\taddq.l #1,a2\n"
def table():
    return "values:\n" + "".join("\tdc.l $%08x\n" % v for v in VALUES)

def register_count(op, size):
    """`op.size d1,d0` for every value, count 0..69 and both CCR inputs."""
    s = HEAD + "\tlea values,a3\n\tmove.w #%d-1,d7\nvloop:\n\tmove.l (a3)+,d6\n\tmoveq #0,d5\ncloop:\n" % len(VALUES)
    for ccr in CCRS:
        s += "\tmove.l d6,d0\n\tmove.l d5,d1\n\tmove #$%02x,ccr\n\t%s.%s d1,d0\n" % (ccr, op, size) + store()
    s += "\taddq.w #1,d5\n\tcmp.w #%d,d5\n\tbne cloop\n\tdbra d7,vloop\n" % len(COUNTS)
    return s + TAIL + table(), len(VALUES) * len(COUNTS) * len(CCRS)

def immediate_count(op):
    """`op.size #n,d0` for n in 1..8, every size, value and CCR input."""
    s = HEAD + "\tlea values,a3\n\tmove.w #%d-1,d7\nvloop:\n\tmove.l (a3)+,d6\n" % len(VALUES)
    n = 0
    for size in "bwl":
        for count in range(1, 9):
            for ccr in CCRS:
                s += "\tmove.l d6,d0\n\tmove #$%02x,ccr\n\t%s.%s #%d,d0\n" % (ccr, op, size, count) + store()
                n += 1
    s += "\tdbra d7,vloop\n"
    return s + TAIL + table(), n * len(VALUES)

def memory():
    """`op.w (a0)` (shift by one) for every op, word value and CCR input; the long is the word in
    memory, zero-extended."""
    s = HEAD + "\tlea values,a3\n\tmove.w #%d-1,d7\nvloop:\n\tmove.l (a3)+,d6\n" % len(VALUES)
    n = 0
    for op in OPS:
        for ccr in CCRS:
            s += "\tmove.w d6,$FFF000\n\tlea $FFF000,a0\n\tmove #$%02x,ccr\n\t%s.w (a0)\n\tmove sr,d2\n\tmoveq #0,d0\n\tmove.w $FFF000,d0\n\tmove.l d0,(a2)+\n\tmove.b d2,(a2)+\n\taddq.l #1,a2\n" % (ccr, op)
            n += 1
    s += "\tdbra d7,vloop\n"
    return s + TAIL + table(), n * len(VALUES)

def variants(everything=True):
    # The committed subset: every op with a register count at one size (each size three times or
    # twice), every op with an immediate count.
    sizes = dict(zip(OPS, "bwlbwlbw"))
    for op in OPS:
        for size in "bwl":
            if everything or sizes[op] == size:
                yield "shift-%s-%s" % (op, size), register_count(op, size)
        yield "shift-%s-imm" % op, immediate_count(op)
    yield "shift-memory", memory()
