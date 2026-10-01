; BCD oracle: OPK selects the instruction, CCRIN the condition codes before it,
; X0 the first destination byte (64 destination values x 256 source values).
; Each case stores the result byte, then the low byte of SR, from $FF0000 on.
	org 0
	dc.l $00FFFE00, start
	dcb.l 62, start
	org $100
	dc.b "SEGA MEGA DRIVE "
	dcb.b $100-16, $20
start:
	move.w #$2700,sr
	lea $FF0000,a2
	move.w #X0,d6
outer:
	move.w #0,d7
inner:
	move.b d6,d0
	move.b d7,d1
	if OPK=0
	move #CCRIN,ccr
	abcd d1,d0
	endif
	if OPK=1
	move #CCRIN,ccr
	sbcd d1,d0
	endif
	if OPK=2
	move #CCRIN,ccr
	nbcd d0
	endif
	if OPK=3
	move.b d6,$FFF001
	move.b d7,$FFF003
	lea $FFF002,a0
	lea $FFF004,a1
	move #CCRIN,ccr
	abcd -(a1),-(a0)
	move sr,d2
	move.b $FFF001,d0
	bra stored
	endif
	if OPK=4
	move.b d6,$FFF001
	move.b d7,$FFF003
	lea $FFF002,a0
	lea $FFF004,a1
	move #CCRIN,ccr
	sbcd -(a1),-(a0)
	move sr,d2
	move.b $FFF001,d0
	bra stored
	endif
	if OPK=5
	move.b d6,$FFF001
	lea $FFF000,a0
	move #CCRIN,ccr
	nbcd 1(a0)
	move sr,d2
	move.b $FFF001,d0
	bra stored
	endif
	move sr,d2
stored:
	move.b d0,(a2)+
	move.b d2,(a2)+
	addq.w #1,d7
	cmp.w #256,d7
	bne inner
	addq.w #1,d6
	cmp.w #X0+64,d6
	bne outer
	move.w #$DEAD,$FFFF00
done:
	bra done
