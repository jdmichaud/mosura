	org 0
	dc.l $00FFFE00, start
	dcb.l 62, start
	org $100
	dc.b "SEGA MEGA DRIVE "
	dcb.b $100-16, $20
start:
	move.w #$2700,sr
	move.b #$02,$FF0010
	lea $FF0010,a0
	move #0,ccr
	nbcd (a0)
	move.b #$02,$FF0011
	lea $FF0011,a1
	move #0,ccr
	nbcd (a1)+
	move.b #$02,$FF0012
	move #0,ccr
	nbcd $FF0012
	move.b #$02,d3
	move #0,ccr
	nbcd d3
	move.b d3,$FF0013
	move.w #$DEAD,$FFFF00
done:
	bra done
