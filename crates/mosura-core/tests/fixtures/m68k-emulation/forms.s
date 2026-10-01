; BCD operand forms. Results from $FF0000: each case stores the destination byte(s), the low
; byte of SR and the address registers it moved.
	org 0
	dc.l $00FFFE00, start
	dcb.l 62, start
	org $100
	dc.b "SEGA MEGA DRIVE "
	dcb.b $100-16, $20
start:
	move.w #$2700,sr
	lea $FF0000,a2
; abcd -(a7),-(a7): A7 steps by two per operand
	move.l #$00FFF100,a7
	move.b #$19,$FFF0FE
	move.b #$28,$FFF0FC
	move #$04,ccr
	abcd -(a7),-(a7)
	move sr,d2
	move.b $FFF0FC,(a2)+
	move.b d2,(a2)+
	move.l a7,(a2)+
; abcd -(a0),-(a0): source at A0-1, destination at A0-2
	lea $FFF102,a0
	move.b #$37,$FFF101
	move.b #$45,$FFF100
	move #$10,ccr
	abcd -(a0),-(a0)
	move sr,d2
	move.b $FFF100,(a2)+
	move.b d2,(a2)+
	move.l a0,(a2)+
; sbcd -(a7),-(a7)
	move.l #$00FFF200,a7
	move.b #$19,$FFF1FE
	move.b #$28,$FFF1FC
	move #$14,ccr
	sbcd -(a7),-(a7)
	move sr,d2
	move.b $FFF1FC,(a2)+
	move.b d2,(a2)+
	move.l a7,(a2)+
; abcd d3,d3: one register is both operands
	move.l #$12345645,d3
	move #$10,ccr
	abcd d3,d3
	move sr,d2
	move.l d3,(a2)+
	move.b d2,(a2)+
	addq.l #1,a2
; multi-byte: 0x009999 + 0x000001 through -(An) with X clear and Z set -> 0x010000, Z clear
	move.l #$00009999,$FFF300
	move.l #$00000001,$FFF310
	lea $FFF304,a0
	lea $FFF314,a1
	move #$04,ccr
	abcd -(a1),-(a0)
	abcd -(a1),-(a0)
	abcd -(a1),-(a0)
	abcd -(a1),-(a0)
	move sr,d2
	move.l $FFF300,(a2)+
	move.b d2,(a2)+
	move.w #$DEAD,$FFFF00
done:
	bra done
