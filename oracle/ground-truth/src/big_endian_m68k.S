/* Big-endian memory and registers on the 68000 (big_endian_mips.S is the same set for MIPS BE).
 * Assembled to raw text (no relocation: data is read PC-relative, stores go through A0).
 *
 *   read_word       D0 = 0, then the word at data_word into D0's low half: 0x00001234.
 *   read_byte_view  D0 = -1, then data_long's first byte into D0's low byte: 0xffffffa1.
 *   store_long      stores 0x11223344 at 0x2000: bytes 11 22 33 44 in that order.
 *   store_high      A0 = the sign-extended word 0xc000 (0xffffc000); stores the word 0x5678 there.
 */
.text
.globl read_word, read_byte_view, store_long, store_high
read_word:
    moveq #0,%d0
    move.w (data_word,%pc),%d0
    rts
read_byte_view:
    moveq #-1,%d0
    move.b (data_long,%pc),%d0
    rts
store_long:
    move.w #0x2000,%a0
    move.l #0x11223344,(%a0)
    rts
store_high:
    move.w #0xc000,%a0
    move.w #0x5678,(%a0)
    rts
data_word:
    .short 0x1234
data_long:
    .long 0xa1b2c3d4
