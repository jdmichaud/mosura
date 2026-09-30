/* Big-endian memory and registers (MIPS BE; big_endian_m68k.S is the same set for the 68000).
 *
 *   read_word       v0 = the halfword at data_word, zero-extended: 0x1234 (bytes 12 34).
 *   read_byte_view  v0 = the first byte of data_long: 0xa1, its most significant (bytes a1 b2 c3 d4).
 *   read_long       v0 = data_long: 0xa1b2c3d4.
 *   store_long      stores 0x11223344 at 0x2000: bytes 11 22 33 44 in that order.
 *
 * Linked by lld (addresses resolved), then used as raw text: the data sits in .text so the one
 * section is the whole image.
 */
.set noreorder
.text
.globl __start, read_word, read_byte_view, read_long, store_long
.type __start,@function
__start:
    jal read_word
    nop
    jal read_byte_view
    nop
    jal read_long
    nop
    jal store_long
    nop
1:  b 1b
    nop
.size __start,.-__start

.type read_word,@function
read_word:
    lui $t0, %hi(data_word)
    jr $ra
    lhu $v0, %lo(data_word)($t0)
.size read_word,.-read_word

.type read_byte_view,@function
read_byte_view:
    lui $t0, %hi(data_long)
    jr $ra
    lbu $v0, %lo(data_long)($t0)
.size read_byte_view,.-read_byte_view

.type read_long,@function
read_long:
    lui $t0, %hi(data_long)
    jr $ra
    lw $v0, %lo(data_long)($t0)
.size read_long,.-read_long

.type store_long,@function
store_long:
    lui $t1, 0x1122
    ori $t1, $t1, 0x3344
    li $t0, 0x2000
    jr $ra
    sw $t1, 0($t0)
.size store_long,.-store_long

.align 2
data_word:
    .short 0x1234
    .short 0
data_long:
    .word 0xa1b2c3d4
.section .note.GNU-stack,"",@progbits
