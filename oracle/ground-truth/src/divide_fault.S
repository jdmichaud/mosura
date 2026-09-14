/* Division routines whose inputs decide between a result and a #DE fault.
 *
 * The x86 DIV/IDIV family divides a double-width dividend and keeps the low
 * half of the quotient; the hardware raises #DE when the divisor is zero or
 * when the quotient does not fit the destination. SLEIGH lifts the narrowing
 * as a SUBPIECE of the wide quotient ("DE exception if quotient doesn't fit"),
 * so an interpreter that executes the p-code literally hands back the
 * truncated value as if it were a result. Each routine is a bare division:
 * every operand comes from the caller's registers, so one body covers the
 * fault domain and the result domain by its inputs alone.
 *   divide_pair    EDX:EAX / ECX, unsigned  -> EAX quotient, EDX remainder
 *   divide_word    DX:AX / CX, unsigned      -> AX, DX (the 16-bit form)
 *   divide_signed  EDX:EAX / ECX, signed    -> EAX, EDX
 * Both the 64-bit and the 32-bit builds keep these operand sizes.
 */
.text
.globl _start, divide_pair, divide_word, divide_signed
.type _start,@function
_start:
    xorl %edx,%edx
    movl $100,%eax
    movl $7,%ecx
    call divide_pair
    call divide_word
    call divide_signed
    ret
.size _start,.-_start

.type divide_pair,@function
divide_pair:
    divl %ecx
    ret
.size divide_pair,.-divide_pair

.type divide_word,@function
divide_word:
    divw %cx
    ret
.size divide_word,.-divide_word

.type divide_signed,@function
divide_signed:
    idivl %ecx
    ret
.size divide_signed,.-divide_signed
.section .note.GNU-stack,"",@progbits
