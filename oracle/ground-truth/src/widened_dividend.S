/* Narrow results of wide unsigned arithmetic (GNU assembler, i386/x86-64).
 *
 * EDI, ESI and ECX are independent unsigned four-byte inputs. Every helper
 * returns EAX. product_quotient/remainder divide the complete EDI*ESI product
 * by ECX; pair_quotient/remainder divide the ESI:EDI pair by ECX. Inputs to
 * native DIV must have a nonzero divisor and a quotient that fits four bytes.
 * product_shift selects bits 44..63; product_low selects bits 0..31.
 *
 * Keep both halves of the dividend and both division results. C promotion
 * cannot replace the widening: 65536*65536/65537 is 65535, remainder 1.
 * Compiler emission must represent these values even when its largest C
 * integer is four bytes. An incomplete-width diagnostic is the failing gate,
 * and removing the widening would merely conceal incorrect arithmetic.
 * Register interfaces and arithmetic are source facts; stripped boundaries
 * come from the build, never from an external binary or hand-authored truth.
 */
.text
.globl _start, product_quotient, product_remainder, pair_quotient, pair_remainder
.globl product_shift, product_low
.type _start,@function
_start:
    movl $65536,%edi
    movl $65536,%esi
    movl $65537,%ecx
    call product_quotient
    movl %eax,sink
    call product_remainder
    movl %eax,sink+4
    call pair_quotient
    movl %eax,sink+8
    call pair_remainder
    movl %eax,sink+12
    call product_shift
    movl %eax,sink+16
    call product_low
    movl %eax,sink+20
    ret
.size _start,.-_start

.type product_quotient,@function
product_quotient:
    movl %edi,%eax
    mull %esi
    divl %ecx
    ret
.size product_quotient,.-product_quotient

.type product_remainder,@function
product_remainder:
    movl %edi,%eax
    mull %esi
    divl %ecx
    movl %edx,%eax
    ret
.size product_remainder,.-product_remainder

.type pair_quotient,@function
pair_quotient:
    movl %edi,%eax
    movl %esi,%edx
    divl %ecx
    ret
.size pair_quotient,.-pair_quotient

.type pair_remainder,@function
pair_remainder:
    movl %edi,%eax
    movl %esi,%edx
    divl %ecx
    movl %edx,%eax
    ret
.size pair_remainder,.-pair_remainder

.type product_shift,@function
product_shift:
    movl %edi,%eax
    mull %esi
    shrl $12,%edx
    movl %edx,%eax
    ret
.size product_shift,.-product_shift

.type product_low,@function
product_low:
    movl %edi,%eax
    mull %esi
    ret
.size product_low,.-product_low

.data
sink: .long 0,0,0,0,0,0
.section .note.GNU-stack,"",@progbits
