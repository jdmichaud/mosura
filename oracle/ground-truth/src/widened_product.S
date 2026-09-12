/* High bits of a widened product (GNU assembler, i386/x86-64).
 *
 * EDI and ESI are independent four-byte inputs. high_product treats them as
 * unsigned; high_signed treats them as signed. Both return four bytes in EAX.
 * MUL/IMUL compute all 64 product bits. SHLD selects bits 30..61, so using a
 * 32-bit multiplication changes the result even though it fits in EAX.
 * Keep the high-word use: truncating the low product alone would hide a missing
 * widening cast in C. For example, 65536 times 65536 must return 4, not zero.
 * These explicit register interfaces are source facts, not ABI inference.
 * Strip symbols before analysis and derive function boundaries from the build.
 */
.text
.globl _start, high_product, high_signed
.type _start,@function
_start:
    movl $65536,%edi
    movl $65536,%esi
    call high_product
    movl %eax,sink
    movl $-65536,%edi
    movl $65536,%esi
    call high_signed
    movl %eax,sink+4
    ret
.size _start,.-_start

.type high_product,@function
high_product:
    movl %edi,%eax
    mull %esi
    shldl $2,%eax,%edx
    movl %edx,%eax
    ret
.size high_product,.-high_product

.type high_signed,@function
high_signed:
    movl %edi,%eax
    imull %esi
    shldl $2,%eax,%edx
    movl %edx,%eax
    ret
.size high_signed,.-high_signed

.data
sink: .long 0,0
.section .note.GNU-stack,"",@progbits
