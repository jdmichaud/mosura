/* Explicit narrow function input under the AAPCS64 compiler specification.
 *
 * upper_input declares w0:uint4 and returns x0:uint8. The model promises that
 * the input is zero-extended into x0. Keep the full-width shift: changing it
 * to a w0 operation would hide the missing ActionPrototypeTypes::extendInput.
 * The caller writes w0, independently witnessing that its upper word is zero.
 */
.text
.globl _start, upper_input
.type _start,%function
_start:
    mov w0,#-1
    bl upper_input
    ret
.size _start,.-_start

.type upper_input,%function
upper_input:
    lsr x0,x0,#32
    ret
.size upper_input,.-upper_input
.section .note.GNU-stack,"",%progbits
