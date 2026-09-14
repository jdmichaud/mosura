/* A routine whose termination depends on its input.
 *
 * The loop decrements the low 16 bits of EAX and tests the whole register.
 * With the upper half clear the counter reaches zero and the routine
 * returns; with any upper bit set the low half cycles modulo 2^16 forever,
 * the shape of a loop that hangs on hardware. An interpreter that stops at
 * a step budget must report that it did, not hand back the registers as a
 * result. _start passes a terminating value so the program itself is sound.
 */
.text
.globl _start, spin_until_zero
.type _start,@function
_start:
    movl $5,%eax
    call spin_until_zero
    ret
.size _start,.-_start

.type spin_until_zero,@function
spin_until_zero:
1:
    testl %eax,%eax
    je 2f
    decw %ax
    jmp 1b
2:
    ret
.size spin_until_zero,.-spin_until_zero
.section .note.GNU-stack,"",@progbits
