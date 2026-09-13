/* A partial read of a global that also has a live full-word definition.
 *
 * Keep the loop, full-word store, and following unaligned halfword read. The
 * shared storage has a whole-word SSA value and a partial value at offset one.
 * Linking its global symbol must precede local VariablePiece rendering, so an
 * emitted typed whole-word view is not treated as a C structure with fields.
 * The loop updates state modulo 2^32; the AX result is its middle two bytes.
 * The caller consumes AX only. Upper result-register bits are outside this contract.
 */
.text
.globl _start, update_slice
.type _start,@function
_start:
    call update_slice
    movw %ax,result
    ret
.size _start,.-_start

.type update_slice,@function
update_slice:
    movl state,%eax
    movl $3,%ecx
1:
    addl $13,%eax
    loop 1b
    movl %eax,state
    movw state+1,%ax
    ret
.size update_slice,.-update_slice

.data
.balign 4
state: .long 0x2468ace0
result: .long 0
.section .note.GNU-stack,"",@progbits
