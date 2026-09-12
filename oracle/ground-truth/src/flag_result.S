/* Self-compiled flag-result contract MVE (GNU assembler, x86-64).
 *
 * flag_test returns only ZF: true means (value & mask) == 0. It does not
 * produce an integer-register result. The two callers consume opposite flag
 * polarities and return distinguishable constants through the ordinary ABI.
 * Keep the TEST immediately before RET and each conditional branch immediately
 * after CALL: materializing ZF in the assembly would hide the missing contract.
 * All functions are directly reachable, so discovery is independent of recovery.
 * The oracle supplies the source-owned ZF storage declaration; this is an explicit
 * assembly protocol, not an inferred change to the platform's default ABI.
 * No bytes in this program come from a survey binary.
 * Build: gcc -nostdlib -static -no-pie -Wl,-e,_start flag_result.S -o flag_result
 */
.text
.globl _start, flag_test, if_zero, if_nonzero
.type _start,@function
_start:
    call if_zero
    call if_nonzero
    ret
.size _start,.-_start

.type flag_test,@function
flag_test:
    testl %edi,%esi
    ret
.size flag_test,.-flag_test

.type if_zero,@function
if_zero:
    call flag_test
    je 1f
    movl $29,%eax
    ret
1:  movl $17,%eax
    ret
.size if_zero,.-if_zero

.type if_nonzero,@function
if_nonzero:
    call flag_test
    jne 1f
    movl $29,%eax
    ret
1:  movl $17,%eax
    ret
.size if_nonzero,.-if_nonzero
.section .note.GNU-stack,"",@progbits
