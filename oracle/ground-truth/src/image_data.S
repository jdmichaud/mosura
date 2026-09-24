/* Routines that read and write the program's own data.
 *
 *   table_sum  EAX = table[0] + table[1] + ECX. The two constants live in .data, a
 *              different block from the code: an interpreter that treats the loaded
 *              image as memory returns 0x33333333 + ECX, one that reads never-written
 *              memory as zero returns ECX alone.
 *   bump       increments the dword `counter` (41 as loaded) and returns the new
 *              value in EAX: 42 from the loaded image, and one more from each state
 *              the previous run left behind.
 * Absolute addressing keeps both widths on one source (static, non-PIE, every
 * address below 4 GiB).
 */
.text
.globl _start, table_sum, bump
.type _start,@function
_start:
    xorl %ecx,%ecx
    call table_sum
    call bump
    ret
.size _start,.-_start

.type table_sum,@function
table_sum:
    movl table,%eax
    addl table+4,%eax
    addl %ecx,%eax
    ret
.size table_sum,.-table_sum

.type bump,@function
bump:
    incl counter
    movl counter,%eax
    ret
.size bump,.-bump

.data
.balign 4
table: .long 0x11111111, 0x22222222
counter: .long 41
.section .note.GNU-stack,"",@progbits
