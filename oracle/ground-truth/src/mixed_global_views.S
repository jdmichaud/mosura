/* One global accessed directly as a word and through a byte-indexed pointer.
 *
 * The first load must copy all 32 bits to control. The loop then copies five
 * adjacent words using a byte offset, with scale one and increments of four.
 * The base address is identical in both access forms. Keep both forms: a word
 * declaration scales the loop twice; a byte declaration truncates the first
 * load unless the wider access is represented as a view of the same storage.
 * Both buffers are mutable so constant folding cannot erase the loads.
 * store_mixed exercises the corresponding wider assignment target: after its
 * byte-indexed copy, it writes the bitwise complement of control over the first
 * destination word. All four bytes of that final store must be observable.
 * No incoming register value or returned value is part of either protocol.
 */
#if defined(__x86_64__)
#define CURSOR %rdi
#else
#define CURSOR %edi
#endif
.text
.globl _start, copy_mixed, store_mixed
.type _start,@function
_start:
    call copy_mixed
    call store_mixed
    ret
.size _start,.-_start

.type copy_mixed,@function
copy_mixed:
    movl source,%eax
    movl %eax,control
    xorl %edi,%edi
    movl $5,%ecx
1:
    movl source(CURSOR),%eax
    movl %eax,destination(CURSOR)
    add $4,CURSOR
    loop 1b
    ret
.size copy_mixed,.-copy_mixed

.type store_mixed,@function
store_mixed:
    xorl %edi,%edi
    movl $5,%ecx
2:
    movl source(CURSOR),%eax
    movl %eax,destination(CURSOR)
    add $4,CURSOR
    loop 2b
    movl control,%eax
    notl %eax
    movl %eax,destination
    ret
.size store_mixed,.-store_mixed

.data
.balign 4
source: .long 3,7,11,19,31
destination: .fill 5,4,0
control: .long 0
.section .note.GNU-stack,"",@progbits
