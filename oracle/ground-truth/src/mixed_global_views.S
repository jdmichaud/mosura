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
 * copy_interior also reads an overlapping word two bytes into source. Keep its
 * base-word read and byte-indexed view: together they require a distinct symbol
 * for the interior access, whose relocation must retain the two-byte offset.
 * store_register holds the final destination address in a register. The native
 * store still writes four bytes, even though it has no absolute memory operand.
 * read_register supplies the corresponding register-held source read.
 * No incoming register value or returned value is part of these protocols.
 */
#if defined(__x86_64__)
#define CURSOR %rdi
#else
#define CURSOR %edi
#endif
.text
.globl _start, copy_mixed, store_mixed, copy_interior, store_register, read_register
.type _start,@function
_start:
    call copy_mixed
    call store_mixed
    call copy_interior
    call store_register
    call read_register
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

.type copy_interior,@function
copy_interior:
    movl source,%eax
    movl %eax,control
    movl source+2,%eax
    movl %eax,control+4
    xorl %edi,%edi
    movl $5,%ecx
3:
    movl source(CURSOR),%eax
    movl %eax,destination(CURSOR)
    add $4,CURSOR
    loop 3b
    ret
.size copy_interior,.-copy_interior

.type store_register,@function
store_register:
    xorl %edi,%edi
    movl $5,%ecx
4:
    movl source(CURSOR),%eax
    movl %eax,destination(CURSOR)
    add $4,CURSOR
    loop 4b
    movl $destination,%ebx
    movl control,%eax
    notl %eax
#if defined(__x86_64__)
    movl %eax,(%rbx)
#else
    movl %eax,(%ebx)
#endif
    ret
.size store_register,.-store_register

.type read_register,@function
read_register:
    movl $source,%ebx
#if defined(__x86_64__)
    movl (%rbx),%eax
#else
    movl (%ebx),%eax
#endif
    movl %eax,control
    xorl %edi,%edi
    movl $5,%ecx
5:
    movl source(CURSOR),%eax
    movl %eax,destination(CURSOR)
    add $4,CURSOR
    loop 5b
    ret
.size read_register,.-read_register

.data
.balign 4
source: .long 3,7,11,19,31
destination: .fill 5,4,0
control: .long 0,0
.section .note.GNU-stack,"",@progbits
