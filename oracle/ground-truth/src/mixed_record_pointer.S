/* Pointer-record discovery in mixed memory (GNU assembler, i386/x86-64).
 *
 * Keep these properties:
 * - MIXED puts code and writable records in one initialized executable section;
 *   the control puts the same records in a non-executable data section.
 * - The selector is mutable and each pointer is isolated between integer fields.
 *   No direct call or adjacent-pointer table exposes either handler.
 * - The linked image has no relocations; strip symbols before analysis.
 * - handler_a is the only caller of deep, so discovery must follow the cascade.
 * - _start contains an address immediate pointing to an interior RET. Its bytes
 *   are an instruction operand, not a stored data pointer or a function entry.
 * - An unused third record holds the address of an instruction operand. Its
 *   bytes decode as NOP; RET, but that address is not an instruction boundary.
 * - The x86-64 pointer field is unaligned; record fields need not be word-aligned.
 *
 * Build each layout with gcc -m32/-m64 -nostdlib -static -no-pie -Wl,-e,_start,
 * adding -DMIXED for the executable/data layout. No survey bytes are included.
 */
#ifdef MIXED
.section .mixed,"awx",@progbits
#else
.text
#endif
.globl _start, dispatch, handler_a, handler_b, deep
.type _start,@function
_start:
#ifdef __x86_64__
    movabsq $1f,%rbx
#else
    movl $1f,%ebx
#endif
.Loperand:
    movl $0x9090c390,%edx
#ifdef __x86_64__
    movl .Lselection(%rip),%eax
#else
    movl .Lselection,%eax
#endif
    call dispatch
    ret
.size _start,.-_start

.type dispatch,@function
dispatch:
    andl $1,%eax
#ifdef __x86_64__
    shll $4,%eax
    leaq .Lrecords(%rip),%rdx
    movl 12(%rdx,%rax),%ecx
    call *4(%rdx,%rax)
#else
    imull $12,%eax
    movl .Lrecords+8(%eax),%ecx
    call *.Lrecords+4(%eax)
#endif
    ret
.size dispatch,.-dispatch

.type handler_a,@function
handler_a:
    movl %ecx,%eax
    call deep
    addl $1,%eax
    ret
.size handler_a,.-handler_a

.type handler_b,@function
handler_b:
    leal (%ecx,%ecx,2),%eax
    ret
.size handler_b,.-handler_b

.type deep,@function
deep:
    addl $7,%eax
1:  ret
.size deep,.-deep

#ifdef MIXED
.section .mixed,"awx",@progbits
#else
.data
#endif
.Lrecords:
    .long 11
#ifdef __x86_64__
    .quad handler_a
#else
    .long handler_a
#endif
    .long 100
    .long 22
#ifdef __x86_64__
    .quad handler_b
#else
    .long handler_b
#endif
    .long 200
    .long 33
#ifdef __x86_64__
    .quad .Loperand+1
#else
    .long .Loperand+1
#endif
    .long 300
.Lselection:
    .long 0
.section .note.GNU-stack,"",@progbits
