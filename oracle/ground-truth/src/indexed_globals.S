/* Byte offsets into word arrays (GNU assembler, i386/x86-64).
 *
 * copy_words copies five adjacent 32-bit words. The cursor is a byte offset,
 * advanced by four; the addressing mode deliberately has scale one. A C global
 * declaration must agree with the pointer type used by the recovered access:
 * declaring a word and adding this byte offset to its address multiplies the
 * stride by four a second time. Keep the mutable source and destination in data,
 * and keep this distinct from copy_scaled's element-indexed addressing control.
 * Neither routine needs an incoming register value or returns a value.
 */
#if defined(__x86_64__)
#define CURSOR %rdi
#else
#define CURSOR %edi
#endif
.text
.globl _start, copy_words, copy_scaled
.type _start,@function
_start:
    call copy_words
    call copy_scaled
    ret
.size _start,.-_start

.type copy_words,@function
copy_words:
    xorl %edi,%edi
    movl $5,%ecx
1:
    movl source(CURSOR),%eax
    movl %eax,destination(CURSOR)
    add $4,CURSOR
    loop 1b
    ret
.size copy_words,.-copy_words

.type copy_scaled,@function
copy_scaled:
    xorl %edi,%edi
    movl $5,%ecx
2:
    movl source(,CURSOR,4),%eax
    movl %eax,control(,CURSOR,4)
    add $1,CURSOR
    loop 2b
    ret
.size copy_scaled,.-copy_scaled

.data
.balign 4
source: .long 3,7,11,19,31
destination: .fill 5,4,0
control: .fill 5,4,0
.section .note.GNU-stack,"",@progbits
