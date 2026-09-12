/* Explicit function input declarations (GNU assembler, i386/x86-64).
 *
 * The assembly protocol orders inputs as EDI:uint4, AH:uint1 and returns EAX:uint4.
 * Keep the byte input distinct from its enclosing output register. relay passes the
 * same declared inputs through a constant register-held target, after modifying the
 * first input. Deindirection must preserve the declaration across its graph rebuild.
 * unused deliberately does not consume its second declared parameter. The interface
 * is a supplied fact, not recoverable from the unused parameter's machine-code uses.
 * Strip all symbols before mosura analysis; derive the function population from nm.
 */
.text
.globl _start, combine, relay, unused
.type _start,@function
_start:
    movl $3,%edi
    movb $5,%ah
    call combine
    movl %eax,sink
    movl $11,%edi
    movb $7,%ah
    call relay
    movl %eax,sink
    movl $19,%edi
    movb $13,%ah
    call unused
    movl %eax,sink
    ret
.size _start,.-_start

.type combine,@function
combine:
    movzbl %ah,%eax
    leal (%eax,%edi,4),%eax
    ret
.size combine,.-combine

.type relay,@function
relay:
    addl $3,%edi
#if defined(__x86_64__)
    leaq combine(%rip),%rcx
    call *%rcx
#else
    movl $combine,%ecx
    call *%ecx
#endif
    addl $1,%eax
    ret
.size relay,.-relay

.type unused,@function
unused:
    leal 7(%edi),%eax
    ret
.size unused,.-unused

.data
sink: .long 0
.section .note.GNU-stack,"",@progbits
