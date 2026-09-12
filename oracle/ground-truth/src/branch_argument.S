/* Self-compiled phi-placement MVE (GNU assembler, x86-32 and x86-64).
 *
 * A mutable callback slot accepts one 32-bit EAX input. Three predecessor
 * blocks assign distinct constants before the shared CALLIND. The ABI may
 * overwrite EAX at the call, so heritage inserts an output guard at the same
 * storage. That guard must not hide the incoming argument's required phi.
 * Keep the selection in memory, the slot writable, and each assignment in a
 * different predecessor block. No return declaration supplies the input.
 * Both functions are directly reachable so discovery is not under test.
 * The x86-64 build is an independent control of the same source protocol.
 * Build: gcc [-m32|-m64] -nostdlib -static -no-pie -Wl,-e,_start branch_argument.S
 */
#ifdef __x86_64__
#define MEMORY(name) name(%rip)
#define POINTER .quad
#else
#define MEMORY(name) name
#define POINTER .long
#endif
.text
.globl _start, choose, target
.type _start,@function
_start:
    call choose
    call target
    ret
.size _start,.-_start

.type choose,@function
choose:
    cmpl $20,MEMORY(selection)
    jb 1f
    je 2f
    movl $43,%eax
    jmp 3f
2:  movl $29,%eax
    jmp 3f
1:  movl $17,%eax
3:  call *MEMORY(slot)
    ret
.size choose,.-choose

.type target,@function
target:
    movl %eax,MEMORY(observed)
    ret
.size target,.-target

.data
.globl slot, selection, observed
slot: POINTER target
selection: .long 0
observed: .long 0
.section .note.GNU-stack,"",@progbits
