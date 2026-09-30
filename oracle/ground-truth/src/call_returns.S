/* Calls that return without their callee running (x86; call_returns_aarch64.S is the same
 * program for a link-register ISA).
 *
 *   caller  pushes a marker, calls callee, reads the marker back from the top of its stack
 *           and pops it: EAX = 0x1234abcd. When the call is skipped rather than entered, the
 *           stack must stand as the callee's return would leave it, or the read returns the
 *           call's own pushed return address instead of the marker.
 *   callee  EAX = 7.
 *   outer   calls middle and adds one: EAX = middle's result + 1.
 *   middle  EAX = 5, then tail-jumps into device.
 *   device  EAX = 99: the routine a harness stubs out. Stubbed, the tail jump returns to outer
 *           at once, so outer answers 6; entered, 100. _start also calls it, so it is a
 *           function the analysis reaches by a call, not only the target of middle's jump.
 */
#if defined(__x86_64__)
#define SP %rsp
#define WORD 8
#else
#define SP %esp
#define WORD 4
#endif
.text
.globl _start, caller, callee, outer, middle, device
.type _start,@function
_start:
    call caller
    call outer
    call device
    ret
.size _start,.-_start

.type caller,@function
caller:
    push $0x1234abcd
    call callee
    movl (SP),%eax
    add $WORD,SP
    ret
.size caller,.-caller

.type callee,@function
callee:
    movl $7,%eax
    ret
.size callee,.-callee

.type outer,@function
outer:
    call middle
    addl $1,%eax
    ret
.size outer,.-outer

.type middle,@function
middle:
    movl $5,%eax
    jmp device
.size middle,.-middle

.type device,@function
device:
    movl $99,%eax
    ret
.size device,.-device
.section .note.GNU-stack,"",@progbits
