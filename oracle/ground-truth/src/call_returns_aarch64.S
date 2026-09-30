/* call_returns.S for a link-register ISA: a call writes x30 and pushes nothing, so the rules
 * that make a skipped call and a stub return correctly must hold without any push to undo.
 *
 *   caller  stores a marker in its frame, calls callee, loads the marker back: x0 = 0x1234abcd.
 *   callee  x0 = 7.
 *   outer   calls middle and adds one: x0 = middle's result + 1.
 *   middle  x0 = 5, then tail-branches into device.
 *   device  x0 = 99: stubbed, outer answers 6; entered, 100.
 */
.text
.globl _start, caller, callee, outer, middle, device
.type _start,@function
_start:
    bl caller
    bl outer
    ret
.size _start,.-_start

.type caller,@function
caller:
    stp x29, x30, [sp, #-32]!
    movz x9, #0xabcd
    movk x9, #0x1234, lsl #16
    str x9, [sp, #16]
    bl callee
    ldr x0, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
.size caller,.-caller

.type callee,@function
callee:
    mov x0, #7
    ret
.size callee,.-callee

.type outer,@function
outer:
    stp x29, x30, [sp, #-16]!
    bl middle
    add x0, x0, #1
    ldp x29, x30, [sp], #16
    ret
.size outer,.-outer

.type middle,@function
middle:
    mov x0, #5
    b device
.size middle,.-middle

.type device,@function
device:
    mov x0, #99
    ret
.size device,.-device
.section .note.GNU-stack,"",@progbits
