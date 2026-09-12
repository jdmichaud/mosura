/* Self-compiled narrow-result extension MVE (AArch64, AAPCS64).
 *
 * The caller uses the upper half of x0 after a call declared to return in w0.
 * AAPCS64's cspec promises zero extension in the x0 output container. Preserve
 * the full-width read: replacing it with w0 hides the missing extension path.
 * The producer explicitly writes w0, so the source also establishes that the
 * upper half is zero. No instructions or addresses come from a survey binary.
 * Build with clang --target=aarch64-linux-gnu and an AArch64-capable linker.
 */
.text
.globl _start, narrow_result, upper_result
.type _start,%function
_start:
    bl upper_result
    ret
.size _start,.-_start

.type narrow_result,%function
narrow_result:
    mov w0,#255
    ret
.size narrow_result,.-narrow_result

.type upper_result,%function
upper_result:
    stp x29,x30,[sp,#-16]!
    mov x0,#-1
    bl narrow_result
    lsr x0,x0,#32
    ldp x29,x30,[sp],#16
    ret
.size upper_result,.-upper_result
.section .note.GNU-stack,"",%progbits
