/* watcall convention probe (task #7 empirical validation). Compiled with a real Open Watcom
 * wcc386 (`~/tools/open-watcom-v2/rel/binl/wcc386 watcall_probe.c -bt=dos`); the caller's
 * arg-register loads are the ground truth for the watcall cspec (specs/x86-32-watcom.cspec).
 * wcc386 emits, for callee(a,b,c,d,e): mov eax,a; mov edx,b; mov ebx,c; mov ecx,d; push e;
 * call callee_ — i.e. args in EAX,EDX,EBX,ECX then stack; and callee returns in EAX with
 * `ret 4` (callee stack cleanup). The 47 caller bytes are inlined in the cspec.rs test. */
int __watcall callee(int a, int b, int c, int d, int e);
int caller(void) { return callee(0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555); }
int __watcall callee(int a, int b, int c, int d, int e) { return a - b + c - d + e; }
