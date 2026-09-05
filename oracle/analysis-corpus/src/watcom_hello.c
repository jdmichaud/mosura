/* Watcom C corpus fixture source. A header-free program (still links the Watcom C
 * run-time, whose _cstart_ startup embeds the copyright banner the detector reads).
 * Built with a real Watcom 10.0a toolchain under dosemu2, target DOS/4GW (LE):
 *   wcc386 watcom_hello.c -bt=dos -fo=hello.obj
 *   wlink system dos4g name watcom_hello.exe file hello.obj \
 *     libpath <WATCOM>/lib386 libpath <WATCOM>/lib386/dos
 * The resulting DOS/4GW-bound LE embeds the run-time banner
 *   "WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994"
 * The toolchain (the RE tracker tmp/watcom-experiments/watcom_10.0a) is not committed;
 * the built .exe is (like the other corpus binaries) for a stable second-oracle fixture. */
int add(int a, int b) { return a + b; }
int main(void) { int s = 0, i; for (i = 0; i < 5; i++) s = add(s, i); return s; }
