/* REFERENCE SOURCE for globfnptr.watcom-x86-32 `dispatch_`.
 *
 * This is not documentation: it is the artifact the MVE is ABOUT. It was worked out from the
 * function's bytes and is VERIFIED AT BUILD TIME to recompile to them — verify-expected.sh
 * compiles this file with the compiler and flags named below and compares the result against the
 * function's bytes in the committed binary. A reference that stops matching fails the build, so
 * it cannot drift into being a statement of intent.
 *
 * mosura is expected to REPRODUCE THIS SOURCE from the bytes. That is the whole test: the
 * compiler proves the source byte-faithful once, at build time; the test then compares text and
 * needs no toolchain.
 *
 * The names are mosura's, deliberately — a decompiler recovers no symbols, so the reference is
 * written in the form a decompiler can produce: address-derived names, and the `pc` prefix that
 * says the type system recovered a pointer-to-code.
 *
 * original: ff 15 <abs32> c3   ->   call DWORD PTR ds:<addr> ; ret
 * func: dispatch_
 * flags: -s -onatx
 * decl: code *pcRam08049070;
 */
void FUN_0804810d(void)
{
  (*pcRam08049070)();
  return;
}
