/* A0 oracle corpus: a freestanding x86-64 C++ ELF exercising the GNU/Itanium
 * demangler. The user functions have external linkage, so their *mangled* names
 * (e.g. _ZN8geometry4areaEii) land in .symtab; auto-analysis demangles them and
 * applies the demangled name. Kept freestanding (no libstdc++/CRT) so the
 * converged Program state is just our own functions — small + reviewable.
 *
 * Coverage: a namespace (geometry::), an overload set (area(int,int) vs
 * area(double)), and a const class method (Shape::perimeter(int) const). */

namespace geometry {
int area(int w, int h) { return w * h; }      // _ZN8geometry4areaEii
double area(double r) { return r * r; }       // _ZN8geometry4areaEd
} // namespace geometry

struct Shape {
    int sides;
    int perimeter(int len) const { return sides * len; }  // _ZNK5Shape9perimeterEi
};

int compute(Shape *s, int len) { return s->perimeter(len); }  // _Z7computeP5Shapei

extern "C" void _start(void) {
    int a = geometry::area(3, 4);
    double b = geometry::area(2.0);
    Shape s;
    s.sides = (int)b;
    int p = compute(&s, a);
    register long rax asm("rax") = 60; /* SYS_exit */
    register long rdi asm("rdi") = p;
    asm volatile("syscall" ::"r"(rax), "r"(rdi) : "memory");
    __builtin_unreachable();
}
