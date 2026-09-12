# Explicit function input contracts

`decompile.function-inputs` supplies an ordered input list by function entry. The same
storage and types apply to the definition and its direct calls, including calls whose
constant target is proved during deindirection and then rebuilt.

```sh
mosura -S <session> decompile <function> \
  -o 'decompile.function-inputs=0x8049034=EDI:uint4,AH:uint1'
```

Separate functions with `;` and parameters with `,`. `hex=void` explicitly declares no
parameters; omitting a function leaves its input recovery enabled. An unused declared
parameter remains in the signature. Register names are resolved against the selected
SLEIGH language, including aliases such as high-byte registers. Unknown registers,
overlapping storage, type/storage width mismatches and duplicate entries are rejected.

The option accepts `bool`, `char`, `intN`, `uintN`, `floatN` and `unknownN`; widths are bytes.
The public core value is `Knobs::function_inputs`, mapping entries to ordered
`RegisterParameter` values. This declaration records a supplied interface; it does not
infer a missing interface from an unused register. Mutable pointer-slot input declarations
remain available through `decompile.indirect-inputs`; a more specific call-site declaration
has precedence when both apply. Result declarations are independent
([result contracts](flag-result-contracts.md)).

The option is request-local and participates in result-cache identity, including parameter
order and the distinction between an absent and empty declaration. Cached and thawed
programs retain the same behavior, and later requests that omit the option recover their
default results. `function.decompile` accepts it. Compiler emission and round operations
reject it until custom prototype lowering is supported. Stack/composite parameter syntax,
full typed function-pointer interfaces and automatic non-default interface recovery remain
separate work.

## Faithful mechanisms

The pinned C++ `ActionPrototypeTypes` forces locked input varnodes to exist before heritage
and extends them when the compiler specification promises an extension. `ActionInputPrototype`
retains their explicit order instead of rebuilding it from parameter trials. The implementation
uses typed `ProtoParameter` values at definitions and call sites; call-local type propagation
reads the parameter type without type-locking a value shared by other caller uses.

`Heritage::heritage` and `collect` include existing inputs with no descendants. This is
necessary when a declared subregister has not yet been linked to its free reads. Deleted
arena slots have their input/unaffected flags cleared so they cannot reenter that location
walk. `FuncProto::unjustifiedInputParam` tests locked parameter storage before consulting
the ABI model; otherwise a declared high byte can be widened into an unrelated parameter.
The C printer reads the locked prototype, preserving its types and unused parameters.
Compiler-specific spelling remains the emitter's responsibility.

## Reproducible evidence

`oracle/ground-truth/src/function_inputs.S` supplies EDI:uint4 and AH:uint1 inputs, an
EAX:uint4 result, an unused parameter and a nested constant indirect call. GCC builds both
i386 and x86-64 artifacts; the build script derives their `.truth` files from `nm`/`objdump`
and strips the symbols. The new declaration regression failed before the consumers were
ported: the i386 definition recovered EAX:4 instead of the declared EDI:4/AH:1 list.

The passing gate checks definition storage/order/types, unused inputs, the deindirection
restart, all call operands and result expressions evaluated at boundary values. The pinned
C++ oracle, supplied the same mapped parameters and results, retains the same inputs and
expressions. The library's IR and the printer's signatures are both checked.

`function_input_extension.S` independently covers AArch64 input extension. It declares
w0:uint4 and reads x0's upper word. The AAPCS64 compiler specification promises zero extension;
both mosura and the mapped C++ oracle reduce the result to zero while retaining the unused
uint4 parameter. The caller's w0 write independently establishes that value in the bytes.

The API gate covers live, cached and thawed requests, declaration isolation, reordered and
empty lists, and rejected invalid storage. Default corpus emission remains byte-identical
for all 751/751 translation units against the preceding pointer-discovery package.
