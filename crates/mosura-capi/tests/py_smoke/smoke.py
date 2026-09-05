"""The Python smoke: the same scenario through ctypes. argv[1] = libmosura_capi.so, argv[2] = a binary."""
import ctypes
import sys

lib = ctypes.CDLL(sys.argv[1])


class View(ctypes.Structure):
    _fields_ = [("ptr", ctypes.POINTER(ctypes.c_uint8)), ("len", ctypes.c_size_t)]


class Bytes(ctypes.Structure):
    _fields_ = [("ptr", ctypes.POINTER(ctypes.c_uint8)), ("len", ctypes.c_size_t), ("cap", ctypes.c_size_t)]


LOG_FN = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t)


class Config(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_uint32), ("version", ctypes.c_uint32),
        ("spec_dirs", ctypes.POINTER(ctypes.c_char_p)), ("spec_dirs_len", ctypes.c_size_t),
        ("fid_dirs", ctypes.POINTER(ctypes.c_char_p)), ("fid_dirs_len", ctypes.c_size_t),
        ("cache_dir", ctypes.c_char_p), ("log", LOG_FN), ("log_user", ctypes.c_void_p),
        ("abort_on_panic", ctypes.c_int),
    ]


lib.mosura_last_error.restype = ctypes.c_char_p
lib.mosura_abi_version.restype = ctypes.c_uint32
lib.mosura_table_rows.restype = ctypes.c_uint64
lib.mosura_table_rows.argtypes = [ctypes.c_void_p]
lib.mosura_ctx_new.argtypes = [ctypes.POINTER(Config), ctypes.POINTER(ctypes.c_void_p)]
lib.mosura_identify.argtypes = [ctypes.c_void_p, View, ctypes.POINTER(ctypes.c_void_p)]
lib.mosura_session_open.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
lib.mosura_session_add_input.argtypes = [ctypes.c_void_p, View, ctypes.c_char_p, ctypes.c_void_p]
lib.mosura_program_open.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
lib.mosura_program_analyze.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
lib.mosura_program_table.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
lib.mosura_table_str.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32, ctypes.POINTER(View)]
lib.mosura_table_u64.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint64)]
lib.mosura_table_column_index.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32)]
lib.mosura_function_decompile.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
lib.mosura_function_c.argtypes = [ctypes.c_void_p, ctypes.POINTER(Bytes)]
lib.mosura_bytes_dispose.argtypes = [ctypes.POINTER(Bytes)]
lib.mosura_release.argtypes = [ctypes.c_void_p]


def check(status, what):
    if status != 0:
        sys.stderr.write(f"{what}: status {status}: {lib.mosura_last_error().decode()}\n")
        sys.exit(1)


def view_str(v):
    return bytes(v.ptr[i] for i in range(v.len)).decode()


data = open(sys.argv[2], "rb").read()
buf = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
bytes_view = View(ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint8)), len(data))

print(f"sizeof(mosura_ctx_config) {ctypes.sizeof(Config)}")
abi = lib.mosura_abi_version()
print(f"abi {abi >> 16}.{abi & 0xffff}")
cfg = Config(size=ctypes.sizeof(Config), version=1)
ctx = ctypes.c_void_p()
check(lib.mosura_ctx_new(ctypes.byref(cfg), ctypes.byref(ctx)), "ctx_new")

tbl = ctypes.c_void_p()
check(lib.mosura_identify(ctx, bytes_view, ctypes.byref(tbl)), "identify")
for r in range(lib.mosura_table_rows(tbl)):
    k, v = View(), View()
    lib.mosura_table_str(tbl, r, 0, ctypes.byref(k))
    lib.mosura_table_str(tbl, r, 1, ctypes.byref(v))
    if view_str(k) == "language":
        print(f"language {view_str(v)}")
lib.mosura_release(tbl)

sess = ctypes.c_void_p()
check(lib.mosura_session_open(ctx, None, None, ctypes.byref(sess)), "session_open")
check(lib.mosura_session_add_input(sess, bytes_view, b"basic.elf", None), "add_input")
prog = ctypes.c_void_p()
check(lib.mosura_program_open(sess, None, None, ctypes.byref(prog)), "program_open")
check(lib.mosura_program_analyze(prog, None, None, None), "analyze")
fns = ctypes.c_void_p()
check(lib.mosura_program_table(prog, b"functions", ctypes.byref(fns)), "table")
rows = lib.mosura_table_rows(fns)
print(f"functions {rows}")
name_col, entry_col = ctypes.c_uint32(), ctypes.c_uint32()
lib.mosura_table_column_index(fns, b"name", ctypes.byref(name_col))
lib.mosura_table_column_index(fns, b"entry", ctypes.byref(entry_col))
main_entry = ctypes.c_uint64()
for r in range(rows):
    nm = View()
    lib.mosura_table_str(fns, r, name_col.value, ctypes.byref(nm))
    if view_str(nm) == "main":
        lib.mosura_table_u64(fns, r, entry_col.value, ctypes.byref(main_entry))
print(f"main {main_entry.value:#x}")

fn = ctypes.c_void_p()
check(lib.mosura_function_decompile(prog, main_entry.value, None, ctypes.byref(fn)), "decompile")
c = Bytes()
check(lib.mosura_function_c(fn, ctypes.byref(c)), "function_c")
text = bytes(c.ptr[i] for i in range(c.len)).decode()
print(f"c {text.splitlines()[0]}")
lib.mosura_bytes_dispose(ctypes.byref(c))

# the boundary from Python: a foreign pointer and a wrong kind are refused with a message
lib.mosura_release(ctypes.c_void_p(0x10))
print("release(foreign) " + ("refused" if lib.mosura_last_error() else "silent"))
rows = lib.mosura_table_rows(sess)
print(f"rows(wrong kind) {rows} " + ("named" if b"not a mosura_table" in lib.mosura_last_error() else "unnamed"))

for h in (fn, fns, prog, sess, ctx):
    lib.mosura_release(h)
print("ok")
