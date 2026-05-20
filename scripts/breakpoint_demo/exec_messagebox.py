r"""Manual smoke: HARD EXEC breakpoint on a heap-allocated 'ret' stub.

We BP a tiny custom function (a single ``ret`` instruction) so the callback
cannot accidentally re-enter the same trap via Python internals.

Run from the project venv with the backend DLL already built::

    .\.venv\Scripts\python.exe -c "from nylib.winutils.breakpoint.veh import ensure_backend_dll; print(ensure_backend_dll())"
    .\.venv\Scripts\python.exe scripts\breakpoint_demo\exec_messagebox.py

Expected: ``[bp] hit ...`` for each call; exit code 0.
"""

import ctypes

from nylib.winutils.breakpoint import BreakPoint, BP_E

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
VirtualAlloc = kernel32.VirtualAlloc
VirtualAlloc.restype = ctypes.c_void_p
VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40

stub = VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
assert stub, "VirtualAlloc failed"
# 0xC3 = ret
ctypes.memset(stub, 0xC3, 1)

stub_fn = ctypes.CFUNCTYPE(None)(stub)

print(f"stub @ 0x{stub:X}")

hits = 0


def on_hit(address, t, frm, ctx):
    global hits
    hits += 1
    print(f"[bp] hit #{hits} address=0x{address:X} t={t!r} "
          f"frm=0x{frm:X} rcx=0x{ctx.rcx:X}")


bp = BreakPoint(stub, 1, on_hit, flag=BP_E.EXEC | BP_E.HARD).install()
try:
    for _ in range(3):
        stub_fn()
finally:
    bp.uninstall()

print(f"done, hits={hits}")
assert hits >= 3, f"expected 3 hits, got {hits}"
