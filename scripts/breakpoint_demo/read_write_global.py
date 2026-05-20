r"""Manual smoke: HARD WRITE breakpoint on a Python buffer.

Expected: at least one ``[write]`` line and `hits>=1`.
"""

import ctypes

from nylib.winutils.breakpoint import BreakPoint, BP_E

buf = (ctypes.c_uint32 * 4)(0, 0, 0, 0)
addr = ctypes.addressof(buf)
print(f"buf @ 0x{addr:X}")

hits = []


def on_write(address, t, frm, ctx):
    hits.append((address, frm))
    print(f"[write] address=0x{address:X} frm=0x{frm:X} t={t!r}", flush=True)


bp = BreakPoint(addr, 4, on_write, flag=BP_E.WRITE | BP_E.HARD).install()
try:
    buf[0] = 0xDEADBEEF
    buf[0] = 0x12345678
    print(f"buf[0]=0x{buf[0]:X}")
finally:
    bp.uninstall()

print(f"hits={len(hits)}")
assert hits, "expected at least one hit"
