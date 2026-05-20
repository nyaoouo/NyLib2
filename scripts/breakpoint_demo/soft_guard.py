r"""Manual smoke: SOFT READ via PAGE_GUARD on a 64 KiB region.

Expected: several ``[soft-read]`` lines (one per first-touch per page);
exit code 0.
"""

import ctypes

from nylib.winutils.breakpoint import BreakPoint, BP_E

PAGE = 0x10000  # 64 KiB
buf = (ctypes.c_ubyte * PAGE)()
addr = ctypes.addressof(buf)
print(f"buf @ 0x{addr:X} (size 0x{PAGE:X})")

hits = []


def on_read(address, t, frm, ctx):
    hits.append((address, frm))
    print(f"[soft-read] address=0x{address:X} frm=0x{frm:X} t={t!r}", flush=True)


bp = BreakPoint(addr, PAGE, on_read, flag=BP_E.READ | BP_E.SOFT).install()
try:
    total = 0
    for i in range(0, PAGE, 0x1000):
        total += buf[i]
    print(f"swept buffer, total={total}")
finally:
    bp.uninstall()

print(f"hits={len(hits)}")
assert hits, "expected at least one hit"
