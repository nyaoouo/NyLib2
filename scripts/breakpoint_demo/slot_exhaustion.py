r"""Manual smoke: five HARD breakpoints; the fifth raises SlotExhaustedError."""

import ctypes

from nylib.winutils.breakpoint import BreakPoint, BP_E, SlotExhaustedError

buf = (ctypes.c_uint64 * 8)(*range(8))
addrs = [ctypes.addressof(buf) + i * 8 for i in range(8)]

bps = []
for a in addrs[:4]:
    bps.append(BreakPoint(a, 8, lambda *_: None, flag=BP_E.READ | BP_E.HARD).install())

try:
    try:
        BreakPoint(addrs[4], 8, lambda *_: None, flag=BP_E.READ | BP_E.HARD).install()
    except SlotExhaustedError as e:
        print("got expected SlotExhaustedError:", e)
    else:
        raise AssertionError("expected SlotExhaustedError")
finally:
    for bp in bps:
        bp.uninstall()

print("ok")
