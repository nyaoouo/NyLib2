r"""Manual smoke: HARD EXEC BP behavior across threads.

A worker thread loops calling a `ret` stub. The main thread:
  1. Installs the BP (worker not yet started -> not tracked).
  2. Starts the worker and waits for its TID.
  3. Lets the worker run for a moment - confirms NO hits there.
  4. Calls bp.refresh_threads() - the worker TID becomes tracked.
  5. Lets the worker run more - confirms hits NOW occur.
  6. Calls bp.detach_tids([worker_tid]) - confirms hits stop again.
"""

import ctypes
import threading
import time

from nylib.winutils.breakpoint import BreakPoint, BP_E

kernel32 = ctypes.WinDLL("kernel32")
VirtualAlloc = kernel32.VirtualAlloc
VirtualAlloc.restype = ctypes.c_void_p
VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
stub = VirtualAlloc(None, 0x1000, 0x3000, 0x40)
ctypes.memset(stub, 0xC3, 1)  # ret
stub_fn = ctypes.CFUNCTYPE(None)(stub)

hits_by_tid: dict[int, int] = {}
hits_lock = threading.Lock()


def on_hit(address, t, frm, ctx):
    with hits_lock:
        hits_by_tid[ctx.tid] = hits_by_tid.get(ctx.tid, 0) + 1


bp = BreakPoint(stub, 1, on_hit, flag=BP_E.EXEC | BP_E.HARD).install()
main_tid = ctypes.windll.kernel32.GetCurrentThreadId()
print(f"installed; tracked_tids={bp.tracked_tids()}; main_tid={main_tid}")

stop = threading.Event()
worker_tid_box = []


def worker():
    worker_tid_box.append(ctypes.windll.kernel32.GetCurrentThreadId())
    while not stop.is_set():
        stub_fn()
        time.sleep(0.005)


t = threading.Thread(target=worker, daemon=True)
t.start()
while not worker_tid_box:
    time.sleep(0.005)
worker_tid = worker_tid_box[0]
print(f"worker_tid={worker_tid}")

# ---- Phase 1: worker running, BP not attached to it.
time.sleep(0.2)
with hits_lock:
    phase1 = dict(hits_by_tid)
print(f"phase 1 (no refresh) hits: {phase1}")
assert phase1.get(worker_tid, 0) == 0, "worker hit without refresh - unexpected"

# ---- Phase 2: refresh, then let it run.
n = bp.refresh_threads()
print(f"refresh_threads() attached {n} TID(s); tracked={bp.tracked_tids()}")
assert worker_tid in bp.tracked_tids()
time.sleep(0.2)
with hits_lock:
    phase2 = dict(hits_by_tid)
phase2_worker = phase2.get(worker_tid, 0) - phase1.get(worker_tid, 0)
print(f"phase 2 worker hits since refresh: {phase2_worker}")
assert phase2_worker >= 1, f"expected hits after refresh, got {phase2}"

# ---- Phase 3: detach the worker, hits stop.
bp.detach_tids([worker_tid])
print(f"after detach_tids([{worker_tid}]): tracked={bp.tracked_tids()}")
assert worker_tid not in bp.tracked_tids()
time.sleep(0.2)
with hits_lock:
    phase3 = dict(hits_by_tid)
phase3_worker = phase3.get(worker_tid, 0) - phase2.get(worker_tid, 0)
print(f"phase 3 worker hits after detach: {phase3_worker}")
# After detach, no NEW worker hits (small race tolerance: <= 2).
assert phase3_worker <= 2, f"expected ~0 hits after detach, got {phase3_worker}"

stop.set()
t.join(timeout=2)
bp.uninstall()
print("ok")
