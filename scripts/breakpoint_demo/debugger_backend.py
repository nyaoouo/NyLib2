r"""Manual smoke: HARD EXEC BP via the debugger backend.

Uses ``backend='debugger'`` instead of the default 'veh'. The debugger backend
auto-attaches HARD BPs to threads created after install via the
CREATE_THREAD_DEBUG_EVENT path - no refresh_threads() call needed.

REQUIRES SeDebugPrivilege (elevated / "Run as administrator"). If launched
without elevation, the script prints a hint and exits with code 2.
"""

import ctypes
import sys
import threading
import time

from nylib.winutils.breakpoint import BreakPoint, BP_E, BackendError

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


try:
    bp = BreakPoint(stub, 1, on_hit, flag=BP_E.EXEC | BP_E.HARD, backend="debugger").install()
except BackendError as e:
    print(f"[skip] debugger backend init failed: {e}", file=sys.stderr)
    print("       (the debugger backend needs an elevated process; re-run as admin)",
          file=sys.stderr)
    sys.exit(2)
main_tid = ctypes.windll.kernel32.GetCurrentThreadId()
print(f"installed; backend=debugger; main_tid={main_tid}; tracked={bp.tracked_tids()}")

# Phase 1: main-thread calls
for _ in range(3):
    stub_fn()
time.sleep(0.1)
with hits_lock:
    p1 = dict(hits_by_tid)
print(f"phase 1 hits (main only): {p1}")
assert p1.get(main_tid, 0) >= 3

# Phase 2: spawn worker AFTER install; debugger backend should auto-attach.
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
print(f"spawned worker_tid={worker_tid}")
# Give the debugger thread time to process CREATE_THREAD_DEBUG_EVENT and
# auto-apply the BP, plus time for the worker to actually call the stub.
time.sleep(0.4)
stop.set()
t.join(timeout=2)

with hits_lock:
    p2 = dict(hits_by_tid)
worker_hits = p2.get(worker_tid, 0)
print(f"phase 2 hits: {p2}")
print(f"worker_hits (no explicit refresh) = {worker_hits}")
assert worker_hits >= 1, f"debugger backend did not auto-attach new thread: {p2}"
print(f"tracked_tids includes worker? {worker_tid in bp.tracked_tids()}")

bp.uninstall()
print("ok")
