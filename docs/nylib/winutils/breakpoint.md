# nylib.winutils.breakpoint

x64 hardware and software breakpoint primitive for local, in-process use. Trap execution, memory reads, or writes; handle the trap in a Python callback with live register and memory access.

Keywords: hardware breakpoints, debug registers, memory trap, EXEC, READ, WRITE, VEH, debugger, BP_E, backend, BreakPoint, register access, callback, per-thread, refresh_threads

## Quick start

```python
# needs: a code address to trap in this process
from nylib.winutils.breakpoint import BreakPoint, BP_E

addr = 0x400000  # code address in this process

def on_trap(address, t, frm, ctx):
    print(f"trapped at {address:X}, rcx={ctx.rcx:X}")
    ctx.rcx += 1  # mutate the thread's registers

bp = BreakPoint(addr, 1, on_trap, flag=BP_E.EXEC).install()
# ... trigger the trap ...
bp.uninstall()
```

## Set up the backend DLL

```python
# needs: MSVC, cl.exe in PATH

# VEH backend (works without elevation)
from nylib.winutils.breakpoint.veh import ensure_backend_dll
ensure_backend_dll()

# or: debugger backend (requires SeDebugPrivilege)
from nylib.winutils.breakpoint.debugger import ensure_backend_dll
ensure_backend_dll()
```

Both calls compile the backend (`veh_backend.cpp` or `debugger_backend.cpp`) to a DLL on first import. The DLL is cached in the module directory and reused thereafter. See `scripts/breakpoint_demo/` for working examples.

## Choose a backend

The `backend=` parameter selects the dispatcher (default `'veh'`):

```python
# needs: addr, size, callback, flag
bp = BreakPoint(addr, size, callback, flag, backend='veh').install()  # VEH
bp = BreakPoint(addr, size, callback, flag, backend='debugger').install()  # debugger
```

**VEH (`'veh'`, default):** No elevation needed. Threads spawned after install do NOT inherit HARD BPs; call `bp.refresh_threads()` to attach them.

**Debugger (`'debugger'`):** **Requires SeDebugPrivilege**. Automatically attaches HARD BPs to new threads via `CREATE_THREAD_DEBUG_EVENT`.

## Flags and size rules

`BP_E` has access flags (EXEC, WRITE, READ) and implementation flags (HARD, SOFT):

```python
from nylib.winutils.breakpoint import BP_E

# Access: pick one
BP_E.EXEC    # trap on execution
BP_E.WRITE   # trap on write
BP_E.READ    # trap on read

# Implementation: pick one
BP_E.HARD    # hardware debug registers (4 per thread)
BP_E.SOFT    # PAGE_GUARD exceptions (process-wide)

bp_flag = BP_E.EXEC | BP_E.HARD  # combine them
```

**Size rules:** EXEC requires `size=1`. WRITE/READ allow `size` of 1, 2, 4, or 8 bytes (HARD) or page-granular (SOFT).

## Handle traps in the callback

The callback signature is `(address, t, frm, ctx)` where `t` is the `BP_E` flag that fired. `ctx` (BpCtx) offers live access to registers and memory:

```python
def on_trap(address, t, frm, ctx):
    print(f"at {address:X}, trapped with flag {t!r}")
    ctx.rcx = 0x1234                 # mutate registers (all x64 + xmm)
    data = ctx.read(ctx.rsp, 8)      # read memory
    stack = ctx.stack(n=4)           # read stack
    ctx.skip(1)                      # ctx.rip += 1
```

`BpCtx` is valid only during the callback; using it after returns `RuntimeError`.

## Per-thread management for HARD breakpoints

HARD BPs (debug registers) are per-thread. Manage them on demand:

```python
# needs: addr, on_trap callback, tid1, tid2 thread IDs
def on_trap(address, t, frm, ctx):
    pass

bp = BreakPoint(addr, 1, on_trap, flag=BP_E.EXEC | BP_E.HARD).install()
bp.attach_tids([tid1, tid2])         # extend to more threads
bp.detach_tids([tid1])               # release from threads
bp.tracked_tids()                    # list threads carrying this BP
bp.refresh_threads()                 # attach newly spawned threads

from nylib.winutils.breakpoint import refresh_all_threads
refresh_all_threads()                # for all installed BPs
```

SOFT BPs (PAGE_GUARD) are process-wide and ignore thread lists.

## Module-level helpers

```python
# needs: addr, on_trap callback, BP_E flag
from nylib.winutils.breakpoint import (
    install, install_decorator, list_breakpoints,
    find_breakpoint, uninstall_all, refresh_all_threads, BP_E,
)

bp = install(addr, 1, on_trap, flag=BP_E.WRITE | BP_E.HARD)

@install_decorator(addr, 1, flag=BP_E.EXEC)
def my_callback(address, t, frm, ctx):
    pass
# my_callback.bp is the BreakPoint

list_breakpoints()
find_breakpoint(addr)
uninstall_all()  # also atexit-registered
```

## Notes

- **AMD64 only**: x64 architecture only (no x86 or ARM support).
- **HARD breakpoint limits**: 4 debug registers per thread. `attach_tids()` raises `SlotExhaustedError` if any thread runs out.
- **SOFT is process-wide**: PAGE_GUARD breakpoints apply to all threads; no per-thread control.
- **New threads and VEH**: After installing a HARD BP with the VEH backend, threads spawned later do not inherit it. Call `bp.refresh_threads()` (or `refresh_all_threads()`) to attach them.
- **Debugger backend coexistence**: Only one debugger may be attached to a process at a time. Attaching the debugger backend while another debugger (Visual Studio, WinDbg) is active will fail.
- **Context validity**: `BpCtx` is live only during the callback. Modifying registers, stack, or memory via `ctx` is safe; accessing `ctx` after the callback raises `RuntimeError`.
