> 本文档为 breakpoint.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="breakpoint.md" -->

<!-- dt:section id="__preamble__" hash="18fdf3409e53" -->
# nylib.winutils.breakpoint

用于本地、进程内使用的 x64 硬件和软件断点基础类型。可捕获执行、内存读取或写入；在 Python 回调中处理捕获，具有实时寄存器和内存访问。

关键词：hardware breakpoints, debug registers, memory trap, EXEC, READ, WRITE, VEH, debugger, BP_E, backend, BreakPoint, register access, callback, per-thread, refresh_threads

<!-- dt:section id="quick-start-0" hash="069c4c73a9be" -->
## Quick start

```python
# 需要：此进程中要捕获的代码地址
from nylib.winutils.breakpoint import BreakPoint, BP_E

addr = 0x400000  # 此进程中的代码地址

def on_trap(address, t, frm, ctx):
    print(f"trapped at {address:X}, rcx={ctx.rcx:X}")
    ctx.rcx += 1  # 修改线程的寄存器

bp = BreakPoint(addr, 1, on_trap, flag=BP_E.EXEC).install()
# ... 触发捕获 ...
bp.uninstall()
```

<!-- dt:section id="set-up-the-backend-dll-0" hash="49954685e11f" -->
## Set up the backend DLL

```python
# 需要：MSVC，PATH 中有 cl.exe

# VEH 后端（无需提权）
from nylib.winutils.breakpoint.veh import ensure_backend_dll
ensure_backend_dll()

# 或：debugger 后端（需要 SeDebugPrivilege）
from nylib.winutils.breakpoint.debugger import ensure_backend_dll
ensure_backend_dll()
```

两个调用都在首次导入时将后端（`veh_backend.cpp` 或 `debugger_backend.cpp`）编译为 DLL。DLL 被缓存在模块目录中并在之后重用。有关工作示例，请查看 `scripts/breakpoint_demo/`。

<!-- dt:section id="choose-a-backend-0" hash="cfb72970a456" -->
## Choose a backend

`backend=` 参数选择调度器（默认为 `'veh'`）：

```python
# 需要：addr、size、callback、flag
bp = BreakPoint(addr, size, callback, flag, backend='veh').install()  # VEH
bp = BreakPoint(addr, size, callback, flag, backend='debugger').install()  # debugger
```

**VEH（`'veh'`，默认）：** 无需提权。在安装后生成的线程不会继承 HARD BP；调用 `bp.refresh_threads()` 来附加它们。

**Debugger（`'debugger'`）：** **需要 SeDebugPrivilege**。通过 `CREATE_THREAD_DEBUG_EVENT` 自动将 HARD BP 附加到新线程。

<!-- dt:section id="flags-and-size-rules-0" hash="559bbb4dae22" -->
## Flags and size rules

`BP_E` 具有访问标志（EXEC、WRITE、READ）和实现标志（HARD、SOFT）：

```python
from nylib.winutils.breakpoint import BP_E

# 访问：选择一个
BP_E.EXEC    # 在执行时捕获
BP_E.WRITE   # 在写入时捕获
BP_E.READ    # 在读取时捕获

# 实现：选择一个
BP_E.HARD    # 硬件调试寄存器（每个线程 4 个）
BP_E.SOFT    # PAGE_GUARD 异常（进程范围）

bp_flag = BP_E.EXEC | BP_E.HARD  # 合并它们
```

**大小规则：** EXEC 需要 `size=1`。WRITE/READ 允许 `size` 为 1、2、4 或 8 字节（HARD）或页粒度（SOFT）。

<!-- dt:section id="handle-traps-in-the-callback-0" hash="32ff3acb3cc1" -->
## Handle traps in the callback

回调签名为 `(address, t, frm, ctx)`，其中 `t` 是触发的 `BP_E` 标志。`ctx`（BpCtx）提供对寄存器和内存的实时访问：

```python
def on_trap(address, t, frm, ctx):
    print(f"at {address:X}, trapped with flag {t!r}")
    ctx.rcx = 0x1234                 # 修改寄存器（所有 x64 + xmm）
    data = ctx.read(ctx.rsp, 8)      # 读取内存
    stack = ctx.stack(n=4)           # 读取栈
    ctx.skip(1)                      # ctx.rip += 1
```

`BpCtx` 仅在回调期间有效；在之后使用返回 `RuntimeError`。

<!-- dt:section id="per-thread-management-for-hard-breakpoints-0" hash="b9b23bbd74b7" -->
## Per-thread management for HARD breakpoints

HARD BP（调试寄存器）是按线程的。按需管理它们：

```python
# 需要：addr、on_trap 回调、tid1、tid2 线程 ID
def on_trap(address, t, frm, ctx):
    pass

bp = BreakPoint(addr, 1, on_trap, flag=BP_E.EXEC | BP_E.HARD).install()
bp.attach_tids([tid1, tid2])         # 扩展到更多线程
bp.detach_tids([tid1])               # 从线程释放
bp.tracked_tids()                    # 列出携带此 BP 的线程
bp.refresh_threads()                 # 附加新生成的线程

from nylib.winutils.breakpoint import refresh_all_threads
refresh_all_threads()                # 对于所有已安装的 BP
```

SOFT BP（PAGE_GUARD）是进程范围的，忽略线程列表。

<!-- dt:section id="module-level-helpers-0" hash="b44349979b73" -->
## Module-level helpers

```python
# 需要：addr、on_trap 回调、BP_E 标志
from nylib.winutils.breakpoint import (
    install, install_decorator, list_breakpoints,
    find_breakpoint, uninstall_all, refresh_all_threads, BP_E,
)

bp = install(addr, 1, on_trap, flag=BP_E.WRITE | BP_E.HARD)

@install_decorator(addr, 1, flag=BP_E.EXEC)
def my_callback(address, t, frm, ctx):
    pass
# my_callback.bp 是 BreakPoint

list_breakpoints()
find_breakpoint(addr)
uninstall_all()  # also atexit-registered
```

<!-- dt:section id="notes-0" hash="807ace60d587" -->
## Notes

- **仅 AMD64**：仅限 x64 架构（不支持 x86 或 ARM）。
- **HARD 断点限制**：每个线程 4 个调试寄存器。如果任何线程用尽，`attach_tids()` 会引发 `SlotExhaustedError`。
- **SOFT 是进程范围的**：PAGE_GUARD 断点适用于所有线程；无每线程控制。
- **新线程和 VEH**：使用 VEH 后端安装 HARD BP 后，稍后生成的线程不会继承它。调用 `bp.refresh_threads()`（或 `refresh_all_threads()`）来附加它们。
- **Debugger 后端共存**：一次只能将一个调试器附加到进程。在另一个调试器（Visual Studio、WinDbg）处于活跃状态时附加 debugger 后端会失败。
- **上下文有效性**：`BpCtx` 仅在回调期间是活跃的。通过 `ctx` 修改寄存器、栈或内存是安全的；在回调后访问 `ctx` 会引发 `RuntimeError`。
