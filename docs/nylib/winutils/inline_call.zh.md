> 本文档为 inline_call.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="inline_call.md" -->

<!-- dt:section id="__preamble__" hash="cdbca5fc15b4" -->
# nylib.winutils.inline_call

在目标线程下一次进入所选函数时，于该线程自身上运行一批有限数量的函数调用，然后继续进入原始代码。`InlineCallQueue` 修补函数入口；`VTableCallQueue` 替换虚表指针槽位。`nylib.ue` 的 `calls='game-thread'` 构建于 `InlineCallQueue` 之上。

关键词: InlineCallQueue, VTableCallQueue, CallTicket, call queue, batch call, inline hook, vtable hook, function entry, game thread, thread_id, quiescent_patch, submit, x64

<!-- dt:section id="quick-start-0" hash="b7f256980571" -->
## 快速开始

提交一个调用，让目标进入被挂钩的函数，然后等待票据。

```python
# needs: a 64-bit target process, capstone, keystone
from nylib.winutils.inline_call import InlineCallQueue

hook = InlineCallQueue(process, trigger_at, capacity=16)
with hook:
    ticket = hook.submit(func_at, 3, 4)
    # The target must enter the hooked function before this returns.
    print(ticket.wait(5000))
```

<!-- dt:section id="hook-a-virtual-function-0" hash="cc27dc8bed2d" -->
## 挂钩虚函数

`VTableCallQueue` 接受一个对齐的虚表指针槽位的地址，而不是函数入口。

```python
# needs: a 64-bit target process, capstone, keystone
from nylib.winutils.inline_call import VTableCallQueue

with VTableCallQueue(process, vtable_at + index * 8) as hook:
    print(hook.call(func_at, 1, 2.0, timeout_ms=5000))
```

<!-- dt:section id="tickets-arguments-and-results-0" hash="839dc241e39d" -->
## 票据、参数与结果

`submit(func, *args, result_type=int)` 返回一个票据；`ticket.wait(timeout_ms=-1)` 返回结果并释放其槽位，`hook.call(...)` 一步完成提交与等待。超时会使票据保持待处理状态。

```python
# needs: an enabled queue on a 64-bit target
import ctypes

ticket = hook.submit(func_at, 7, ctypes.c_float(0.5), result_type=ctypes.c_float)
try:
    value = ticket.wait(1000)
except TimeoutError:
    value = ticket.wait()  # still pending: wait again
hook.call(func_at, result_type=None, timeout_ms=1000)
```

最多支持八个标量参数：整数、`float` / `ctypes.c_double` 以及 `ctypes.c_float`。结果类型为 `int`、`float` / `ctypes.c_double`、`ctypes.c_float` 或 `None`。

<!-- dt:section id="drain-on-one-thread-0" hash="3e9db481c1f0" -->
## 在单个线程上排空

传入 `thread_id` 可让只有该线程运行已排队的调用；其他线程继续进入原始函数。不存在的线程 id 会使调用一直待处理直到超时。

```python
# needs: a 64-bit target process, capstone, keystone
with InlineCallQueue(process, trigger_at, thread_id=game_tid) as hook:
    hook.call(func_at, timeout_ms=5000)
```

<!-- dt:section id="notes-0" hash="2d072d6924bb" -->
## 注意

- 请在 64 位 Python 中使用 64 位目标。原生异常无法穿过生成的分发器进行展开。
- `capacity` 是 1 到 64 之间的 2 的幂；当有这么多票据尚未释放时，`submit` 会抛出 `BufferError`。
- 对于热点内联触发点，向 `InlineCallQueue` 传入 `quiescent_patch=True`：它会在安装、移除和代码释放期间挂起目标的其他线程并检查它们的指令指针。
- 如果 2 GB 范围内没有可用的 trampoline 页，`InlineCallQueue` 会使用 15 字节的绝对跳转，并且需要同样长度的可重定位入口代码。
- 关闭队列（离开 `with` 时同样如此）会拒绝待处理的票据：请先等待所有票据。
- 如果目标在调用完成前退出，`ticket.wait` 会抛出 `ProcessLookupError`。
- 不带队列的普通挂钩见 [index.md](index.md#inline-hook)（`InlineHook`、`VTableHook`）。
