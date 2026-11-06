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

<!-- dt:section id="notes-0" hash="10973f175098" -->
## 注意事项

- 请在 64 位 Python 中使用 64 位目标。原生异常无法穿过生成的分发器展开。
- 所有线程中同一时间只运行一次排空,使用通过交换获取的队列头标志。排空运行期间进入的调用(包括重新进入触发点的已排队调用)会运行原函数,不排空任何内容。调用按提交顺序逐个运行,每个调用返回后下一个才开始;每次进入最多运行 `capacity` 个调用。
- `capacity` 是 1 到 64 之间的 2 的幂;当有这么多票据未释放时,`submit` 会抛出 `BufferError`。
- 对于热内联触发点,向 `InlineCallQueue` 传入 `quiescent_patch=True`:它会在安装、移除和代码释放期间挂起其他目标线程并检查它们的指令指针。当目标是本 Python 进程时,另一个在 GIL 交接中被挂起的 Python 线程可能导致补丁或代码释放挂起:在这些步骤期间请让其他 Python 线程保持空闲。远程目标不受影响。
- 如果 2 GB 范围内没有可用的跳板页,`InlineCallQueue` 会使用 15 字节的绝对跳转,并要求入口代码有同样多的可重定位字节。
- 传入 `_jmp_support=1` 可重定位直接的 `jmp` 和 `Jcc` 入口指令;默认仍会拒绝它们。
- 关闭队列(包括离开 `with` 时)会拒绝未完成的票据:请先等待每一张票据。
- 队列通过 `Process.map_shared` 获取其本地视图和目标视图;适配器可以提供其他共享内存后端。
- 如果目标在调用完成之前退出,`ticket.wait` 会抛出 `ProcessLookupError`。
- 不带队列的普通钩子见 [index.md](index.md#inline-hook)(`InlineHook`、`VTableHook`)。
