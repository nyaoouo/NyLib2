# Inline call queue

`InlineCallQueue` runs queued function calls in the thread that naturally enters a chosen function. It inherits `InlineHook` and keeps the original function's arguments and return behavior. A single entry can process a bounded batch without scanning empty slots.

```python
import ctypes

from nylib.process import Process
from nylib.winutils.inline_call import InlineCallQueue

process = Process.from_name('game.exe')
hook = InlineCallQueue(process, trigger_address, capacity=16)
hook.enabled = True

# Submit first; the target's next natural call to trigger_address runs the batch.
first = hook.submit(integer_function, 3, 4)
second = hook.submit(double_function, 9.0, result_type=float)

print(first.wait(5000))
print(second.wait(5000))
hook.close()
process.close()
```

`submit(func, *args, result_type=int)` returns a `CallTicket`. `ticket.done` checks completion; `ticket.wait(timeout_ms=-1)` returns the result and releases the slot. `ticket.close()` releases a completed slot without waiting, but refuses a pending call. `hook.call(func, *args, result_type=int, timeout_ms=-1)` submits and waits. A timeout leaves the ticket queued, so keep both the ticket and hook and wait again. The queue rejects submissions when its capacity is exhausted. A `with InlineCallQueue(...) as hook:` block enables the hook on entry and closes it on exit; close refuses pending tickets.

The queue supports up to eight scalar arguments. `int` and `bool` supply 64-bit integer or pointer bits, Python `float` and `ctypes.c_double` supply `double`, and `ctypes.c_float` supplies `float`. The dispatcher places the first four arguments in the Windows x64 integer and XMM registers and the rest on the stack. It captures both RAX and XMM0. `result_type=int` returns an unsigned 64-bit value; `float` or `ctypes.c_double` returns a double; `ctypes.c_float` returns a float; `None` discards the result. Pass pointers as integer addresses. Struct, vector and arbitrary byte arguments are not supported. Functions must use the standard [Windows x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention).

The host writes each request only while its ring slot is unpublished. An atomic 64-bit exchange publishes the tail after the request is complete. The target consumes entries in order, publishes completion after writing both return registers, and then continues into the original function. Python threads submitting to the same hook are serialized by a lock. Calls that re-enter the trigger function bypass the queue while the current batch is running. The ring size is a power of two from 1 to 64; each entry processes at most `capacity` calls so a busy producer cannot keep the target inside the dispatcher indefinitely.

Only one target thread may enter the trigger function at a time. Enable, disable and free the hook while the trigger function is quiescent; patching its first instructions while another thread executes there is unsafe. The hook rejects copied branches and RIP-relative instructions, checks that target and requested function addresses are executable, restores page protection after patching, and flushes the instruction cache. It retains code and the shared mapping while calls are pending, and refuses to close until every ticket has finished and been released. If the target exits, `wait()` raises `ProcessLookupError` and `close()` releases local resources.

The dispatcher does not register x64 unwind metadata or catch faults from requested native functions. Do not allow native exceptions to unwind through it; an invalid function pointer or a fault in a called function can terminate the target. The hook requires a 64-bit target and process rights for memory operations and shared section mapping. [Microsoft's unwind documentation](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64) describes the metadata required for exception propagation through generated non-leaf code.
