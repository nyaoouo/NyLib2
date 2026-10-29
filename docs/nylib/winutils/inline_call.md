# Call queues

`InlineCallQueue` patches a function entry; `VTableCallQueue` replaces a vtable pointer slot. Both run queued calls on the next natural invocation, then continue to the original function.

```python
from nylib.winutils.inline_call import InlineCallQueue, VTableCallQueue

hook = InlineCallQueue(process, trigger_at, capacity=16)
# For a virtual function instead: VTableCallQueue(process, vtable_at + index * 8)
with hook:
    ticket = hook.submit(func_at, 3, 4)
    # The target must enter the hooked function before this returns.
    print(ticket.wait(5000))
```

`submit(func, *args, result_type=int)` returns a ticket. `ticket.wait(timeout_ms=-1)` returns the result and releases its slot; `hook.call(...)` submits and waits in one step. A timeout leaves the ticket pending. Up to eight scalar arguments are supported: integers, `float`/`ctypes.c_double`, and `ctypes.c_float`. Return types are `int`, `float`/`ctypes.c_double`, `ctypes.c_float`, or `None`.

Set `thread_id` in `InlineCallQueue(process, addr, capacity=16, thread_id=None)` to let only that thread drain requests. Other threads continue into the original function. A nonexistent thread id leaves calls pending until timeout.

Use a 64-bit target. For a hot inline trigger, pass `quiescent_patch=True` to suspend other target threads and check their instruction pointers during installation, removal and code release. Close refuses pending tickets. The vtable variant requires an aligned pointer slot. Native exceptions cannot unwind through the generated dispatcher.
