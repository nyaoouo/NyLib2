# nylib.winutils.inline_call

Run a bounded batch of function calls on a target's own thread the next time it enters a chosen function, then continue into the original code. `InlineCallQueue` patches a function entry; `VTableCallQueue` replaces a vtable pointer slot. `nylib.ue`'s `calls='game-thread'` is built on `InlineCallQueue`.

Keywords: InlineCallQueue, VTableCallQueue, CallTicket, call queue, batch call, inline hook, vtable hook, function entry, game thread, thread_id, quiescent_patch, submit, x64

## Quick start

Submit a call, let the target enter the hooked function, then wait for the ticket.

```python
# needs: a 64-bit target process, capstone, keystone
from nylib.winutils.inline_call import InlineCallQueue

hook = InlineCallQueue(process, trigger_at, capacity=16)
with hook:
    ticket = hook.submit(func_at, 3, 4)
    # The target must enter the hooked function before this returns.
    print(ticket.wait(5000))
```

## Hook a virtual function

`VTableCallQueue` takes the address of an aligned vtable pointer slot instead of a function entry.

```python
# needs: a 64-bit target process, capstone, keystone
from nylib.winutils.inline_call import VTableCallQueue

with VTableCallQueue(process, vtable_at + index * 8) as hook:
    print(hook.call(func_at, 1, 2.0, timeout_ms=5000))
```

## Tickets, arguments and results

`submit(func, *args, result_type=int)` returns a ticket; `ticket.wait(timeout_ms=-1)` returns the result and releases its slot, and `hook.call(...)` submits and waits in one step. A timeout leaves the ticket pending.

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

Up to eight scalar arguments are supported: integers, `float` / `ctypes.c_double`, and `ctypes.c_float`. Result types are `int`, `float` / `ctypes.c_double`, `ctypes.c_float`, or `None`.

## Drain on one thread

Pass `thread_id` to let only that thread run queued calls; other threads continue into the original function. A nonexistent thread id leaves calls pending until timeout.

```python
# needs: a 64-bit target process, capstone, keystone
with InlineCallQueue(process, trigger_at, thread_id=game_tid) as hook:
    hook.call(func_at, timeout_ms=5000)
```

## Notes

- Use a 64-bit target from a 64-bit Python. Native exceptions cannot unwind through the generated dispatcher.
- `capacity` is a power of two from 1 to 64; `submit` raises `BufferError` while that many tickets are unreleased.
- For a hot inline trigger, pass `quiescent_patch=True` to `InlineCallQueue`: it suspends the other target threads and checks their instruction pointers during installation, removal and code release.
- If no trampoline page is available within 2 GB, `InlineCallQueue` uses a 15-byte absolute jump and needs that much relocatable entry code.
- Closing the queue (also on leaving `with`) refuses pending tickets: wait for every ticket first.
- `ticket.wait` raises `ProcessLookupError` if the target exits before the call completes.
- The plain hooks without a queue are in [index.md](index.md#inline-hook) (`InlineHook`, `VTableHook`).
