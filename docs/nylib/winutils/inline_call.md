# nylib.winutils.inline_call

Run a bounded batch of function calls on a target's own thread the next time it enters a chosen function, then continue into the original code. `InlineCallQueue` patches a function entry; `VTableCallQueue` replaces a vtable pointer slot. `nylib.ue`'s `calls='game-thread'` is built on `InlineCallQueue`.

Keywords: InlineCallQueue, VTableCallQueue, CallTicket, call queue, batch call, inline hook, vtable hook, function entry, game thread, thread_id, quiescent_patch, submit, withdraw, withdrawn, exit_slot, x64

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

`ticket.withdraw()` returns `True` if it stops a waiting call, which then never runs; it also returns `True` when already withdrawn. It returns `False` if the call has started, finished or its result was already taken. A ticket ended by a target exit raises its `ProcessLookupError` instead. This works for both queue types; a timeout alone does not withdraw a ticket.

`ticket.withdrawn` records an explicit withdrawal, and `ticket.done` is then `True`. Both `wait()` and `close()` raise `RuntimeError('inline call was withdrawn')`, including a wait on another thread. A withdrawn ticket does not prevent disabling or closing the queue, but its slot can be reused only after the dispatcher has passed it; `submit` can still raise `BufferError` until then.

The slot states are 0 free, 1 waiting, 2 running, 3 done and 4 withdrawn. When `wait()` detects a target exit, or the queue closes after detecting one, it atomically withdraws any affected call still waiting and records the slot state it found in `ticket.exit_slot`:

| `exit_slot` | Meaning |
| --- | --- |
| `1` | The exit withdrew the waiting call; it never runs, even if an exiting thread later enters the trigger. |
| `2` | The dispatcher had started the call; its outcome is unknown. |
| `3` | The call finished. |
| `4` | Not expected: a withdrawn call is no longer tracked when the exit is handled. It never runs. |
| `None` | The ticket has not ended because of a target exit. |

Reading `exit_slot` never accesses target memory. A ticket a target exit ended keeps `withdrawn` false whatever its `exit_slot`, and its `wait()`, `close()` and `withdraw()` raise its `ProcessLookupError`; a finished call's result is not returned.

## Drain on one thread

Pass `thread_id` to let only that thread run queued calls; other threads continue into the original function. A nonexistent thread id leaves calls pending until timeout.

```python
# needs: a 64-bit target process, capstone, keystone
with InlineCallQueue(process, trigger_at, thread_id=game_tid) as hook:
    hook.call(func_at, timeout_ms=5000)
```

## Notes

- Use a 64-bit target from a 64-bit Python. Native exceptions cannot unwind through the generated dispatcher.
- Only one drain runs at a time across all threads, using a queue-header flag acquired by exchange. An entry while a drain runs, including a queued call re-entering the trigger, runs the original function and drains nothing. Calls run one at a time in submit order, each returning before the next starts; at most `capacity` calls run per entry. A withdrawn slot is skipped in its turn and leaves the drain flag unchanged.
- `capacity` is a power of two from 1 to 64; `submit` raises `BufferError` while that many tickets are unreleased.
- For a hot inline trigger, pass `quiescent_patch=True` to `InlineCallQueue`: it suspends the other target threads and checks their instruction pointers during installation, removal and code release. The quiescent window works on the queue's process handle directly, which needs VM operation, read and write access, and it does not use overridden `Process` memory methods.
- If no trampoline page is available within 2 GB, `InlineCallQueue` uses a 15-byte absolute jump and needs that much relocatable entry code.
- Pass `_jmp_support=1` to relocate direct `jmp` and `Jcc` entry instructions; the default still rejects them.
- Closing the queue (also on leaving `with`) refuses pending tickets while the target is alive: wait for or withdraw every ticket first.
- The queue obtains its local and target views through `Process.map_shared`; adapters can provide another shared-memory backend.
- `ticket.wait` raises `ProcessLookupError` if the target exits before the call completes.
- A target reported as exited may still have a thread running. With the native `Process.map_shared` backend, closing a queue after detecting an exit releases only the host's view; the target's queue view, dispatcher page and hook stay until its address space goes away. A custom mapping uses its own `close()` implementation.
- The plain hooks without a queue are in [index.md](index.md#inline-hook) (`InlineHook`, `VTableHook`).
