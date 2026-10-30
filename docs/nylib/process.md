# nylib.process

Read and write another process's memory, call its functions remotely, and manage its module list. Use it to inspect or modify a running game, hook functions, inject DLLs, or test memory operations cross-process.

Keywords: Process, Thread, RemoteCall, read memory, write memory, function call, QueueUserAPC, APC, get_thread, iter_threads, DLL injection, PEB, export, pattern scan, module list, get_proc_address, enum_exports, load_library, ReadProcessMemory, WriteProcessMemory, rpm

## Quick start

Create a `Process` from a PID or name; read/write memory with typed accessors; call remote functions and await the result.

```python
# needs: a running target process

from nylib.process import Process

# Attach to a running process by name or PID.
p = Process.from_name('game.exe')
# or: p = Process(12345)

# Read a 32-bit integer at a remote address.
value = p.read_u32(0x140000000)

# Write a string.
p.write_string(0x140001000, 'hello')

# Call a remote function (address), await the result.
result = p.call(0x140010000, 100, 200)

# Call without blocking; check when ready.
pending = p.call(func_address, 1, 2, block=False)
# pending.done -> True when the call finishes
# pending.wait() -> blocks and returns the result
```

## Read and write memory

```python
from nylib.process import Process
from nylib import winapi

p = Process.current

# Read/write individual values.
p.read_u8(id(p))         # unsigned byte
p.read_i32(id(p))        # signed 32-bit
p.read_u64(id(p))        # unsigned 64-bit
p.read_float(id(p))
p.read_ptr(id(p))        # pointer-sized (usize)

# Read a ctypes struct; copied once via ReadProcessMemory.
peb = p.read(p.process_basic_information.PebBaseAddress, winapi.PEB)
```

## Enumerate modules

```python
# needs: a running target process

# Iterate loaded DLLs.
for ldr_entry in p.enum_ldr_data():
    print(ldr_entry.BaseDllName.remote_value(p))  # module name
    print(hex(ldr_entry.DllBase))                  # base address

# Get a specific module; cache is consulted first.
kernel32 = p.get_ldr_data('kernel32.dll')
print(hex(kernel32.DllBase))

# Get and call an export by name.
addr = p.get_proc_address('kernel32.dll', 'GetTickCount')
result = p.call(addr)

# Enumerate all exports from a module.
for export in p.enum_exports('kernel32.dll'):
    print(export.name, hex(export.address))
```

## Threads and APC calls

Open the target's threads, then run a call on an existing thread through `QueueUserAPC` instead of a new remote thread.

```python
# needs: a running target process and an alertable target thread

for thread in p.iter_threads():
    with thread:
        print(thread.thread_id, thread.process_id)

with p.get_thread(thread_id) as thread:
    # Execute on this existing thread, with automatic suspend/queue/resume.
    pending = p.call(func_address, 1, 2, queue_apc_thread=thread, block=False)
    result = pending.wait(5000)
```

- `get_thread(thread_id, da=0x1FFFFF)` validates that the thread belongs to the process; `iter_threads(da=0x1FFFFF)` opens the process's threads from a Toolhelp snapshot, skipping a thread that exited after the snapshot or whose id another process reused; other `OpenThread` errors raise. Each returned `Thread` owns its handle: use `with thread:` or call `thread.close()`.
- `thread.suspend()` and `thread.resume()` return the previous suspend count. `thread.description()` returns the name set by `SetThreadDescription`, or `None` if unnamed; `thread.creation_time()` returns a FILETIME (100-ns ticks since 1601), and the earliest thread of a process is its initial thread. Both raise `OSError` without `THREAD_QUERY_LIMITED_INFORMATION`.
- `call(..., queue_apc_thread=None)` uses `CreateRemoteThread` by default; a `Thread` or a local thread handle selects [`QueueUserAPC`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc). The thread must belong to the target process and allow query, suspend/resume and set-context access; the process handle also needs `PROCESS_DUP_HANDLE` for the completion event. `Process.current.call` takes another thread of the current process; selecting the calling thread raises `ValueError`.
- The APC runs when the target thread enters an alertable wait, such as `SleepEx(..., True)`. Suspending and resuming preserves its previous suspend count and does not force an ordinary thread to become alertable; a thread that was already suspended stays suspended until its owner resumes it.
- Blocking calls and `RemoteCall.done` / `.wait()` track callback completion; the target thread can keep running afterward. A timeout leaves the call pending: keep the `RemoteCall` and wait again. Dropping a pending call retains its remote code and completion resources until process exit.
- If queueing succeeds but resuming fails, an `OSError` is raised and the queued callback memory is retained. Finish pending calls before closing the process handle.

## Pattern scanning

```python
# needs: a running target process with loaded DLL

# Create a cached scanner for a DLL; speeds repeated scans.
scanner = p.scanner('game.dll')
matches = scanner.search('48 8B EC 48 81 EC ?? ?? ?? ??')
for addr, captured in matches:
    print(hex(addr))

# Static PE scanner (from disk image, not live memory).
static = p.static_scanner('game.dll')
```

## Allocate and call

```python
from nylib.process import Process

# Process.call() stores bytes arguments in a Namespace automatically.
p = Process.current
strlen = p.call(p.get_proc_address('kernel32.dll', 'lstrlenA'), b'hello')
print(strlen)  # 5
```

```python
# needs: a running target process

# Namespace: allocate and manage temporary memory.
with p.name_space() as ns:
    data_ptr = ns.store(b'some data')
    # Pass the pointer to a remote function.
    result = p.call(remote_func_ptr, data_ptr)
    # Automatically freed on __exit__.
```

## Load a DLL

```python
# needs: target process with thread and VM rights

# Inject a DLL by calling LoadLibraryA in the remote process.
module_handle = p.load_library('C:/path/to/my.dll')
```

## Process.current

```python
from nylib.process import Process

# The current (host) process.
p = Process.current

# Read/write is zero-copy via ctypes.from_address()
# (a bad address crashes the interpreter, not a graceful error).

# But you can safely inspect it:
print(p.process_id)
print(hex(p.peb.ProcessParameters))  # access PEB fields
```

## Notes

- `Process.current` reads via `ctypes.from_address()` — a bad address crashes the interpreter instead of raising. To get error handling, open `Process(pid)` even for the same PID (reads via `ReadProcessMemory`).
- `read(address, type_)` accepts a ctypes type or an int (byte count); returns the struct (copied once) or raw bytes.
- Calling `p.call(..., block=False)` returns a `RemoteCall` handle. Call `.wait()` to block for the result, or check `.done` to poll.
- `Namespace` allocates aligned chunks. `.store(data)` writes and returns the pointer; `.free()` deallocates, or use it as a context manager.
- `scanner(dll_name)` scans only that module's memory, not all committed regions. `static_scanner()` scans the PE file on disk.
