> 本文档为 process.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="process.md" -->

<!-- dt:section id="__preamble__" hash="92db441a67fa" -->
# nylib.process

读取和写入另一个进程的内存，远程调用其函数，并管理其模块列表。使用它来检查或修改正在运行的游戏，钩取函数，注入DLL，或测试跨进程内存操作。

关键词: Process, Thread, RemoteCall, read memory, write memory, function call, QueueUserAPC, APC, get_thread, iter_threads, DLL injection, PEB, export, pattern scan, module list, get_proc_address, enum_exports, load_library, ReadProcessMemory, WriteProcessMemory, rpm

<!-- dt:section id="quick-start-0" hash="a8c76e2f6f37" -->
## 快速开始

从 PID 或名称创建 `Process`；使用类型化访问器读取/写入内存；调用远程函数并等待结果。

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

<!-- dt:section id="read-and-write-memory-0" hash="7b4cb35fafdc" -->
## 读取和写入内存

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

<!-- dt:section id="enumerate-modules-0" hash="3a51502b96d5" -->
## 列举模块

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

<!-- dt:section id="threads-and-apc-calls-0" hash="d8fa331f5c6d" -->
## 线程与 APC 调用

打开目标进程的线程，然后通过 `QueueUserAPC` 而不是新建远程线程，在已有线程上运行调用。

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

- `get_thread(thread_id, da=0x1FFFFF)` 会验证该线程属于此进程；`iter_threads(da=0x1FFFFF)` 通过 Toolhelp 快照打开该进程的线程。每个返回的 `Thread` 拥有自己的句柄：使用 `with thread:` 或调用 `thread.close()`。
- `thread.suspend()` 和 `thread.resume()` 返回之前的挂起计数。`thread.description()` 返回由 `SetThreadDescription` 设置的名称，若未命名则返回 `None`；`thread.creation_time()` 返回 FILETIME（自 1601 年起的 100 纳秒刻度数），进程中最早的线程即其初始线程。两者在没有 `THREAD_QUERY_LIMITED_INFORMATION` 时都会抛出 `OSError`。
- `call(..., queue_apc_thread=None)` 默认使用 `CreateRemoteThread`；传入 `Thread` 或本地线程句柄则选用 [`QueueUserAPC`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)。该线程必须属于目标进程，并允许查询、挂起/恢复和设置上下文的访问权限；进程句柄还需要 `PROCESS_DUP_HANDLE` 以用于完成事件。`Process.current.call` 接受当前进程的另一个线程；选择调用线程自身会抛出 `ValueError`。
- 当目标线程进入可警报等待（例如 `SleepEx(..., True)`）时，APC 才会运行。挂起和恢复会保留其之前的挂起计数，并且不会强制普通线程变为可警报；已经处于挂起状态的线程会保持挂起，直到其所有者恢复它。
- 阻塞调用以及 `RemoteCall.done` / `.wait()` 跟踪的是回调的完成；目标线程之后可以继续运行。超时会使调用保持未完成状态：保留该 `RemoteCall` 并再次等待。丢弃一个未完成的调用会保留其远程代码和完成资源，直到进程退出。
- 如果入队成功但恢复失败，则会抛出 `OSError`，并保留已入队的回调内存。请在关闭进程句柄之前等待所有未完成的调用结束。

<!-- dt:section id="pattern-scanning-0" hash="75b1c346d8d2" -->
## 特征扫描

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

<!-- dt:section id="allocate-and-call-0" hash="11a85fc7a1ec" -->
## 分配并调用

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

<!-- dt:section id="load-a-dll-0" hash="cff7203cef3e" -->
## 加载 DLL

```python
# needs: target process with thread and VM rights

# Inject a DLL by calling LoadLibraryA in the remote process.
module_handle = p.load_library('C:/path/to/my.dll')
```

<!-- dt:section id="process-current-0" hash="685c6d6398e8" -->
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

<!-- dt:section id="notes-0" hash="f5dcf0464a69" -->
## 注意

- `Process.current` 通过 `ctypes.from_address()` 读取 — 坏地址会使解释器崩溃而不是抛出异常。要获得错误处理，即使是同一个 PID 也要打开 `Process(pid)`（通过 `ReadProcessMemory` 读取）。
- `read(address, type_)` 接受 ctypes 类型或整数（字节计数）；返回结构体（复制一次）或原始字节。
- 调用 `p.call(..., block=False)` 返回一个 `RemoteCall` 句柄。调用 `.wait()` 来阻塞等待结果，或检查 `.done` 来轮询。
- `Namespace` 分配对齐的块。`.store(data)` 写入并返回指针；`.free()` 释放，或将其作为上下文管理器使用。
- `scanner(dll_name)` 仅扫描该模块的内存，不扫描所有已提交的区域。`static_scanner()` 扫描磁盘上的 PE 文件。
