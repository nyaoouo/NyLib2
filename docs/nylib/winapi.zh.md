> 本文档为 winapi.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="winapi.md" -->

<!-- dt:section id="__preamble__" hash="7aac5ea1522c" -->
# nylib.winapi

围绕 Windows kernel32、ntdll、user32、advapi32、shell32、ole32、msvcrt、version 和 propsys DLL 的类型化 ctypes 包装器。每个 API 默认在失败时引发异常；使用 `_ignore_error=True` 调用以禁用此行为。

关键词: Win32 API、ctypes、kernel32、ntdll、user32、OpenProcess、ReadProcessMemory、VirtualQueryEx、NtQueryInformationProcess、def_win_api、_gil、PyDLL、GIL、WinError、process memory、token privileges、PEB、HANDLE、NTSTATUS

<!-- dt:section id="quick-start-0" hash="6c13a3981f9b" -->
## 快速开始

```python
from nylib.winapi import GetCurrentProcessId, GetCurrentProcess

pid = GetCurrentProcessId()
print(f'PID: {pid}')
proc_handle = GetCurrentProcess()  # always succeeds
```

<!-- dt:section id="query-process-memory-0" hash="880e50f00805" -->
## 查询进程内存

```python
import ctypes
from nylib.winapi import GetCurrentProcess, VirtualQueryEx, MEMORY_BASIC_INFORMATION

proc = GetCurrentProcess()
info = MEMORY_BASIC_INFORMATION()
addr = 0x400000
VirtualQueryEx(proc, addr, ctypes.byref(info), ctypes.sizeof(info))
print(f'Region: {info.BaseAddress:#x}, size: {info.RegionSize}')
```

<!-- dt:section id="read-process-information-from-peb-0" hash="66b3c3923a24" -->
## 从 PEB 读取进程信息

```python
import ctypes
from nylib.winapi import GetCurrentProcess, NtQueryInformationProcess, PROCESS_BASIC_INFORMATION

proc = GetCurrentProcess()
info = PROCESS_BASIC_INFORMATION()
NtQueryInformationProcess(proc, 0, ctypes.byref(info), ctypes.sizeof(info), None)
print(f'PEB at {info.PebBaseAddress:#x}')
```

<!-- dt:section id="manage-process-tokens-0" hash="0ae4f0442679" -->
## 管理进程令牌

```python
# 需要：启用 SeDebugPrivilege 的管理员权限
import ctypes
from nylib.winapi import GetCurrentProcess, OpenProcessToken, LookupPrivilegeValue, TOKEN_PRIVILEGES, AdjustTokenPrivileges

proc = GetCurrentProcess()
token = ctypes.c_void_p()
OpenProcessToken(proc, 0x0028, ctypes.byref(token))

privs = TOKEN_PRIVILEGES()
privs.count = 1
LookupPrivilegeValue(None, 'SeDebugPrivilege', ctypes.byref(privs.Privileges[0].Luid))
privs.Privileges[0].Attributes = 0x00000002  # SE_PRIVILEGE_ENABLED
AdjustTokenPrivileges(token, False, ctypes.byref(privs), ctypes.sizeof(privs), None, None)
```

<!-- dt:section id="add-a-missing-api-0" hash="2652f8d705be" -->
## 添加缺失的 API

DLL 在第一次调用时加载、导出函数在第一次调用时解析，所有绑定共用一个 DLL 缓存。

```python
from nylib.winapi.utils import def_win_api
import ctypes

GetTickCount = def_win_api('kernel32.dll', 'GetTickCount', ctypes.c_uint32, ())
ms = GetTickCount()
print(f'Milliseconds since boot: {ms}')
```

<!-- dt:section id="notes-0" hash="5c1a024a2022" -->
## 注意事项

- 所有包装的函数在失败时引发 `ctypes.WinError`（NTSTATUS 函数引发 `OSError`）。传递 `_ignore_error=True` 给任何调用以禁用此行为。
- 对于带错误模式（`error_zero`、`error_nonzero`、`error_val`）的绑定，用 `ctypes.get_last_error()` 从 `use_last_error` 保存的那份副本读取该调用的错误码，不要用 `ctypes.GetLastError()`。没有错误模式的绑定不做捕获，调用之后副本里仍是之前的值。导入 `nylib.winapi` 之后，`ctypes.GetLastError()` 第一次被调用时，nylib 会记录一条警告。
- 传入 `_gil=True` 时，调用经由持有 GIL 的 PyDLL 函数进行：原生调用期间不会有其他 Python 线程运行，并且解析完成后，该调用在任何地方都不释放 GIL。每种模式的第一次调用可能因加载 DLL 或查找导出函数而释放一次 GIL；在必须持有 GIL 的代码段之前，先调用 `binding.resolve(gil=True)`。
- 对于引发 `ctypes.WinError` 的包装函数（NTSTATUS 函数除外），无论哪种 GIL 模式，异常的 `winerror` 都是该调用自身的 Win32 错误码。在 `_ignore_error=True` 的调用失败后，用 `ctypes.get_last_error()` 读取该错误码。不设置错误码的调用会让这份副本保持之前的值。包装函数会把报告的错误码写回线程，但在 Python 3.13+ 上，调用方读取之前，一次 GIL 切换就可能覆盖线程里的值，`_gil=True` 时尤其如此。
- 旧写法 `def_win_api(func, res_type, arg_types, ...)`（传入 ctypes 函数）仍按原来的方式工作，错误标志须以关键字参数传入；它不支持 `_gil=True`。
- 来自 `defs.py` 的结构体（PEB、MEMORY_BASIC_INFORMATION、IMAGE_NT_HEADERS64 等）被重新导出；使用 `ctypes.byref()` 将它们传递给 API 调用。
- 大多数 API 使用伪句柄，如 `GetCurrentProcess()`，不需要关闭；其他则返回需要 `CloseHandle()` 的 `HANDLE` 值。
- NTSTATUS 函数使用 `error_nt=True` 并检查 `NT_SUCCESS(result)` — 仅在结果 >= 0x80000000 时引发异常。
