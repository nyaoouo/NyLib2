# nylib.winapi

Typed ctypes wrappers around Windows kernel32, ntdll, user32, advapi32, shell32, ole32, msvcrt, version and propsys DLLs. Every API raises on failure by default; call with `_ignore_error=True` to suppress.

Keywords: Win32 API, ctypes, kernel32, ntdll, user32, OpenProcess, ReadProcessMemory, VirtualQueryEx, NtQueryInformationProcess, def_win_api, WinError, process memory, token privileges, PEB, HANDLE, NTSTATUS

## Quick start

```python
from nylib.winapi import GetCurrentProcessId, GetCurrentProcess

pid = GetCurrentProcessId()
print(f'PID: {pid}')
proc_handle = GetCurrentProcess()  # always succeeds
```

## Query process memory

```python
import ctypes
from nylib.winapi import GetCurrentProcess, VirtualQueryEx, MEMORY_BASIC_INFORMATION

proc = GetCurrentProcess()
info = MEMORY_BASIC_INFORMATION()
addr = 0x400000
VirtualQueryEx(proc, addr, ctypes.byref(info), ctypes.sizeof(info))
print(f'Region: {info.BaseAddress:#x}, size: {info.RegionSize}')
```

## Read process information from PEB

```python
import ctypes
from nylib.winapi import GetCurrentProcess, NtQueryInformationProcess, PROCESS_BASIC_INFORMATION

proc = GetCurrentProcess()
info = PROCESS_BASIC_INFORMATION()
NtQueryInformationProcess(proc, 0, ctypes.byref(info), ctypes.sizeof(info), None)
print(f'PEB at {info.PebBaseAddress:#x}')
```

## Manage process tokens

```python
# needs: administrator rights to enable SeDebugPrivilege
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

## Add a missing API

```python
from nylib.winapi.utils import def_win_api
import ctypes

_dll = ctypes.WinDLL('kernel32.dll')
GetTickCount = def_win_api(_dll.GetTickCount, ctypes.c_uint32, ())
ms = GetTickCount()
print(f'Milliseconds since boot: {ms}')
```

## Notes

- All wrapped functions raise `ctypes.WinError` on failure (with NTSTATUS functions raising `OSError`). Pass `_ignore_error=True` to any call to suppress this.
- Structures from `defs.py` (PEB, MEMORY_BASIC_INFORMATION, IMAGE_NT_HEADERS64, etc.) are re-exported; use `ctypes.byref()` to pass them to API calls.
- Most APIs use pseudo-handles like `GetCurrentProcess()` which do not need closing; others return `HANDLE` values that require `CloseHandle()`.
- NTSTATUS functions use `error_nt=True` and check `NT_SUCCESS(result)` — only raise if result is >= 0x80000000.
