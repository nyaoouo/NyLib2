# nylib.winapi

Typed ctypes wrappers around Windows kernel32, ntdll, user32, advapi32, shell32, ole32, msvcrt, version and propsys DLLs. Every API raises on failure by default; call with `_ignore_error=True` to suppress.

Keywords: Win32 API, ctypes, kernel32, ntdll, user32, OpenProcess, ReadProcessMemory, VirtualQueryEx, NtQueryInformationProcess, def_win_api, _gil, PyDLL, GIL, WinError, process memory, token privileges, PEB, HANDLE, NTSTATUS, NYLIB_WINAPI_THUNK

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

The DLL loads and the export resolves on the first call, using a DLL cache shared by every binding.

```python
from nylib.winapi.utils import def_win_api
import ctypes

GetTickCount = def_win_api('kernel32.dll', 'GetTickCount', ctypes.c_uint32, ())
ms = GetTickCount()
print(f'Milliseconds since boot: {ms}')
```

## Notes

- All wrapped functions raise `ctypes.WinError` on failure (with NTSTATUS functions raising `OSError`). Pass `_ignore_error=True` to any call to suppress this.
- For bindings with an error mode (`error_zero`, `error_nonzero`, `error_val`), read the call's code from the `use_last_error` copy with `ctypes.get_last_error()`, never `ctypes.GetLastError()`. Bindings without an error mode do not capture, so the copy keeps an older value after them. After importing `nylib.winapi`, nylib logs one warning when `ctypes.GetLastError()` is first called.
- Pass `_gil=True` to call through a GIL-holding PyDLL function: no other Python thread runs during the native call, and once resolved, the call releases the GIL nowhere. The first call in each mode may release it for DLL loading or export lookup; the first error-mode call in a process may release it several times while loading DLLs, resolving exports and setting up the stubs. Call `binding.resolve(gil=True)` ahead of a region that must hold the GIL.
- For wrappers that raise `ctypes.WinError` (not the NTSTATUS ones), the exception's `winerror` is the call's own Win32 code in either GIL mode. After a failed call with `_ignore_error=True`, read that code with `ctypes.get_last_error()`. A call that sets no code preserves that copy's previous value.
- On x64, a name-form binding with an error mode calls its export through a small machine-code stub that captures the last error natively. The binding captures it in Python with the same results if `NYLIB_WINAPI_THUNK=0` is set before the first such call, the process refuses executable memory (ACG), the interpreter is not x64, the binding has more than 16 argument types, the TLS index is 64 or more, function-table registration fails, or the self-test fails. After a call that sets a code, the thread still holds that code in either GIL mode: with `_gil=False` the stub leaves it there and the wrapper does not write it back again (except to repair a failed error-message lookup); with `_gil=True` the wrapper writes it back. On Python 3.13+ a GIL switch can overwrite the thread's value before the caller reads it.
- The legacy form `def_win_api(func, res_type, arg_types, ...)`, with a ctypes function, still works as before, with the error flags passed by keyword; it does not support `_gil=True`.
- Structures from `defs.py` (PEB, MEMORY_BASIC_INFORMATION, IMAGE_NT_HEADERS64, etc.) are re-exported; use `ctypes.byref()` to pass them to API calls.
- Most APIs use pseudo-handles like `GetCurrentProcess()` which do not need closing; others return `HANDLE` values that require `CloseHandle()`.
- NTSTATUS functions use `error_nt=True` and check `NT_SUCCESS(result)` — only raise if result is >= 0x80000000.
