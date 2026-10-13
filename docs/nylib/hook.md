# nylib.hook

Wrap Microsoft Detours to intercept and redirect function calls at runtime. Use it to hook Win32 functions, DLL exports, or any address in the target process.

Keywords: Hook, create_hook, DetourTransaction, hook function, detour, trampoline, function interception, DetourAttach, DetourDetach, DetourTransactionBegin, DetourTransactionCommit, Win32 API hooking, function redirect, intercept calls, target address

## Quick start

Create a hook with the address and signature, then install it to begin intercepting calls.

```python
# needs: installs hooks
import ctypes
import ctypes.wintypes
from nylib.hook import Hook

user32 = ctypes.CDLL('User32.dll')
MessageBoxW_orig = ctypes.CFUNCTYPE(
    ctypes.wintypes.INT,
    ctypes.wintypes.HWND,
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.UINT
)(user32.MessageBoxW)
MessageBoxW_addr = ctypes.cast(MessageBoxW_orig, ctypes.c_void_p).value

def my_hook(hook_obj, hwnd, title, message, flags):
    return hook_obj.original(hwnd, f"[HOOKED] {title}", message, flags)

hook = Hook(
    at=MessageBoxW_addr,
    hook_func=my_hook,
    restype=ctypes.wintypes.INT,
    argtypes=[ctypes.wintypes.HWND, ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR, ctypes.wintypes.UINT]
)
hook.install()
hook.uninstall()
```

## Hook with a decorator

Use `create_hook` to define the hook function inline with a decorator.

```python
# needs: installs hooks
import ctypes
import ctypes.wintypes
from nylib.hook import create_hook

user32 = ctypes.CDLL('User32.dll')
MessageBoxW_orig = ctypes.CFUNCTYPE(
    ctypes.wintypes.INT,
    ctypes.wintypes.HWND,
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.UINT
)(user32.MessageBoxW)
MessageBoxW_addr = ctypes.cast(MessageBoxW_orig, ctypes.c_void_p).value

@create_hook(
    at=MessageBoxW_addr,
    restype=ctypes.wintypes.INT,
    argtypes=[ctypes.wintypes.HWND, ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR, ctypes.wintypes.UINT],
    auto_install=True
)
def message_box_hook(hook_obj, hwnd, title, message, flags):
    return hook_obj.original(hwnd, f"Modified: {title}", message, flags)

message_box_hook.uninstall()
```

## Access the original function

The trampoline pointer to the original function is stored in `hook.original`. Call it directly to invoke the unhooked code.

```python
# needs: target process with function at address
import ctypes
from nylib.hook import Hook

# After hook.install(), hook.original is a callable that bypasses the hook
addr = 0x7FF6_0000_1234  # address of target function
hook = Hook(
    at=addr,
    hook_func=lambda hook_obj, x: x * 2,
    restype=ctypes.c_int,
    argtypes=[ctypes.c_int]
)
hook.install()

# Call through hook.original to execute original code
result = hook.original(42)
```

## Manage hook lifecycle

Control when the hook is active with `install()` and `uninstall()`. Both are idempotent.

```python
# needs: target process with function at address
import ctypes
from nylib.hook import Hook

addr = 0x7FF6_0000_1234  # address of target function
hook = Hook(
    at=addr,
    hook_func=lambda hook_obj, x: x + 1,
    restype=ctypes.c_int,
    argtypes=[ctypes.c_int]
)

# Install once; subsequent calls are no-ops
hook.install()
hook.install()  # still installed

# Uninstall to restore original
hook.uninstall()
hook.uninstall()  # still uninstalled

# Check state
print(hook.is_installed)  # True or False
```

## Notes

- The hook function receives the `Hook` object as its first argument; all other arguments match the target signature. Use `hook.original` to call the unhooked code.
- `Hook.install()` and `Hook.uninstall()` are idempotent: calling them multiple times on the same state is safe.
- Hooks run in a `DetourTransaction` managed by the library. Do not manually call `DetourTransactionBegin` or `DetourTransactionCommit` inside a hook function.
- The hook must stay alive (not garbage-collected) while installed; store it in a module-level or long-lived variable.
- Requires the target DLL (`DetoursEx.dll`) to be present in the Python installation directory or alongside the frozen executable.
