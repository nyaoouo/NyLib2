> 本文档为 hook.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="hook.md" -->

<!-- dt:section id="__preamble__" hash="62a3fcb69a70" -->
# nylib.hook

包装 Microsoft Detours 以在运行时拦截并重定向函数调用。使用它来 hook Win32 函数、DLL 导出或目标进程中的任何地址。

关键词: Hook, create_hook, DetourTransaction, hook function, detour, trampoline, function interception, DetourAttach, DetourDetach, DetourTransactionBegin, DetourTransactionCommit, Win32 API hooking, function redirect, intercept calls, target address

<!-- dt:section id="quick-start-0" hash="456365758e20" -->
## Quick start

使用地址和签名创建一个 hook，然后安装它来开始拦截调用。

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

<!-- dt:section id="hook-with-a-decorator-0" hash="0a1958c5be46" -->
## Hook with a decorator

使用 `create_hook` 来内联定义 hook 函数，使用装饰器。

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

<!-- dt:section id="access-the-original-function-0" hash="c1280aaab2b8" -->
## Access the original function

原始函数的 trampoline 指针存储在 `hook.original` 中。直接调用它来调用未 hook 的代码。

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

<!-- dt:section id="manage-hook-lifecycle-0" hash="d59d8bd91778" -->
## Manage hook lifecycle

使用 `install()` 和 `uninstall()` 控制 hook 何时活跃。两者都是幂等的。

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

<!-- dt:section id="notes-0" hash="619a01133e85" -->
## Notes

- hook 函数作为其第一个参数接收 `Hook` 对象；所有其他参数与目标签名匹配。使用 `hook.original` 来调用未 hook 的代码。
- `Hook.install()` 和 `Hook.uninstall()` 是幂等的：在相同状态下多次调用它们是安全的。
- hooks 运行在由库管理的 `DetourTransaction` 中。不要在 hook 函数内手动调用 `DetourTransactionBegin` 或 `DetourTransactionCommit`。
- hook 必须保持活跃（不被垃圾回收）同时被安装；将其存储在模块级别或长期存在的变量中。
- 需要目标 DLL（`DetoursEx.dll`）存在于 Python 安装目录或冻结可执行文件旁边。
