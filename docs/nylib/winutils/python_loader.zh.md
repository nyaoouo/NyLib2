> 本文档为 python_loader.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="python_loader.md" -->

<!-- dt:section id="__preamble__" hash="3490bdc0f986" -->
# nylib.winutils.python_loader

在远程 Win32 进程中注入并运行 Python 代码。加载器通过 `PyConfig` 在目标进程中初始化 CPython，支持在多次注入中重用脚本，并可以在不向目标文件系统写入的情况下交付负载。

关键词: inject, python, remote process, DLL, code execution, PyConfig, script packing, host-guest communication, debugging, DebugView, process injection, pipe RPC

<!-- dt:section id="quick-start-0" hash="abf7de03e659" -->
## 快速开始

向运行的进程注入脚本并在其中执行代码。

```python
# needs: a running notepad.exe process
from nylib.process import Process
from nylib.winutils.python_loader import run_script

target = Process.from_name('notepad.exe')
run_script(target, 'my_inject_script.py')
```

<!-- dt:section id="build-the-loader-dll-0" hash="7b32d5471910" -->
## 构建加载器 DLL

在注入前必须编译 C++ 加载器；在每个开发会话中执行一次。

```python
# needs: MSVC on PATH (install Visual Studio; use ensure_msvc for compatibility)
from nylib.winutils.python_loader import build_loader, ensure_loader_dll

# Compile python_loader.cpp to python_loader.dll (overwrites any existing file).
dll = ensure_loader_dll()  # returns path, builds on demand

# Or rebuild explicitly.
dll = ensure_loader_dll(rebuild=True)
```

在冻结应用中，`ensure_loader_dll` 从不编译：缺失的 DLL 会抛出 `FileNotFoundError`，`rebuild=True` 会抛出 `RuntimeError`。在冻结前使用 `build_loader()` 预先编译；PyInstaller 钩子仅在已安装 MSVC 时才会自行编译缺失的 DLL，否则记录一条 WARNING。

<!-- dt:section id="inject-and-run-python-code-0" hash="565193d56210" -->
## 注入并运行 Python 代码

在目标进程中执行代码字符串或文件；解释器默认在多个调用中被重用。

```python
# needs: a running target process
from nylib.process import Process
from nylib.winutils.python_loader import run_code, run_script

target = Process.from_name('notepad.exe')

# Inject a code string (handy for one-offs and debugging).
rc = run_code(target, "print('hello from', __name__); import sys; print(sys.version)")

# Or run a script file from disk.
rc = run_script(target, 'script.py')

# Interpreter persists across calls (PLF_REUSE_INTERPRETER is the default).
run_code(target, "x = 42")
run_code(target, "print(x)")  # prints 42
```

<!-- dt:section id="pack-and-inject-self-contained-payloads-0" hash="d21a282434e4" -->
## 打包和注入自包含负载

将脚本及其同级模块打包为单个自解压的 Python 源代码，然后注入而不向目标文件系统写入。

```python
# needs: my_pkg/__init__.py and sibling modules on disk; a running game.exe process
from nylib.process import Process
from nylib.winutils.python_loader import pack_script, run_packed

# Pack a script tree: my_pkg/__init__.py and siblings -> single .py source.
payload = pack_script('my_pkg/__init__.py', is_main=True)

# Or: convenience wrapper packs and injects in one call.
target = Process.from_name('game.exe')
rc = run_packed(target, 'my_pkg/__init__.py')

# The injected code can now import sibling modules by name.
# In my_pkg/__init__.py: from . import helper_module  # works
```

<!-- dt:section id="debug-with-debugview-or-log-file-0" hash="66dee69edfac" -->
## 使用 DebugView 或日志文件进行调试

加载器阶段通过 `OutputDebugStringW` 和 `log_path` 参数进行跟踪。

```python
# needs: a running target process
from nylib.winutils.python_loader import run_code
from nylib.process import Process

target = Process.from_name('notepad.exe')

# Monitor with Sysinternals DebugView (Capture Global + Win32 enabled).
run_code(target, "print('test')")

# Or write to a file with PID/TID headers.
run_code(target, "x = 1", log_path='C:/tmp/loader.log')
```

<!-- dt:section id="communicate-via-pipe-rpc-0" hash="5be7864d8eaa" -->
## 通过管道 RPC 通信

主进程和客进程通过命名管道和 `RpcServer` / `RpcClient` 通信（详见 `pipe_rpc`）。

```python
# needs: target is running an RpcServer on \\.\pipe\myrpc
from nylib.winutils.pipe_rpc import RpcClient

client = RpcClient(r'\\.\pipe\myrpc')
result = client.rpc.add(2, 3)  # calls guest's add function
```

<!-- dt:section id="command-line-interface-0" hash="b8ca0c36e237" -->
## 命令行接口

构建 DLL：`./.venv/Scripts/python.exe -m nylib.winutils.python_loader build --rebuild`

注入脚本：`./.venv/Scripts/python.exe -m nylib.winutils.python_loader inject --process notepad.exe --script script.py`

注入内联代码：`./.venv/Scripts/python.exe -m nylib.winutils.python_loader inject --process notepad.exe --code "print(42)"`

打包脚本：`./.venv/Scripts/python.exe -m nylib.winutils.python_loader pack --script script.py --out payload.py`

查询注入状态：`./.venv/Scripts/python.exe -m nylib.winutils.python_loader info --process 1234`

<!-- dt:section id="notes-0" hash="daa88aee087b" -->
## 注意

- **SeDebugPrivilege**：打开其他用户或提升权限的进程需要 `SeDebugPrivilege`。`inject` 子命令调用 `enable_privilege()`（尽力而为）来获取它；同一用户、非提升权限的进程可能无需它即可工作。
- **Python 位数**：代码仅以 x64 构建（`_PTR_SIZE = 8`）；目标位数未显式检查。
- **Python 版本一致性**：目标必须与主机具有相同的 `python3XX.dll` 主版本号（例如 `python311.dll`）。如果目标具有不同的布局，请传递 `python_dll=` 和 `python_home=` 来覆盖发现。
- **PyInstaller 包**：如果主机与 PyInstaller 打包，`default_python_home()` 和 `default_python_dll()` 会自动检测 `_MEIPASS`，因此注入到 PyInstaller 打包的目标中可行。非打包的目标使用 `base_prefix` 以避免 venv stdlib 丢失错误。
- **解释器重用**：加载器在多个 `run_code()` / `run_script()` 调用中重用 Python 解释器（设置 `reuse=False` 以禁用）。LoadPython 使用 `ScopedLock`（CRITICAL_SECTION）序列化访问，解释器通过 PyGILState_Ensure/Release 在工作线程上运行，因此并发注入是线程安全的。
- **替代入口点**：`python_hijack.md` 描述了一个替代方案：`python_hijack` 构建一个代理 DLL，拦截 DLL 加载并在 `DLL_PROCESS_ATTACH` 上启动 Python；当 `python_loader` 无法打开目标时使用它。
