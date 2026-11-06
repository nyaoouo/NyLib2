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

<!-- dt:section id="notes-0" hash="db6fcb23edf4" -->
## 注意事项

- **SeDebugPrivilege**：打开其他用户的进程或提权进程需要 `SeDebugPrivilege`。`inject` 子命令会调用 `enable_privilege()`（尽力而为）来获取该权限；同一用户的非提权进程可能无需该权限即可工作。
- **Python 位数**：代码仅按 x64 构建（`_PTR_SIZE = 8`）；不会显式检查目标的位数。
- **Python 版本一致性**：目标必须具有与宿主相同主次版本的 `python3XX.dll`（例如 `python311.dll`）。如果目标的布局不同，请传入 `python_dll=` 和 `python_home=` 以覆盖自动发现。
- **PyInstaller 包**：默认值会让被注入的解释器指向宿主自身的文件：`default_python_home()` 对打包后的宿主（冻结宿主）使用 `sys._MEIPASS`，对普通宿主（包括 venv）使用 `sys.base_prefix`；`default_python_dll()` 查找宿主的 Python DLL，`default_python_paths()` 复制宿主现有的搜索路径并添加可编辑安装的源码根目录。加载器 DLL 默认取模块旁边的文件。这些默认值适用于普通的、未打包的宿主。对于 PyInstaller 宿主（onedir 或 onefile），标准库、`nylib` 和应用中的大多数纯 Python 模块都位于 exe 的 PYZ 归档中，只有宿主的冻结导入器才能读取。目标中的普通解释器只能访问 `base_library.zip` 中的引导子集、扩展模块（`.pyd`）和数据文件；诸如 `ctypes`、`json`、`pickle`、`base64` 和 `nylib.process` 之类的导入会失败，目录形式的 `pack_script` / `run_packed` 负载也会失败，因为它会导入 `base64` 和 `pickle`（单个文件则作为其自身的源码原样传递）。要从打包后的宿主注入，请传入 `python_dll=`、`python_home=` 和 `python_paths=`，指向与宿主相同主次版本的常规 Python 安装（该安装中已安装 `nylib` 及负载的其他导入，或将其列在 `python_paths` 中），并传入 `loader=`，指向位于 `_MEIPASS` 之外的加载器 DLL。onefile 宿主在退出时还会删除其临时的 `_MEIPASS` 文件夹，这又增加了第二个失败原因。
- **解释器复用**：加载器在多次 `run_code()` / `run_script()` 调用之间复用 Python 解释器（设置 `reuse=False` 可禁用）。LoadPython 使用 `ScopedLock`（CRITICAL_SECTION）来串行化访问，解释器通过 PyGILState_Ensure/Release 在工作线程上运行，因此并发注入是线程安全的。
- **替代入口**：`python_hijack.md` 描述了一种替代方案：`python_hijack` 构建一个代理 DLL，拦截 DLL 加载并在 `DLL_PROCESS_ATTACH` 时启动 Python；当 `python_loader` 无法打开目标时使用它。
