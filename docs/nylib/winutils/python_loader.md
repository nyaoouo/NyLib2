# nylib.winutils.python_loader

Inject and run Python code in a remote Win32 process. The loader initializes CPython in the target via `PyConfig`, supports script reuse across multiple injections, and can ship payloads without writing to the target's filesystem.

Keywords: inject, python, remote process, DLL, code execution, PyConfig, script packing, host-guest communication, debugging, DebugView, process injection, pipe RPC

## Quick start

Inject a script into a running process and execute code inside it.

```python
# needs: a running notepad.exe process
from nylib.process import Process
from nylib.winutils.python_loader import run_script

target = Process.from_name('notepad.exe')
run_script(target, 'my_inject_script.py')
```

## Build the loader DLL

The C++ loader must be compiled before injection; do this once per development session.

```python
# needs: MSVC on PATH (install Visual Studio; use ensure_msvc for compatibility)
from nylib.winutils.python_loader import build_loader, ensure_loader_dll

# Compile python_loader.cpp to python_loader.dll (overwrites any existing file).
dll = ensure_loader_dll()  # returns path, builds on demand

# Or rebuild explicitly.
dll = ensure_loader_dll(rebuild=True)
```

## Inject and run Python code

Execute code strings or files in the target process; the interpreter is reused across calls by default.

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

## Pack and inject self-contained payloads

Package a script and its sibling modules into a single self-extracting Python source, then inject without writing to the target filesystem.

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

## Debug with DebugView or log file

Loader phases are traced via `OutputDebugStringW` and `log_path` parameter.

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

## Communicate via pipe RPC

Guest and host talk via named pipes and `RpcServer` / `RpcClient` (see `pipe_rpc` for details).

```python
# needs: target is running an RpcServer on \\.\pipe\myrpc
from nylib.winutils.pipe_rpc import RpcClient

client = RpcClient(r'\\.\pipe\myrpc')
result = client.rpc.add(2, 3)  # calls guest's add function
```

## Command-line interface

Build the DLL: `./.venv/Scripts/python.exe -m nylib.winutils.python_loader build --rebuild`

Inject a script: `./.venv/Scripts/python.exe -m nylib.winutils.python_loader inject --process notepad.exe --script script.py`

Inject inline code: `./.venv/Scripts/python.exe -m nylib.winutils.python_loader inject --process notepad.exe --code "print(42)"`

Pack a script: `./.venv/Scripts/python.exe -m nylib.winutils.python_loader pack --script script.py --out payload.py`

Query injected state: `./.venv/Scripts/python.exe -m nylib.winutils.python_loader info --process 1234`

## Notes

- **SeDebugPrivilege**: Opening processes of other users or elevated processes requires `SeDebugPrivilege`. The `inject` subcommand calls `enable_privilege()` (best-effort) to acquire it; same-user, non-elevated processes may work without it.
- **Python bitness**: The code is built x64 only (`_PTR_SIZE = 8`); target bitness not explicitly checked.
- **Python version consistency**: The target must have the same major.minor version of `python3XX.dll` (e.g., `python311.dll`) as the host. Pass `python_dll=` and `python_home=` to override discovery if the target has a different layout.
- **PyInstaller bundles**: If the host is bundled with PyInstaller, `default_python_home()` and `default_python_dll()` detect `_MEIPASS` automatically, so injection into PyInstaller-bundled targets works. Non-bundled targets use `base_prefix` to avoid venv stdlib missing errors.
- **Interpreter reuse**: The loader reuses the Python interpreter across multiple `run_code()` / `run_script()` calls (set `reuse=False` to disable). LoadPython uses a `ScopedLock` (CRITICAL_SECTION) to serialize access, and the interpreter runs on a worker thread via PyGILState_Ensure/Release, so concurrent injections are thread-safe.
- **Alternative entry point**: `python_hijack.md` describes an alternative: `python_hijack` builds a proxy DLL that intercepts DLL load and starts Python on `DLL_PROCESS_ATTACH`; use it when `python_loader` cannot open the target.
