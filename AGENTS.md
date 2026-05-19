# AGENTS.md

Guide for coding agents (Claude, Copilot, Gemini, etc.) working in this
repository. Human-facing documentation lives in `readme.md`.

This file is intentionally self-contained: read it before touching code,
and read `.agent-memory/` for deeper conventions if it exists locally.

---

## 1. What `nylib` is

A Windows-only Python toolkit for game / process inspection, code
injection, function hooking, and on-screen Dear ImGui overlays. Most
modules are thin, typed `ctypes` wrappers over Win32 plus a few
hand-rolled C extensions.

- **Platform:** Windows x64. Many APIs (`WriteProcessMemory`,
  `Detours`, `IsUserAnAdmin`, ...) make no sense elsewhere.
- **Python:** 3.11 - 3.14. The shipped pyimgui `.pyd` filenames encode
  the ABI tag, so consumers must build their own against their CPython.
- **Install:** `pip install .` from a checkout, or
  `pip install -e .` for editable use. See section 5.

---

## 2. Repository layout

```
nylib/                       importable package
  __init__.py                (empty re-export shell)
  __pyinstaller/             PyInstaller hooks (auto-discovered via entry point)
  ctype/                     remote-process aware ctypes accessors
  hook/                      Microsoft Detours wrapper (`Hook`, `create_hook`)
  imguiutils/                widgets & FA icon TTFs for the pyimgui frontend
  mono/                      Unity / Mono runtime inspector
  pattern.py                 IDA-style "AA BB ?? CC" scanner
  process/                   `Process` class - memory R/W, module enum, scan
  pyimgui/                   stub package - native `.pyd` built by the user
  structs/                   PDB / DWARF struct helpers
  tkinter_/                  small tkinter extras
  utils/                     pip bootstrap, eventloop, threading, web, ...
  winapi/                    typed ctypes for kernel32 / ntdll / user32 / ...
  winutils/                  high-level Win32 helpers (see section 4)

scripts/                     dev-only tools (NOT installed; not in the wheel)
  dxtest/                    DirectX 9/10/11/12 injection smoke tests
  generate_bind/             pybind11 binding generator from C headers
  ida/                       IDA Pro loaders & sig workers
  pyimgui/  pyimgui2/        build scripts for the `pyimgui` C extension
  sig_thief/                 signature thief (PE Authenticode)
  test_inject/               sample injection target

pyproject.toml               package metadata + PyInstaller entry point
readme.md                    short user-facing intro & example
license.txt                  GPL v3
.agent-memory/               local-only notes for AI agents (git-ignored)
```

`scripts/` is **outside** the installable package on purpose. Anything
under `nylib/` ships in the wheel; anything under `scripts/` is a
development tool and is only available from a checkout.

---

## 3. Module reference

Treat this section as the public API map. Imports shown are the
canonical entry points.

### `nylib.process`

```python
from nylib.process import Process
```

- `Process.from_name(name)` / `Process.from_id(pid)` - construct from a
  process name (bytes or str) or PID.
- `Process.current` - the calling process.
- Memory: `alloc`, `free`, `read(addr, type)`, `write(addr, value)`,
  `virtual_query`, `virtual_protect`, `iter_memory_region`,
  `alloc_near`.
- Modules: `enum_ldr_data()`, `get_module(name)`, `base_address`.
- Scanning: cached `CachedRawMemoryPatternScanner` and
  `StaticPatternSearcher` via `Process` helpers (see `pattern.py`).

### `nylib.winapi`

Typed `ctypes` wrappers around the Win32 surface used internally:
`kernel32`, `ntdll`, `user32`, `advapi32`, `shell32`, `msvcrt`. Plus
`utils.py` with helpers such as `DEFAULT_ENCODING` and small `byref`
wrappers. Prefer importing the symbol you need directly:

```python
from nylib.winapi import OpenProcess, ReadProcessMemory, MEMORY_BASIC_INFORMATION
```

### `nylib.winutils`

High-level Win32 helpers; subpackages are loaded lazily.

| Module | Purpose |
| --- | --- |
| `winutils.process` | `enable_privilege()`, `run_admin()`, `iter_processes()`, `pid_by_executable()`, `create_suspend_process` |
| `winutils.ensure_env` | locate / install Visual Studio + Windows SDK + LLVM toolchains |
| `winutils.msvc` | `load_vcvarsall(arch)` and friends |
| `winutils.llvm_pdb` | PDB symbol helpers via LLVM |
| `winutils.driver` | minimal kernel-driver helpers |
| `winutils.inline_hook` | hot-patch trampoline based on `keystone-engine` + `capstone` |
| `winutils.pe_unmap` | rebuild an in-memory PE back to its on-disk layout |
| `winutils.pipe`, `winutils.pipe_rpc` | named-pipe transport plus a tiny RPC layer (used by `python_loader` host <-> guest) |
| `winutils.python_hijack` | build a stub DLL that proxies a real DLL and runs Python on attach |
| `winutils.python_loader` | C source for an in-process Python loader (`python_loader.cpp`) |
| `winutils.sign` | Authenticode helpers - `bypass.py` (memory patching) and `native.py` |

`python_hijack` and `python_loader` are how you get arbitrary Python
into a third-party process. The hijack flow compiles a tiny C++ proxy
from `dllmain.template.cpp` next to the target DLL; the loader is the
in-process side.

### `nylib.hook`

Microsoft Detours wrapper:

```python
from nylib.hook import Hook, create_hook
```

- `Hook(addr, callback, restype, argtypes)` - manual install/uninstall.
- `@create_hook(addr, restype, argtypes)` - decorator form.
- Inside the callback, `hook.original(*args)` invokes the original.
- The Detours `.dll` is loaded lazily via
  `nylib.hook.detours`; ship it next to the binary when freezing.

### `nylib.pattern`

IDA-flavoured byte-pattern scanner used by `Process`:

```python
from nylib.pattern import CachedRawMemoryPatternScanner, StaticPatternSearcher
scanner = StaticPatternSearcher.from_pe(pe_path)
for addr in scanner.search('48 8B ?? ?? ?? ?? ?? 48 8B ??'):
    ...
```

### `nylib.ctype`

Drop-in `ctypes`-style declarative structures that read/write through
an *accessor* - usually `CAccessorProcess(process)` so the same struct
definition works on local memory and on another process's memory.

### `nylib.pyimgui` (build-it-yourself)

Direct Dear ImGui bindings produced from the C++ headers. **The
compiled `.pyd` files are not shipped** - they are CPython-ABI-specific
and the build chain depends on a local MSVC + libclang setup.

Generator entry points:

- `scripts/pyimgui2/pyimgui_generate.py` - current generator
  (`pyimgui2`, supports DX9/10/11/12 frontends and inbound hooks).
- `scripts/pyimgui/pyimgui_generate.py` - legacy.

Typical workflow on a fresh checkout:

```bash
# uses MSVC + libclang via nylib.winutils.ensure_env
.\.venv\Scripts\python.exe scripts\pyimgui2\pyimgui_generate.py --skip --skip-stubs
# regenerate stubs
.\.venv\Scripts\python.exe scripts\pyimgui2\pyimgui_generate.py --skip
```

Build outputs are copied into `nylib/` so `import nylib.pyimgui` works
directly after a build. At import time the core `pyimgui.pyd` rewrites
its own `__path__` so frontend submodules (`pyimgui.dx9`,
`pyimgui.dx11`, ...) load from the sibling `pyimgui/` directory.

Inbound (in-process) overlays:

```python
from nylib.pyimgui import Dx11Inbound, Dx12Inbound  # plus Dx9/Dx10/Vk/Gl3
```

Standalone windows:

```python
from nylib.pyimgui import Dx11Window
```

See `scripts/pyimgui2/pyimgui_test.py` for a runnable demo.

### `nylib.imguiutils`

Higher-level pyimgui widgets that depend on the user having a working
`nylib.pyimgui`:

- `alerts.py`, `message_box.py` - modal helpers.
- `file_dialog.py` - native-style file dialog implemented in pyimgui.
- `window_manager.py` - multi-window orchestration.
- `icons/` - Font Awesome TTFs (`solid`, `regular`) plus generated
  unicode-name constants. The TTFs are shipped in the wheel; they are
  loaded with `atlas.AddFontFromFileTTF`.

### `nylib.mono`

Tools for inspecting Unity / Mono games at runtime:

- `defines/` - typed handles for `MonoDomain`, `MonoImage`, `MonoClass`,
  `MonoMethod`, ...
- `type_cast.py` - Mono <-> Python value marshalling.
- `imgui_inspect.MonoInspector` - tree-style inspector window built on
  `nylib.pyimgui`.

### `nylib.utils`

Catch-all for non-Win32 helpers. The notable ones:

- `pip.required(*pkgs)` - lazy install. Inside a frozen exe or when
  `PYTHON_PIP_ALL_REQ_INSTALLED=1`, it becomes a no-op (see section 6).
- `pip.set_pip_default_index(url=None)` - probe a list of mirrors
  (PyPI + several Chinese mirrors) and configure pip to use a working
  one.
- `ks_asm` - keystone/capstone wrappers.
- `web` - tiny `requests`/`tqdm`-backed download helper.
- `eventloop`, `threading_`, `async_call`, `mutex`, `delegate` -
  concurrency utilities.
- `pkg_archive` - `base64+zlib+pickle` self-extracting Python payload
  builder (used by `python_loader`).
- `template`, `preprocessor`, `yaml2json`, `prime`, `simple` - small
  text / data utilities.

### `nylib.structs`, `nylib.tkinter_`, `nylib.__pyinstaller`

- `structs/` - PDB-derived and ad-hoc binary struct definitions.
- `tkinter_/` - small additions on top of stdlib `tkinter`.
- `__pyinstaller/` - PyInstaller integration; see section 6.

---

## 4. Scripts directory

The `scripts/` tree is **not** part of the installable package. It is
development scaffolding meant to be run from a checkout with the local
venv.

| Folder | Role |
| --- | --- |
| `scripts/pyimgui2/` | Current pyimgui generator + build + demo. Treat this as the canonical source for the `nylib.pyimgui` build. |
| `scripts/pyimgui/` | Legacy pyimgui generator. Kept for reference. |
| `scripts/dxtest/` | Tiny DX9/10/11/12 host executables used to validate the pyimgui Inbound hooks. Run `python scripts/dxtest/build.py all`, then `python scripts/dxtest/inject.py dx11 --seconds 6`. |
| `scripts/generate_bind/` | Standalone pybind11 generator used by pyimgui and Mono. |
| `scripts/ida/` | IDA Pro plugins / loaders (e.g. `loader_hthh_nxo64.py`, `NySigWorker2.py`). Load these from inside IDA. |
| `scripts/sig_thief/` | Steal a valid Authenticode signature from one PE and apply it to another. |
| `scripts/test_inject/` | Example client/host pair driving `nylib.winutils.python_loader`. |
| `scripts/setup_llvm_dev.py` | Bootstrap an LLVM dev environment via `nylib.winutils.ensure_env`. |
| `scripts/gen_fa_icons.py` | Regenerate `nylib/imguiutils/icons/fa/{solid,regular}.py` from the upstream Font Awesome metadata. |

Conventions:

- All commands assume the project venv: `.venv\Scripts\python.exe`,
  **never** bare `python`.
- Generators write into the source tree (`scripts/pyimgui2/pyimgui/`,
  then copied to `nylib/`).

---

## 5. Installing & developing

```bash
# editable install for development
.\.venv\Scripts\pip.exe install -e .

# minimal install (no native extras pre-installed)
pip install .

# with extras for eager dependency install
pip install ".[hook]"      # pefile
pip install ".[asm]"       # keystone-engine, capstone, setuptools
pip install ".[web]"       # requests, tqdm
pip install ".[full]"      # all of the above
```

The package itself declares no required runtime dependencies. The
modules that need native bindings call `nylib.utils.pip.required(...)`
on first use, which transparently `pip install`s the missing wheel.

**Important:** `pip install nylib` does **not** give you the
`nylib.pyimgui` C extension. You must run the pyimgui generator (see
section 3) inside the same checkout, against the same Python you intend
to run from. The compiled `pyimgui*.pyd` and the
`nylib/pyimgui/*.pyd` siblings are explicitly excluded from the wheel
because they encode the CPython ABI tag.

---

## 6. Packaging consumer apps with PyInstaller

`nylib` ships its own PyInstaller hooks under `nylib/__pyinstaller/` and
exposes them through the standard `pyinstaller40` entry point in
`pyproject.toml`:

```toml
[project.entry-points."pyinstaller40"]
hook-dirs = "nylib.__pyinstaller:get_hook_dirs"
```

What this gives you for free, once `nylib` is `pip install`ed:

- `hook-nylib.pyimgui.py` - bundles every `pyimgui/*.pyd` sibling
  next to the core `pyimgui.pyd` and registers them as hidden imports
  (`nylib.pyimgui.dx9` plus the short alias `pyimgui.dx9`, etc.).
- `hook-pyimgui.py` - same, for top-level `import pyimgui`.
- `hook-keystone.py` - collects `keystone.dll`.
- `hook-capstone.py` - collects `capstone.dll` (defensive; usually
  already covered by `pyinstaller-hooks-contrib`).
- `hook-nylib.imguiutils.icons.py` - collects the Font Awesome TTFs
  and pins every icon-set submodule as a hidden import.

### Two installation modes

**A. `nylib` installed via `pip` (recommended).** No extra flags are
needed. PyInstaller discovers the hooks automatically:

```bash
pyinstaller your_app.py
```

**B. `nylib` used in-tree (no install step).** Point PyInstaller at the
hooks directory yourself:

```bash
pyinstaller --additional-hooks-dir nylib\__pyinstaller your_app.py
```

or, programmatically:

```python
import PyInstaller.__main__
import nylib.__pyinstaller as h

PyInstaller.__main__.run([
    "your_app.py",
    *(f"--additional-hooks-dir={d}" for d in h.get_hook_dirs()),
])
```

### Behaviour of `nylib.utils.pip.required` under freezing

`nylib.utils.pip` detects `sys.frozen` (or the env var
`PYTHON_PIP_ALL_REQ_INSTALLED=1`) at import time and replaces
`required(...)` with a no-op:

```python
if os.environ.get('PYTHON_PIP_ALL_REQ_INSTALLED') or getattr(sys, 'frozen', False):
    required = lambda *_a: True
```

This is because pip's `dist-info` metadata is not bundled by
PyInstaller, so the lazy `is_installed` check would always return
False and try to `pip install` from inside a frozen exe - which then
fails because `pip._internal` is not bundled either.

The practical consequence: **the build-time venv must already have the
native packages installed**, so PyInstaller can pick them up. Run
something like:

```bash
.\.venv\Scripts\pip.exe install pefile capstone keystone-engine setuptools requests tqdm
```

before freezing, or `pip install ".[full]"`.

### Expected bundle layout

After a successful freeze the bundle should contain:

```
<bundle>\nylib\pyimgui.cp3XX-win_amd64.pyd
<bundle>\nylib\pyimgui\dx9.cp3XX-win_amd64.pyd
<bundle>\nylib\pyimgui\dx10.cp3XX-win_amd64.pyd
<bundle>\nylib\pyimgui\dx11.cp3XX-win_amd64.pyd
<bundle>\nylib\pyimgui\dx12.cp3XX-win_amd64.pyd
<bundle>\nylib\imguiutils\icons\fa\resources\*.ttf
<bundle>\keystone\keystone.dll
<bundle>\capstone\lib\capstone.dll
```

Missing frontend `.pyd` files mean the pyimgui hook did not run -
check that `nylib` is installed (entry-point mode) or that
`--additional-hooks-dir` is set (in-tree mode).

---

## 7. Working conventions for agents

1. **Use the project venv.** Always invoke `.\.venv\Scripts\python.exe`
   and `.\.venv\Scripts\pip.exe`, never the bare `python` / `pip`.
2. **Plan before side effects.** Side-effecting operations (file
   writes, `git commit`, `pip install`, running build scripts) need an
   explicit plan and user approval before execution.
3. **Minimal diffs.** Don't reformat or rewrite unrelated code while
   doing a small change.
4. **Rollback before retry.** If a fix didn't work, revert it cleanly
   before trying the next approach. Don't stack speculative patches.
5. **No emojis in code, comments, commit messages, or docs** unless
   the user explicitly asks for them.
6. **Compiled binaries stay out of git.** `*.pyd`, `*.dll`, `*.pdb`,
   `*.lib`, `*.exp`, `*.dmp` and the build outputs under
   `nylib/pyimgui/`, `nylib/pyimgui*.pyd`,
   `nylib/winutils/python_loader/python_loader.dll` are all
   `.gitignore`d. The wheel excludes them too (see
   `[tool.setuptools.exclude-package-data]` in `pyproject.toml`).
7. **`.agent-memory/` is local-only.** Read it for context, but never
   commit anything inside it.
8. **English only** for code, comments, identifiers, config,
   documentation, and commit messages.

---

## 8. Quick reference

```python
# enable SeDebugPrivilege and relaunch as admin if needed
from nylib.winutils.process import enable_privilege, run_admin
run_admin(); enable_privilege()

# attach to a process by name
from nylib.process import Process
proc = Process.from_name('notepad.exe')

# walk loaded modules
for ldr in proc.enum_ldr_data():
    print(ldr.FullDllName.remote_value(proc))

# scan a pattern
from nylib.pattern import CachedRawMemoryPatternScanner
scanner = CachedRawMemoryPatternScanner(proc, base, size)
for hit in scanner.search('48 8B ?? ?? ?? ?? ?? 48 8B ??'):
    ...

# hook a function
from nylib.hook import create_hook
import ctypes
@create_hook(addr, restype=ctypes.c_int, argtypes=(ctypes.c_int,), auto_install=True)
def my_hook(self, x):
    return self.original(x) + 1
```
