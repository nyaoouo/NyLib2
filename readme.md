# NyLib2

> A Windows-focused Python toolkit for process inspection, memory R/W, function
> hooking, code injection, hardware/software breakpoints, and on-screen Dear ImGui
> overlays.

`nylib` is mostly thin, typed `ctypes` wrappers over the Win32 surface plus a few
hand-rolled C extensions. It is aimed at game / process reverse engineering and
runtime tooling on **Windows x64**.

- **Platform:** Windows x64. Most APIs (`WriteProcessMemory`, Detours, hardware
  debug registers, Authenticode, ...) are Windows-only by nature.
- **Python:** 3.11 - 3.14.
- **No required runtime deps:** native-binding packages are lazily `pip install`ed
  on first use (and the same path no-ops inside a PyInstaller-frozen bundle).

> AI coding agents should read [`AGENTS.md`](AGENTS.md) for the full API map and
> working conventions.

Per-module quick starts and task recipes live under [`docs/nylib/`](docs/nylib/).

---

## Install

```bash
# editable install for development
pip install -e .

# plain install from a checkout
pip install .

# optional eager-install extras (otherwise installed lazily on first use)
pip install ".[hook]"   # pefile
pip install ".[asm]"    # keystone-engine, capstone, setuptools
pip install ".[web]"    # requests, tqdm
pip install ".[full]"   # all of the above
```

> **Note:** `pip install` does **not** give you the `nylib.pyimgui` C extension.
> It is CPython-ABI-specific and must be built locally - see
> [pyimgui](#dear-imgui-overlays-nylibpyimgui) below.

---

## Feature map

| Area | Module | What you get | Docs |
| --- | --- | --- | --- |
| Process / memory | `nylib.process` | attach by name/PID, read/write/alloc, module enum, region scan | [docs/nylib/process.md](docs/nylib/process.md) |
| Pattern scanning | `nylib.pattern` | IDA-style `"48 8B ?? ??"` scanner (live memory or static PE) | [docs/nylib/pattern.md](docs/nylib/pattern.md) |
| PDB symbols | `nylib.pdb` | read PDB files via Microsoft DIA; write PDB files from a model | [docs/nylib/pdb.md](docs/nylib/pdb.md) |
| Remote ctypes | `nylib.ctype` | declarative structs that read/write through a process accessor | [docs/nylib/ctype.md](docs/nylib/ctype.md) |
| Function hooking | `nylib.hook` | Microsoft Detours wrapper (`Hook`, `@create_hook`) | [docs/nylib/hook.md](docs/nylib/hook.md) |
| Call queues | `nylib.winutils.inline_call` | run queued calls on a target's own thread at its next entry to a hooked function or vtable slot | [docs/nylib/winutils/inline_call.md](docs/nylib/winutils/inline_call.md) |
| Breakpoints | `nylib.winutils.breakpoint` | x64 HW/SW breakpoints (VEH + debugger backends) | [docs/nylib/winutils/breakpoint.md](docs/nylib/winutils/breakpoint.md) |
| PE mapping | `nylib.winutils.pe_map` | pure PE planning, local or cross-process DLL loading from bytes, and optional post-attach block discard | [docs/nylib/winutils/pe_map.md](docs/nylib/winutils/pe_map.md) |
| Injection | `nylib.winutils.python_loader` / `python_hijack` | run arbitrary Python inside a third-party process | [docs/nylib/winutils/python_loader.md](docs/nylib/winutils/python_loader.md) |
| Code signing | `nylib.winutils.sign` | Authenticode + kernel-driver cross-cert signing, no `signtool` | [docs/nylib/winutils/sign.md](docs/nylib/winutils/sign.md) |
| Dear ImGui | `nylib.pyimgui` | direct ImGui bindings, standalone windows + injected overlays | [docs/nylib/pyimgui/index.md](docs/nylib/pyimgui/index.md) |
| ImGui widgets | `nylib.imguiutils` | alerts, file dialog, window manager, and a full debug view | [docs/nylib/imguiutils.md](docs/nylib/imguiutils.md) |
| Unity / Mono | `nylib.mono` | runtime inspector for Mono/IL2CPP-style games | [docs/nylib/mono.md](docs/nylib/mono.md) |
| Unreal Engine | `nylib.ue` | UE4.25+/UE5 reflection dumper (snapshots, Dumper-7-format exports, IDA importer), runtime objects with opt-in writes and UFunction calls | [docs/nylib/ue/index.md](docs/nylib/ue/index.md) |
| VMware | `nylib.vmware_wp` | drive VMware Workstation Pro (power/snapshots/guest/REST) | [docs/nylib/vmware_wp.md](docs/nylib/vmware_wp.md) |
| Compression | `nylib.utils.oodle` | Oodle Data compression and Oodle Network 1 UDP/TCP packet codecs, bundled 2.9.14 DLLs | [docs/nylib/utils/oodle.md](docs/nylib/utils/oodle.md) |
| Image encoding | `nylib.utils.imagecodec` | JPEG (Windows WIC) and PNG (zlib) encoding of RGBA8 pixels | [docs/nylib/utils/imagecodec.md](docs/nylib/utils/imagecodec.md) |
| Misc | `nylib.utils`, `nylib.logging` | lazy pip, asm, eventloop, color logging, ... | [docs/nylib/utils.md](docs/nylib/utils.md), [docs/nylib/logging.md](docs/nylib/logging.md) |

---

## Quick start

### Attach to a process and walk modules

```python
from nylib.winutils.process import enable_privilege, run_admin
from nylib.process import Process

run_admin()          # relaunch elevated if needed
enable_privilege()   # SeDebugPrivilege

proc = Process.from_name('notepad.exe')   # or Process(1234)
for ldr in proc.enum_ldr_data():          # enumerate loaded modules
    print(ldr.FullDllName.remote_value(proc))
```

### Scan a byte pattern

```python
from nylib.pattern import CachedRawMemoryPatternScanner, StaticPatternSearcher

# live process memory
scanner = CachedRawMemoryPatternScanner(proc, base, size)
for hit in scanner.search('48 8B ?? ?? ?? ?? ?? 48 8B ??'):
    ...

# static scan straight off the PE on disk
searcher = StaticPatternSearcher(r'C:\path\to\game.exe')
for addr in searcher.search('48 8B ?? ?? ?? ?? ?? 48 8B ??'):
    ...
```

### Hook a function (Detours)

```python
import ctypes
from nylib.hook import create_hook

@create_hook(addr, restype=ctypes.c_int, argtypes=(ctypes.c_int,), auto_install=True)
def my_hook(self, x):
    return self.original(x) + 1
```

### Set a hardware breakpoint

```python
from nylib.winutils.breakpoint import BreakPoint, BP_E

def on_hit(address, t, frm, ctx):
    print(f"hit @ {address:X} from {frm:X} rcx={ctx.rcx:X}")
    ctx.rcx += 1   # mutate the trapping thread's registers

bp = BreakPoint(addr, 1, on_hit, flag=BP_E.EXEC).install()
# ...
bp.uninstall()
```

### Show a Dear ImGui window / overlay

```python
from nylib.pyimgui import Dx11Window, imgui

def render():
    imgui.Begin("Hello")
    imgui.Text("from nylib.pyimgui")
    imgui.End()

wnd = Dx11Window(render)
# overlay mode: set wnd.overlay to True for a frameless, topmost, click-through desktop overlay (DX11/DX12)
wnd.Serve()
```

For an **injected** in-process overlay (ESP-style), use the Inbound classes:

```python
from nylib.pyimgui import Dx11Inbound, Dx12Inbound   # plus Dx9/Dx10/Vk/Gl3
```

See [`scripts/pyimgui2/pyimgui_test.py`](scripts/pyimgui2/pyimgui_test.py) for a
runnable demo across all frontends.

### Drive a VMware Workstation VM

```python
from nylib.vmware_wp import Vmrun, VmwareConfig

vr = Vmrun.from_config(VmwareConfig())          # auto-resolves encrypted-VM passwords
vr.power(r"D:\vm\Win11\Win11.vmx", "start")
print(vr.list_running_vms())
```

Full details in [`nylib/vmware_wp/README.md`](nylib/vmware_wp/README.md).

### Dump and attach to an Unreal Engine game

```python
# needs a running game
from nylib.ue import dump, Unreal

result = dump('TRIANGLE_STRATEGY-Win64-Shipping.exe')
with Unreal.attach('TRIANGLE_STRATEGY-Win64-Shipping.exe', dump=result.path) as ue:
    print(ue.world())
```

Usage docs: [docs/nylib/ue/index.md](docs/nylib/ue/index.md).

---

## Inject Python into a process

- [`nylib/winutils/python_loader`](nylib/winutils/python_loader) - C source for an
  in-process Python loader (host <-> guest over a named pipe).
- [`nylib/winutils/python_hijack`](nylib/winutils/python_hijack) - build a stub DLL
  that proxies a real DLL and runs Python on attach.

---

## Dear ImGui overlays (`nylib.pyimgui`)

The compiled `pyimgui*.pyd` files are **not shipped** - they encode the CPython ABI
tag and depend on a local MSVC + libclang setup. Build them from a checkout:

```bash
# generate + build (uses MSVC + libclang via nylib.winutils.ensure_env)
.\.venv\Scripts\python.exe scripts\pyimgui2\pyimgui_generate.py --skip --skip-stubs
# regenerate stubs
.\.venv\Scripts\python.exe scripts\pyimgui2\pyimgui_generate.py --skip
```

Build outputs are copied into `nylib/` so `import nylib.pyimgui` works directly
afterwards. Frontends: DX9 / DX10 / DX11 / DX12 / OpenGL3 / Vulkan, each as a
standalone window and an injected inbound overlay.

---

## Packaging with PyInstaller

`nylib` ships its own PyInstaller hooks under `nylib/__pyinstaller/` and registers
them through the standard `pyinstaller40` entry point, so once `nylib` is installed
they are auto-discovered:

```bash
pyinstaller your_app.py
```

This bundles the `pyimgui` frontends, the Font Awesome TTFs, the
keystone/capstone DLLs, and the Oodle DLLs, and registers their hidden
imports. See `AGENTS.md` section 6 for in-tree usage and the expected
bundle layout.

---

## Development tools (`scripts/`)

`scripts/` is **not** part of the installable package - it is development
scaffolding run from a checkout. Highlights: the `pyimgui2` generator/build/demo,
DirectX injection smoke tests (`dxtest`), IDA loaders & sig workers (`ida`),
breakpoint smoke scripts (`breakpoint_demo`), and a Windows driver-policy manager
(`windows_driver_policy_manage`). See `AGENTS.md` section 4 for the full list.

---

## License

[GPL v3](./license.txt)
