# PyInstaller hooks for nylib

`nylib.pyimgui` is a pybind11 extension that **rewrites its own `__path__`
at import time** so that the frontend backends shipped as sibling
extensions (`pyimgui/dx9.pyd`, `pyimgui/dx11.pyd`, ...) become importable
as `pyimgui.dx9`, `pyimgui.dx11`, ... etc. PyInstaller's static analyser
cannot follow that runtime trick.

`nylib` also pulls in two ctypes-based libraries (`keystone-engine`,
`capstone`) whose native `.dll` / `.so` / `.dylib` is loaded at import
time relative to the package directory. Without help, PyInstaller does
not bundle the native libraries either.

This directory provides the hooks that close all of those gaps, so a
downstream project freezing code that imports `nylib` works
out-of-the-box with no per-project spec hacks beyond pointing PyInstaller
at this hooks directory.

## Hooks

| File                          | Triggers on import of            | Effect                                                                          |
|-------------------------------|----------------------------------|---------------------------------------------------------------------------------|
| `hook-nylib.pyimgui.py`       | `nylib.pyimgui` (and submodules) | Bundles this interpreter's frontend `.pyd` files and the pure-Python modules (`esp.py`) into `nylib/pyimgui/`; hidden-imports the aliases |
| `hook-pyimgui.py`             | top-level `pyimgui` import       | Same, but bundled into top-level `pyimgui/`                                     |
| `hook-keystone.py`            | `keystone`                       | Collects `keystone.dll` next to the `keystone` package via `collect_dynamic_libs` |
| `hook-capstone.py`            | `capstone`                       | Collects `capstone.dll`. Strictly redundant with `pyinstaller-hooks-contrib` (always installed alongside PyInstaller) — kept as a defensive fallback for stripped-down installs |
| `hook-nylib.utils.oodle.py`   | `nylib.utils.oodle`              | Collects the bundled `oo2core_9_win64.dll` and `oo2net_9_win64.dll` into `nylib/utils/oodle/` via `collect_dynamic_libs` |
| `hook-nylib.imguiutils.icons.py` | `nylib.imguiutils.icons`      | Collects the Font Awesome TTFs and pins every icon-set submodule as a hidden import |
| `hook-nylib.winutils.sign.py` | `nylib.winutils.sign`            | Bundles the cross-certificate store `MSCVStore.p7b` as data                     |
| `hook-nylib.winutils.breakpoint.py` | `nylib.winutils.breakpoint` | Bundles the backend sources and DLLs (builds a missing DLL at freeze time) and pins the `veh` / `debugger` hidden imports |
| `hook-nylib.winutils.python_loader.py` | `nylib.winutils.python_loader` | Bundles `python_loader.cpp` and `python_loader.dll` (builds a missing DLL at freeze time) |

The pyimgui hooks discover the `*.pyd` files next to the loaded core
extension whose ABI tag the interpreter being frozen accepts
(`importlib.machinery.EXTENSION_SUFFIXES`), register them as PyInstaller
`binaries`, and add their dotted module names to `hiddenimports` so the
analyser keeps them. Frontends built for another CPython version are
skipped, so no foreign `pythonXY.dll` is pulled in. The pure-Python modules
there (`esp.py`) and the `.pyi` stubs are added as data, because the
analyser cannot see them. The keystone
and capstone hooks are one-liners delegating to
`PyInstaller.utils.hooks.collect_dynamic_libs`.

## Frozen-runtime behaviour of `nylib.utils.pip`

`nylib` libraries declare their import-time C-extension dependencies via
`nylib.utils.pip.required('capstone', 'keystone-engine', ...)`. In a
non-frozen environment, `required(...)` checks pip's installed-package
metadata and, on miss, invokes `pip._internal.commands.install` to fetch
them automatically.

Neither of those works inside a PyInstaller bundle: pip's `dist-info`
metadata is not collected by PyInstaller (so the presence check always
returns False), and pip's internal commands are not bundled either (so
the install fallback raises `ModuleNotFoundError`). To prevent crashes,
`nylib.utils.pip` detects `sys.frozen` at module-import time and replaces
`required` with a no-op:

```python
if os.environ.get('PYTHON_PIP_ALL_REQ_INSTALLED') or getattr(sys, 'frozen', False):
    required = lambda *_a: True
```

This means **downstream consumers do not need to add a runtime hook** to
bypass `pip.required` — provided the C-extension packages themselves
(`capstone`, `keystone-engine`, `pefile`, `setuptools`) are present in
the build-time venv so PyInstaller can bundle them, freezing Just Works.

## Telling PyInstaller about the hooks

**Option A — installed package.** A pip install of `nylib`, regular or
editable (`pip install -e`), writes the dist-info that holds the
`pyinstaller40` entry point (declared in nylib's own `pyproject.toml`), so
PyInstaller finds the hooks with no flags:

```bash
pyinstaller your_app.py
```

**Option B — in-tree usage.** A checkout reached through a `.pth`
file, `PYTHONPATH` or `sys.path` has no dist-info and counts as in-tree,
although `import nylib` works. Pass the hooks directory on the PyInstaller
command line (or `hookspath=nylib.__pyinstaller.get_hook_dirs()` in a spec file):

```bash
pyinstaller --additional-hooks-dir path/to/nylib/__pyinstaller your_app.py
```

Without it the freeze succeeds, but the app fails at its first frontend
import. Programmatically:

```python
import PyInstaller.__main__
import nylib.__pyinstaller as h
PyInstaller.__main__.run([
    'your_app.py',
    *(f'--additional-hooks-dir={d}' for d in h.get_hook_dirs()),
])
```

## Verifying

After freezing, a onedir build (the PyInstaller 6 default, which puts
everything except the exe under `_internal/`) should contain:

```
<dist>/<app>/_internal/nylib/pyimgui.cp3XX-win_amd64.pyd
<dist>/<app>/_internal/nylib/pyimgui/dx9.cp3XX-win_amd64.pyd
<dist>/<app>/_internal/nylib/pyimgui/dx10.cp3XX-win_amd64.pyd
<dist>/<app>/_internal/nylib/pyimgui/dx11.cp3XX-win_amd64.pyd
<dist>/<app>/_internal/nylib/pyimgui/dx12.cp3XX-win_amd64.pyd
<dist>/<app>/_internal/nylib/pyimgui/esp.py
<dist>/<app>/_internal/nylib/imguiutils/icons/fa/resources/*.ttf
<dist>/<app>/_internal/keystone/keystone.dll
<dist>/<app>/_internal/capstone/lib/capstone.dll
<dist>/<app>/_internal/nylib/utils/oodle/oo2core_9_win64.dll
<dist>/<app>/_internal/nylib/utils/oodle/oo2net_9_win64.dll
```

`cp3XX` is the ABI tag of the interpreter that froze the app; the gl3 / vk
frontends appear when they were built. If any of the frontend `.pyd` files
are missing from `nylib/pyimgui/`, PyInstaller didn't pick up this hook —
re-check option A/B above. If `keystone.dll` is missing, the freeze likely
ran without the hooks directory being found (see option B).
