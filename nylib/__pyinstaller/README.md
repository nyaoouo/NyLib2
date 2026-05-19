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
| `hook-nylib.pyimgui.py`       | `nylib.pyimgui` (and submodules) | Bundles frontend `.pyd` files into `nylib/pyimgui/`; hidden-imports the aliases |
| `hook-pyimgui.py`             | top-level `pyimgui` import       | Same, but bundled into top-level `pyimgui/`                                     |
| `hook-keystone.py`            | `keystone`                       | Collects `keystone.dll` next to the `keystone` package via `collect_dynamic_libs` |
| `hook-capstone.py`            | `capstone`                       | Collects `capstone.dll`. Strictly redundant with `pyinstaller-hooks-contrib` (always installed alongside PyInstaller) — kept as a defensive fallback for stripped-down installs |

The pyimgui hooks discover every `*.pyd` next to the loaded core
extension, register them as PyInstaller `binaries`, and add their dotted
module names to `hiddenimports` so the analyser keeps them. The keystone
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

**Option A — installed package.** If you publish `nylib` via a `pyproject.toml`,
declare the standard PyInstaller entry point so the hooks are auto-discovered:

```toml
[project.entry-points."pyinstaller40"]
hook-dirs = "nylib.__pyinstaller:get_hook_dirs"
```

**Option B — in-tree usage.** If you run `nylib` from a checkout (no install
step), pass the hooks directory on the PyInstaller command line:

```bash
pyinstaller \
  --additional-hooks-dir path/to/nylib/__pyinstaller \
  --collect-binaries nylib.pyimgui \
  your_app.py
```

or programmatically:

```python
import nylib.__pyinstaller as h
PyInstaller.__main__.run([
    'your_app.py',
    *(f'--additional-hooks-dir={d}' for d in h.get_hook_dirs()),
])
```

## Verifying

After freezing, the bundle layout should contain:

```
<bundle>/nylib/pyimgui.cp3XX-win_amd64.pyd
<bundle>/nylib/pyimgui/dx9.cp3XX-win_amd64.pyd
<bundle>/nylib/pyimgui/dx10.cp3XX-win_amd64.pyd
<bundle>/nylib/pyimgui/dx11.cp3XX-win_amd64.pyd
<bundle>/nylib/pyimgui/dx12.cp3XX-win_amd64.pyd
<bundle>/keystone/keystone.dll
<bundle>/capstone/lib/capstone.dll
```

If any of the frontend `.pyd` files are missing from `<bundle>/nylib/pyimgui/`,
PyInstaller didn't pick up this hook — re-check option A/B above. If
`keystone.dll` is missing, the freeze likely ran without
`--additional-hooks-dir` pointing at this directory (or without the entry
point registered).
