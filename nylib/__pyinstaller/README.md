# PyInstaller hooks for nylib

`nylib.pyimgui` is a pybind11 extension that **rewrites its own `__path__`
at import time** so that the frontend backends shipped as sibling
extensions (`pyimgui/dx9.pyd`, `pyimgui/dx11.pyd`, ...) become importable
as `pyimgui.dx9`, `pyimgui.dx11`, ... etc.

PyInstaller's static analyser cannot follow that runtime trick, so by
default it neither bundles the frontend `.pyd` files nor recognises the
submodule imports. This directory provides the hooks that close the gap.

## Hooks

| File                          | Triggers on import of            | Bundles to       |
|-------------------------------|----------------------------------|------------------|
| `hook-nylib.pyimgui.py`       | `nylib.pyimgui` (and submodules) | `nylib/pyimgui/` |
| `hook-pyimgui.py`             | top-level `pyimgui` import       | `pyimgui/`       |

Both hooks discover every `*.pyd` next to the loaded core extension,
register them as PyInstaller `binaries`, and add their dotted module names
to `hiddenimports` so the analyser keeps them.

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
```

If any of the frontend `.pyd` files are missing from `<bundle>/nylib/pyimgui/`,
PyInstaller didn't pick up this hook — re-check option A/B above.
