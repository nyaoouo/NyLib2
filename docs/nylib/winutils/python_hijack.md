# nylib.winutils.python_hijack

Build a proxy DLL that forwards all exports from a target DLL and runs Python code when the target application loads it. Used to inject Python into applications that hard-load a specific DLL.

Keywords: DLL proxy, DLL hijacking, DLL forwarding, export forwarding, pefile, MSVC, injection, process attach, main.py, pyHijack.ini, x86, x64, bitness, hijack, create_src

## Quick start

Build a proxy DLL that runs `main.py` when the target application loads the hijacked DLL:

```python
# needs: MSVC (Visual Studio), target DLL path
from nylib.winutils.python_hijack import hijack

hijack(
    pe_path=r"C:\target\mylib.dll",
    dst_dir=r"C:\target",
    plat_spec='x86_amd64',  # or 'x86' for 32-bit
)
# Output: C:\target\mylib.dll (proxy), C:\target\mylib.pyHijack.dll (original renamed)
# Config: C:\target\pyHijack.ini
```

## Build the proxy DLL

Call `hijack()` with the target DLL path and destination directory. The function generates C++ and assembly source, compiles them with MSVC, and places the proxy DLL where the original was. The original is renamed with a `.pyHijack` suffix:

```python
# needs: MSVC
from nylib.winutils.python_hijack import hijack

hijack(
    pe_path=r"C:\app\engine.dll",
    dst_dir=r"C:\app",
    default_config={
        'python_main': r'.\my_script.py',
        'python_dll': r'C:\Python310\python310.dll',
        'create_console': '1',  # 1 to show console, '' to hide
    },
    plat_spec='x86_amd64',
)
```

Parameters:
- `pe_path` — path to the target DLL (read to extract exports)
- `dst_dir` — where to place the proxy DLL (default: same directory as `pe_path`)
- `default_config` — dict with keys: `orig` (original DLL path, auto-set; if the proxy is placed at the target location, the original is renamed `.pyHijack.<ext>` and `orig` points to the renamed file), `python_dll` (full path to Python runtime DLL, auto-detected from the current interpreter if not set), `python_main` (path to the script, relative or absolute; default `.\main.py`), `create_console` (1 or empty string, whether to show a console on attach)
- `build_dir` — temp directory for compilation intermediates (auto-created if not set)
- `plat_spec` — `'x86_amd64'` (64-bit, default) or `'x86'` (32-bit); must match the target DLL

The proxy forwards every export from the original DLL. When the target application loads it, the proxy loads the real DLL, initializes Python, and runs the script specified in `python_main` in a background thread.

## Configuration and Python script

The build generates `pyHijack.ini` next to the proxy DLL, with paths read at runtime. The `[Python]` section holds `sys.path` from the build time; edit it to add library paths. The directory of the script (parent directory of `python_main`) is always added to `sys.path`:

```ini
[Hijack]
orig = C:\app\engine.pyHijack.dll
python_dll = C:\Python310\python310.dll
python_main = .\main.py
create_console = 1

[Python]
path = C:\mylibs;C:\other\libs
```

The script runs in a background thread after the real DLL loads. It can import from the application's Python environment and call back into it via ctypes or other mechanisms. The script's `__file__` is set to the value of `python_main` from the config (defaults to `.\main.py`, relative to the current working directory at runtime).

## Notes

- **Bitness must match.** The proxy DLL's architecture (`plat_spec`) must match the target application's bitness (x86 app ← x86 DLL; x64 app ← x64 DLL). Mismatch causes loader failure.
- **MSVC required to build.** The proxy is compiled with MSVC (`cl.exe`, `ml.exe`/`ml64.exe`); ensure Visual Studio with C++ toolset and Windows SDK are installed. `ensure_msvc()` is called automatically.
- **Config file location.** `pyHijack.ini` must be in the same directory as the proxy DLL at runtime. If missing, defaults from the template are used.
- **Original DLL path.** If `dst_dir == pe_path.parent` (target directory), the original is renamed to `<name>.pyHijack.<ext>` to avoid collision. Otherwise, specify `orig` in `default_config` to point to the real DLL.
- **Python DLL and interpreter.** By default, the active Python interpreter's DLL is auto-detected. Set `python_dll` in `default_config` to override. The script runs with that interpreter's version and `sys.path` from build time.
