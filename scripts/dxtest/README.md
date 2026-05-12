# dxtest

Small DirectX host programs for pyimgui2 inbound rendering tests.

The hosts load an app-local `dxtest_bootstrap.dll`. `inject.py` replaces that DLL with a `nylib.winutils.python_hijack` proxy, then starts a Python payload that imports only the matching pyimgui2 frontend module.

## Commands

```powershell
.\.venv\Scripts\python.exe scripts\dxtest\build.py all
.\.venv\Scripts\python.exe scripts\dxtest\inject.py dx9 --seconds 10
.\.venv\Scripts\python.exe scripts\dxtest\inject.py dx11 --seconds 10
.\.venv\Scripts\python.exe scripts\dxtest\inject.py dx12 --seconds 10
.\.venv\Scripts\python.exe scripts\dxtest\run_all.py --seconds 10
```

Each payload writes marker files in `scripts/dxtest/out/<backend>/markers`. `payload_drawn.txt` means the injected render callback executed at least once.
Add `--console` to `inject.py` only when debugging injected Python output manually.