# breakpoint_demo

Manual smoke scripts for `nylib.winutils.breakpoint`. Build the backend DLL
once:

```
.\.venv\Scripts\python.exe -c "from nylib.winutils.breakpoint.veh import ensure_backend_dll; ensure_backend_dll()"
```

Then run any of:

| script | what it does |
|---|---|
| `exec_messagebox.py`   | HARD EXEC BP on a 1-byte `ret` stub; prints `frm` and `rcx`. (Named after `MessageBoxW` historically; the script now uses a custom stub to avoid blocking.) |
| `read_write_global.py` | HARD WRITE BP on a Python buffer; expects at least one hit. |
| `slot_exhaustion.py`   | Five HARD BPs; the fifth must raise `SlotExhaustedError`. |
| `soft_guard.py`        | SOFT READ via PAGE_GUARD over a 64 KiB region. |
| `new_thread.py`        | Manual thread-management API: install BP, spawn worker, verify it doesn't hit until `bp.refresh_threads()` is called; then detach. |
| `debugger_backend.py`  | Same scenario via `backend='debugger'`: the worker thread auto-attaches via `CREATE_THREAD_DEBUG_EVENT`. **Needs an elevated host** (re-run as administrator); skips with exit 2 otherwise. |

For the full freeze/inject demo (PyInstaller-frozen `inject.exe`
attaching to a tiny `target.exe`), see `.ignore/bp_target/README.md`.
