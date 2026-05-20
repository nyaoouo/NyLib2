"""Debugger backend: in-process worker thread doing DebugActiveProcess.

The native side lives in ``debugger_backend.cpp`` and is built into
``debugger_backend.dll`` on demand by :func:`build_backend`. The DLL exports
the same eleven-function ABI as the VEH backend.

Privilege requirement
---------------------
``DebugActiveProcess(GetCurrentProcessId())`` requires SeDebugPrivilege, which
in turn requires the host process to be running **elevated** (the user being a
member of Administrators is not sufficient -- the process needs an elevated
token, e.g. launched via "Run as administrator" or programmatically through
``nylib.winutils.process.run_admin()``).

If SeDebugPrivilege cannot be acquired, :class:`DebuggerBackend` raises
:class:`BackendError` from ``__init__`` with a message pointing here. Use the
VEH backend (``backend='veh'``, the default) when elevation is not available.

What you get over VEH
---------------------
* ``CREATE_THREAD_DEBUG_EVENT`` is delivered for every new thread, so HARD BPs
  are **automatically** applied to threads spawned after install -- no manual
  ``refresh_threads()`` call required.
* The trapping thread is suspended by the kernel during dispatch, so the
  dispatcher doesn't have to play games with EFLAGS.RF / TF re-arming.

Caveats
-------
* Only one debugger may be attached to a process at a time. Attaching this
  backend while another debugger (Visual Studio, WinDbg, ...) is already
  active will fail.
* The debugger worker thread cannot itself be a debuggee target; BPs that
  would land on it are silently filtered out.
"""

from __future__ import annotations

import ctypes
import pathlib
import shutil
import subprocess
import sys
import tempfile

from ..backend import BreakpointBackend
from ..exceptions import BackendError, SlotExhaustedError, InvalidBreakpointError

_BACKEND_VERSION = 1

_DIR = pathlib.Path(__file__).parent
_DEFAULT_DLL = _DIR / "debugger_backend.dll"
_DEFAULT_CPP = _DIR / "debugger_backend.cpp"


def build_backend(dst: str | pathlib.Path = _DEFAULT_DLL, build_dir=None) -> pathlib.Path:
    """Compile ``debugger_backend.cpp`` into ``dst``."""
    from ... import msvc, ensure_env  # type: ignore[attr-defined]
    ensure_env.ensure_msvc()
    plat_spec = "x86_amd64"
    build_env = msvc.load_vcvarsall(plat_spec)
    dst = pathlib.Path(dst).absolute()
    if dst.exists():
        dst.unlink()
    if build_dir is None:
        tmp_dir = pathlib.Path(tempfile.mkdtemp())
        cleanup = True
    else:
        tmp_dir = pathlib.Path(build_dir)
        tmp_dir.mkdir(exist_ok=True, parents=True)
        cleanup = False
    try:
        subprocess.run(
            [
                msvc.where("cl.exe", plat_spec),
                "/D_WINDLL", "/std:c++20", "/EHa", "/O2", "/W3",
                str(_DEFAULT_CPP),
                "/link", "/DLL", "/OUT:" + str(dst),
            ],
            cwd=tmp_dir, env=build_env, check=True, shell=True,
        )
    finally:
        if cleanup:
            shutil.rmtree(tmp_dir, ignore_errors=True)
    for ext in (".exp", ".obj", ".lib"):
        side = dst.with_suffix(ext)
        if side.exists():
            side.unlink()
    return dst


def ensure_backend_dll(path=None, rebuild: bool = False) -> pathlib.Path:
    path = pathlib.Path(path) if path is not None else _DEFAULT_DLL
    if rebuild and getattr(sys, "frozen", False):
        raise RuntimeError("cannot rebuild backend DLL in a frozen build")
    if rebuild or not path.exists():
        if getattr(sys, "frozen", False):
            raise FileNotFoundError(f"bundled backend DLL missing: {path}")
        build_backend(path)
    return path


_TRAMPOLINE_FN = ctypes.CFUNCTYPE(
    None, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint64, ctypes.c_uint64,
)


class DebuggerBackend(BreakpointBackend):
    """ctypes wrapper around debugger_backend.dll.

    Caveat: ``DebugActiveProcess(GetCurrentProcessId())`` cannot coexist with
    another debugger attached to the host. Only one debugger may be active.
    """

    name = "debugger"

    def __init__(self):
        self._dll_path = ensure_backend_dll()
        self._dll = ctypes.CDLL(str(self._dll_path))
        self._bind()
        # DebugActiveProcess(self) needs SeDebugPrivilege; enable it best-effort.
        try:
            from ...process import enable_privilege  # type: ignore[attr-defined]
            enable_privilege()
        except Exception:
            pass  # not fatal here; init will fail with a clear error if it matters
        h = self._dll.BpBackendInit(_BACKEND_VERSION)
        if not h:                # h may be None (NULL c_void_p) or 0
            raise BackendError(
                "BpBackendInit (debugger) returned 0 "
                "(see DebugView; common causes: SeDebugPrivilege not held, or "
                "another debugger already attached)"
            )
        self._handle = int(h)
        self._handle_map: dict[int, dict] = {}
        self._trampolines: list = []

    def _bind(self) -> None:
        d = self._dll
        d.BpBackendInit.restype = ctypes.c_void_p
        d.BpBackendInit.argtypes = [ctypes.c_uint32]
        d.BpBackendShutdown.restype = ctypes.c_uint32
        d.BpBackendShutdown.argtypes = [ctypes.c_void_p]
        d.BpInstall.restype = ctypes.c_void_p
        d.BpInstall.argtypes = [
            ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32,
        ]
        d.BpUninstall.restype = ctypes.c_uint32
        d.BpUninstall.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        d.BpEnable.restype = ctypes.c_uint32
        d.BpEnable.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
        d.BpSlotsFree.restype = ctypes.c_uint32
        d.BpSlotsFree.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        d.BpLastError.restype = ctypes.c_uint32
        d.BpLastError.argtypes = []
        for name in ("BpAttachTids", "BpDetachTids", "BpListTids"):
            getattr(d, name).restype = ctypes.c_uint32
            getattr(d, name).argtypes = [
                ctypes.c_void_p, ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32,
            ]
        d.BpSnapshotTids.restype = ctypes.c_uint32
        d.BpSnapshotTids.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32,
        ]

    def install(self, *, address, size, flags, callback, user_data, tids):
        from .. import BP_E
        from ..ctx import BpCtx

        kernel32 = ctypes.windll.kernel32

        def trampoline(bp_handle, bp_t, frm, context_addr):
            slot = self._handle_map.get(int(bp_handle))
            if slot is None:
                return
            bp = slot["bp"]
            cb = slot["callback"]
            if bp is not None:
                bp.hits += 1
            ctx = BpCtx(
                context_addr=int(context_addr),
                bp=bp,
                address=bp.address if bp is not None else 0,
                tid=kernel32.GetCurrentThreadId(),   # debugger thread, not trapping thread
                frm=int(frm),
            )
            try:
                cb(bp.address if bp is not None else 0, BP_E(int(bp_t)), int(frm), ctx)
            except Exception:
                import traceback
                traceback.print_exc()
            finally:
                ctx._invalidate()

        cfun = _TRAMPOLINE_FN(trampoline)
        self._trampolines.append(cfun)

        if tids:
            arr_t = ctypes.c_uint32 * len(tids)
            arr = arr_t(*tids)
            tid_ptr = ctypes.cast(arr, ctypes.POINTER(ctypes.c_uint32))
            tid_count = len(tids)
        else:
            arr = None
            tid_ptr = ctypes.POINTER(ctypes.c_uint32)()
            tid_count = 0
        _ = arr

        h = self._dll.BpInstall(
            self._handle,
            ctypes.c_uint64(address),
            ctypes.c_uint32(size),
            ctypes.c_uint32(int(flags)),
            ctypes.cast(cfun, ctypes.c_void_p),
            ctypes.c_void_p(user_data or 0),
            tid_ptr,
            ctypes.c_uint32(tid_count),
        )
        if not h:
            err = int(self._dll.BpLastError())
            if err == 3:
                raise SlotExhaustedError("HW DR slots exhausted on at least one thread")
            if err == 4:
                raise SlotExhaustedError("region exceeds 4 DR slots after splitting")
            if err == 5:
                raise BackendError("backend failed to apply DR registers", status=err)
            if err == 6:
                raise InvalidBreakpointError("backend rejected flags/size combination")
            raise BackendError(f"BpInstall returned 0 (err={err})", status=err)
        self._handle_map[int(h)] = {"bp": None, "trampoline": cfun, "callback": callback}
        return int(h)

    def bind_bp(self, handle: int, bp) -> None:
        slot = self._handle_map.get(int(handle))
        if slot is not None:
            slot["bp"] = bp

    def uninstall(self, handle):
        rc = self._dll.BpUninstall(self._handle, ctypes.c_void_p(handle))
        if rc != 0:
            raise BackendError("BpUninstall failed", status=int(rc))
        self._handle_map.pop(int(handle), None)

    def set_enabled(self, handle, enabled):
        rc = self._dll.BpEnable(self._handle, ctypes.c_void_p(handle), 1 if enabled else 0)
        if rc != 0:
            raise BackendError("BpEnable failed", status=int(rc))

    def slots_free(self, tid: int) -> int:
        return int(self._dll.BpSlotsFree(self._handle, ctypes.c_uint32(tid)))

    def attach_tids(self, handle: int, tids) -> None:
        tids = tuple(int(t) for t in tids)
        if not tids: return
        arr = (ctypes.c_uint32 * len(tids))(*tids)
        rc = self._dll.BpAttachTids(
            self._handle, ctypes.c_void_p(handle),
            ctypes.cast(arr, ctypes.POINTER(ctypes.c_uint32)),
            ctypes.c_uint32(len(tids)),
        )
        if rc != 0:
            err = int(self._dll.BpLastError())
            if err == 3:
                raise SlotExhaustedError("HW DR slots exhausted on at least one requested TID")
            raise BackendError(f"BpAttachTids failed (rc={rc}, err={err})", status=err)

    def detach_tids(self, handle: int, tids) -> None:
        tids = tuple(int(t) for t in tids)
        if not tids: return
        arr = (ctypes.c_uint32 * len(tids))(*tids)
        rc = self._dll.BpDetachTids(
            self._handle, ctypes.c_void_p(handle),
            ctypes.cast(arr, ctypes.POINTER(ctypes.c_uint32)),
            ctypes.c_uint32(len(tids)),
        )
        if rc != 0:
            raise BackendError(f"BpDetachTids failed (rc={rc})", status=rc)

    def list_tids(self, handle: int) -> list[int]:
        cap = 64
        while True:
            arr = (ctypes.c_uint32 * cap)()
            n = int(self._dll.BpListTids(
                self._handle, ctypes.c_void_p(handle),
                ctypes.cast(arr, ctypes.POINTER(ctypes.c_uint32)),
                ctypes.c_uint32(cap),
            ))
            if n <= cap:
                return [int(arr[i]) for i in range(n)]
            cap = n + 16

    def snapshot_tids(self) -> list[int]:
        cap = 256
        while True:
            arr = (ctypes.c_uint32 * cap)()
            n = int(self._dll.BpSnapshotTids(
                self._handle,
                ctypes.cast(arr, ctypes.POINTER(ctypes.c_uint32)),
                ctypes.c_uint32(cap),
            ))
            if n <= cap:
                return [int(arr[i]) for i in range(n)]
            cap = n + 64

    def shutdown(self) -> None:
        if self._handle:
            rc = self._dll.BpBackendShutdown(self._handle)
            if rc != 0:
                raise BackendError("BpBackendShutdown failed", status=int(rc))
            self._handle = 0
            self._handle_map.clear()
