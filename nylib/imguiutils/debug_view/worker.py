"""Async memory worker for DebugViewState.

This file is split into three sections, added in successive tasks:
  - Task 4:  safe_read       (memory reader that never raises)
  - Task 5:  cache dataclasses + WorkerSnapshot
  - Task 6:  _decode_with_sync (capstone instruction-sync)
  - Task 7:  MemWorker thread (the public worker class)

We only have safe_read here for now.
"""
from __future__ import annotations

import ctypes
import dataclasses
import typing

# Win32 memory constants
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

_BAD_PROTECT = PAGE_NOACCESS | PAGE_GUARD


@dataclasses.dataclass(frozen=True)
class DisasmCache:
    base: int                                # first byte covered (cursor - pre_used)
    data: bytes
    instructions: list                       # list[capstone.CsInsn]; loosely typed for testability
    sync_failed: bool                        # 16-offset sync gave up
    cursor: int                              # disasm_cursor that produced this cache
    pre_bytes: int                           # bytes before cursor at decode time
    post_bytes: int                          # bytes after cursor at decode time


@dataclasses.dataclass(frozen=True)
class HexCache:
    base: int                                # cursor - pre_bytes
    data: bytes
    read_failed: bytes                       # one byte per byte: 0 readable, 1 failed
    cursor: int
    pre_bytes: int
    post_bytes: int


@dataclasses.dataclass(frozen=True)
class RegionInfo:
    base: int
    size: int
    state: int                               # MEM_COMMIT / MEM_RESERVE / MEM_FREE
    protect: int
    module_name: str | None
    module_base: int | None
    module_size: int | None
    cursor: int                              # which cursor this header reflects
    error: str | None = None


@dataclasses.dataclass(frozen=True)
class WorkerSnapshot:
    disasm: typing.Optional[DisasmCache]
    hex: typing.Optional[HexCache]
    region: typing.Optional[RegionInfo]
    worker_tid: int
    seq: int


def _is_region_readable(state: int, protect: int) -> bool:
    return state == MEM_COMMIT and (protect & _BAD_PROTECT) == 0


def safe_read(addr: int, size: int) -> tuple[bytes, bytes]:
    """Read `size` bytes from `addr`. Never raises.

    Returns `(data, failed)` where `data` is exactly `size` bytes long
    (unreadable bytes filled with `\\x00`) and `failed` is exactly `size`
    bytes long, each byte 0 when readable / 1 when not.
    """
    size = int(size)
    addr = int(addr)
    if size <= 0:
        return b"", b""

    from nylib.process import Process

    out = bytearray(size)
    failed = bytearray(size)
    proc = Process.current
    pos = 0
    while pos < size:
        cur_addr = addr + pos
        try:
            mbi = proc.virtual_query(cur_addr)
        except Exception:
            failed[pos:] = b"\x01" * (size - pos)
            break
        if mbi.RegionSize <= 0:
            failed[pos:] = b"\x01" * (size - pos)
            break
        region_end = int(mbi.BaseAddress) + int(mbi.RegionSize)
        span = min(region_end - cur_addr, size - pos)
        if not _is_region_readable(int(mbi.State), int(mbi.Protect)):
            failed[pos:pos + span] = b"\x01" * span
        else:
            try:
                chunk = ctypes.string_at(cur_addr, span)
                out[pos:pos + span] = chunk
            except Exception:
                failed[pos:pos + span] = b"\x01" * span
        pos += span
    return bytes(out), bytes(failed)


# Capstone is wrapped in a module-level singleton; lazy-loaded so the
# pure-Python test suite for non-decode code paths doesn't pay the import.
_cs = None


def _get_cs():
    global _cs
    if _cs is None:
        from nylib.utils.pip import required
        required("setuptools", "capstone")
        import capstone
        _cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    return _cs


def _decode_with_sync(*, data: bytes, base: int, cursor: int,
                      pre_bytes: int, post_bytes: int) -> "DisasmCache":
    """Try 16 candidate start offsets to find one whose decode aligns to cursor.

    `data` covers `[base, base + len(data))` and must contain `cursor`.
    Returns a DisasmCache; on failure, `sync_failed=True` and `instructions=[]`
    (the renderer will fall back to `db 0xNN` rows).
    """
    cs = _get_cs()
    cursor_off = cursor - base
    if cursor_off < 0 or cursor_off > len(data):
        return DisasmCache(base=base, data=data, instructions=[],
                           sync_failed=True, cursor=cursor,
                           pre_bytes=pre_bytes, post_bytes=post_bytes)
    best: list = []
    best_k = 0
    for k in range(16):
        if k > cursor_off:
            break
        start_addr = base + k
        try:
            insns = list(cs.disasm(bytes(data[k:]), start_addr))
        except Exception:
            continue
        if any(i.address == cursor for i in insns):
            return DisasmCache(base=start_addr, data=bytes(data[k:]),
                               instructions=insns, sync_failed=False,
                               cursor=cursor,
                               pre_bytes=pre_bytes - k, post_bytes=post_bytes)
        if not best:
            best, best_k = insns, k
    return DisasmCache(base=base + best_k, data=bytes(data[best_k:]),
                       instructions=best, sync_failed=True, cursor=cursor,
                       pre_bytes=max(0, pre_bytes - best_k), post_bytes=post_bytes)


import logging
import threading
import time

_log = logging.getLogger("nylib.imguiutils.debug_view")


class MemWorker:
    """Daemon thread that fills DisasmCache / HexCache / RegionInfo for a state.

    One worker per DebugViewState. Snapshot publication is atomic via a
    mutex around a single reference swap; the render thread reads through
    `snapshot()` which holds the lock only long enough to grab the ref.
    """

    def __init__(self, state) -> None:
        self._state = state
        self._lock = threading.Lock()
        self._front: WorkerSnapshot | None = None
        self._seq = 0
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._tid: int = 0

    @property
    def tid(self) -> int:
        return self._tid

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run,
            name=f"DebugView-worker-{self._state._uid}",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        self._wake.set()
        t = self._thread
        if t is not None and t.is_alive():
            t.join(timeout=timeout)
            if t.is_alive():
                _log.warning("MemWorker did not stop within %.1fs", timeout)
        self._thread = None

    def request_refresh(self) -> None:
        self._wake.set()

    def snapshot(self) -> "WorkerSnapshot | None":
        with self._lock:
            return self._front

    # ----- internal -----

    def _run(self) -> None:
        self._tid = threading.get_native_id()
        while not self._stop.is_set():
            self._wake.clear()
            if self._stop.is_set():
                break
            try:
                snap = self._build_snapshot()
            except Exception as exc:   # never let the loop die on Exception
                _log.exception("MemWorker pass failed")
                snap = WorkerSnapshot(
                    disasm=None, hex=None,
                    region=RegionInfo(base=0, size=0, state=0, protect=0,
                                       module_name=None, module_base=None,
                                       module_size=None, cursor=0,
                                       error=str(exc)),
                    worker_tid=self._tid,
                    seq=self._seq + 1,
                )
                time.sleep(1.0)
            with self._lock:
                self._front = snap
                self._seq += 1
            if self._stop.is_set():
                break
            interval = max(0.01, self._state.update_interval_ms / 1000.0)
            self._wake.wait(timeout=interval)

    def _build_snapshot(self) -> "WorkerSnapshot":
        st = self._state
        # Apply pending edge-scroll extensions before reading cursors.
        if st._extend_down:
            st.disasm_post_bytes = min(st.disasm_post_bytes * 2, st.disasm_window_max)
            st.hex_post_bytes    = min(st.hex_post_bytes * 2,    st.hex_window_max)
            st._extend_down = False

        d, h = st.disasm_cursor, st.hex_cursor
        disasm = self._read_disasm(d, st.disasm_pre_bytes, st.disasm_post_bytes) if d else None
        hex_cache = self._read_hex(h, st.hex_pre_bytes, st.hex_post_bytes) if h else None
        region = self._compute_region(st.focused_view, d, h)
        return WorkerSnapshot(
            disasm=disasm, hex=hex_cache, region=region,
            worker_tid=self._tid, seq=self._seq + 1,
        )

    def _read_disasm(self, cursor: int, pre: int, post: int) -> DisasmCache:
        data, _failed = safe_read(cursor - pre, pre + post)
        return _decode_with_sync(data=data, base=cursor - pre, cursor=cursor,
                                  pre_bytes=pre, post_bytes=post)

    def _read_hex(self, cursor: int, pre: int, post: int) -> HexCache:
        data, failed = safe_read(cursor - pre, pre + post)
        return HexCache(base=cursor - pre, data=data, read_failed=failed,
                        cursor=cursor, pre_bytes=pre, post_bytes=post)

    def _compute_region(self, focused: str | None, d: int, h: int) -> "RegionInfo | None":
        addr = h if focused == "hex" else d
        if not addr:
            return None
        try:
            from nylib.process import Process
            proc = Process.current
            mbi = proc.virtual_query(addr)
        except Exception as exc:
            return RegionInfo(base=0, size=0, state=0, protect=0,
                              module_name=None, module_base=None,
                              module_size=None, cursor=addr, error=str(exc))
        mod_name = mod_base = mod_size = None
        try:
            for entry in proc.enum_ldr_data():
                base = int(entry.DllBase or 0)
                size = int(entry.SizeOfImage or 0)
                if base <= addr < base + size:
                    try:
                        mod_name = entry.BaseDllName.remote_value(proc)
                    except Exception:
                        mod_name = None
                    mod_base, mod_size = base, size
                    break
        except Exception:
            pass
        return RegionInfo(
            base=int(mbi.BaseAddress), size=int(mbi.RegionSize),
            state=int(mbi.State), protect=int(mbi.Protect),
            module_name=mod_name, module_base=mod_base, module_size=mod_size,
            cursor=addr, error=None,
        )


__all__ = [
    "safe_read",
    "DisasmCache",
    "HexCache",
    "RegionInfo",
    "WorkerSnapshot",
    "_decode_with_sync",
    "MemWorker",
]
