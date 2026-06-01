"""Shared async pattern scanner for pattern_scan + search tools.

One ScanWorker per (pattern, scope) request. Spawns a daemon thread
that walks a FROZEN region list, calling LocalMemoryPatternScanner on
each region. Hits are accumulated; after `page_size` hits the worker
pauses on an event until `request_more()` is called.
"""
from __future__ import annotations

import collections
import dataclasses
import logging
import threading
import typing

from nylib.pattern import LocalMemoryPatternScanner, compile_pattern

_log = logging.getLogger("nylib.imguiutils.debug_view.tools._scan_worker")


@dataclasses.dataclass(frozen=True)
class Hit:
    addr: int
    context: bytes = b""    # leading match bytes, len <= 32


@dataclasses.dataclass(frozen=True)
class ScanStatus:
    state: str    # "running" | "paused" | "done" | "cancelled" | "errored"
    bytes_scanned: int
    total_bytes: int
    hits_total: int
    hits_loaded: int
    error: typing.Optional[str] = None


@dataclasses.dataclass
class ScopeChoice:
    mode: str    # "module" | "window" | "committed"
    module_name: typing.Optional[str] = None
    include_private: bool = False


class ScanWorker:
    """Async byte-pattern scanner with lazy paging.

    One-shot; spawn a fresh worker per (pattern, scope) change.

    Public API:
        start()           -> begin scanning
        request_more()    -> unblock next page
        request_cancel()  -> cooperative cancel (checked between hits)
        drain()           -> return hits collected since last drain
        status()          -> immutable snapshot
        join(timeout)     -> wait for thread exit
    """

    def __init__(self, *, pattern, scope_regions, page_size: int = 100,
                 hit_cap: int = 10_000):
        if isinstance(pattern, str):
            # Pre-compile to validate; not used directly below but raises
            # early if pattern is garbage.
            compile_pattern(pattern)
            self._pattern_text = pattern
        else:
            # bytes pattern: convert to compile_pattern hex form.
            self._pattern_text = " ".join(f"{b:02x}" for b in pattern)
        # FREEZE the region list. tuple-of-tuples == immutable.
        self._regions: tuple[tuple[int, int], ...] = tuple(
            (int(a), int(s)) for a, s in scope_regions
        )
        self._page_size = max(1, int(page_size))
        self._hit_cap = max(1, int(hit_cap))
        self._total_bytes = sum(s for _, s in self._regions)

        self._lock = threading.Lock()
        self._more_event = threading.Event()
        self._cancel = threading.Event()
        self._pending: collections.deque = collections.deque()
        self._state: str = "running"
        self._error: typing.Optional[str] = None
        self._bytes_scanned: int = 0
        self._hits_total: int = 0
        self._thread: typing.Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run, name="ScanWorker", daemon=True,
        )
        self._thread.start()

    def request_more(self) -> None:
        self._more_event.set()

    def request_cancel(self) -> None:
        self._cancel.set()
        self._more_event.set()

    def drain(self) -> list[Hit]:
        with self._lock:
            out = list(self._pending)
            self._pending.clear()
            if self._state == "paused" and len(out) > 0:
                # Caller has acknowledged; nothing else to do here.
                pass
        return out

    def status(self) -> ScanStatus:
        # `hits_loaded` reports total hits the worker has produced (not the
        # subset acknowledged by `drain()`). This lets callers poll progress
        # without a drain-side-effect; pattern_scan / search UIs maintain
        # their own per-frame drain accounting.
        with self._lock:
            return ScanStatus(
                state=self._state,
                bytes_scanned=self._bytes_scanned,
                total_bytes=self._total_bytes,
                hits_total=self._hits_total,
                hits_loaded=self._hits_total,
                error=self._error,
            )

    def join(self, timeout: typing.Optional[float] = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    # ----- worker thread body -----

    def _run(self) -> None:
        try:
            in_batch = 0
            for region_addr, region_size in self._regions:
                if self._cancel.is_set():
                    break
                scanner = LocalMemoryPatternScanner(region_addr, region_size)
                try:
                    for addr, _args in scanner.search(self._pattern_text):
                        if self._cancel.is_set():
                            break
                        if self._hits_total >= self._hit_cap:
                            break
                        with self._lock:
                            self._pending.append(Hit(addr=int(addr)))
                            self._hits_total += 1
                        in_batch += 1
                        if in_batch >= self._page_size:
                            with self._lock:
                                self._state = "paused"
                            self._more_event.wait()
                            self._more_event.clear()
                            in_batch = 0
                            with self._lock:
                                self._state = "running"
                            if self._cancel.is_set():
                                break
                except Exception as exc:
                    _log.exception("scanner failed on region 0x%X+0x%X",
                                   region_addr, region_size)
                    with self._lock:
                        self._state = "errored"
                        self._error = repr(exc)
                    return
                with self._lock:
                    self._bytes_scanned += region_size
                if self._hits_total >= self._hit_cap:
                    break
            with self._lock:
                if self._cancel.is_set():
                    self._state = "cancelled"
                elif self._state != "errored":
                    self._state = "done"
        except Exception as exc:
            _log.exception("ScanWorker thread crashed")
            with self._lock:
                self._state = "errored"
                self._error = repr(exc)


__all__ = ["Hit", "ScanStatus", "ScopeChoice", "ScanWorker"]
