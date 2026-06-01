"""BpHitRecorder - wraps a BreakPoint callback, records per-`frm`
hit metadata, auto-excludes the DebugView's worker TID.

Each captured hit is stored as an immutable `HitSample` in a per-frm
ring buffer (default 64 most-recent). `snapshot()` returns one
`HitRecord` per frm with the full sample history attached.

Used by `DebugViewState.install_bp` to instrument BPs created from the
debug view UI. BPs created outside the view (no recorder) are not
auto-excluded.
"""
from __future__ import annotations

import collections
import dataclasses
import logging
import threading
import time
import typing

if typing.TYPE_CHECKING:
    from ..state import DebugViewState

_log = logging.getLogger("nylib.imguiutils.debug_view")


# Default ring-buffer depth per frm. Bounded so a hot BP can't bloat
# memory; configurable via BpHitRecorder(history=...).
_DEFAULT_HISTORY = 64
_MAX_HISTORY = 1024


@dataclasses.dataclass(frozen=True)
class HitSample:
    """One captured BP hit (immutable). Stored in HitRecord.samples.

    `xmm` is a tuple of (name, 16-byte-buffer) pairs ordered xmm0..xmm15,
    captured from BpCtx.xmm at hit time. Empty tuple if the backend or
    ctx didn't expose XMM (older backends, or capture failure)."""
    when_ns: int
    regs: tuple[tuple[str, int], ...]   # canonical-ordered (name, value) pairs
    stack: tuple[int, ...]
    xmm: tuple[tuple[str, bytes], ...] = ()


@dataclasses.dataclass(frozen=True)
class HitRecord:
    """Per-frm aggregate returned by `snapshot()`. `samples` is the
    bounded ring buffer of most-recent hits, oldest first / newest last."""
    frm: int
    count: int
    last_seen_ns: int
    samples: tuple[HitSample, ...]

    # ----- backwards-compat shims (v1.0 callers) -----

    @property
    def last_regs(self) -> tuple[tuple[str, int], ...]:
        """Most-recent sample's regs, or () when no samples."""
        return self.samples[-1].regs if self.samples else ()

    @property
    def last_stack(self) -> tuple[int, ...]:
        """Most-recent sample's stack, or () when no samples."""
        return self.samples[-1].stack if self.samples else ()

    @property
    def last_xmm(self) -> tuple[tuple[str, bytes], ...]:
        """Most-recent sample's xmm snapshot, or () when no samples."""
        return self.samples[-1].xmm if self.samples else ()


@dataclasses.dataclass
class _HitInternal:
    count: int
    last_seen_ns: int
    samples: "collections.deque[HitSample]"


_REG_DISPLAY_ORDER = (
    "rip", "rsp", "rbp",
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eflags",
)


def _order_regs(regs: dict[str, int]) -> tuple[tuple[str, int], ...]:
    """Return regs as a stable ordered tuple. Known x64 regs first in
    canonical order, any unknown extras appended in alphabetical order."""
    known = []
    for name in _REG_DISPLAY_ORDER:
        if name in regs:
            known.append((name, int(regs[name])))
    extras = sorted(
        (name, int(val)) for name, val in regs.items()
        if name not in _REG_DISPLAY_ORDER
    )
    return tuple(known) + tuple(extras)


class BpHitRecorder:
    """Callable that wraps a user BP callback, recording per-`frm` stats.

    Auto-excludes the DebugView's worker TID (set on `state.worker_tid`)
    so the worker's continuous memory reads don't produce hit records.
    The BP itself still installs on all threads; only the recorder's
    per-call filter drops worker-thread hits.

    Each captured hit appends a `HitSample` to a bounded ring buffer
    (default 64) per frm. Older samples are evicted as new ones arrive.
    """

    def __init__(self, *, state: "DebugViewState",
                 user_callback: typing.Callable | None = None,
                 stack_frames: int = 32,
                 history: int = _DEFAULT_HISTORY) -> None:
        self._state = state
        self._user_callback = user_callback
        self._stack_frames = max(1, min(64, int(stack_frames)))
        self._history = max(1, min(_MAX_HISTORY, int(history)))
        self._lock = threading.Lock()
        self._hits: dict[int, _HitInternal] = {}
        self._total = 0

    def __call__(self, address: int, t, frm: int, ctx) -> None:
        try:
            if ctx.tid == self._state.worker_tid:
                return
            try:
                stack = tuple(ctx.stack(self._stack_frames))
            except Exception:
                stack = ()
            try:
                regs_dict = ctx.regs
                # Coerce to immutable ordered tuple-of-tuples for HitSample.
                # Stable display order: instruction pointer + stack pointers
                # first, then GPRs, then eflags. Unknown extras append last.
                regs = _order_regs(regs_dict)
            except Exception:
                regs = ()
            try:
                # BpCtx.xmm returns {name: bytes(16)} ordered xmm0..xmm15.
                # Older backends without an .xmm attribute fall through to
                # the empty-tuple default on HitSample.
                xmm_dict = ctx.xmm
                xmm = tuple((name, bytes(buf)) for name, buf in xmm_dict.items())
            except Exception:
                xmm = ()
            now_ns = time.monotonic_ns()
            sample = HitSample(when_ns=now_ns, regs=regs, stack=stack, xmm=xmm)
            with self._lock:
                h = self._hits.get(frm)
                if h is None:
                    h = _HitInternal(
                        count=0, last_seen_ns=now_ns,
                        samples=collections.deque(maxlen=self._history),
                    )
                    self._hits[frm] = h
                h.count += 1
                h.last_seen_ns = now_ns
                h.samples.append(sample)
                self._total += 1
            if self._user_callback is not None:
                try:
                    self._user_callback(address, t, frm, ctx)
                except Exception:
                    _log.exception("user BP callback failed")
        except Exception:
            _log.exception("BpHitRecorder failed")

    def snapshot(self) -> list[HitRecord]:
        """Return all hits as immutable HitRecord items, sorted by count desc."""
        with self._lock:
            records = [HitRecord(frm=k, count=v.count,
                                  last_seen_ns=v.last_seen_ns,
                                  samples=tuple(v.samples))
                       for k, v in self._hits.items()]
        records.sort(key=lambda r: r.count, reverse=True)
        return records

    def total(self) -> int:
        with self._lock:
            return self._total

    def set_stack_frames(self, n: int) -> None:
        self._stack_frames = max(1, min(64, int(n)))


__all__ = ["BpHitRecorder", "HitRecord", "HitSample"]
