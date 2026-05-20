"""Windows x64 hardware/software breakpoint primitive.

Quick start::

    from nylib.winutils.breakpoint import BreakPoint, BP_E

    def on_hit(address, t, frm, ctx):
        print(f"hit @ {address:X} from {frm:X} ecx={ctx.ecx:X}")
        ctx.ecx += 1   # mutate the trapping thread's registers

    bp = BreakPoint(addr, 1, on_hit, flag=BP_E.EXEC).install()
    ...
    bp.uninstall()

Module-level helpers::

    install(addr, size, cb, flag=...)        shorthand for BreakPoint(...).install()
    install_decorator(addr, size, flag=...)  decorator that installs and attaches .bp
    list_breakpoints() -> list[BreakPoint]
    find_breakpoint(address) -> BreakPoint | None
    uninstall_all() -> int                   tear everything down, returns count

Backends
--------
Two backends ship; pick via the ``backend=`` kwarg to :class:`BreakPoint` (or
``BreakPoint.install``):

* ``'veh'`` (default): VEH-based dispatcher. Works without elevation. Threads
  spawned after ``install()`` do NOT inherit ``tids=None`` HARD BPs - call
  ``bp.refresh_threads()`` (or ``refresh_all_threads()`` for everything).
* ``'debugger'``: in-process debugger thread using ``DebugActiveProcess``.
  **Requires SeDebugPrivilege (elevated process).** Automatically attaches
  HARD BPs to threads spawned after install via ``CREATE_THREAD_DEBUG_EVENT``.

Per-thread management (HARD BPs only)::

    bp.attach_tids([tid1, tid2])    # extend an installed HARD BP
    bp.detach_tids([tid1])          # release slots for those TIDs
    bp.tracked_tids()               # list TIDs carrying this BP
    bp.refresh_threads()            # snapshot + attach any new TIDs (returns count)
    refresh_all_threads()           # do the above for every installed BP

Known limitations (v1):
    * AMD64 only (x64).
    * In-process / local only. Pass ``target=`` to extend later (raises
      NotImplementedError in v1).
    * The debugger backend requires an elevated host (SeDebugPrivilege).
    * ``BpCtx.disable_once()`` is a marker only in v1; the backend does not
      consume it.

See ``docs/superpowers/specs/2026-05-19-breakpoint-design.md`` for the full
design and ``docs/superpowers/plans/2026-05-20-breakpoint.md`` for the
implementation plan.
"""

from __future__ import annotations

import atexit
import enum
import threading
import typing

from .ctx import BpCtx
from .backend import select_backend, loaded_backends
from .exceptions import (
    BreakpointError,
    SlotExhaustedError,
    InvalidBreakpointError,
    BackendError,
)


class BP_E(enum.IntFlag):
    """Breakpoint mode flags. See ``BP_E`` docstring in spec section 4.1."""

    EXEC  = 1 << 0
    WRITE = 1 << 1
    READ  = 1 << 2
    HARD  = 1 << 8
    SOFT  = 1 << 9


_ACCESS_MASK = BP_E.EXEC | BP_E.WRITE | BP_E.READ
_IMPL_MASK = BP_E.HARD | BP_E.SOFT


class BreakPoint:
    """A single breakpoint. Construct, then call install()."""

    def __init__(
        self,
        address: int,
        size: int,
        callback: typing.Callable[[int, "BP_E", int, BpCtx], None],
        flag: "BP_E" = BP_E.READ,
        *,
        backend: str = "veh",
        tids: typing.Sequence[int] | None = None,
        target: typing.Any = None,
        enabled: bool = True,
    ):
        if target is not None:
            raise NotImplementedError(
                "remote BreakPoint targets are reserved for a future version"
            )
        self._validate(address, size, flag)
        self.address = int(address)
        self.size = int(size)
        self.flag = BP_E(int(flag))
        self.callback = callback
        self.tids = tuple(tids) if tids is not None else None
        self._backend_name = backend
        self._enabled = bool(enabled)
        self.handle: int = 0
        self.installed: bool = False
        self.hits: int = 0  # incremented by native side via the trampoline

    @staticmethod
    def _validate(address: int, size: int, flag: "BP_E") -> None:
        if size <= 0:
            raise InvalidBreakpointError("size must be > 0")
        access = flag & _ACCESS_MASK
        if access == 0:
            raise InvalidBreakpointError(
                "flag must include one of BP_E.EXEC, WRITE, READ"
            )
        if access == BP_E.EXEC and size != 1:
            raise InvalidBreakpointError("EXEC breakpoints: size must be 1")

    def install(self) -> "BreakPoint":
        if self.installed:
            return self
        backend = select_backend(self._backend_name)
        handle = backend.install(
            address=self.address,
            size=self.size,
            flags=int(self.flag),
            callback=self.callback,
            user_data=id(self),
            tids=self.tids,
        )
        if handle == 0:
            raise BackendError("backend.install returned 0")
        if hasattr(backend, "bind_bp"):
            backend.bind_bp(handle, self)
        self.handle = handle
        self.installed = True
        if not self._enabled:
            backend.set_enabled(handle, False)
        _registry_add(self)
        return self

    def uninstall(self) -> "BreakPoint":
        if not self.installed:
            return self
        backend = select_backend(self._backend_name)
        backend.uninstall(self.handle)
        _registry_remove(self)
        self.installed = False
        self.handle = 0
        return self

    def enable(self) -> None:
        if not self.installed:
            self._enabled = True
            return
        select_backend(self._backend_name).set_enabled(self.handle, True)
        self._enabled = True

    def disable(self) -> None:
        if not self.installed:
            self._enabled = False
            return
        select_backend(self._backend_name).set_enabled(self.handle, False)
        self._enabled = False

    def is_enabled(self) -> bool:
        return self._enabled

    # ----- per-thread management (HARD BPs only) -----

    def attach_tids(self, tids: typing.Iterable[int]) -> "BreakPoint":
        """Add HW DR slots for *tids* (extends an already-installed HARD BP).

        No-op for SOFT BPs (they're per-process). Raises ``SlotExhaustedError``
        if any TID has no free slot.
        """
        if not self.installed:
            raise BreakpointError("BreakPoint must be installed before attach_tids()")
        backend = select_backend(self._backend_name)
        backend.attach_tids(self.handle, list(tids))
        return self

    def detach_tids(self, tids: typing.Iterable[int]) -> "BreakPoint":
        """Release HW DR slots for *tids*. No-op for SOFT BPs."""
        if not self.installed:
            return self
        backend = select_backend(self._backend_name)
        backend.detach_tids(self.handle, list(tids))
        return self

    def tracked_tids(self) -> list[int]:
        """Return the list of TIDs currently carrying this BP's HW slots."""
        if not self.installed:
            return []
        backend = select_backend(self._backend_name)
        return backend.list_tids(self.handle)

    def refresh_threads(self) -> int:
        """Snapshot the process's TIDs and attach any newly-seen ones.

        Returns the number of TIDs newly attached. No-op for SOFT BPs.
        """
        if not self.installed:
            return 0
        backend = select_backend(self._backend_name)
        live = set(backend.snapshot_tids())
        seen = set(backend.list_tids(self.handle))
        new = sorted(live - seen)
        if not new:
            return 0
        try:
            backend.attach_tids(self.handle, new)
        except SlotExhaustedError:
            # Partial failure: backend rolled the failing TID back; report 0
            # only if NO progress was made. Otherwise re-query to count.
            after = set(backend.list_tids(self.handle))
            return len(after - seen)
        return len(new)

    def __enter__(self) -> "BreakPoint":
        return self.install()

    def __exit__(self, *exc) -> None:
        self.uninstall()

    def __repr__(self) -> str:
        # IntFlag's __str__ became int-like in Python 3.11+. Build a readable
        # set-bit list so list_breakpoints() output stays self-explanatory.
        names = []
        for bit in (BP_E.EXEC, BP_E.WRITE, BP_E.READ, BP_E.HARD, BP_E.SOFT):
            if self.flag & bit:
                names.append(bit.name)
        flag_str = "|".join(names) if names else str(int(self.flag))
        return (
            f"<BreakPoint addr=0x{self.address:X} size={self.size} "
            f"flags={flag_str} installed={self.installed} hits={self.hits}>"
        )


# ---------------------------------------------------------------------------
# Module-level registry
# ---------------------------------------------------------------------------

_registry: list[BreakPoint] = []
_registry_lock = threading.RLock()


def _registry_add(bp: BreakPoint) -> None:
    with _registry_lock:
        if bp not in _registry:
            _registry.append(bp)


def _registry_remove(bp: BreakPoint) -> None:
    with _registry_lock:
        try:
            _registry.remove(bp)
        except ValueError:
            pass


def list_breakpoints() -> list[BreakPoint]:
    with _registry_lock:
        return list(_registry)


def find_breakpoint(address: int) -> BreakPoint | None:
    with _registry_lock:
        for bp in _registry:
            if bp.address <= int(address) < bp.address + bp.size:
                return bp
    return None


def install(
    address: int,
    size: int,
    callback: typing.Callable[[int, "BP_E", int, BpCtx], None],
    flag: "BP_E" = BP_E.READ,
    **kw,
) -> BreakPoint:
    return BreakPoint(address, size, callback, flag, **kw).install()


def install_decorator(
    address: int,
    size: int,
    flag: "BP_E" = BP_E.READ,
    **kw,
):
    def deco(func):
        bp = BreakPoint(address, size, func, flag, **kw).install()
        # Attach the BP to the function so the caller can still reach .uninstall().
        func.bp = bp
        return func
    return deco


def refresh_all_threads() -> int:
    """Call ``refresh_threads()`` on every installed BP. Returns total attachments."""
    total = 0
    for bp in list_breakpoints():
        try:
            total += bp.refresh_threads()
        except Exception:
            pass
    return total


def uninstall_all() -> int:
    count = 0
    with _registry_lock:
        snap = list(_registry)
    for bp in snap:
        try:
            bp.uninstall()
            count += 1
        except Exception:
            pass
    for backend in loaded_backends():
        try:
            backend.shutdown()
        except Exception:
            pass
    return count


atexit.register(uninstall_all)


__all__ = [
    "BP_E",
    "BpCtx",
    "BreakPoint",
    "BreakpointError",
    "SlotExhaustedError",
    "InvalidBreakpointError",
    "BackendError",
    "install",
    "install_decorator",
    "list_breakpoints",
    "find_breakpoint",
    "uninstall_all",
    "refresh_all_threads",
]
