"""Backend abstraction for nylib.winutils.breakpoint."""

from __future__ import annotations

import abc
import threading
import typing


class BreakpointBackend(abc.ABC):
    """Backend ABC. Each backend wraps one native dispatcher DLL."""

    name: str = "<unset>"

    @abc.abstractmethod
    def install(
        self,
        *,
        address: int,
        size: int,
        flags: int,
        callback: typing.Callable,
        user_data: int,
        tids: typing.Sequence[int] | None,
    ) -> int:
        """Install a breakpoint. Returns an opaque handle (non-zero on success)."""

    @abc.abstractmethod
    def uninstall(self, handle: int) -> None: ...

    @abc.abstractmethod
    def set_enabled(self, handle: int, enabled: bool) -> None: ...

    @abc.abstractmethod
    def slots_free(self, tid: int) -> int: ...

    @abc.abstractmethod
    def shutdown(self) -> None: ...

    # ----- optional per-thread management (HARD BPs only) -----
    # Backends that don't support per-TID slot management can leave these as
    # no-ops; the BreakPoint wrapper checks `hasattr(backend, ...)`.

    def attach_tids(self, handle: int, tids) -> None:  # noqa: D401
        """Add HW DR slots for `tids` to an existing HARD BP. Default: no-op."""
        return None

    def detach_tids(self, handle: int, tids) -> None:
        """Release HW DR slots for `tids`. Default: no-op."""
        return None

    def list_tids(self, handle: int) -> list[int]:
        """Return TIDs currently carrying this BP. Default: empty."""
        return []

    def snapshot_tids(self) -> list[int]:
        """Snapshot the host process's TIDs. Default: empty."""
        return []


# ---------------------------------------------------------------------------
# Backend factory + registry
# ---------------------------------------------------------------------------

class _BackendToken:
    def __init__(self, name: str):
        self._name = name

    def unregister(self) -> None:
        with _registry_lock:
            _backends.pop(self._name, None)
            _factories.pop(self._name, None)


_registry_lock = threading.RLock()
_factories: dict[str, typing.Callable[[], BreakpointBackend]] = {}
_backends: dict[str, BreakpointBackend] = {}


def register_backend(
    name: str,
    factory: typing.Callable[[], BreakpointBackend],
) -> _BackendToken:
    """Register a backend factory. Used by tests and the built-in registrations below."""
    with _registry_lock:
        _factories[name] = factory
        _backends.pop(name, None)
    return _BackendToken(name)


def select_backend(name: str = "veh") -> BreakpointBackend:
    """Return (creating on first use) the named backend instance."""
    with _registry_lock:
        if name in _backends:
            return _backends[name]
        factory = _factories.get(name)
        if factory is None:
            raise ValueError(f"unknown backend: {name!r}")
        backend = factory()
        _backends[name] = backend
        return backend


def loaded_backends() -> list[BreakpointBackend]:
    with _registry_lock:
        return list(_backends.values())


# ---------------------------------------------------------------------------
# Default factory registrations (lazy import; importing veh would load ctypes)
# ---------------------------------------------------------------------------

def _veh_factory() -> BreakpointBackend:
    from .veh import VehBackend
    return VehBackend()


def _debugger_factory() -> BreakpointBackend:
    from .debugger import DebuggerBackend
    return DebuggerBackend()


register_backend("veh", _veh_factory)
register_backend("debugger", _debugger_factory)
