"""Type sources over the stage-6 core (9-a4, RT3): snapshot-backed with a live fallback, and plain live reflection."""
import logging
import struct
import threading
import time
import typing
from typing import Callable

from ..engine.unreal import UEClass, UEObject
from ..model import TypeRecord
from ..reflect import _MAX_OUTERS, LiveResolver, Reflection

if typing.TYPE_CHECKING:
    from ..engine.core import Engine
    from ..snapshot import Snapshot

logger = logging.getLogger('nylib.ue.runtime.typesource')

_SEED_CLASSES = (('UEObject.GetCppName.ActorClass', 'Actor'), ('UEObject.GetCppName.InterfaceClass', 'Interface'))


def _check_int(value, name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f'{name} must be an int, got {type(value).__name__}')


def _counts(record: TypeRecord) -> tuple[int, int]:
    properties = getattr(record, 'properties', None)
    if properties is None:
        properties = getattr(record, 'params', ())
    return len(properties), len(getattr(record, 'functions', {}))


def _link_reader(e: 'Engine') -> Callable[[int], tuple[int, int, int, int]]:
    """Reads one object's `(class, comparison index, number, outer)` in one fresh read (RT1's `read` rule for the FName fields)."""
    off = e.off.UObject
    lo = min(off.Class, off.Name, off.Outer)
    size = max(off.Class + 8, off.Name + e.off.InSDK.Name.FNameSize, off.Outer + 8) - lo
    cls, outer = off.Class - lo, off.Outer - lo
    comparison_index = off.Name - lo + e.off.FName.CompIdx
    number = None if e.settings.Internal.bUseOutlineNumberName else off.Name - lo + e.off.FName.Number

    def read(address: int) -> tuple[int, int, int, int]:
        data = e.mem.read(address + lo, size)
        return (struct.unpack_from('<Q', data, cls)[0], struct.unpack_from('<i', data, comparison_index)[0],
                0 if number is None else struct.unpack_from('<I', data, number)[0], struct.unpack_from('<Q', data, outer)[0])
    return read


def _link_signature(e: 'Engine', address: int) -> tuple[tuple[int, int, int, int], ...] | None:
    """One link per object of `address`'s outer chain, outermost last; None for a cycle or LiveResolver's outer bound."""
    read = _link_reader(e)
    chain, links = [address], []
    while True:
        links.append(link := read(chain[-1]))
        if not (outer := link[3]):
            return tuple(links)
        if outer in chain or len(chain) > _MAX_OUTERS:
            return None
        chain.append(outer)


def _signature_holds(e: 'Engine', address: int, signature: tuple[tuple[int, int, int, int], ...]) -> bool:
    """Re-reads the links of `signature` in order; False at the first difference."""
    read = _link_reader(e)
    for link in signature:
        if read(address) != link:
            return False
        address = link[3]
    return True


class _NotedResolver(LiveResolver):
    """A LiveResolver that reports every path it resolves to `note`."""

    def __init__(self, e: 'Engine', note: Callable[[str, int], None]):
        super().__init__(e)
        self._note = note

    def path(self, address: int) -> str | None:
        path = super().path(address)
        if path is not None:
            self._note(path, address)
        return path


class LiveTypeSource:
    kind = 'live'

    def __init__(self, e: 'Engine', locate: Callable[[str], int | None], first_class: Callable[[str], int | None],
                 lock: threading.RLock):
        self.e = e
        self._locate = locate
        self._first_class = first_class
        self._lock = lock
        self._records: dict[str, TypeRecord] = {}
        self._negative: set[str] = set()
        self._noted: dict[str, int] = {}
        self._path_memo: dict[int, tuple[str, tuple[tuple[int, int, int, int], ...]]] = {}
        self._seeded = False

    def _seed_once(self) -> None:
        """E3's GetCppName statics, seeded from `first_class` once so the first build never walks GObjects."""
        if self._seeded:
            return
        self._seeded = True
        statics = self.e.statics
        for key, name in _SEED_CLASSES:
            if key in statics:
                continue
            address = self._first_class(name)
            if address is not None:
                statics[key] = UEClass(self.e, address)

    def type(self, path: str, address: int | None = None) -> TypeRecord | None:
        if not isinstance(path, str):
            raise TypeError(f'path must be a str, got {type(path).__name__}')
        if address is not None:
            _check_int(address, 'address')
        if (record := self._records.get(path)) is not None:
            return record
        if address is None and path in self._negative:
            return None
        with self._lock:
            if (record := self._records.get(path)) is not None:
                return record
            if address is None:
                if path in self._negative:
                    return None
                obj_address = self._noted.get(path)
                if obj_address is None:
                    obj_address = self._locate(path)
                if obj_address is None:
                    self._negative.add(path)
                    return None
            else:
                obj_address = address
            self._seed_once()
            start = time.perf_counter()
            record = Reflection(self.e, _NotedResolver(self.e, self.note)).type_record(UEObject(self.e, obj_address))
            if record is None:
                return None
            if record.path != path:
                logger.debug('type_record at %#x resolves to %s, not %s', obj_address, record.path, path)
                self._noted.pop(path, None)
                return None
            self._records[path] = record
            n, m = _counts(record)
            logger.debug('read %s: %d properties, %d functions (%d ms)', path, n, m, (time.perf_counter() - start) * 1000)
            return record

    def path_of(self, address: int) -> str | None:
        _check_int(address, 'address')
        if address == 0:
            return None
        e = self.e
        if (cached := self._path_memo.get(address)) is not None and _signature_holds(e, address, cached[1]):
            return cached[0]
        with self._lock:
            if (cached := self._path_memo.get(address)) is not None and _signature_holds(e, address, cached[1]):
                return cached[0]
            if (before := _link_signature(e, address)) is None:
                return None
            if (path := LiveResolver(e).path(address)) is None:
                return None
            self.note(path, address)
            if _link_signature(e, address) == before:
                self._path_memo[address] = (path, before)
            return path

    def note(self, path: str, address: int) -> None:
        if not isinstance(path, str):
            raise TypeError(f'path must be a str, got {type(path).__name__}')
        _check_int(address, 'address')
        with self._lock:
            self._noted[path] = address

    def refresh(self) -> None:
        with self._lock:
            self._negative.clear()
            self._noted.clear()
            self._path_memo.clear()


class SnapshotTypeSource:
    kind = 'snapshot'

    def __init__(self, snapshot: 'Snapshot', live: LiveTypeSource, lock: threading.RLock):
        self.snapshot = snapshot
        self.live = live
        self._lock = lock

    def type(self, path: str, address: int | None = None) -> TypeRecord | None:
        if not isinstance(path, str):
            raise TypeError(f'path must be a str, got {type(path).__name__}')
        if address is not None:
            _check_int(address, 'address')
        with self._lock:
            record = self.snapshot.type(path)
        if record is not None:
            return record
        record = self.live.type(path, address)
        if record is not None:
            logger.debug('type %s is not in the snapshot; read live', path)
        return record

    def path_of(self, address: int) -> str | None:
        return self.live.path_of(address)

    def note(self, path: str, address: int) -> None:
        self.live.note(path, address)

    def refresh(self) -> None:
        self.live.refresh()
