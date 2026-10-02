"""Runtime sessions (RT8): Unreal.attach / attach_current, the session context (RT0), policies and lookups."""
import enum
import logging
import os
import re
import threading
from typing import Iterable

from .. import pipeline, profiles, store
from ..engine.accessor import view
from ..engine.context import EngineContext
from ..engine.unreal import UEClass
from ..errors import AmbiguousNameError, CallsDisabledError, DetectionError, DumpMismatchError, MemoryReadError, OutputRootError, \
    ReadOnlySessionError, SessionError, UnverifiedOffsetsError
from ..memory import ProcessSource, current_process
from ..model import ClassRecord, EnumRecord, FunctionRecord, StructRecord, hexs, unhex
from ..snapshot import SCHEMA_MAJOR, Snapshot
from .accessor import RuntimeAccessor
from .index import ObjectIndex
from .names import FNameValue, NameDecoder
from .types import ClassFactory, RawPointer, StructView, UObjectProxy
from .typesource import LiveTypeSource, SnapshotTypeSource

logger = logging.getLogger('nylib.ue.runtime.session')
_info = logging.getLogger('nylib.ue.runtime')

_SUPER_STEPS = 256
_TEXT_KEYS = ('Off.InSDK.Text.TextDatOffset', 'Off.InSDK.Text.InTextDataStringOffset')
_KNOWN_LABELS = ('auto:', 'profile:')
_PYTHON_EXE_RE = re.compile(r'pythonw?[0-9.]*\.exe', re.IGNORECASE)
_GAME_THREAD = ("calls='game-thread' (a detour on UObject::ProcessEvent) is not implemented yet (stage 15); "
                "use calls='remote-thread' outside the game or calls='any-thread' inside it")


def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _closed_error() -> SessionError:
    return SessionError('the session is closed')


class RuntimeContext:
    """One session's shared state (RT0); codecs, containers and dynamic classes reach the target only through it."""

    def __init__(self, e, *, write: bool, calls: str | None, mode: str):
        self.e = e
        self.write = bool(write)
        self.calls = calls
        self.mode = mode
        self.closed = False
        self.lock = threading.RLock()
        self.acc = self.names = self.index = self.types = self.factory = None

    def proxy(self, address: int) -> UObjectProxy | None:
        if not _is_int(address):
            raise TypeError(f'address must be an int, got {type(address).__name__}')
        if address == 0:
            return None
        e = self.e
        return self._proxy_of(address, e.mem.ptr(address + e.off.UObject.Class))

    def _proxy_of(self, address: int, cls: int) -> UObjectProxy:
        return view(self.factory.class_for(self.types.path_of(cls), cls), address, self.acc)

    def struct_view(self, path: str, address: int) -> StructView:
        if not isinstance(path, str):
            raise TypeError(f'path must be a str, got {type(path).__name__}')
        if not _is_int(address):
            raise TypeError(f'address must be an int, got {type(address).__name__}')
        if address == 0:
            raise ValueError('null struct address')
        return view(self.factory.struct_for(path), address, self.acc)

    def raw_view(self, address: int) -> RawPointer | None:
        if not _is_int(address):
            raise TypeError(f'address must be an int, got {type(address).__name__}')
        return None if address == 0 else view(self.factory.raw_class(), address, self.acc)

    def enum_class(self, path: str | None) -> type[enum.IntEnum] | None:
        if path is None:
            return None
        if not isinstance(path, str):
            raise TypeError(f'path must be a str or None, got {type(path).__name__}')
        return self.factory.enum_for(path)

    def is_subclass(self, path: str, base: str) -> bool:
        if not isinstance(path, str) or not isinstance(base, str):
            raise TypeError('path and base must be str')
        if path == base:
            return True
        p = path
        for _ in range(_SUPER_STEPS):
            rec = self.types.type(p)
            if not isinstance(rec, StructRecord) or rec.super is None:
                return False
            if (p := rec.super) == base:
                return True
        return False

    def weak_get(self, index: int, serial: int) -> UObjectProxy | None:
        if not _is_int(index) or not _is_int(serial):
            raise TypeError('index and serial must be int')
        if index < 0 or serial == 0 or index >= self.e.objects.num():
            return None
        obj, item_serial = self.index.item(index)
        if obj == 0 or item_serial != serial:
            return None
        return self.proxy(obj)

    def weak_ref(self, obj: UObjectProxy | None) -> tuple[int, int]:
        if obj is None:
            return 0, 0
        if not isinstance(obj, UObjectProxy) or type(obj)._ue_ctx_ is not self:
            raise TypeError(f'expected an object of this session, got {type(obj).__name__}')
        e = self.e
        i = e.mem.i32(obj._address_ + e.off.UObject.Index)
        addr, serial = self.index.item(i)
        if addr != obj._address_:
            raise ValueError(f'{obj!r} is not at its GObjects slot {i}')
        if serial == 0:
            raise NotImplementedError('the object has no weak-pointer serial number yet; giving it one needs the engine')
        return i, serial

    def text_layout(self) -> tuple[int, int]:
        e = self.e
        if all(e.provenance.get(k, '').startswith(_KNOWN_LABELS) for k in _TEXT_KEYS):
            return e.off.InSDK.Text.TextDatOffset, e.off.InSDK.Text.InTextDataStringOffset
        raise DetectionError('Off::InSDK::Text::InitTextOffsets',
                             'the FText layout is unknown in this session: TextDatOffset and InTextDataStringOffset need a ProcessEvent '
                             'call, which v1 does not make; pin both in a profile ([offsets] "Off.InSDK.Text.TextDatOffset" and '
                             '"Off.InSDK.Text.InTextDataStringOffset")')

    def check_write(self, label: str) -> None:
        if self.closed:
            raise _closed_error()
        if not self.write:
            if self.mode == 'internal':
                text = f'cannot write {label}: the session is read-only. Attach with write=True.'
            else:
                text = f'cannot write {label}: the session is read-only. Attach with write=True (opens the target with VM_WRITE | VM_OPERATION).'
            raise ReadOnlySessionError(text, member=label)

    def invoke(self, obj: UObjectProxy, fn: FunctionRecord, args: tuple, kwargs: dict):
        if self.closed:
            raise _closed_error()
        if self.calls is None:
            owner = type(obj)._ue_name_
            raise CallsDisabledError(
                f"{owner}.{fn.name} needs a UFunction call (ProcessEvent in the target), and this session was attached with calls=None. "
                f"Choose a policy:\n"
                f"  Unreal.attach(..., calls='remote-thread')    external: a new remote thread, not the game thread; can crash the game\n"
                f"  Unreal.attach_current(calls='any-thread')    injected: runs on the calling thread; can crash\n"
                f"calls='game-thread' (queued onto the game thread through a ProcessEvent detour) is not available yet.",
                owner=owner, function=fn.name)
        raise NotImplementedError('UFunction calls are not implemented yet (stage 10)')


def unverified_gate(keys: Iterable[str], *, write: bool, allow_unverified: bool, source: str = 'probe',
                    target: str = '<exe>') -> tuple[str, ...]:
    """D13 (literal, no key exempt): refuse write=True over unverified offsets unless allow_unverified; returns the keys."""
    if not isinstance(source, str) or not isinstance(target, str):
        raise TypeError('source and target must be str')
    try:
        gating = tuple(keys)
    except TypeError:
        raise TypeError(f'keys must be an iterable of str, got {type(keys).__name__}') from None
    if not all(isinstance(k, str) for k in gating):
        raise TypeError('keys must be an iterable of str')
    if write and gating:
        if not allow_unverified:
            raise UnverifiedOffsetsError(
                f'{len(gating)} offsets of this {source} are unverified, and write=True would write through them:\n'
                + ''.join(f'  {k}\n' for k in gating)
                + f'Check them with:  python -m nylib.ue probe {target}\n'
                  f'Then pin them in a profile (a snapshot session needs a new dump made with it), or pass allow_unverified=True.',
                keys=gating)
        logger.warning('write=True with %d unverified offsets of this %s (allow_unverified=True): %s', len(gating), source, ', '.join(gating))
    return gating


def _check_path_arg(value, name: str) -> str:
    s = os.fspath(value)
    if not isinstance(s, str):
        raise TypeError(f'{name} must be a str path, got {type(s).__name__}')
    if s == '':
        raise ValueError(f'{name} must not be empty')
    return s


def _check_dump_profile(dump, profile):
    if dump is not None and not (isinstance(dump, str) and dump in ('latest', 'auto')):
        if not isinstance(dump, (str, os.PathLike)):
            raise TypeError(f"dump must be None, 'latest', 'auto' or a folder, got {type(dump).__name__}")
        dump = _check_path_arg(dump, 'dump')
    if profile is not None and not isinstance(profile, (str, os.PathLike, profiles.Profile)):
        raise TypeError(f'profile must be None, str, os.PathLike or Profile, got {type(profile).__name__}')
    return dump


def _check_tail(out, open_target):
    if out is not None:
        if not isinstance(out, (str, os.PathLike)):
            raise TypeError(f'out must be None, str or os.PathLike, got {type(out).__name__}')
        _check_path_arg(out, 'out')
    if open_target is not None and not callable(open_target):
        raise TypeError(f'_open_target must be callable, got {type(open_target).__name__}')


def _meta_hex(value):
    try:
        return unhex(value)
    except ValueError:
        return None


def _hexs_or_unknown(value) -> str:
    return hexs(value) if _is_int(value) else '?'


def _profile_label(profile) -> str:
    if isinstance(profile, profiles.Profile):
        return profile.path or '<string>'
    return os.path.abspath(os.fspath(profile))


class Unreal:
    """A runtime session over one target; constructed only by attach / attach_current."""

    def __init__(self, *args, **kwargs):
        raise TypeError('use Unreal.attach(...) or Unreal.attach_current(...)')

    @classmethod
    def attach(cls, target: int | str, *, dump=None, profile=None, write: bool = False, calls: str | None = None,
               allow_unverified: bool = False, out=None, _open_target=None) -> 'Unreal':
        """Attach to a running game from outside (external) or to a capture through `_open_target`."""
        if target is None:
            raise TypeError('Unreal.attach needs a target; inside the game use Unreal.attach_current()')
        if isinstance(target, bool) or not isinstance(target, (int, str)):
            raise TypeError(f'target must be an int or str, got {type(target).__name__}')
        if target == '':
            raise ValueError('target must not be empty')
        dump = _check_dump_profile(dump, profile)
        if calls is not None and calls != 'remote-thread':
            if calls == 'any-thread':
                raise ValueError("calls='any-thread' runs ProcessEvent on the calling thread, which exists only inside the game: "
                                 "use Unreal.attach_current(calls='any-thread')")
            if calls == 'game-thread':
                raise NotImplementedError(_GAME_THREAD)
            raise ValueError(f"calls must be None or 'remote-thread' for an external session, got {calls!r}")
        _check_tail(out, _open_target)
        root = store.resolve_out_root(out)
        return cls._attach(target, root, dump=dump, profile=profile, write=write, calls=calls, allow_unverified=allow_unverified,
                           open_target=_open_target)

    @classmethod
    def attach_current(cls, *, dump=None, profile=None, write: bool = False, calls: str | None = None,
                       allow_unverified: bool = False, out=None, _open_target=None) -> 'Unreal':
        """Attach to the game this code runs inside (injected)."""
        dump = _check_dump_profile(dump, profile)
        if calls is not None and calls != 'any-thread':
            if calls == 'remote-thread':
                raise ValueError("calls='remote-thread' starts a thread in another process; inside the game use calls='any-thread'")
            if calls == 'game-thread':
                raise NotImplementedError(_GAME_THREAD)
            raise ValueError(f"calls must be None or 'any-thread' inside the game, got {calls!r}")
        _check_tail(out, _open_target)
        if dump in ('latest', 'auto'):
            root = store.resolve_out_root(out, internal=True)
        else:
            try:
                root = store.resolve_out_root(out, internal=True)
            except OutputRootError:
                root = None
        return cls._attach(None, root, dump=dump, profile=profile, write=write, calls=calls, allow_unverified=allow_unverified,
                           open_target=_open_target)

    @classmethod
    def _attach(cls, target, root, *, dump, profile, write, calls, allow_unverified, open_target) -> 'Unreal':
        write = bool(write)
        snap = opened = None
        dumped = False
        try:
            if dump not in (None, 'latest', 'auto'):
                snap = Snapshot.load(dump)
            elif dump is None and isinstance(profile, (str, os.PathLike)):
                profile = profiles.load_profile(profile)
            opened = (open_target or pipeline.open_target)(target, write=write, remote_calls=(calls == 'remote-thread'), cache_bytes=None)
            info = opened.info
            if dump is not None:
                snap, ectx, dumped = cls._snapshot_engine(target, root, dump, snap, profile, opened, write, allow_unverified)
                unverified = tuple(ectx.unverified())
                if not dumped:
                    unverified_gate(unverified, write=write, allow_unverified=allow_unverified, source='snapshot', target=info.exe)
            else:
                ectx, unverified, probe_line = cls._live_engine(opened, profile, root, write, allow_unverified)

            ctx = RuntimeContext(ectx.engine, write=write, calls=calls, mode=info.mode)
            e, lock = ctx.e, ctx.lock
            ctx.names = NameDecoder(e, lock)
            ctx.index = index = ObjectIndex(e, ctx.names.decode, lock)
            live = LiveTypeSource(e, index.find, lambda name: next(iter(index.classes_named(name)), None), lock)
            ctx.types = SnapshotTypeSource(snap, live, lock) if snap is not None else live
            ctx.acc = RuntimeAccessor(e.mem)
            ctx.acc.ctx = ctx
            ctx.factory = ClassFactory(ctx)

            if snap is not None:
                _info.info('snapshot %s matches the running build (pe %s / %s)', os.path.basename(snap.path), hexs(info.pe_timestamp),
                           hexs(info.size_of_image))
                counts = snap.meta.get('counts')
                try:
                    n = sum(counts[k] for k in ('classes', 'structs', 'enums'))
                except (TypeError, KeyError):
                    n = None
                _info.info('types load on first use' + (f' (index: {n:,} types)' if _is_int(n) else ''))
                if profile is not None and not dumped:
                    logger.warning('profile %s ignored: offsets and types come from the snapshot', _profile_label(profile))
            else:
                _info.info(probe_line)
                _info.info('types are read from the live process on first use')
        except BaseException:
            if snap is not None:
                snap.close()
            if opened is not None:
                opened.close()
            raise

        self = object.__new__(cls)
        self._ctx, self._opened, self._snap = ctx, opened, snap
        self.mode, self.pid, self.exe, self.target = info.mode, info.pid, info.exe, info
        self.types = 'snapshot' if snap is not None else 'live'
        self.snapshot = os.path.abspath(snap.path) if snap is not None else None
        self.write, self.calls = write, calls
        self.unverified = tuple(unverified)
        return self

    @staticmethod
    def _snapshot_engine(target, root, dump, snap, profile, opened, write, allow_unverified):
        info = opened.info
        exe, ts, size = info.exe, info.pe_timestamp, info.size_of_image
        out_part = f' --out {root}' if root is not None else ''
        dumped = False
        loaded = None
        if dump in ('latest', 'auto'):
            refs = [r for r in store.find_snapshots(root, exe=exe, pe_timestamp=ts, size_of_image=size) if _schema_major(r) == SCHEMA_MAJOR]
            if refs:
                snap = loaded = Snapshot.load(refs[0].path)
            elif dump == 'latest':
                newest = next(iter(store.find_snapshots(root, exe=exe)), None)
                text = f'no snapshot matches the running build\n  running   {exe}  pe {hexs(ts)} / {hexs(size)}\n'
                if newest is not None:
                    text += (f'  newest    {newest.path}  pe {_hexs_or_unknown(newest.pe_timestamp)} / {_hexs_or_unknown(newest.size_of_image)}\n'
                             f'  The game was updated; offsets from an older build are not safe to write through.\n')
                else:
                    text += f'  newest    none under {root}\n'
                text += f'  Run:  python -m nylib.ue dump {exe}{out_part}\n  or attach with dump=\'auto\' to do that automatically.'
                raise DumpMismatchError(text, running=(exe, ts, size), newest=newest.path if newest is not None else None, out_root=root)
            else:
                _info.info('no snapshot for build %s; running the dumper (%s)', hexs(ts), info.mode)
                shared = pipeline.OpenedTarget(opened.source, opened.info, opened.process, opened.check_alive, None)
                res = pipeline.dump(target, profile=profile, out=root, _open_target=lambda *a, **k: shared)
                unverified_gate(res.unverified, write=write, allow_unverified=allow_unverified, source='dump', target=exe)
                snap = loaded = Snapshot.load(res.path)
                dumped = True
        else:
            t = snap.meta.get('target')
            t = t if isinstance(t, dict) else {}
            module = t.get('module')
            module = module if isinstance(module, dict) else {}
            ts2, size2 = module.get('pe_timestamp'), module.get('size')
            snap_exe = t.get('exe')
            if _meta_hex(ts2) != ts or _meta_hex(size2) != size:
                ts2 = ts2 if _meta_hex(ts2) is not None else '?'
                size2 = size2 if _meta_hex(size2) is not None else '?'
                raise DumpMismatchError(
                    f'snapshot {dump} is for another build\n  running   {exe}  pe {hexs(ts)} / {hexs(size)}\n'
                    f'  snapshot  {snap_exe if isinstance(snap_exe, str) else "?"}  pe {ts2} / {size2}\n'
                    f'  Offsets from another build are not safe to write through.\n  Run:  python -m nylib.ue dump {exe}{out_part}',
                    running=(exe, ts, size), snapshot=dump, out_root=root)
            if not (isinstance(snap_exe, str) and snap_exe.casefold() == exe.casefold()):
                logger.warning('snapshot %s was taken from %s; the target is %s (same build)', dump, snap_exe, exe)
        try:
            if dumped:
                opened.source.refresh()
            ectx = EngineContext.from_snapshot(snap.meta, snap.offsets, opened.source.fresh)
        except BaseException:
            if loaded is not None:
                loaded.close()
            raise
        return snap, ectx, dumped

    @staticmethod
    def _live_engine(opened, profile, root, write, allow_unverified):
        report = pipeline.probe_opened(opened, profile=profile, out_root=root)
        if not report.ok:
            raise report.error
        meta = report.context.to_meta()
        if meta['globals']['GObjects']['decrypted']:
            hook = report.context.engine.objects.DecryptionLambdaStr
            raise DetectionError('Unreal.attach', f'runtime sessions cannot use a GObjects decryption hook in v1 (the probe used {hook}); '
                                                  f'dump the game instead')
        unverified = unverified_gate(report.unverified, write=write, allow_unverified=allow_unverified, target=opened.info.exe)
        ectx = EngineContext.from_snapshot(meta, report.context.to_offsets(), opened.source.fresh)
        g = meta['globals']
        probe_line = (f'probe: GObjects {g["GObjects"]["rva"]} · GNames {g["GNames"]["rva"]} · {len(report.values)} offsets '
                      f'({report.seconds:.1f}s)')
        del report, meta
        opened.source.refresh()
        return ectx, unverified, probe_line

    @staticmethod
    def injected() -> bool:
        """True unless the main module is a python(w) executable (a heuristic: a frozen Python app looks injected)."""
        return not _PYTHON_EXE_RE.fullmatch(ProcessSource(current_process(), cache=False).main_module.name)

    # lookups

    def _live(self) -> RuntimeContext:
        if (ctx := self._ctx).closed:
            raise _closed_error()
        return ctx

    def _class_address(self, cls) -> int:
        ctx = self._ctx
        if isinstance(cls, str):
            if (found := self.find_class(cls)) is None:
                raise LookupError(f'no class {cls!r}')
            return found._address_
        if isinstance(cls, UObjectProxy) and type(cls)._ue_ctx_ is ctx:
            if ctx.index.is_class_object(cls._address_):
                return cls._address_
            raise TypeError(f'{cls!r} is not a class object')
        if isinstance(cls, type) and issubclass(cls, UObjectProxy) and getattr(cls, '_ue_ctx_', None) is ctx:
            if cls._ue_path_ is None:
                raise TypeError(f'{cls.__name__} is the session root class and names no UE class')
            if (found := self.find_class(cls._ue_path_)) is None:
                raise LookupError(f'no class {cls._ue_path_!r}')
            return found._address_
        raise TypeError(f'expected a class name, path, class object or proxy class of this session, got {type(cls).__name__}')

    def _proxies(self, addresses, what: str, class_address: int | None) -> list:
        ctx, out, lost, moved = self._ctx, [], 0, 0
        e = ctx.e
        for a in addresses:
            try:
                cls = e.mem.ptr(a + e.off.UObject.Class)
                if class_address is not None and class_address not in ctx.index.super_chain(cls):
                    moved += 1
                    continue
                out.append(ctx._proxy_of(a, cls))
            except MemoryReadError:
                lost += 1
        if lost or moved:
            logger.debug('%s: left out %d unreadable objects and %d no longer of the class', what, lost, moved)
        return out

    def find(self, path: str) -> UObjectProxy | None:
        ctx = self._live()
        if not isinstance(path, str):
            raise TypeError(f'path must be a str, got {type(path).__name__}')
        a = ctx.index.find(path)
        return ctx.proxy(a) if a is not None else None

    def find_class(self, name: str) -> UObjectProxy | None:
        ctx = self._live()
        if not isinstance(name, str):
            raise TypeError(f'name must be a str, got {type(name).__name__}')
        if '/' in name:
            a = ctx.index.find(name)
            return ctx.proxy(a) if a is not None and ctx.index.is_class_object(a) else None
        found = ctx.index.classes_named(name)
        if not found:
            return None
        if len(found) == 1:
            return ctx.proxy(found[0])
        paths = [ctx.types.path_of(a) for a in found]
        raise AmbiguousNameError(f'{name!r} matches {len(paths)} classes:\n' + ''.join(f'  {p}\n' for p in paths)
                                 + f'pass the full path, e.g. ue.find_class({paths[0]!r})', name=name, candidates=paths)

    def objects_of(self, cls) -> list[UObjectProxy]:
        ctx = self._live()
        a = self._class_address(cls)
        return self._proxies(ctx.index.instances(a), 'objects_of', a)

    def search(self, pattern: str, class_=None) -> list[UObjectProxy]:
        ctx = self._live()
        if not isinstance(pattern, str):
            raise TypeError(f'pattern must be a str, got {type(pattern).__name__}')
        a = self._class_address(class_) if class_ is not None else None
        return self._proxies(ctx.index.search(pattern, a), 'search', a)

    def cdo(self, cls) -> UObjectProxy | None:
        ctx = self._live()
        return ctx.proxy(UEClass(ctx.e, self._class_address(cls)).get_default_object().address)

    def component(self, actor: UObjectProxy, cls) -> UObjectProxy | None:
        ctx = self._live()
        if not isinstance(actor, UObjectProxy) or type(actor)._ue_ctx_ is not ctx:
            raise TypeError(f'actor must be an object of this session, got {type(actor).__name__}')
        address = self._class_address(cls)
        if (a := ctx.index.owned(actor._address_, address)) is None:
            return None
        e = ctx.e
        try:
            row_cls = e.mem.ptr(a + e.off.UObject.Class)
            row_outer = e.mem.ptr(a + e.off.UObject.Outer)
            if address not in ctx.index.super_chain(row_cls) or row_outer != actor._address_:
                logger.debug('component: dropped a stale row (address reused since the index was built)')
                return None
            return ctx._proxy_of(a, row_cls)
        except MemoryReadError:
            logger.debug('component: dropped an unreadable row (address reused since the index was built)')
            return None

    def world(self) -> UObjectProxy | None:
        ctx = self._live()
        e = ctx.e
        if (gworld := e.off.InSDK.World.GWorld) == 0:
            raise DetectionError('Off::InSDK::World::InitGWorld', 'GWorld was not found on this target')
        return ctx.proxy(e.mem.ptr(e.platform.get_module_base() + gworld))

    def local_player_controller(self) -> UObjectProxy | None:
        if (world := self.world()) is None or (gi := world._get_('OwningGameInstance')) is None:
            return None
        players = gi._get_('LocalPlayers')
        if players is None or len(players) == 0 or (player := players[0]) is None:
            return None
        return player._get_('PlayerController')

    def enum(self, path: str) -> type[enum.IntEnum] | None:
        return self._live().enum_class(path)

    def fname(self, text: str) -> FNameValue | None:
        return self._live().names.lookup(text)

    def type(self, path: str) -> type | None:
        ctx = self._live()
        if not isinstance(path, str):
            raise TypeError(f'path must be a str, got {type(path).__name__}')
        rec = ctx.types.type(path)
        if isinstance(rec, ClassRecord):
            return ctx.factory.class_for(path)
        if isinstance(rec, StructRecord):
            return ctx.factory.struct_for(path)
        if isinstance(rec, EnumRecord):
            return ctx.factory.enum_for(path)
        return None

    def refresh(self) -> None:
        ctx = self._live()
        ctx.index.refresh()
        ctx.names.refresh()
        ctx.types.refresh()

    def close(self) -> None:
        ctx = self._ctx
        if ctx.closed:
            return
        ctx.closed = True
        with ctx.lock:
            if self._snap is not None:
                self._snap.close()
        self._opened.close()

    def __enter__(self) -> 'Unreal':
        self._live()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __repr__(self) -> str:
        return f'<Unreal {self.mode} pid {self.pid} {self.exe} types={self.types} {"writable" if self.write else "read-only"}>'


def _schema_major(ref) -> int | None:
    try:
        return int(ref.schema_version.split('.')[0])
    except (AttributeError, ValueError):
        return None
