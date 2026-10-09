"""UFunction calls (RT10): argument binding, marshalling into call memory, function resolution and detached results."""
import collections
import logging
import struct
import time
from typing import ClassVar

from .. import calls
from ..engine.unreal import UEClass
from ..errors import CallError, MarshalError, MemoryReadError, SessionError
from ..flags import EFunctionFlags
from ..memory import MemorySource
from ..model import ClassRecord, FunctionRecord, StructRecord, UNKNOWN_KIND
from ..names import make_name_valid
from . import codecs
from .accessor import RuntimeAccessor
from .codecs import FTextValue, WeakObjectPtr, kind_layout, make_codec
from .containers import FixedArrayValue, TArrayValue, TMapValue, TSetValue, _bit_set, _bit_words, _read_sparse, _sparse_slot_size
from .index import DESTROYED_FLAGS
from .names import NameDecoder
from .types import StructView, UObjectProxy, member_names, py_name

_log = logging.getLogger('nylib.ue.runtime.invoke')

MAX_DEPTH = 32
MAX_ELEMENTS = 1 << 20
MAX_FALLBACK_READ = 1 << 24

_DETAILS = ('refused', 'timed_out', 'exited', 'exception', 'partial', 'state')
_STRING_KINDS = frozenset({'StrProperty', 'AnsiStrProperty', 'Utf8StrProperty'})
_UNSUPPORTED_ARGS = frozenset({
    'DelegateProperty', 'MulticastInlineDelegateProperty', 'MulticastSparseDelegateProperty', 'SoftObjectProperty',
    'SoftClassProperty', 'LazyObjectProperty', 'FieldPathProperty', 'OptionalProperty', UNKNOWN_KIND,
})
_COPIED_VIEW_KINDS = _UNSUPPORTED_ARGS | {'TextProperty', 'InterfaceProperty'}
_OBJECT_KINDS = frozenset({'ObjectProperty', 'ClassProperty', 'WeakObjectProperty'})
_NET_KINDS = (('NetServer', EFunctionFlags.NetServer), ('NetClient', EFunctionFlags.NetClient), ('NetMulticast', EFunctionFlags.NetMulticast))
_ASCII_FOLD = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
_STRUCT_CHAIN_BOUND = 256
_LATENT_INFO = '/Script/Engine.LatentActionInfo'


def _fold(text: str) -> str:
    return text.translate(_ASCII_FOLD)


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _owner_path(fn) -> str:
    """The path of the class listing fn (fn.path without ':' + fn.name), or '' when fn.path does not end with it."""
    if not fn.name or not fn.path.endswith(':' + fn.name):
        return ''
    return fn.path[:-(len(fn.name) + 1)]


def _label(fn) -> str:
    short = _owner_path(fn).rpartition('.')[2]
    return f'{short}.{fn.name}' if short else fn.name


def _details(exc) -> dict:
    return {k: getattr(exc, k, None) for k in _DETAILS}


class StructValue(tuple):
    """An immutable struct value from a call result: a named tuple of its members in layout order."""
    __slots__ = ()
    _ue_path_: ClassVar[str]
    _ue_raw_: ClassVar[tuple[str, ...]]

    def _get_(self, name: str):
        if not isinstance(name, str):
            raise TypeError(f'name must be str, got {type(name).__name__}')
        raw = type(self)._ue_raw_
        for i in range(len(raw) - 1, -1, -1):
            if raw[i] == name:
                return self[i]
        if name in (fields := getattr(self, '_fields', ())):
            return self[fields.index(name)]
        raise AttributeError(f'{type(self).__name__} has no member {name!r}')

    def __repr__(self) -> str:
        parts = []
        for raw, value in zip(getattr(type(self), '_ue_raw_', ()), self):
            try:
                parts.append(f'{raw}={value!r}')
            except Exception:
                parts.append(f'{raw}=<unreadable>')
        return f'{type(self).__name__}({", ".join(parts)})'


class FTextCopy(FTextValue):
    """An FText's bytes copied out of a call's parameter block; str() reads its text through the session."""

    def __init__(self, ctx, raw: bytes, label: str = 'FText'):
        if not isinstance(raw, (bytes, bytearray, memoryview)):
            raise TypeError(f'raw must be bytes-like, got {type(raw).__name__}')
        self._ctx = ctx
        self._address = None
        self._label = label
        self.raw = bytes(raw)

    @property
    def string(self) -> str:
        dat, sto = self._ctx.text_layout()
        if len(self.raw) < dat + 8:
            raise ValueError(f'{self._label}: the FText copy holds {len(self.raw):#x} bytes, too few for its data pointer at {dat:#x}')
        data = int.from_bytes(self.raw[dat:dat + 8], 'little')
        if data == 0:
            return ''
        return codecs._read_string(self._ctx, data + sto, self._label)

    def __repr__(self) -> str:
        try:
            return f'FTextCopy({self.string!r})'
        except Exception:
            return f'FTextCopy(<{len(self.raw)} bytes>)'


class _CallMemory(MemorySource):
    """Read-only call memory: the parameter block from one snapshot, other reads through the session, then one strict read."""

    def __init__(self, mem: MemorySource, process, base: int, snap: bytes):
        self._mem, self._process, self._base, self._snap = mem, process, base, snap
        self._end = base + len(snap)

    def _outside(self, address: int, size: int) -> bytes:
        try:
            return self._mem.read(address, size)
        except MemoryReadError:
            if size > MAX_FALLBACK_READ or self._process is None:
                raise
            return calls.read_target(self._process, address, size)

    def _read(self, address: int, size: int) -> bytes:
        end, base = address + size, self._base
        if base <= address and end <= self._end:
            return self._snap[address - base:end - base]
        out, pos = [], address
        while pos < end:
            if pos < base:
                nxt = min(end, base)
                out.append(self._outside(pos, nxt - pos))
            elif pos < self._end:
                nxt = min(end, self._end)
                out.append(self._snap[pos - base:nxt - base])
            else:
                nxt = end
                out.append(self._outside(pos, nxt - pos))
            pos = nxt
        return b''.join(out)

    def _readable_ranges(self, address: int, size: int) -> list[tuple[int, int]]:
        end, out = address + size, []
        lo, hi = max(address, self._base), min(end, self._end)
        if lo < hi:
            out.append((lo, hi - lo))
        if address < self._base:
            out += self._mem.readable_ranges(address, min(end, self._base) - address)
        if end > self._end:
            start = max(address, self._end)
            out += self._mem.readable_ranges(start, end - start)
        return out

    def regions(self):
        return self._mem.regions()

    def modules(self):
        return self._mem.modules()


class _EngineView:
    """The session's engine with `mem` replaced by the call memory."""
    __slots__ = ('_engine', 'mem')

    def __init__(self, engine, mem):
        self._engine = engine
        self.mem = mem

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, '_engine'), name)


class _CallView:
    """One call's view of the session context: e, acc and names over the call memory; everything else is the session's."""

    def __init__(self, inv: 'Invoker', mem: _CallMemory):
        ctx = inv.ctx
        self.__dict__['_session'] = ctx
        self._inv = inv
        self.e = _EngineView(ctx.e, mem)
        self.acc = RuntimeAccessor(mem)
        self.acc.ctx = ctx
        self.names = NameDecoder(self.e, ctx.lock)

    def __getattr__(self, name):
        try:
            ctx = self.__dict__['_session']
        except KeyError:
            raise AttributeError(name) from None
        return getattr(ctx, name)

    def struct_view(self, path: str, address: int):
        return self._inv._dec_struct(self, path, address, path, 0)


class Invoker:
    """Runs a session's UFunction calls through one transport (RT10)."""

    def __init__(self, ctx, transport):
        self.ctx = ctx
        self.transport = transport
        self.closed = False
        self._resolved = {}
        self._checked = {}
        self._value_types = {}
        self._result_types = {}
        self._warned = set()
        self._structs = {}
        self._texts = {}
        self._codecs = {}

    # helpers

    def _policy(self):
        return getattr(self.transport, 'policy', None)

    def _call_error(self, message: str, label: str, **details) -> CallError:
        d = dict.fromkeys(_DETAILS)
        d.update(details)
        return CallError(message, **d, function=label, transport=self._policy())

    def _refusal(self, label: str, message: str, refused: str) -> CallError:
        return self._call_error(message, label, refused=refused, state='not started')

    def _wrapped(self, label: str, exc: CallError) -> CallError:
        return CallError(f'{label}: {exc}', **_details(exc), function=label, transport=self._policy())

    def _check_target(self, obj, fn) -> None:
        if not isinstance(obj, UObjectProxy) or type(obj)._ue_ctx_ is not self.ctx:
            raise TypeError(f'expected an object of this session, got {type(obj).__name__}')
        if not isinstance(fn, FunctionRecord):
            raise TypeError(f'expected a FunctionRecord, got {type(fn).__name__}')

    def _struct(self, path: str):
        """(members in layout order, own-first levels) of a struct path; LookupError when unresolvable."""
        if (hit := self._structs.get(path)) is not None:
            return hit
        ctx = self.ctx
        with ctx.lock:
            if (hit := self._structs.get(path)) is not None:
                return hit
            levels, seen, p = [], set(), path
            while p is not None:
                if p in seen or len(levels) > _STRUCT_CHAIN_BOUND:
                    raise LookupError(f'struct super chain is too deep or cyclic at {p!r}')
                seen.add(p)
                rec = ctx.types.type(p)
                if not isinstance(rec, StructRecord):
                    raise LookupError(f'struct {p!r} not found')
                levels.append(rec)
                p = rec.super
            flat = tuple(m for rec in reversed(levels) for m in rec.properties)
            own_first = tuple(tuple(rec.properties) for rec in levels)
            self._structs[path] = hit = (flat, own_first)
            return hit

    def _holds_text(self, t, depth: int = 0) -> bool:
        if t.kind == 'TextProperty':
            return True
        if t.kind != 'StructProperty' or t.struct is None or depth > MAX_DEPTH:
            return False
        if (hit := self._texts.get(t.struct)) is not None:
            return hit
        try:
            flat = self._struct(t.struct)[0]
        except LookupError:
            return False
        found = any(self._holds_text(m.type, depth + 1) for m in flat)
        with self.ctx.lock:
            self._texts[t.struct] = found
        return found

    def _codec(self, t, size):
        key = (id(t), size)
        if (hit := self._codecs.get(key)) is not None and hit[0] is t:
            return hit[1]
        codec = make_codec(self.ctx, t, size)
        with self.ctx.lock:
            self._codecs[key] = (t, codec)
        return codec

    # the call

    def invoke(self, obj: UObjectProxy, fn: FunctionRecord, args: tuple, kwargs: dict):
        ctx, transport = self.ctx, self.transport
        if self.closed or ctx.closed:
            raise SessionError('the session is closed')
        self._check_target(obj, fn)
        label = _label(fn)
        if fn.flags & EFunctionFlags.Delegate:
            raise self._refusal(label, f'{label} is a delegate signature, not a callable function', 'delegate')
        if any(p.type.kind == 'StructProperty' and p.type.struct == _LATENT_INFO and calls.param_role(p) != 'local' for p in fn.params):
            raise self._refusal(label, f'{label} is a latent function (it takes an FLatentActionInfo): the game keeps pointers into its call '
                                       f'memory after it returns and writes through them later, so v1 cannot call it; nothing was called',
                                'latent')
        bound = self.bind(obj, fn, args, kwargs)
        self.check(fn)
        receiver, address = self.resolve(obj, fn)
        e = ctx.e
        if e.mem.u32(receiver + e.off.UObject.Flags) & DESTROYED_FLAGS:
            raise self._refusal(label, f'{label}: the receiver {obj!r} is being destroyed, and UE would skip the call without a sign; '
                                       f'nothing was called', 'destroyed')
        try:
            pe = calls.process_event_address(transport.process, e.mem, receiver, e.off.InSDK.ProcessEvent.PEIndex)
        except CallError as exc:
            raise self._wrapped(label, exc) from exc
        self.encode(calls.CallArena(None), fn, bound)
        self._warn_net(fn, label)

        try:
            arena = transport.arena()
        except CallError as exc:
            raise self._wrapped(label, exc) from exc
        timeout = ctx.call_timeout
        entered = returned = False
        try:
            params = self.encode(arena, fn, bound)
            arena.flush()
            n = arena.size
            entered = True
            t0 = time.perf_counter()
            calls.process_event(transport, receiver, address, pe, params, timeout=timeout)
            ms = (time.perf_counter() - t0) * 1000
            returned = True
            result = self.decode(fn, params, arena)
        except BaseException as exc:
            self._release(arena, label, exc, entered, returned, timeout)
            if isinstance(exc, CallError) and getattr(exc, 'function', None) is None:
                raise self._wrapped(label, exc) from exc
            raise
        self._release(arena, label, None, entered, returned, timeout)
        _log.debug('call %s via %s: %.2f ms, %#x bytes of call memory', label, self._policy(), ms, n)
        return result

    def _release(self, arena, label: str, exc, entered: bool, returned: bool, timeout) -> None:
        """Free the call memory when the call is known not started or finished and the transport is open, else leave it."""
        is_call = isinstance(exc, CallError)
        if is_call and getattr(exc, 'exited', None):
            arena.leak()
            return
        if exc is None or returned:
            state = 'finished'
        elif not entered:
            state = 'not started'
        else:
            state = (getattr(exc, 'state', None) or 'unknown') if is_call else 'unknown'
        closed = bool(getattr(self.transport, 'closed', False))
        if state in ('not started', 'finished') and not closed:
            arena.free()
            return
        n = arena.leak()
        if is_call and getattr(exc, 'timed_out', None):
            reason = f'it did not return within {timeout} s'
        elif exc is not None and not is_call:
            reason = f'it was interrupted ({type(exc).__name__})'
        elif closed:
            reason = 'the session was closed during the call'
        else:
            reason = f'its state is unknown ({exc})'
        text = f'{label}: {reason}; {n:#x} bytes of call memory stay in the game, with any memory the engine allocated'
        if self._policy() == 'remote-thread':
            text += " and the call's code block"
        if state != 'finished':
            text += ', and the call may still be running'
        _log.warning(text)

    def _warn_net(self, fn, label: str) -> None:
        if not fn.flags & EFunctionFlags.Net or fn.path in self._warned:
            return
        with self.ctx.lock:
            if fn.path in self._warned:
                return
            self._warned.add(fn.path)
        kinds = ', '.join(name for name, flag in _NET_KINDS if fn.flags & flag) or 'Net'
        _log.warning('%s is a network function (%s); in a connected game, calling it may send a network message', label, kinds)

    # arguments

    def bind(self, obj: UObjectProxy, fn: FunctionRecord, args: tuple, kwargs: dict) -> dict:
        label = _label(fn)
        lay = calls.layout(fn)
        inputs = lay.inputs
        if len(args) > len(inputs):
            raise MarshalError(f'{label}() takes {len(inputs)} positional arguments but {len(args)} were given', function=label, param=None)
        given = {p.name: v for p, v in zip(inputs, args)}
        output_only = [p for p in lay.outputs if calls.param_role(p) in ('out', 'return')]
        for key, value in kwargs.items():
            p = self._match(inputs, key, label, ambiguous=True)
            if p is None:
                if (o := self._match(output_only, key, label, ambiguous=False)) is not None:
                    raise MarshalError(f"{label}(): {o.name!r} is an out parameter; its value comes back in the result", function=label, param=o.name)
                raise MarshalError(f'{label}() has no parameter {key!r}', function=label, param=None)
            if p.name in given:
                raise MarshalError(f'{label}() got multiple values for parameter {p.name!r}', function=label, param=p.name)
            given[p.name] = value
        for p in inputs:
            if p.name not in given and self._holds_text(p.type):
                raise MarshalError(f"{label}({p.name}): an FText cannot be left out (zero bytes are not a valid FText, and the game crashes "
                                   f"when it reads one); pass an FText value, for example "
                                   f"ue.cdo('/Script/Engine.KismetTextLibrary').GetEmptyText()", function=label, param=p.name)
        return {p.name: given[p.name] for p in inputs if p.name in given}

    @staticmethod
    def _match(params, key: str, label: str, *, ambiguous: bool):
        """The parameter a keyword names: raw name, then Python names (first wins), then one ASCII-case-folded match."""
        for p in params:
            if p.name == key:
                return p
        for p in params:
            if key in member_names(p.name):
                return p
        folded = _fold(key)
        hits = [p for p in params if _fold(p.name) == folded or any(_fold(n) == folded for n in member_names(p.name))]
        if len(hits) > 1 and ambiguous:
            raise MarshalError(f'{label}(): {key!r} matches {hits[0].name!r} and {hits[1].name!r} when case is ignored; use the exact name',
                               function=label, param=None)
        return hits[0] if hits else None

    def check(self, fn: FunctionRecord) -> None:
        if (hit := self._checked.get(fn.path)) is not None:
            if hit:
                raise MarshalError(hit[0], function=hit[1], param=hit[2])
            return
        label = _label(fn)
        verdict = ()
        for p in calls.layout(fn).outputs:
            if (what := self._unreadable(p.type, p.size, 0)) is not None:
                verdict = (f'{label}(): output {p.name!r} holds {what}, which v1 cannot read; the call was not made', label, p.name)
                break
        with self.ctx.lock:
            self._checked[fn.path] = verdict
        if verdict:
            raise MarshalError(verdict[0], function=verdict[1], param=verdict[2])

    def _unreadable(self, t, size, depth: int):
        """What in type t the decode walk cannot read, else None."""
        if depth > MAX_DEPTH:
            return f'nesting deeper than {MAX_DEPTH} levels'
        if t.kind == 'OptionalProperty':
            return f'a TOptional ({t.prop})'
        if t.kind == UNKNOWN_KIND:
            return f'a property of unknown kind ({t.prop})'
        if (err := codecs._build_error(make_codec(self.ctx, t, size))) is not None:
            return f'a {t.kind} that cannot be decoded ({err})'
        if t.kind == 'StructProperty':
            try:
                flat = self._struct(t.struct)[0]
            except LookupError as exc:
                return f'an unresolvable struct ({exc})'
            for m in flat:
                if (what := self._unreadable(m.type, m.size, depth + 1)) is not None:
                    return what
            return None
        for sub in (t.inner, t.element, t.key, t.value):
            if sub is not None and (what := self._unreadable(sub, None, depth + 1)) is not None:
                return what
        return None

    def resolve(self, obj: UObjectProxy, fn: FunctionRecord) -> tuple[int, int]:
        self._check_target(obj, fn)
        ctx, label = self.ctx, _label(fn)
        e = ctx.e
        owner = _owner_path(fn)
        if owner == '':
            raise self._refusal(label, f'{label}: {fn.path} is not a class function', 'not a class function')
        if fn.flags & EFunctionFlags.Static:
            if (oc := ctx.index.find(owner)) is None:
                raise self._not_found(label, fn)
            cdo = UEClass(e, oc).get_default_object().address
            if cdo == 0:
                raise self._refusal(label, f'{label}: {owner} has no default object, which static functions run on', 'no default object')
            if (address := self._memo(fn.path)) is None:
                address = next((f.address for f in UEClass(e, oc).get_functions() if f.get_fname().to_raw_string() == fn.name), None)
                if address is None and (address := ctx.index.find(fn.path)) is None:
                    raise self._not_found(label, fn)
                self._remember(fn.path, address)
            return cdo, address
        cls = e.mem.ptr(obj._address_ + e.off.UObject.Class)
        chain = ctx.index.super_chain(cls)
        paths = [ctx.types.path_of(c) for c in chain]
        stop = paths.index(owner) if owner in paths else None
        if stop is None and not self._implements(paths, owner):
            raise self._refusal(label, f'{label}: {obj!r} is not a {owner}, so the function would run on an object of another class', 'class')
        key = (cls, fn.path)
        if (address := self._memo(key)) is None:
            address = self._walk(chain[:None if stop is None else stop + 1], fn.name)
            if address is None and (address := ctx.index.find(fn.path)) is None:
                raise self._not_found(label, fn)
            self._remember(key, address)
        return obj._address_, address

    def _not_found(self, label: str, fn) -> CallError:
        return self._refusal(label, f'{label}: {fn.path} was not found in the running game', 'not found')

    def _implements(self, paths, owner: str) -> bool:
        for p in paths:
            rec = self.ctx.types.type(p) if p is not None else None
            if isinstance(rec, ClassRecord) and any(i.cls == owner for i in rec.interfaces):
                return True
        return False

    def _walk(self, chain, name: str):
        """The first function named `name` (ASCII case-folded) among the own functions of the classes in chain."""
        target, e = _fold(name), self.ctx.e
        for c in chain:
            try:
                for f in UEClass(e, c).get_functions():
                    if _fold(f.get_fname().to_raw_string()) == target:
                        return f.address
            except MemoryReadError:
                continue
        return None

    def _memo(self, key):
        if (hit := self._resolved.get(key)) is None:
            return None
        address, path = hit
        return address if self.ctx.types.path_of(address) == path else None

    def _remember(self, key, address: int) -> None:
        if (path := self.ctx.types.path_of(address)) is None:
            return
        with self.ctx.lock:
            self._resolved[key] = (address, path)

    # encoding

    def encode(self, arena, fn: FunctionRecord, bound: dict) -> int:
        label = _label(fn)
        lay = calls.layout(fn)
        params = arena.alloc(lay.size, align=16)
        names = {p.name for p in lay.inputs}
        for key in bound:
            if key not in names:
                raise MarshalError(f'{label}() has no parameter {key!r}', function=label, param=None)
        for p in lay.inputs:
            if p.name not in bound:
                continue
            value, plabel = bound[p.name], f'{label}({p.name})'
            ref = calls.param_role(p) == 'ref'
            try:
                if ref and not self._empty(p.type, p.array_dim, value, 0):
                    raise MarshalError(f'{plabel}: a ref parameter must hold no string, array, set, map or FText value (the game may '
                                       f'reallocate it, and its memory must never be ours)')
                self._enc(arena, p.type, p.size, p.array_dim, value, params + p.offset, plabel, 0, ref)
            except MarshalError as exc:
                if getattr(exc, 'function', None) is None:
                    exc.function, exc.param = label, p.name
                raise
            except (TypeError, ValueError, AttributeError, LookupError, NotImplementedError) as exc:
                raise MarshalError(str(exc), function=label, param=p.name) from exc
        return params

    def _empty(self, t, array_dim: int, value, depth: int) -> bool:
        """True unless value holds a string, array, set or map element, or an FText, at any depth."""
        if depth > MAX_DEPTH:
            return True
        if array_dim > 1:
            if isinstance(value, FixedArrayValue):
                value = value.to_list()
            return not isinstance(value, (list, tuple)) or all(self._empty(t, 1, v, depth + 1) for v in value)
        kind = t.kind
        if isinstance(value, FTextValue):
            return False
        if kind in _STRING_KINDS:
            return not (isinstance(value, str) and value)
        if kind in ('ArrayProperty', 'SetProperty', 'MapProperty'):
            return not isinstance(value, (list, tuple, set, frozenset, dict, TArrayValue, TSetValue, TMapValue)) or len(value) == 0
        if kind == 'StructProperty' and not isinstance(value, StructView):
            try:
                flat, own_first = self._struct(t.struct)
            except LookupError:
                return True
            if isinstance(value, dict):
                pairs = [(m, v) for k, v in value.items() if (m := self._member_by_key(own_first, k)) is not None]
            elif isinstance(value, (list, tuple)):
                pairs = list(zip(flat, value))
            else:
                return True
            return all(self._empty(m.type, m.array_dim, v, depth + 1) for m, v in pairs)
        return True

    @staticmethod
    def _member_by_key(own_first, key):
        """RT4's dict key rule: a raw member name, else a Python name; own members before inherited ones."""
        for level in own_first:
            for m in level:
                if m.name == key:
                    return m
        for level in own_first:
            for m in level:
                if key in member_names(m.name):
                    return m
        return None

    def _enc(self, arena, t, size: int, array_dim: int, value, address: int, plabel: str, depth: int, ref: bool) -> None:
        """Lay out one value of type t at address in the arena (the encode walk)."""
        ctx = self.ctx
        if depth > MAX_DEPTH:
            raise MarshalError(f'{plabel}: arguments nest deeper than {MAX_DEPTH} levels')
        if array_dim > 1:
            if isinstance(value, FixedArrayValue):
                value = value.to_list()
            if not isinstance(value, (list, tuple)) or len(value) != array_dim:
                raise ValueError(f'{plabel}: expected a list or tuple of {array_dim} elements, got {value!r}')
            for i, v in enumerate(value):
                self._enc(arena, t, size, 1, v, address + i * size, f'{plabel}[{i}]', depth + 1, ref)
            return
        kind = t.kind
        if kind in _STRING_KINDS:
            if not isinstance(value, str):
                raise TypeError(f'{plabel}: expected str, got {type(value).__name__}')
            arena.write(address, arena.fstring(value, kind=kind))
        elif kind == 'ArrayProperty':
            if isinstance(value, TArrayValue):
                value = value.to_list()
            if not isinstance(value, (list, tuple)):
                raise TypeError(f'{plabel}: expected a list, tuple or TArrayValue, got {type(value).__name__}')
            if not (n := len(value)):
                return
            es, ea = kind_layout(ctx, t.inner)
            block = arena.alloc(n * es, align=max(ea, 8))
            for i, v in enumerate(value):
                self._enc(arena, t.inner, es, 1, v, block + i * es, f'{plabel}[{i}]', depth + 1, ref)
            arena.write(address, struct.pack('<Qii', block, n, n))
        elif kind == 'StructProperty':
            self._enc_struct(arena, t, value, address, plabel, depth, ref)
        elif kind in ('SetProperty', 'MapProperty'):
            if not isinstance(value, (list, tuple, set, frozenset, dict, TSetValue, TMapValue)):
                raise TypeError(f'{plabel}: expected an empty list, tuple, set, frozenset, dict, TSetValue or TMapValue, got {type(value).__name__}')
            if len(value):
                raise MarshalError(f"{plabel}: TSet and TMap arguments must be empty in v1 (building one needs the engine's hashing)")
        elif kind == 'TextProperty':
            arena.write(address, self._text_bytes(value, size, plabel))
        elif kind == 'InterfaceProperty':
            if value is not None:
                raise NotImplementedError(f'{plabel}: assigning an interface needs its pointer offset, which v1 does not verify')
        elif kind in _UNSUPPORTED_ARGS:
            raise MarshalError(f'{plabel}: {kind} arguments are not supported in v1')
        else:
            if kind in _OBJECT_KINDS and isinstance(value, int) and not isinstance(value, bool):
                if value <= 0:
                    raise MarshalError(f'{plabel}: {value} is not an object address; pass None for a null object')
                value = self._live_object(value, plabel)
            elif kind == 'WeakObjectProperty' and isinstance(value, WeakObjectPtr):
                value = self._weak_target(value, plabel)
            for op in codecs._plan(self._codec(t, size), ctx, address, value, plabel):
                if callable(op):
                    raise MarshalError(f'{plabel}: {kind} values cannot be laid out in call memory in v1')
                if len(op) == 2:
                    arena.write(*op)
                else:
                    a, field_mask, bits = op
                    arena.write(a, bytes(((arena.peek(a, 1)[0] & ~field_mask & 0xFF) | bits,)))

    def _live_object(self, address: int, plabel: str):
        """The proxy of the object at address, which its GObjects slot must hold and which must not be being destroyed."""
        ctx = self.ctx
        e = ctx.e
        try:
            i = e.mem.i32(address + e.off.UObject.Index)
            live = (0 <= i < e.objects.num() and e.objects.get_by_index(i).address == address
                    and not e.mem.u32(address + e.off.UObject.Flags) & DESTROYED_FLAGS)
            proxy = ctx.proxy(address) if live else None
        except MemoryReadError as exc:
            raise MarshalError(f'{plabel}: no readable object at {address:#x}: {exc}') from exc
        if not live:
            raise MarshalError(f'{plabel}: {address:#x} is not a live object')
        return proxy

    def _weak_target(self, value, plabel: str):
        """The proxy, or None for a null pointer, a weak pointer argument of this session points at."""
        owner = value._ctx
        if owner is not self.ctx and not (isinstance(owner, _CallView) and owner._session is self.ctx):
            raise MarshalError(f'{plabel}: a weak pointer of another session cannot be passed; get the object in this session')
        if value.index == 0 and value.serial == 0:
            return None
        try:
            obj = value.get()
        except MemoryReadError as exc:
            raise MarshalError(f'{plabel}: the weak pointer {value!r} cannot be resolved: {exc}') from exc
        if obj is None:
            raise MarshalError(f'{plabel}: the weak pointer {value!r} no longer points at an object; pass None for a null object')
        return obj

    def _text_bytes(self, value, size: int, plabel: str) -> bytes:
        ctx = self.ctx
        if isinstance(value, str):
            raise MarshalError(f"{plabel}: an FText argument cannot be made from a str in v1; convert it first: "
                               f"ue.cdo('/Script/Engine.KismetTextLibrary').Conv_StringToText(text)")
        if not isinstance(value, FTextValue):
            raise TypeError(f'{plabel}: expected an FTextValue or FTextCopy of this session, got {type(value).__name__}')
        if value._ctx is not ctx:
            raise MarshalError(f"{plabel}: an FText of another session cannot be passed (its bytes point into that session's game); "
                               f"get one in this session, e.g. ue.cdo('/Script/Engine.KismetTextLibrary').GetEmptyText()")
        if isinstance(value, FTextCopy):
            if len(value.raw) < size:
                raise ValueError(f'{plabel}: the FText copy holds {len(value.raw):#x} bytes, but an FText here is {size:#x}')
            return value.raw[:size]
        return ctx.acc.read(value._address, size)

    def _enc_struct(self, arena, t, value, address: int, plabel: str, depth: int, ref: bool) -> None:
        ctx = self.ctx
        path = t.struct
        flat, own_first = self._struct(path)
        if isinstance(value, StructView):
            if ref:
                raise MarshalError(f'{plabel}: a ref parameter takes no StructView (the game may change it in place); pass a tuple or dict')
            if type(value)._ue_path_ != path:
                raise TypeError(f'{plabel}: expected a StructView of {path}, got {value!r}')
            same = type(value)._ue_ctx_ is ctx
            for m in flat:
                mlabel, maddr = f'{plabel}.{m.name}', address + m.offset
                if same and m.type.kind in _COPIED_VIEW_KINDS:
                    arena.write(maddr, ctx.acc.read(value._address_ + m.offset, m.size * m.array_dim))
                    continue
                self._enc(arena, m.type, m.size, m.array_dim, self._view_member(value, m, mlabel, same), maddr, mlabel, depth + 1, ref)
            return
        if isinstance(value, dict):
            pairs, named = [], set()
            for key, v in value.items():
                if (m := self._member_by_key(own_first, key)) is None:
                    raise AttributeError(f'{path} has no member {key!r}')
                pairs.append((m, v))
                named.add(id(m))
            for m in flat:
                if id(m) not in named and self._holds_text(m.type):
                    raise MarshalError(f'{plabel}.{m.name}: an FText cannot be left out (zero bytes are not a valid FText); pass an FText value')
        elif isinstance(value, (tuple, list)):
            if len(value) != len(flat):
                raise ValueError(f'{plabel}: expected {len(flat)} members, got {len(value)}')
            pairs = list(zip(flat, value))
        else:
            raise TypeError(f'{plabel}: expected a StructView, tuple, list or dict for {path}')
        for m, v in pairs:
            self._enc(arena, m.type, m.size, m.array_dim, v, address + m.offset, f'{plabel}.{m.name}', depth + 1, ref)

    def _view_member(self, view_, m, mlabel: str, same: bool):
        """Member m of a StructView: its codec at the view's address in this session, else `_get_` by raw name."""
        if not same:
            value = view_._get_(m.name)
            return value.to_list() if isinstance(value, FixedArrayValue) else value
        codec = self._codec(m.type, m.size)
        base = view_._address_ + m.offset
        if m.array_dim > 1:
            return [codec.get(self.ctx, base + i * m.size, f'{mlabel}[{i}]') for i in range(m.array_dim)]
        return codec.get(self.ctx, base, mlabel)

    # results

    def decode(self, fn: FunctionRecord, params: int, arena):
        label = _label(fn)
        lay = calls.layout(fn)
        try:
            snap = arena.read(params, lay.size)
        except CallError as exc:
            raise self._call_error(f'{label} was called, but its outputs could not be read: {exc}', label, partial={}, state='finished') from exc
        if not lay.outputs:
            return None
        try:
            result_type = self.result_type(fn) if len(lay.outputs) > 1 else None
        except Exception as exc:
            raise self._call_error(f'{label} was called, but its outputs could not be read: {exc}', label, partial={}, state='finished') from exc
        v = _CallView(self, _CallMemory(self.ctx.e.mem, getattr(self.transport, 'process', None), params, snap))
        decoded, values = {}, []
        for p in lay.outputs:
            try:
                value = self._dec(v, p.type, p.size, p.array_dim, params + p.offset, f'{label}({p.name})', 0)
            except Exception as exc:
                raise self._call_error(f'{label} was called, but output {p.name!r} could not be read: {exc}', label,
                                       partial=dict(decoded), state='finished') from exc
            decoded[py_name(p.name)] = value
            values.append(value)
        return values[0] if result_type is None else result_type(*values)

    def _dec(self, v, t, size: int, array_dim: int, address: int, plabel: str, depth: int):
        """Read one value of type t at address through the call view (the decode walk)."""
        ctx = self.ctx
        if depth > MAX_DEPTH:
            raise ValueError(f'{plabel}: values nest deeper than {MAX_DEPTH} levels')
        if array_dim > 1:
            return [self._dec(v, t, size, 1, address + i * size, f'{plabel}[{i}]', depth + 1) for i in range(array_dim)]
        kind = t.kind
        if kind in _STRING_KINDS:
            self._bounded(codecs._array_header(v, address, plabel)[1], plabel)
            return self._codec(t, size).get(v, address, plabel)
        if kind == 'ArrayProperty':
            data, num, _ = codecs._array_header(v, address, plabel)
            self._bounded(num, plabel)
            es = kind_layout(ctx, t.inner)[0]
            return [self._dec(v, t.inner, es, 1, data + i * es, f'{plabel}[{i}]', depth + 1) for i in range(num)]
        if kind == 'SetProperty':
            es, ea = kind_layout(ctx, t.element)
            return [self._dec(v, t.element, es, 1, a, f'{plabel}[{i}]', depth + 1)
                    for i, a in enumerate(self._slots(v, address, plabel, 'TSet', es, ea))]
        if kind == 'MapProperty':
            ks, ka = kind_layout(ctx, t.key)
            vs, va = kind_layout(ctx, t.value)
            voff = _align(ks, va)
            pair_align = max(ka, va)
            result = {}
            for a in self._slots(v, address, plabel, 'TMap', _align(voff + vs, pair_align), pair_align):
                key = self._dec(v, t.key, ks, 1, a, f'{plabel}.key', depth + 1)
                value = self._dec(v, t.value, vs, 1, a + voff, f'{plabel}[{key!r}]', depth + 1)
                try:
                    result[key] = value
                except TypeError as exc:
                    raise ValueError(f'{plabel}: a key of {t.key.kind} cannot be a dict key ({exc})') from exc
            return result
        if kind == 'StructProperty':
            return self._dec_struct(v, t.struct, address, plabel, depth)
        if kind == 'TextProperty':
            return FTextCopy(ctx, v.acc.read(address, size), plabel)
        if kind == 'MulticastInlineDelegateProperty':
            self._bounded(codecs._array_header(v, address + size - 0x10, plabel)[1], plabel)
            return self._codec(t, size).get(v, address, plabel).bindings()
        return self._codec(t, size).get(v, address, plabel)

    @staticmethod
    def _bounded(num: int, plabel: str) -> None:
        if num > MAX_ELEMENTS:
            raise ValueError(f'{plabel}: {num} elements are more than the {MAX_ELEMENTS} a call output may hold')

    def _slots(self, v, address: int, plabel: str, kind: str, value_size: int, value_align: int) -> list:
        """Addresses of the allocated slots of a TSet / TMap, in slot order (RT5's sparse layout)."""
        hdr, data, data_num, _ = _read_sparse(v, address, plabel, kind)
        self._bounded(data_num, plabel)
        words = _bit_words(v, hdr, data_num, plabel)
        stride = _sparse_slot_size(value_size, value_align)
        return [data + i * stride for i in range(data_num) if _bit_set(words, i)]

    def _dec_struct(self, v, path: str, address: int, plabel: str, depth: int):
        flat = self._struct(path)[0]
        values = [self._dec(v, m.type, m.size, m.array_dim, address + m.offset, f'{plabel}.{m.name}', depth + 1) for m in flat]
        return self.value_type(path)(*values)

    def value_type(self, path: str) -> type:
        if (hit := self._value_types.get(path)) is not None:
            return hit
        ctx = self.ctx
        with ctx.lock:
            if (hit := self._value_types.get(path)) is not None:
                return hit
            record = ctx.types.type(path)
            if not isinstance(record, StructRecord):
                raise LookupError(f'no struct type {path!r}')
            flat = self._struct(path)[0]
            nt = collections.namedtuple(record.cpp_name, [py_name(m.name) for m in flat], rename=True)
            hit = type(record.cpp_name, (StructValue, nt), {'__slots__': (), '_ue_path_': path, '_ue_raw_': tuple(m.name for m in flat)})
            self._value_types[path] = hit
            return hit

    def result_type(self, fn: FunctionRecord) -> type:
        if (hit := self._result_types.get(fn.path)) is not None:
            return hit
        ctx = self.ctx
        with ctx.lock:
            if (hit := self._result_types.get(fn.path)) is not None:
                return hit
            owner = _owner_path(fn)
            record = ctx.types.type(owner) if owner else None
            owner_cpp = record.cpp_name if isinstance(record, ClassRecord) else make_name_valid(owner.rpartition('.')[2])
            fields = [py_name(p.name) for p in calls.layout(fn).outputs]
            try:
                hit = collections.namedtuple(f'{owner_cpp}_{py_name(fn.name)}', fields, rename=True)
            except ValueError:
                hit = collections.namedtuple('CallResult', fields, rename=True)
            self._result_types[fn.path] = hit
            return hit

    # session

    def refresh(self) -> None:
        with self.ctx.lock:
            self._resolved.clear()

    def close(self) -> None:
        self.closed = True
        if self.transport is not None:
            self.transport.close()
