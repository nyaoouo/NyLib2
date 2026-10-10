"""Value codecs (RT4): get/set one property's value at an address through ctx.acc.
A type that cannot be resolved builds an error codec, whose get and set raise, instead of raising at build time.
"""
import copy
import struct
from typing import Any, NamedTuple, Protocol

from ..engine.accessor import view
from ..engine.containers import TArray
from ..errors import MemoryReadError
from ..model import PropType, StructRecord, UNKNOWN_KIND

NATURAL_SIZES: dict[str, int] = {
    'Int8Property': 1, 'ByteProperty': 1,
    'Int16Property': 2, 'UInt16Property': 2,
    'IntProperty': 4, 'UInt32Property': 4, 'FloatProperty': 4,
    'Int64Property': 8, 'UInt64Property': 8, 'DoubleProperty': 8,
    'ObjectProperty': 8, 'ClassProperty': 8, 'WeakObjectProperty': 8,
    'InterfaceProperty': 0x10,
}
HINT_RESIZE = ('changing the size of a container needs the engine allocator (FMemory), which v1 does not call; '
               'change elements in place or use a UFunction')

_SIGNED_INT_KINDS = frozenset({'Int8Property', 'Int16Property', 'IntProperty', 'Int64Property'})
_UNSIGNED_INT_KINDS = frozenset({'UInt16Property', 'UInt32Property', 'UInt64Property'})
_CONTAINER_KINDS = frozenset({
    'ArrayProperty', 'SetProperty', 'MapProperty', 'StrProperty', 'AnsiStrProperty', 'Utf8StrProperty',
    'MulticastInlineDelegateProperty',
})
_STRUCT_CHAIN_BOUND = 256
_CLASS_PATH = '/Script/CoreUObject.Class'


class Codec(Protocol):                                  # the protocol; codecs need not subclass it
    """get(ctx, address, label) / set(ctx, address, value, label) over one property's bytes, through ctx.acc."""
    kind: str
    size: int
    align: int

    def get(self, ctx, address: int, label: str): ...
    def set(self, ctx, address: int, value, label: str) -> None: ...


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _check_int(value, label: str, allow_bool: bool) -> None:
    if isinstance(value, bool) and not allow_bool:
        raise TypeError(f'{label}: expected int, got bool')
    if not isinstance(value, int):
        raise TypeError(f'{label}: expected int, got {type(value).__name__}')


def _relabel(exc: Exception, label: str) -> Exception:
    """A new exception of exc's type and attributes whose message is prefixed with f'{label}: '."""
    msg = f'{label}: {exc}'
    try:
        return type(exc)(msg)
    except Exception:
        pass
    new = type(exc).__new__(type(exc), msg)
    new.__dict__.update(vars(exc))
    new.args = (msg,)
    if str(new) != msg:  # str() reads fields __new__ left unset (UnicodeDecodeError): copy instead, label as a note
        new = copy.copy(exc)
        new.__notes__ = [*getattr(exc, '__notes__', ()), label]
    return new


def _array_header(ctx, address: int, label: str) -> tuple[int, int, int]:
    hdr = view(TArray, address, ctx.acc)
    data, num, mx = hdr.Data, hdr.NumElements, hdr.MaxElements
    if not (0 <= num <= mx and (num == 0 or data != 0)):
        raise ValueError(f'{label}: corrupt TArray (Data {data:#x}, Num {num}, Max {mx})')
    return data, num, mx


def _read_string(ctx, address: int, label: str, encoding: str = 'utf-16-le', unit: int = 2) -> str:
    """The units of the string TArray at address before the first NUL, reading at most Num - 1 units."""
    data, num, _ = _array_header(ctx, address, label)
    if num <= 1:
        return ''
    raw = ctx.acc.read(data, (num - 1) * unit)
    if unit == 2:
        return raw.decode(encoding, 'surrogatepass').split('\0', 1)[0]
    return raw.split(b'\0', 1)[0].decode(encoding)


def _plan(codec, ctx, address: int, value, label: str) -> list:
    """The writes codec.set would make, after every check it makes; nothing is written."""
    if (ops := getattr(codec, '_ops', None)) is None:
        return [lambda: codec.set(ctx, address, value, label)]
    return ops(ctx, address, value, label)


def _commit(ctx, ops: list, label: str) -> None:
    """Gate once, then apply planned writes: (address, bytes), (address, field_mask, bits) or a callable."""
    ctx.check_write(label)
    for op in ops:
        if callable(op):
            op()
        elif len(op) == 2:
            ctx.acc.write(*op)
        else:
            address, field_mask, bits = op
            b = ctx.acc.read(address, 1)[0]
            ctx.acc.write(address, bytes(((b & ~field_mask & 0xFF) | bits,)))


def _build_error(codec) -> Exception | None:
    """The error an error or unsupported codec holds, else None."""
    if isinstance(codec, _ErrorCodec):
        return codec._error
    if isinstance(codec, _UnsupportedCodec):
        return NotImplementedError(f'{codec._prop} values are not supported in v1')
    return None


class WeakObjectPtr:
    """FWeakObjectPtr: an object index plus its GObjects slot serial number."""

    def __init__(self, ctx, index: int, serial: int):
        self._ctx = ctx
        self.index = index
        self.serial = serial

    def get(self):
        return self._ctx.weak_get(self.index, self.serial)

    def __eq__(self, other):
        if isinstance(other, WeakObjectPtr):
            return (self.index, self.serial) == (other.index, other.serial)
        return NotImplemented

    def __hash__(self):
        return hash((self.index, self.serial))

    def __repr__(self):
        return f'WeakObjectPtr(index={self.index}, serial={self.serial})'


class LazyObjectPtr:
    """FLazyObjectPtr: a weak pointer plus the FGuid it was last resolved from."""

    def __init__(self, weak: WeakObjectPtr, guid: str):
        self.weak = weak
        self.guid = guid

    def get(self):
        return self.weak.get()

    def __repr__(self):
        return f'LazyObjectPtr(weak={self.weak!r}, guid={self.guid!r})'


class SoftObjectPtr:
    """FSoftObjectPtr: a weak pointer plus the asset path it was last resolved from."""

    def __init__(self, ctx, weak: WeakObjectPtr, path: str):
        self._ctx = ctx
        self.weak = weak
        self.path = path

    def get(self):
        obj = self.weak.get()
        if obj is not None:
            return obj
        if not self.path:
            return None
        address = self._ctx.index.find(self.path)
        if address is None:
            return None
        return self._ctx.proxy(address)

    def __repr__(self):
        return f'SoftObjectPtr(path={self.path!r})'


def _clean_name(value) -> str:
    if value is None:
        return ''
    text = str(value)
    return '' if text == 'None' else text


def _soft_object_path(view_) -> str:
    asset_path = getattr(view_, 'AssetPath', None)
    if asset_path is not None:
        base = f'{_clean_name(getattr(asset_path, "PackageName", None))}.{_clean_name(getattr(asset_path, "AssetName", None))}'
    else:
        base = _clean_name(getattr(view_, 'AssetPathName', None))
    sub = _clean_name(getattr(view_, 'SubPathString', None))
    return f'{base}:{sub}' if sub else base


class FTextValue:
    """FText, decoded only on demand (str() / .string); v1 cannot write one."""

    def __init__(self, ctx, address: int, label: str = 'FText'):
        self._ctx = ctx
        self._address = address
        self._label = label

    @property
    def string(self) -> str:
        dat, sto = self._ctx.text_layout()
        data = self._ctx.e.mem.ptr(self._address + dat)
        if data == 0:
            return ''
        return _read_string(self._ctx, data + sto, self._label)

    def __str__(self) -> str:
        return self.string

    def __repr__(self):
        return f'FTextValue({self.string!r})'


class DelegateBinding(NamedTuple):
    object: Any
    function_name: Any


class DelegateValue:
    """A single-cast FScriptDelegate: a weak object plus the bound function's FName."""

    def __init__(self, obj, function_name):
        self.object = obj
        self.function_name = function_name
        self.binding = None if function_name == 'None' else DelegateBinding(obj, function_name)

    def __repr__(self):
        return f'DelegateValue(object={self.object!r}, function_name={self.function_name!r})'


class SparseDelegateValue:
    """FSparseDelegate: only whether it is bound; the bindings live in storage v1 does not read."""

    def __init__(self, is_bound: bool):
        self.is_bound = is_bound

    def bindings(self):
        raise NotImplementedError('sparse delegate bindings live in FSparseDelegateStorage, which v1 does not read')

    def __repr__(self):
        return f'SparseDelegateValue(is_bound={self.is_bound!r})'


class FieldPathValue:
    """FFieldPath: the decoded FName chain, stored order; str() joins it reversed with '.'."""

    def __init__(self, names: tuple):
        self.names = names

    def __str__(self) -> str:
        return '.'.join(reversed(self.names))

    def __repr__(self):
        return f'FieldPathValue({self.names!r})'


class _Codec:
    __slots__ = ('kind', 'size', 'align', '_get', '_ops')

    def __init__(self, kind, size, align, get_fn, ops_fn):
        self.kind, self.size, self.align = kind, size, align
        self._get, self._ops = get_fn, ops_fn

    def get(self, ctx, address, label):
        return self._get(ctx, address, label)

    def set(self, ctx, address, value, label):
        _commit(ctx, self._ops(ctx, address, value, label), label)


class _ErrorCodec:
    """A codec that failed to build: get and set re-raise the build error, prefixed with the label."""
    __slots__ = ('kind', 'size', 'align', '_error')

    def __init__(self, kind, size, error: Exception):
        self.kind, self.size, self.align = kind, size if size is not None else 0, 1
        self._error = error

    def _raise(self, label):
        raise _relabel(self._error, label)

    def get(self, ctx, address, label):
        self._raise(label)

    def set(self, ctx, address, value, label):
        self._raise(label)

    def _ops(self, ctx, address, value, label):
        self._raise(label)


class _UnsupportedCodec:
    """OptionalProperty / unknown: get and set always refuse; the class still builds."""
    __slots__ = ('kind', 'size', 'align', '_prop')

    def __init__(self, kind, size, prop: str):
        self.kind, self.size, self.align = kind, size, 1
        self._prop = prop

    def _raise(self):
        raise NotImplementedError(f'{self._prop} values are not supported in v1')

    def get(self, ctx, address, label):
        self._raise()

    def set(self, ctx, address, value, label):
        self._raise()

    def _ops(self, ctx, address, value, label):
        self._raise()


def _int_codec(size: int, signed: bool, allow_bool: bool):
    lo = -(1 << (8 * size - 1)) if signed else 0
    hi = (1 << (8 * size - 1)) - 1 if signed else (1 << (8 * size)) - 1

    def _get(ctx, address, label):
        return int.from_bytes(ctx.acc.read(address, size), 'little', signed=signed)

    def _ops(ctx, address, value, label):
        _check_int(value, label, allow_bool)
        if value < lo or value > hi:
            raise ValueError(f'{label}: {value} is outside [{lo}, {hi}]')
        return [(address, value.to_bytes(size, 'little', signed=signed))]

    return _get, _ops


def _float_codec(fmt: str, size: int):
    def _get(ctx, address, label):
        return struct.unpack(fmt, ctx.acc.read(address, size))[0]

    def _ops(ctx, address, value, label):
        if not isinstance(value, (int, float)):
            raise TypeError(f'{label}: expected int or float, got {type(value).__name__}')
        try:
            data = struct.pack(fmt, value)
        except OverflowError:
            raise ValueError(f'{label}: {value!r} does not fit in {size} bytes') from None
        return [(address, data)]

    return _get, _ops


def _resolve_byte(ptype: PropType):
    enum_path = ptype.enum

    def _get(ctx, address, label):
        raw = ctx.acc.read(address, 1)[0]
        cls = ctx.enum_class(enum_path) if enum_path else None
        if cls is not None:
            try:
                return cls(raw)
            except ValueError:
                return raw
        return raw

    def _ops(ctx, address, value, label):
        _check_int(value, label, allow_bool=False)
        if value < 0 or value > 0xFF:
            raise ValueError(f'{label}: {value} is outside [0, 255]')
        return [(address, bytes((value,)))]

    return _get, _ops


def _resolve_enum(ptype: PropType):
    underlying = ptype.underlying
    if underlying is None:
        raise LookupError(f'EnumProperty {ptype.prop!r} has no underlying type')
    size = NATURAL_SIZES.get(underlying.kind)
    if size is None:
        raise LookupError(f'EnumProperty {ptype.prop!r} has an unsupported underlying kind {underlying.kind!r}')
    signed = underlying.kind in _SIGNED_INT_KINDS
    enum_path = ptype.enum
    get_fn, ops_fn = _int_codec(size, signed, allow_bool=False)

    def _get(ctx, address, label):
        raw = get_fn(ctx, address, label)
        cls = ctx.enum_class(enum_path) if enum_path else None
        if cls is not None:
            try:
                return cls(raw)
            except ValueError:
                return raw
        return raw

    return size, size, _get, ops_fn


def _resolve_bool(ptype: PropType):
    if ptype.byte_offset is None or ptype.field_mask is None or ptype.byte_mask is None:
        raise LookupError(f'BoolProperty {ptype.prop!r} has no bit layout')
    byte_offset, field_mask, byte_mask = ptype.byte_offset, ptype.field_mask, ptype.byte_mask
    size = ptype.field_size if ptype.field_size is not None else 1

    def _get(ctx, address, label):
        return bool(ctx.acc.read(address + byte_offset, 1)[0] & field_mask)

    def _ops(ctx, address, value, label):
        if not isinstance(value, int):
            raise TypeError(f'{label}: expected bool or int, got {type(value).__name__}')
        return [(address + byte_offset, field_mask, byte_mask if value else 0)]

    return size, 1, _get, _ops


def _name_codec():
    def _get(ctx, address, label):
        return ctx.names.read(address)

    def _ops(ctx, address, value, label):
        if not isinstance(value, str):
            raise TypeError(f'{label}: expected str, got {type(value).__name__}')
        size = ctx.e.off.InSDK.Name.FNameSize
        raw = getattr(value, 'raw', None)
        comparison_index = getattr(value, 'comparison_index', None)
        number = getattr(value, 'number', None)
        data = None
        if raw is not None and len(raw) == size and comparison_index is not None:
            if ctx.names.decode(comparison_index, number or 0) == value:
                data = raw
        if data is None:
            found = ctx.names.lookup(value)
            if found is None:
                raise ValueError(f'{label}: {value!r} is not in the name pool; v1 cannot add names (that needs the engine)')
            data = found.raw
        return [(address, data)]

    return _get, _ops


def _text_codec():
    def _get(ctx, address, label):
        return FTextValue(ctx, address, label)

    def _ops(ctx, address, value, label):
        raise NotImplementedError('FText values cannot be written in v1')

    return _get, _ops


def _checked_object(ctx, value, base: str | None, kind: str, label: str) -> int:
    """The address of value, a proxy of this session whose runtime class, read fresh, is base or derives from it."""
    from .types import UObjectProxy
    if base is None:
        raise TypeError(f'{label}: {kind} has no class to check against')
    if not isinstance(value, UObjectProxy) or type(value)._ue_ctx_ is not ctx:
        raise TypeError(f'{label}: expected a UObjectProxy of this session, got {value!r}')
    addr = value._address_
    cls = ctx.e.mem.ptr(addr + ctx.e.off.UObject.Class)
    path = ctx.types.path_of(cls) if cls else None
    if path is None or not ctx.is_subclass(path, base):
        raise TypeError(f'{label}: {value!r} is not a {base}')
    return addr


def _object_codec(ptype: PropType):
    cls_path = ptype.cls

    def _get(ctx, address, label):
        addr = int.from_bytes(ctx.acc.read(address, 8), 'little', signed=False)
        return ctx.proxy(addr)

    def _ops(ctx, address, value, label):
        if value is None:
            return [(address, bytes(8))]
        addr = _checked_object(ctx, value, cls_path, 'ObjectProperty', label)
        return [(address, addr.to_bytes(8, 'little'))]

    return _get, _ops


def _class_codec(ptype: PropType):
    meta_path = ptype.meta_class

    def _get(ctx, address, label):
        addr = int.from_bytes(ctx.acc.read(address, 8), 'little', signed=False)
        return ctx.proxy(addr)

    def _ops(ctx, address, value, label):
        if value is None:
            return [(address, bytes(8))]
        if meta_path is None:
            raise TypeError(f'{label}: ClassProperty has no meta class to check against')
        addr = _checked_object(ctx, value, _CLASS_PATH, 'ClassProperty', label)
        path = ctx.types.path_of(addr)
        if path is None or not ctx.is_subclass(path, meta_path):
            raise TypeError(f'{label}: {value!r} is not a subclass of {meta_path}')
        return [(address, addr.to_bytes(8, 'little'))]

    return _get, _ops


def _interface_codec():
    def _get(ctx, address, label):
        addr = int.from_bytes(ctx.acc.read(address, 8), 'little', signed=False)
        return ctx.proxy(addr)

    def _ops(ctx, address, value, label):
        if value is None:
            return [(address, bytes(0x10))]
        raise NotImplementedError('assigning an interface needs its pointer offset, which v1 does not verify')

    return _get, _ops


def _read_weak_pair(ctx, address) -> tuple[int, int]:
    raw = ctx.acc.read(address, 8)
    return (int.from_bytes(raw[0:4], 'little', signed=True), int.from_bytes(raw[4:8], 'little', signed=True))


def _weak_pair_bytes(index: int, serial: int) -> bytes:
    return index.to_bytes(4, 'little', signed=True) + serial.to_bytes(4, 'little', signed=True)


def _weak_object_codec(ptype: PropType):
    cls_path = ptype.cls

    def _get(ctx, address, label):
        index, serial = _read_weak_pair(ctx, address)
        return WeakObjectPtr(ctx, index, serial)

    def _ops(ctx, address, value, label):
        if value is None:
            index, serial = 0, 0
        elif isinstance(value, WeakObjectPtr):
            index, serial = value.index, value.serial
        else:
            _checked_object(ctx, value, cls_path, 'WeakObjectProperty', label)
            index, serial = ctx.weak_ref(value)
        return [(address, _weak_pair_bytes(index, serial))]

    return _get, _ops


def _lazy_oid(ctx) -> int:
    return 0x8 if ctx.e.settings.Internal.bIsWeakObjectPtrWithoutTag else 0xC


def _resolve_lazy(ctx):
    oid = _lazy_oid(ctx)
    size = oid + 0x10

    def _get(ctx, address, label):
        index, serial = _read_weak_pair(ctx, address)
        weak = WeakObjectPtr(ctx, index, serial)
        a, b, c, d = struct.unpack('<4I', ctx.acc.read(address + oid, 16))
        return LazyObjectPtr(weak, '%08X-%08X-%08X-%08X' % (a, b, c, d))

    def _ops(ctx, address, value, label):
        raise NotImplementedError('LazyObjectProperty values cannot be written in v1')

    return size, 4, _get, _ops


def _resolve_soft(ctx, kind: str):
    oid8 = _align(_lazy_oid(ctx), 8)
    rec = ctx.types.type('/Script/CoreUObject.SoftObjectPath')
    if not isinstance(rec, StructRecord):
        raise LookupError("struct '/Script/CoreUObject.SoftObjectPath' not found")
    size = _align(oid8 + rec.size, 8)

    def _get(ctx, address, label):
        index, serial = _read_weak_pair(ctx, address)
        weak = WeakObjectPtr(ctx, index, serial)
        path_view = ctx.struct_view('/Script/CoreUObject.SoftObjectPath', address + oid8)
        return SoftObjectPtr(ctx, weak, _soft_object_path(path_view))

    def _ops(ctx, address, value, label):
        raise NotImplementedError(f'{kind} values cannot be written in v1')

    return size, 8, _get, _ops


def _resolve_field_path(ctx):
    size = ctx.e.property_sizes.FieldPathProperty
    off = 0x1C if size > 0x20 else 0x10

    def _get(ctx, address, label):
        arr = view(TArray, address + off, ctx.acc)
        names = tuple(ctx.names.read(arr.element_address(i, ctx.e.off.InSDK.Name.FNameSize)) for i in range(arr.num()))
        return FieldPathValue(names)

    def _ops(ctx, address, value, label):
        raise NotImplementedError('FieldPathProperty values cannot be written in v1')

    return size, 8, _get, _ops


def _resolve_delegate(ctx):
    size = ctx.e.property_sizes.DelegateProperty

    def _get(ctx, address, label):
        index, serial = _read_weak_pair(ctx, address)
        fname = ctx.names.read(address + 8)
        return DelegateValue(WeakObjectPtr(ctx, index, serial).get(), fname)

    def _ops(ctx, address, value, label):
        raise NotImplementedError('DelegateProperty values cannot be written in v1')

    return size, 4, _get, _ops


def _resolve_sparse():
    def _get(ctx, address, label):
        return SparseDelegateValue(ctx.acc.read(address, 1)[0] != 0)

    def _ops(ctx, address, value, label):
        raise NotImplementedError('MulticastSparseDelegateProperty values cannot be written in v1')

    return _get, _ops


def _struct_chain(ctx, path: str) -> list:
    """Own struct first, then each super in order."""
    chain, seen, p = [], set(), path
    while p is not None:
        if p in seen or len(chain) > _STRUCT_CHAIN_BOUND:
            raise LookupError(f'struct super chain is too deep or cyclic at {p!r}')
        seen.add(p)
        rec = ctx.types.type(p)
        if not isinstance(rec, StructRecord):
            raise LookupError(f'struct {p!r} not found')
        chain.append(rec)
        p = rec.super
    return chain


def _resolve_struct(ctx, ptype: PropType):
    struct_path = ptype.struct
    rec = ctx.types.type(struct_path)
    if not isinstance(rec, StructRecord):
        raise LookupError(f'struct {struct_path!r} not found')
    align = max(rec.min_alignment, 1)
    size = _align(rec.size, align)
    members_cache: list = []

    def _members(ctx):
        """Returns (flat, own_first): flat in layout order (super before own), own_first per level, own first."""
        if not members_cache:
            own_first = [[(m, _member_codec(ctx, m)) for m in level.properties] for level in _struct_chain(ctx, struct_path)]
            flat = [mc for group in reversed(own_first) for mc in group]
            members_cache.append((flat, own_first))
        return members_cache[0]

    def _get(ctx, address, label):
        return ctx.struct_view(struct_path, address)

    def _ops(ctx, address, value, label):
        members, own_first = _members(ctx)
        if isinstance(value, dict):
            from .types import member_names
            by_raw, by_py = {}, {}
            for group in own_first:
                for mc in group:
                    by_raw.setdefault(mc[0].name, mc)
                    for n in member_names(mc[0].name):
                        by_py.setdefault(n, mc)
            pairs = []
            for key, v in value.items():
                if (mc := by_raw.get(key) or by_py.get(key)) is None:
                    raise AttributeError(f'{struct_path} has no member {key!r}')
                pairs.append((mc, v))
        elif isinstance(value, (tuple, list)):
            if len(value) != len(members):
                raise ValueError(f'{label}: expected {len(members)} members, got {len(value)}')
            pairs = list(zip(members, value))
        elif hasattr(value, '_ue_path_'):
            if getattr(value, '_ue_path_', None) != struct_path:
                raise TypeError(f'{label}: expected a StructView of {struct_path}, got {value!r}')
            pairs = [(mc, _member_of_view(ctx, value, *mc, f'{label}.{mc[0].name}')) for mc in members]
        else:
            raise TypeError(f'{label}: expected a StructView, tuple, list or dict for {struct_path}')
        ops = []
        for (m, codec), v in pairs:
            ops += _plan(codec, ctx, address + m.offset, v, f'{label}.{m.name}')
        return ops

    return size, align, _get, _ops


def _member_codec(ctx, m):
    codec = make_codec(ctx, m.type, m.size)
    if m.array_dim > 1:
        from . import containers
        codec = containers.fixed_array_codec(codec, m.array_dim)
    return codec


def _member_of_view(ctx, view_, m, codec, label: str):
    """Member m of a StructView: by offset in this session, else by raw name; fixed arrays as lists."""
    if type(view_)._ue_ctx_ is ctx:
        value = codec.get(ctx, view_._address_ + m.offset, label)
    else:
        value = view_._get_(m.name)
    return value.to_list() if m.array_dim > 1 else value


def _resolve(ctx, ptype: PropType):
    kind = ptype.kind
    if kind == 'ByteProperty':
        return (1, 1, *_resolve_byte(ptype))
    if kind in _SIGNED_INT_KINDS or kind in _UNSIGNED_INT_KINDS:
        size = NATURAL_SIZES[kind]
        return (size, size, *_int_codec(size, kind in _SIGNED_INT_KINDS, allow_bool=True))
    if kind in ('FloatProperty', 'DoubleProperty'):
        size = NATURAL_SIZES[kind]
        return (size, size, *_float_codec('<f' if kind == 'FloatProperty' else '<d', size))
    if kind == 'ObjectProperty':
        return (8, 8, *_object_codec(ptype))
    if kind == 'ClassProperty':
        return (8, 8, *_class_codec(ptype))
    if kind == 'InterfaceProperty':
        return (0x10, 8, *_interface_codec())
    if kind == 'WeakObjectProperty':
        return (8, 4, *_weak_object_codec(ptype))
    if kind == 'EnumProperty':
        return _resolve_enum(ptype)
    if kind == 'BoolProperty':
        return _resolve_bool(ptype)
    if kind == 'NameProperty':
        return (ctx.e.off.InSDK.Name.FNameSize, 4, *_name_codec())
    if kind == 'TextProperty':
        text_size = ctx.e.off.InSDK.Text.TextSize
        return (text_size if text_size > 0 else 0x18, 8, *_text_codec())
    if kind == 'LazyObjectProperty':
        return _resolve_lazy(ctx)
    if kind in ('SoftObjectProperty', 'SoftClassProperty'):
        return _resolve_soft(ctx, kind)
    if kind == 'FieldPathProperty':
        return _resolve_field_path(ctx)
    if kind == 'DelegateProperty':
        return _resolve_delegate(ctx)
    if kind == 'MulticastSparseDelegateProperty':
        return (1, 1, *_resolve_sparse())
    if kind == 'StructProperty':
        return _resolve_struct(ctx, ptype)
    raise LookupError(f'no layout for kind {kind!r}')


def kind_layout(ctx, ptype: PropType) -> tuple:
    """The (size, align) of the codec table's 'size when None' column for ptype's own kind.
    Raises the error its error codec would hold, and NotImplementedError for OptionalProperty and unknown kinds.
    """
    if not isinstance(ptype, PropType):
        raise TypeError(f'ptype must be a PropType, got {type(ptype).__name__}')
    codec = make_codec(ctx, ptype)
    if (exc := _build_error(codec)) is not None:
        raise exc
    return codec.size, codec.align


def make_codec(ctx, ptype: PropType, size: int | None = None):
    """Build a Codec for ptype; an unresolvable type or a bad fixed size gives an error codec instead of raising."""
    if not isinstance(ptype, PropType):
        raise TypeError(f'ptype must be a PropType, got {type(ptype).__name__}')
    if size is not None and not isinstance(size, int):
        raise TypeError(f'size must be int or None, got {type(size).__name__}')
    if size is not None and size < 1:
        raise ValueError('size must be >= 1')
    kind = ptype.kind
    if kind in _CONTAINER_KINDS:
        from . import containers
        return containers.make_container_codec(ctx, ptype, size)
    if kind in ('OptionalProperty', UNKNOWN_KIND):
        return _UnsupportedCodec(kind, size if size is not None else 0, ptype.prop)
    try:
        if size is not None and kind in NATURAL_SIZES and size != NATURAL_SIZES[kind]:
            raise ValueError(f'{kind} cannot be {size:#x} bytes')
        layout_size, align, get_fn, ops_fn = _resolve(ctx, ptype)
    except (LookupError, ValueError, MemoryReadError) as exc:
        return _ErrorCodec(kind, size, exc)
    return _Codec(kind, size if size is not None else layout_size, align, get_fn, ops_fn)


def raw_pointer_codec() -> Codec:
    def _get(ctx, address, label):
        addr = int.from_bytes(ctx.acc.read(address, 8), 'little', signed=False)
        return ctx.raw_view(addr)

    def _ops(ctx, address, value, label):
        raise NotImplementedError('raw pointer values cannot be written in v1')

    return _Codec('raw', 8, 8, _get, _ops)
