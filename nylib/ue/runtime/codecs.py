"""Value codecs (RT4): get/set one property's value at an address through ctx.acc.

Every data problem (an unresolvable struct/enum/SoftObjectPath type, a missing
inner/underlying type, a bad BoolProperty mask, or a size that disagrees with a
fixed-size kind) makes an error codec instead of raising at build time, so one
bad member never stops a class from building.
"""
import keyword
import struct
from typing import Any, NamedTuple, Protocol

from ..engine.accessor import view
from ..engine.containers import FString, TArray
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


def _py_name(raw: str) -> str:
    return raw + '_' if keyword.iskeyword(raw) else raw


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

    def __init__(self, ctx, address: int):
        self._ctx = ctx
        self._address = address

    @property
    def string(self) -> str:
        dat, sto = self._ctx.text_layout()
        data = self._ctx.e.mem.ptr(self._address + dat)
        if data == 0:
            return ''
        return view(FString, data + sto, self._ctx.acc).to_wstring()

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
    __slots__ = ('kind', 'size', 'align', '_get', '_set')

    def __init__(self, kind, size, align, get_fn, set_fn):
        self.kind, self.size, self.align = kind, size, align
        self._get, self._set = get_fn, set_fn

    def get(self, ctx, address, label):
        return self._get(ctx, address, label)

    def set(self, ctx, address, value, label):
        self._set(ctx, address, value, label)


class _ErrorCodec:
    """A codec that failed to build: get and set re-raise the build error, prefixed with the label."""
    __slots__ = ('kind', 'size', 'align', '_error')

    def __init__(self, kind, size, error: Exception):
        self.kind, self.size, self.align = kind, size, 1
        self._error = error

    def _raise(self, label):
        raise type(self._error)(f'{label}: {self._error}')

    def get(self, ctx, address, label):
        self._raise(label)

    def set(self, ctx, address, value, label):
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


def _int_codec(size: int, signed: bool, allow_bool: bool):
    lo = -(1 << (8 * size - 1)) if signed else 0
    hi = (1 << (8 * size - 1)) - 1 if signed else (1 << (8 * size)) - 1

    def _get(ctx, address, label):
        return int.from_bytes(ctx.acc.read(address, size), 'little', signed=signed)

    def _set(ctx, address, value, label):
        _check_int(value, label, allow_bool)
        if value < lo or value > hi:
            raise ValueError(f'{label}: {value} is outside [{lo}, {hi}]')
        ctx.check_write(label)
        ctx.acc.write(address, value.to_bytes(size, 'little', signed=signed))

    return _get, _set


def _float_codec(fmt: str, size: int):
    def _get(ctx, address, label):
        return struct.unpack(fmt, ctx.acc.read(address, size))[0]

    def _set(ctx, address, value, label):
        if not isinstance(value, (int, float)):
            raise TypeError(f'{label}: expected int or float, got {type(value).__name__}')
        try:
            data = struct.pack(fmt, value)
        except OverflowError:
            raise ValueError(f'{label}: {value!r} does not fit in {size} bytes') from None
        ctx.check_write(label)
        ctx.acc.write(address, data)

    return _get, _set


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

    def _set(ctx, address, value, label):
        _check_int(value, label, allow_bool=False)
        if value < 0 or value > 0xFF:
            raise ValueError(f'{label}: {value} is outside [0, 255]')
        ctx.check_write(label)
        ctx.acc.write(address, bytes((value,)))

    return _get, _set


def _resolve_enum(ptype: PropType):
    underlying = ptype.underlying
    if underlying is None:
        raise LookupError(f'EnumProperty {ptype.prop!r} has no underlying type')
    size = NATURAL_SIZES.get(underlying.kind)
    if size is None:
        raise LookupError(f'EnumProperty {ptype.prop!r} has an unsupported underlying kind {underlying.kind!r}')
    signed = underlying.kind in _SIGNED_INT_KINDS
    enum_path = ptype.enum
    get_fn, set_fn = _int_codec(size, signed, allow_bool=False)

    def _get(ctx, address, label):
        raw = get_fn(ctx, address, label)
        cls = ctx.enum_class(enum_path) if enum_path else None
        if cls is not None:
            try:
                return cls(raw)
            except ValueError:
                return raw
        return raw

    return size, size, _get, set_fn


def _resolve_bool(ptype: PropType):
    if ptype.byte_offset is None or ptype.field_mask is None or ptype.byte_mask is None:
        raise LookupError(f'BoolProperty {ptype.prop!r} has no bit layout')
    byte_offset, field_mask, byte_mask = ptype.byte_offset, ptype.field_mask, ptype.byte_mask
    size = ptype.field_size if ptype.field_size is not None else 1

    def _get(ctx, address, label):
        return bool(ctx.acc.read(address + byte_offset, 1)[0] & field_mask)

    def _set(ctx, address, value, label):
        if not isinstance(value, int):
            raise TypeError(f'{label}: expected bool or int, got {type(value).__name__}')
        ctx.check_write(label)
        b = ctx.acc.read(address + byte_offset, 1)[0]
        b = b & ~field_mask & 0xFF
        if value:
            b |= byte_mask
        ctx.acc.write(address + byte_offset, bytes((b,)))

    return size, 1, _get, _set


def _name_codec():
    def _get(ctx, address, label):
        return ctx.names.read(address)

    def _set(ctx, address, value, label):
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
        ctx.check_write(label)
        ctx.acc.write(address, data)

    return _get, _set


def _text_codec():
    def _get(ctx, address, label):
        return FTextValue(ctx, address)

    def _set(ctx, address, value, label):
        raise NotImplementedError('FText values cannot be written in v1')

    return _get, _set


def _proxy_of_session(ctx, value, label: str):
    if getattr(value, '_ue_ctx_', None) is not ctx:
        raise TypeError(f'{label}: expected a UObjectProxy of this session, got {value!r}')
    return value._address_, value._ue_path_


def _object_codec(ptype: PropType):
    cls_path = ptype.cls

    def _get(ctx, address, label):
        addr = int.from_bytes(ctx.acc.read(address, 8), 'little', signed=False)
        return ctx.proxy(addr)

    def _set(ctx, address, value, label):
        if value is None:
            ctx.check_write(label)
            ctx.acc.write(address, bytes(8))
            return
        if cls_path is None:
            raise TypeError(f'{label}: ObjectProperty has no class to check against')
        addr, path = _proxy_of_session(ctx, value, label)
        if not ctx.is_subclass(path, cls_path):
            raise TypeError(f'{label}: {value!r} is not a {cls_path}')
        ctx.check_write(label)
        ctx.acc.write(address, addr.to_bytes(8, 'little'))

    return _get, _set


def _class_codec(ptype: PropType):
    meta_path = ptype.meta_class

    def _get(ctx, address, label):
        addr = int.from_bytes(ctx.acc.read(address, 8), 'little', signed=False)
        return ctx.proxy(addr)

    def _set(ctx, address, value, label):
        if value is None:
            ctx.check_write(label)
            ctx.acc.write(address, bytes(8))
            return
        if meta_path is None:
            raise TypeError(f'{label}: ClassProperty has no meta class to check against')
        addr, _ = _proxy_of_session(ctx, value, label)
        path = ctx.types.path_of(addr)
        if path is None or not ctx.is_subclass(path, meta_path):
            raise TypeError(f'{label}: {value!r} is not a subclass of {meta_path}')
        ctx.check_write(label)
        ctx.acc.write(address, addr.to_bytes(8, 'little'))

    return _get, _set


def _interface_codec():
    def _get(ctx, address, label):
        addr = int.from_bytes(ctx.acc.read(address, 8), 'little', signed=False)
        return ctx.proxy(addr)

    def _set(ctx, address, value, label):
        if value is None:
            ctx.check_write(label)
            ctx.acc.write(address, bytes(0x10))
            return
        raise NotImplementedError('assigning an interface needs its pointer offset, which v1 does not verify')

    return _get, _set


def _read_weak_pair(ctx, address) -> tuple[int, int]:
    raw = ctx.acc.read(address, 8)
    return (int.from_bytes(raw[0:4], 'little', signed=True), int.from_bytes(raw[4:8], 'little', signed=True))


def _write_weak_pair(ctx, address, index: int, serial: int) -> None:
    ctx.acc.write(address, index.to_bytes(4, 'little', signed=True) + serial.to_bytes(4, 'little', signed=True))


def _weak_object_codec():
    def _get(ctx, address, label):
        index, serial = _read_weak_pair(ctx, address)
        return WeakObjectPtr(ctx, index, serial)

    def _set(ctx, address, value, label):
        if isinstance(value, WeakObjectPtr):
            index, serial = value.index, value.serial
        else:
            index, serial = ctx.weak_ref(value)
        ctx.check_write(label)
        _write_weak_pair(ctx, address, index, serial)

    return _get, _set


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

    def _set(ctx, address, value, label):
        raise NotImplementedError('LazyObjectProperty values cannot be written in v1')

    return size, 4, _get, _set


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

    def _set(ctx, address, value, label):
        raise NotImplementedError(f'{kind} values cannot be written in v1')

    return size, 8, _get, _set


def _resolve_field_path(ctx):
    size = ctx.e.property_sizes.FieldPathProperty
    off = 0x1C if size > 0x20 else 0x10

    def _get(ctx, address, label):
        arr = view(TArray, address + off, ctx.acc)
        names = tuple(ctx.names.read(arr.element_address(i, ctx.e.off.InSDK.Name.FNameSize)) for i in range(arr.num()))
        return FieldPathValue(names)

    def _set(ctx, address, value, label):
        raise NotImplementedError('FieldPathProperty values cannot be written in v1')

    return size, 8, _get, _set


def _resolve_delegate(ctx):
    size = ctx.e.property_sizes.DelegateProperty

    def _get(ctx, address, label):
        index, serial = _read_weak_pair(ctx, address)
        fname = ctx.names.read(address + 8)
        return DelegateValue(WeakObjectPtr(ctx, index, serial).get(), fname)

    def _set(ctx, address, value, label):
        raise NotImplementedError('DelegateProperty values cannot be written in v1')

    return size, 4, _get, _set


def _resolve_sparse():
    def _get(ctx, address, label):
        return SparseDelegateValue(ctx.acc.read(address, 1)[0] != 0)

    def _set(ctx, address, value, label):
        raise NotImplementedError('MulticastSparseDelegateProperty values cannot be written in v1')

    return _get, _set


def _flatten_struct_members(ctx, path: str) -> list:
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
    members = []
    for rec in reversed(chain):
        members.extend(rec.properties)
    return members


def _resolve_struct(ctx, ptype: PropType):
    struct_path = ptype.struct
    rec = ctx.types.type(struct_path)
    if not isinstance(rec, StructRecord):
        raise LookupError(f'struct {struct_path!r} not found')
    align = max(rec.min_alignment, 1)
    size = _align(rec.size, align)
    members_cache: list = []

    def _members(ctx):
        if not members_cache:
            members_cache.append(_flatten_struct_members(ctx, struct_path))
        return members_cache[0]

    def _get(ctx, address, label):
        return ctx.struct_view(struct_path, address)

    def _set(ctx, address, value, label):
        members = _members(ctx)
        if isinstance(value, dict):
            by_raw = {m.name: m for m in members}
            by_py = {_py_name(m.name): m for m in members}
            for key, v in value.items():
                m = by_raw.get(key) or by_py.get(key)
                if m is None:
                    raise AttributeError(f'{struct_path} has no member {key!r}')
                make_codec(ctx, m.type, m.size).set(ctx, address + m.offset, v, f'{label}.{m.name}')
        elif isinstance(value, (tuple, list)):
            if len(value) != len(members):
                raise ValueError(f'{label}: expected {len(members)} members, got {len(value)}')
            for m, v in zip(members, value):
                make_codec(ctx, m.type, m.size).set(ctx, address + m.offset, v, f'{label}.{m.name}')
        elif hasattr(value, '_ue_path_'):
            if getattr(value, '_ue_path_', None) != struct_path:
                raise TypeError(f'{label}: expected a StructView of {struct_path}, got {value!r}')
            for m in members:
                sub = getattr(value, m.name)
                make_codec(ctx, m.type, m.size).set(ctx, address + m.offset, sub, f'{label}.{m.name}')
        else:
            raise TypeError(f'{label}: expected a StructView, tuple, list or dict for {struct_path}')

    return size, align, _get, _set


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
        return (8, 4, *_weak_object_codec())
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
    """The (size, align) of the codec table's 'size when None' column for ptype's own kind."""
    if not isinstance(ptype, PropType):
        raise TypeError(f'ptype must be a PropType, got {type(ptype).__name__}')
    if ptype.kind in ('OptionalProperty', UNKNOWN_KIND):
        raise NotImplementedError(f'{ptype.prop} values are not supported in v1')
    size, align, _get, _set = _resolve(ctx, ptype)
    return size, align


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
        layout_size, align, get_fn, set_fn = _resolve(ctx, ptype)
    except (LookupError, ValueError) as exc:
        return _ErrorCodec(kind, size if size is not None else 0, exc)
    return _Codec(kind, size if size is not None else layout_size, align, get_fn, set_fn)


def raw_pointer_codec() -> Codec:
    def _get(ctx, address, label):
        addr = int.from_bytes(ctx.acc.read(address, 8), 'little', signed=False)
        return ctx.raw_view(addr)

    def _set(ctx, address, value, label):
        raise NotImplementedError('raw pointer values cannot be written in v1')

    return _Codec('raw', 8, 8, _get, _set)
