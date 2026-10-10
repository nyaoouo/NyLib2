"""Dynamic nylib.ctype classes per UE class/struct/enum: property descriptors, functions, cast and naming (3.3)."""
import enum
import keyword
import logging
import typing

from .codecs import make_codec, raw_pointer_codec
from .containers import array_codec, fixed_array_codec, map_codec
from ..engine.accessor import SourceAccessor, view
from ..engine.containers import ViewStruct
from ..engine.unreal import UEObject, UEStruct
from ..errors import SessionError
from ..model import ClassRecord, EnumRecord, PropertyRecord, PropType, StructRecord
from ..names import make_name_valid
from ..reflect import LiveResolver
from ... import ctype

if typing.TYPE_CHECKING:
    from .session import RuntimeContext

_log = logging.getLogger('nylib.ue.runtime.types')

RESERVED = frozenset({'cast'})
_CORE_ATTRS = frozenset({'_address_', '_accessor_', '_is_self_allocated_'})
_MAX_SUPER_DEPTH = 256
_PREDEFINED_OFF_KEYS = {'/Script/Engine.Level': 'Off.InSDK.ULevel.Actors', '/Script/Engine.DataTable': 'Off.InSDK.UDataTable.RowMap'}


def _reserved(name: str) -> bool:
    return name in RESERVED or (name.startswith('_') and name.endswith('_'))


def py_name(raw: str) -> str:
    if not isinstance(raw, str):
        raise TypeError(f'raw must be str, got {type(raw).__name__}')
    v = make_name_valid(raw)
    return v + '_' if keyword.iskeyword(v) else v


def member_names(raw: str) -> tuple[str, ...]:
    v = py_name(raw)
    candidates = [v]
    if raw != v and raw.isidentifier():
        candidates.append(raw)
    return tuple(n for n in candidates if not _reserved(n))


def _enum_member_name(raw_name: str) -> str:
    v = make_name_valid(raw_name.rsplit('::', 1)[-1])
    if v in ('name', 'value', 'mro') or keyword.iskeyword(v):
        v = v + '_'
    if v.startswith('_'):
        v = 'V' + v
    return v


def _build_enum(record) -> type[enum.IntEnum]:
    members: dict[str, int] = {}
    for name, value in record.values:
        mname = _enum_member_name(name)
        if mname not in members:
            members[mname] = value
    return enum.IntEnum(record.cpp_name, members)


_BYTE_ARRAY_CACHE: dict[int, type] = {}


def _byte_array(size: int) -> type:
    t = _BYTE_ARRAY_CACHE.get(size)
    if t is None:
        t = _BYTE_ARRAY_CACHE[size] = ctype.c_uint8 * size
    return t


class PropertyDescriptor(ctype.Field):
    """A reflected member: a codec bound to its offset, reachable by its raw and Python names."""

    def __init__(self, codec, record: PropertyRecord):
        self.codec = codec
        self.record = record
        self.raw_name = record.name
        super().__init__(_byte_array(max(1, codec.size)), record.offset)

    def __get__(self, instance, owner):
        if instance is None:
            return self
        cls = type(instance)
        return self.codec.get(cls._ue_ctx_, instance._address_ + self.offset, f'{cls._ue_name_}.{self.raw_name}')

    def __set__(self, instance, value) -> None:
        cls = type(instance)
        self.codec.set(cls._ue_ctx_, instance._address_ + self.offset, value, f'{cls._ue_name_}.{self.raw_name}')


class FunctionDescriptor:
    """A reflected UFunction: `__get__` binds a callable that routes to `ctx.invoke`."""

    def __init__(self, record):
        self.record = record

    def __get__(self, instance, owner):
        if instance is None:
            return self
        record, ctx = self.record, type(instance)._ue_ctx_

        def call(*args, **kwargs):
            return ctx.invoke(instance, record, args, kwargs)
        call.__name__ = record.name
        return call


def _check_view_kwargs(cls, kwargs) -> None:
    acc, addr = kwargs.get('_accessor_'), kwargs.get('_address_')
    if not isinstance(acc, SourceAccessor) or not isinstance(addr, int) or isinstance(addr, bool):
        raise TypeError(f'{cls.__name__} is only constructed through the session (view(), cast(), or a member read)')


def _setattr_impl(self, name, value) -> None:
    if name in _CORE_ATTRS:
        object.__setattr__(self, name, value)
        return
    cls = type(self)
    desc = cls._ue_members_.get(name) or cls._ue_attrs_.get(name)
    if desc is None:
        raise AttributeError(f'{cls._ue_name_} has no member {name!r}; UE member names are case-sensitive')
    desc.__set__(self, value)


def _get_impl(self, name):
    if not isinstance(name, str):
        raise TypeError(f'name must be str, got {type(name).__name__}')
    cls = type(self)
    desc = cls._ue_members_.get(name) or cls._ue_attrs_.get(name)
    if desc is None:
        raise AttributeError(f'{cls._ue_name_} has no member {name!r}')
    return desc.__get__(self, cls)


def _set_impl(self, name, value) -> None:
    if not isinstance(name, str):
        raise TypeError(f'name must be str, got {type(name).__name__}')
    cls = type(self)
    desc = cls._ue_members_.get(name) or cls._ue_attrs_.get(name)
    if desc is None:
        raise AttributeError(f'{cls._ue_name_} has no member {name!r}')
    desc.__set__(self, value)


def _cast_impl(self, t):
    ctx = type(self)._ue_ctx_
    if ctx.closed:
        raise SessionError('the session is closed')
    if isinstance(t, type) and issubclass(t, (UObjectProxy, StructView, RawPointer)) and getattr(t, '_ue_ctx_', None) is ctx:
        return view(t, self._address_, ctx.acc)
    if isinstance(t, str):
        record = ctx.types.type(t)
        if isinstance(record, ClassRecord):
            return view(ctx.factory.class_for(t), self._address_, ctx.acc)
        if isinstance(record, StructRecord):
            return view(ctx.factory.struct_for(t), self._address_, ctx.acc)
        raise LookupError(f'no class or struct {t!r}')
    if isinstance(t, UObjectProxy) and type(t)._ue_ctx_ is ctx:
        return _cast_impl(self, t._path_)
    raise TypeError(f'cast target must be a class, path or object, got {type(t).__name__}')


def _own_fields_mro(cls):
    """Own PropertyDescriptors of `cls` in super-first, reflection order (one entry per raw name)."""
    seen, result = set(), []
    for c in reversed(cls.__mro__):
        for desc in c.__dict__.get('_fields_', ()):
            if desc.raw_name in seen:
                continue
            seen.add(desc.raw_name)
            result.append((desc.raw_name, desc))
    return result


def _struct_repr(obj, depth: int) -> str:
    cls = type(obj)
    name = cls._ue_type_.cpp_name if cls._ue_type_ is not None else cls.__name__
    if depth >= 4:
        return f'{name}(...)'
    parts = []
    for raw_name, desc in _own_fields_mro(cls):
        try:
            value = desc.__get__(obj, cls)
        except Exception:
            parts.append(f'{raw_name}=<unreadable>')
            continue
        if isinstance(value, StructView):
            parts.append(f'{raw_name}={_struct_repr(value, depth + 1)}')
            continue
        try:
            parts.append(f'{raw_name}={value!r}')
        except Exception:
            parts.append(f'{raw_name}=<unreadable>')
    return f'{name}({", ".join(parts)})'


class UObjectProxy(ViewStruct):
    """A session-bound view of one UObject: reflected members, UFunctions and the 3.3 object model."""
    _ue_ctx_: typing.ClassVar['RuntimeContext']
    _ue_path_: typing.ClassVar[str | None] = None
    _ue_name_: typing.ClassVar[str] = 'UObject'
    _ue_type_: typing.ClassVar[ClassRecord | None] = None
    _ue_members_: typing.ClassVar[dict] = {}
    _ue_attrs_: typing.ClassVar[dict] = {}
    _ue_functions_: typing.ClassVar[dict] = {}

    def __new__(cls, *args, **kwargs):
        _check_view_kwargs(cls, kwargs)
        return object.__new__(cls)

    def __setattr__(self, name, value) -> None:
        _setattr_impl(self, name, value)

    def _get_(self, name: str):
        return _get_impl(self, name)

    def _set_(self, name: str, value) -> None:
        _set_impl(self, name, value)

    def _call_(self, name: str, /, *args, **kwargs):
        if not isinstance(name, str):
            raise TypeError(f'name must be str, got {type(name).__name__}')
        cls = type(self)
        record = cls._ue_functions_.get(name)
        if record is None:
            attr = getattr(cls, name, None)
            if isinstance(attr, FunctionDescriptor):
                record = attr.record
        if record is None:
            raise AttributeError(f'{cls._ue_name_} has no function {name!r}')
        return cls._ue_ctx_.invoke(self, record, args, kwargs)

    @property
    def _path_(self) -> str:
        ctx = type(self)._ue_ctx_
        if ctx.closed:
            raise SessionError('the session is closed')
        path = LiveResolver(ctx.e).path(self._address_)
        if path is None:
            raise ValueError('the outer chain is cyclic or longer than 256')
        return path

    @property
    def _full_name_(self) -> str:
        ctx = type(self)._ue_ctx_
        if ctx.closed:
            raise SessionError('the session is closed')
        return UEObject(ctx.e, self._address_).get_full_name()

    def cast(self, t):
        return _cast_impl(self, t)

    def __eq__(self, other):
        if isinstance(other, UObjectProxy) and type(other)._ue_ctx_ is type(self)._ue_ctx_:
            return self._address_ == other._address_
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._address_)

    def __repr__(self) -> str:
        try:
            path = self._path_
        except Exception:
            path = None
        name, addr = type(self)._ue_name_, f'0x{self._address_:X}'
        return f'<{name} {path} at {addr}>' if path is not None else f'<{name} at {addr}>'

    def __dir__(self):
        cls = type(self)
        names = set(super().__dir__())
        names.update(cls._ue_members_, cls._ue_attrs_, cls._ue_functions_)
        return sorted(names)


class StructView(ViewStruct):
    """A session-bound view of one UE struct instance, in place: reflected members, no functions."""
    _ue_ctx_: typing.ClassVar['RuntimeContext']
    _ue_path_: typing.ClassVar[str | None] = None
    _ue_name_: typing.ClassVar[str] = ''
    _ue_type_: typing.ClassVar[StructRecord | None] = None
    _ue_members_: typing.ClassVar[dict] = {}
    _ue_attrs_: typing.ClassVar[dict] = {}

    def __new__(cls, *args, **kwargs):
        _check_view_kwargs(cls, kwargs)
        return object.__new__(cls)

    def __setattr__(self, name, value) -> None:
        _setattr_impl(self, name, value)

    def _get_(self, name: str):
        return _get_impl(self, name)

    def _set_(self, name: str, value) -> None:
        _set_impl(self, name, value)

    def cast(self, t):
        return _cast_impl(self, t)

    def __eq__(self, other):
        if isinstance(other, StructView) and type(other)._ue_ctx_ is type(self)._ue_ctx_:
            return type(self)._ue_path_ == type(other)._ue_path_ and self._address_ == other._address_
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._address_)

    def __repr__(self) -> str:
        return _struct_repr(self, 0)

    def __dir__(self):
        cls = type(self)
        names = set(super().__dir__())
        names.update(cls._ue_members_, cls._ue_attrs_)
        return sorted(names)


class RawPointer(ViewStruct):
    """An untyped address view: no members, `cast()` only."""
    _size_ = 0
    _ue_ctx_: typing.ClassVar['RuntimeContext']

    def __new__(cls, *args, **kwargs):
        _check_view_kwargs(cls, kwargs)
        return object.__new__(cls)

    def __setattr__(self, name, value) -> None:
        if name in _CORE_ATTRS:
            object.__setattr__(self, name, value)
            return
        raise AttributeError(f'RawPointer has no member {name!r}')

    def cast(self, t):
        return _cast_impl(self, t)

    def __eq__(self, other):
        if isinstance(other, RawPointer) and type(other)._ue_ctx_ is type(self)._ue_ctx_:
            return self._address_ == other._address_
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._address_)

    def __repr__(self) -> str:
        return f'<pointer 0x{self._address_:X}>'


def _build_own_properties(ctx, properties):
    own_fields, own_members, own_attrs = [], {}, {}
    for prop in properties:
        codec = make_codec(ctx, prop.type, prop.size)
        if prop.array_dim > 1:
            codec = fixed_array_codec(codec, prop.array_dim)
        desc = PropertyDescriptor(codec, prop)
        own_fields.append(desc)
        own_members.setdefault(prop.name, desc)
        for n in member_names(prop.name):
            own_attrs.setdefault(n, desc)
    return own_fields, own_members, own_attrs


def _predefined_codec(ctx, path: str):
    if path == '/Script/Engine.Level':
        return array_codec(ctx, make_codec(ctx, PropType('ObjectProperty', 'ObjectProperty', cls='/Script/Engine.Actor')))
    return map_codec(ctx, make_codec(ctx, PropType('NameProperty', 'NameProperty')), raw_pointer_codec())


def _off_value(e, key: str):
    value = e.off
    for part in key.split('.')[1:]:
        value = getattr(value, part)
    return value


def _apply_predefined(cls, record, ctx) -> None:
    """Dumper-7's predefined (unreflected) members: ULevel.Actors and UDataTable.RowMap."""
    key = _PREDEFINED_OFF_KEYS.get(record.path)
    if key is None:
        return
    name = key.rsplit('.', 1)[-1]
    if name in cls._ue_members_ or name in cls._ue_attrs_:
        return
    if not ctx.e.provenance.get(key, '').startswith(('auto:', 'profile:')):
        return
    offset = _off_value(ctx.e, key)
    if offset <= 0:
        return
    codec = _predefined_codec(ctx, record.path)
    prec = PropertyRecord(name=name, offset=offset, size=codec.size, array_dim=1, flags=0, type=PropType(prop='unknown', kind='unknown'))
    desc = PropertyDescriptor(codec, prec)
    desc.name, desc.parent = name, cls
    setattr(cls, name, desc)
    cls._ue_members_[name] = desc
    cls._ue_attrs_[name] = desc
    cls._fields_ = cls._fields_ + [desc]


class ClassFactory:
    """Session-cached dynamic classes: one UObjectProxy/StructView subclass per UE class/struct path."""

    def __init__(self, ctx: 'RuntimeContext'):
        self._ctx = ctx
        self._classes: dict[str, type[UObjectProxy]] = {}
        self._structs: dict[str, type[StructView]] = {}
        self._enums: dict[str, type[enum.IntEnum]] = {}
        self._base = None
        self._struct_base = None
        self._raw = None

    def base_proxy(self) -> type[UObjectProxy]:
        if self._base is None:
            ctx = self._ctx
            with ctx.lock:
                if self._base is None:
                    self._base = type('UObject', (UObjectProxy,), {
                        '_ue_ctx_': ctx, '_ue_path_': None, '_ue_name_': 'UObject', '_ue_type_': None,
                        '_ue_members_': {}, '_ue_attrs_': {}, '_ue_functions_': {}, '_fields_': [], '_size_': 0, '_pad_size_': 1,
                    })
        return self._base

    def raw_class(self) -> type[RawPointer]:
        if self._raw is None:
            with self._ctx.lock:
                if self._raw is None:
                    self._raw = type('RawPointer', (RawPointer,), {'_ue_ctx_': self._ctx})
        return self._raw

    def _struct_root(self) -> type[StructView]:
        if self._struct_base is None:
            ctx = self._ctx
            with ctx.lock:
                if self._struct_base is None:
                    self._struct_base = type('StructView', (StructView,), {
                        '_ue_ctx_': ctx, '_ue_path_': None, '_ue_name_': '', '_ue_type_': None,
                        '_ue_members_': {}, '_ue_attrs_': {}, '_fields_': [], '_size_': 0, '_pad_size_': 1,
                    })
        return self._struct_base

    def class_for(self, path: str | None = None, address: int | None = None) -> type[UObjectProxy]:
        if path is not None and not isinstance(path, str):
            raise TypeError(f'path must be str or None, got {type(path).__name__}')
        if address is not None and (not isinstance(address, int) or isinstance(address, bool)):
            raise TypeError(f'address must be int or None, got {type(address).__name__}')
        return self._class_for(path, address, 0)

    def _class_for(self, path, address, depth: int) -> type[UObjectProxy]:
        if depth > _MAX_SUPER_DEPTH:
            raise LookupError(f'class supers of {path!r} are nested more than {_MAX_SUPER_DEPTH} levels deep')
        if path is not None and (cls := self._classes.get(path)) is not None:
            return cls
        ctx = self._ctx
        with ctx.lock:
            if path is not None and (cls := self._classes.get(path)) is not None:
                return cls
            record = ctx.types.type(path, address) if path is not None else None
            if isinstance(record, ClassRecord):
                if record.super is None:
                    super_cls = self.base_proxy()
                else:
                    super_addr = UEStruct(ctx.e, address).get_super().address if address is not None else None
                    super_cls = self._class_for(record.super, super_addr, depth + 1)
                cls = self._build_class(record, super_cls)
                self._classes[path] = cls
                return cls
            if address is not None:
                for super_addr in ctx.index.super_chain(address)[1:]:
                    super_path = ctx.types.path_of(super_addr)
                    if super_path is None:
                        continue
                    super_record = ctx.types.type(super_path, super_addr)
                    if isinstance(super_record, ClassRecord):
                        _log.debug('class_for: %s falls back to %s through the super chain', path, super_path)
                        return self._class_for(super_path, super_addr, depth + 1)
            return self.base_proxy()

    def _build_class(self, record: ClassRecord, super_cls: type[UObjectProxy]) -> type[UObjectProxy]:
        ctx = self._ctx
        own_fields, own_members, own_attrs = _build_own_properties(ctx, record.properties)
        own_functions = {}
        for frecord in record.functions.values():
            own_functions.setdefault(frecord.name, frecord)
        namespace = {
            '_ue_ctx_': ctx, '_ue_path_': record.path, '_ue_name_': record.name, '_ue_type_': record,
            '_ue_members_': {**super_cls._ue_members_, **own_members},
            '_ue_attrs_': {**super_cls._ue_attrs_, **own_attrs},
            '_ue_functions_': {**super_cls._ue_functions_, **own_functions},
            '_fields_': own_fields, '_size_': record.size, '_pad_size_': max(record.min_alignment, 1),
        }
        namespace.update(own_attrs)
        for frecord in record.functions.values():
            fdesc = FunctionDescriptor(frecord)
            for n in member_names(frecord.name):
                namespace.setdefault(n, fdesc)
        cls = type(record.cpp_name, (super_cls,), namespace)
        for desc in own_fields:
            desc.name, desc.parent = desc.raw_name, cls
        _apply_predefined(cls, record, ctx)
        return cls

    def struct_for(self, path: str) -> type[StructView]:
        if not isinstance(path, str):
            raise TypeError(f'path must be str, got {type(path).__name__}')
        return self._struct_for(path, 0)

    def _struct_for(self, path: str, depth: int) -> type[StructView]:
        if depth > _MAX_SUPER_DEPTH:
            raise LookupError(f'struct supers of {path!r} are nested more than {_MAX_SUPER_DEPTH} levels deep')
        if (cls := self._structs.get(path)) is not None:
            return cls
        with self._ctx.lock:
            if (cls := self._structs.get(path)) is not None:
                return cls
            record = self._ctx.types.type(path)
            if not isinstance(record, StructRecord) or isinstance(record, ClassRecord):
                raise LookupError(f'no struct type {path!r}')
            super_cls = self._struct_for(record.super, depth + 1) if record.super is not None else self._struct_root()
            cls = self._build_struct_class(record, super_cls)
            self._structs[path] = cls
            return cls

    def _build_struct_class(self, record: StructRecord, super_cls: type[StructView]) -> type[StructView]:
        ctx = self._ctx
        own_fields, own_members, own_attrs = _build_own_properties(ctx, record.properties)
        namespace = {
            '_ue_ctx_': ctx, '_ue_path_': record.path, '_ue_name_': record.name, '_ue_type_': record,
            '_ue_members_': {**super_cls._ue_members_, **own_members},
            '_ue_attrs_': {**super_cls._ue_attrs_, **own_attrs},
            '_fields_': own_fields, '_size_': record.size, '_pad_size_': max(record.min_alignment, 1),
        }
        namespace.update(own_attrs)
        cls = type(record.cpp_name, (super_cls,), namespace)
        for desc in own_fields:
            desc.name, desc.parent = desc.raw_name, cls
        return cls

    def enum_for(self, path: str) -> type[enum.IntEnum] | None:
        if not isinstance(path, str):
            raise TypeError(f'path must be str, got {type(path).__name__}')
        if (cls := self._enums.get(path)) is not None:
            return cls
        with self._ctx.lock:
            if (cls := self._enums.get(path)) is not None:
                return cls
            record = self._ctx.types.type(path)
            if not isinstance(record, EnumRecord):
                return None
            cls = self._enums[path] = _build_enum(record)
            return cls
