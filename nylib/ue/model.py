"""Reflection data model: records and JSON codecs for UE types and objects, plus the
Dumper-7 naming/path rules. Addresses are per-launch and never serialised."""
import dataclasses
import re
from typing import ClassVar, Iterable, Iterator

from .flags import EPropertyFlags
from .names import strip_path

_HEX_RE = re.compile(r'-?0[xX][0-9A-Fa-f]+')

PROPERTY_KINDS: tuple[str, ...] = (
    'ByteProperty', 'Int8Property', 'Int16Property', 'IntProperty', 'Int64Property',
    'UInt16Property', 'UInt32Property', 'UInt64Property', 'FloatProperty', 'DoubleProperty',
    'BoolProperty', 'EnumProperty', 'NameProperty', 'StrProperty', 'TextProperty',
    'Utf8StrProperty', 'AnsiStrProperty',
    'ObjectProperty', 'WeakObjectProperty', 'LazyObjectProperty', 'SoftObjectProperty',
    'InterfaceProperty', 'ClassProperty', 'SoftClassProperty',
    'StructProperty', 'ArrayProperty', 'SetProperty', 'MapProperty', 'OptionalProperty',
    'DelegateProperty', 'MulticastInlineDelegateProperty', 'MulticastSparseDelegateProperty',
    'FieldPathProperty',
)
UNKNOWN_KIND = 'unknown'
ENUM_SIZE_SOURCES = ('reflection', 'property', 'max_value')

# PropType.to_json: kind -> ordered JSON keys ('class' maps to attribute `.cls`, via _KEY_TO_ATTR).
_KIND_KEYS = {
    'ByteProperty': ('enum',),
    'BoolProperty': ('field_size', 'byte_offset', 'byte_mask', 'field_mask', 'bit'),
    'EnumProperty': ('enum', 'underlying'),
    'ObjectProperty': ('class',),
    'WeakObjectProperty': ('class',),
    'LazyObjectProperty': ('class',),
    'SoftObjectProperty': ('class',),
    'InterfaceProperty': ('class',),
    'ClassProperty': ('class', 'meta_class'),
    'SoftClassProperty': ('class', 'meta_class'),
    'StructProperty': ('struct',),
    'ArrayProperty': ('inner',),
    'SetProperty': ('element',),
    'OptionalProperty': ('value',),
    'MapProperty': ('key', 'value'),
    'DelegateProperty': ('signature',),
    'MulticastInlineDelegateProperty': ('signature',),
    'MulticastSparseDelegateProperty': ('signature',),
    'FieldPathProperty': ('field_class',),
}
_KEY_TO_ATTR = {'class': 'cls'}
_NESTED_ATTRS = frozenset({'underlying', 'inner', 'element', 'key', 'value'})
_STR_ATTRS = frozenset({'enum', 'struct', 'cls', 'meta_class', 'signature', 'field_class'})
_INT_ATTRS = frozenset({'field_size', 'byte_offset', 'byte_mask', 'field_mask'})


def hexs(value: int, width: int = 0) -> str:
    if not isinstance(value, int) or not isinstance(width, int):
        raise TypeError('value and width must be int')
    if width < 0:
        raise ValueError('width must be >= 0')
    if value >= 0:
        return '0x' + format(value, f'0{width}X')
    return '-0x' + format(-value, f'0{width}X')


def unhex(text: str) -> int:
    if not isinstance(text, str) or not _HEX_RE.fullmatch(text):
        raise ValueError(f'invalid hex literal {text!r}')
    return int(text, 16)


def _require_dict(data, what: str) -> None:
    if not isinstance(data, dict):
        raise ValueError(f'{what} data must be a dict, got {type(data).__name__}')


def _require_key(data: dict, key: str, expected_type):
    if key not in data:
        raise ValueError(f'missing key {key!r}')
    value = data[key]
    if expected_type is int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f'key {key!r} must be an int')
    elif not isinstance(value, expected_type):
        raise ValueError(f'key {key!r} must be a {expected_type.__name__}')
    return value


def _require_key_nullable(data: dict, key: str, expected_type):
    if key not in data:
        raise ValueError(f'missing key {key!r}')
    value = data[key]
    if value is None:
        return None
    if expected_type is int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f'key {key!r} must be an int or null')
    elif not isinstance(value, expected_type):
        raise ValueError(f'key {key!r} must be a {expected_type.__name__} or null')
    return value


def _hex_key(data: dict, key: str) -> int:
    return unhex(_require_key(data, key, str))


@dataclasses.dataclass(slots=True)
class PropType:
    prop: str
    kind: str
    enum: str | None = None
    underlying: 'PropType | None' = None
    struct: str | None = None
    cls: str | None = None
    meta_class: str | None = None
    inner: 'PropType | None' = None
    element: 'PropType | None' = None
    key: 'PropType | None' = None
    value: 'PropType | None' = None
    signature: str | None = None
    field_class: str | None = None
    field_size: int | None = None
    byte_offset: int | None = None
    byte_mask: int | None = None
    field_mask: int | None = None

    def __post_init__(self):
        if self.kind not in PROPERTY_KINDS and self.kind != UNKNOWN_KIND:
            raise ValueError(f'invalid PropType kind {self.kind!r}')
        allowed = {_KEY_TO_ATTR.get(k, k) for k in _KIND_KEYS.get(self.kind, ())}
        for f in dataclasses.fields(self):
            if f.name in ('prop', 'kind') or f.name in allowed:
                continue
            if getattr(self, f.name) is not None:
                raise ValueError(f'field {f.name!r} is not valid for kind {self.kind!r}')

    @property
    def bit(self) -> int | None:
        fm = self.field_mask
        if (self.kind != 'BoolProperty' or self.byte_offset is None or fm is None
                or fm == 0xFF or fm <= 0 or (fm & (fm - 1)) != 0):
            return None
        return self.byte_offset * 8 + fm.bit_length() - 1

    def to_json(self) -> dict:
        d = {'prop': self.prop}
        if self.kind == UNKNOWN_KIND:
            d['unknown'] = True
        elif self.kind != self.prop:
            d['kind'] = self.kind
        for key in _KIND_KEYS.get(self.kind, ()):
            attr = _KEY_TO_ATTR.get(key, key)
            value = getattr(self, attr)
            d[key] = value.to_json() if isinstance(value, PropType) else value
        return d

    @classmethod
    def from_json(cls, data: dict) -> 'PropType':
        _require_dict(data, 'PropType')
        prop = data.get('prop')
        if not isinstance(prop, str):
            raise ValueError("missing key 'prop'")
        if 'kind' in data:
            kind = data['kind']
            if kind not in PROPERTY_KINDS and kind != UNKNOWN_KIND:
                raise ValueError(f'invalid PropType kind {kind!r}')
        elif data.get('unknown') is True:
            kind = UNKNOWN_KIND
        elif prop in PROPERTY_KINDS:
            kind = prop
        else:
            kind = UNKNOWN_KIND
        kwargs = {}
        for key in _KIND_KEYS.get(kind, ()):
            if key == 'bit':
                continue  # derived, never accepted as input
            attr = _KEY_TO_ATTR.get(key, key)
            raw = data.get(key)
            if attr in _NESTED_ATTRS:
                if raw is not None and not isinstance(raw, dict):
                    raise ValueError(f'key {key!r} must be a dict or null')
                kwargs[attr] = cls.from_json(raw) if raw is not None else None
            elif attr in _STR_ATTRS:
                if raw is not None and not isinstance(raw, str):
                    raise ValueError(f'key {key!r} must be a str or null')
                kwargs[attr] = raw
            elif attr in _INT_ATTRS:
                if raw is not None and (not isinstance(raw, int) or isinstance(raw, bool)):
                    raise ValueError(f'key {key!r} must be an int or null')
                kwargs[attr] = raw
        return cls(prop=prop, kind=kind, **kwargs)


@dataclasses.dataclass(slots=True)
class PropertyRecord:
    name: str
    offset: int
    size: int
    array_dim: int
    flags: int
    type: PropType
    address: int | None = None

    def to_json(self) -> dict:
        return {
            'name': self.name,
            'offset': hexs(self.offset),
            'size': hexs(self.size),
            'array_dim': self.array_dim,
            'flags': hexs(self.flags, 16),
            'type': self.type.to_json(),
        }

    @classmethod
    def from_json(cls, data: dict) -> 'PropertyRecord':
        _require_dict(data, 'PropertyRecord')
        return cls(
            name=_require_key(data, 'name', str),
            offset=_hex_key(data, 'offset'),
            size=_hex_key(data, 'size'),
            array_dim=_require_key(data, 'array_dim', int),
            flags=_hex_key(data, 'flags'),
            type=PropType.from_json(_require_key(data, 'type', dict)),
            address=None,
        )


@dataclasses.dataclass(slots=True)
class FunctionRecord:
    path: str
    name: str
    package: str
    flags: int
    params_size: int
    params: list[PropertyRecord]
    exec_rva: int | None
    address: int | None = None
    kind: ClassVar[str] = 'function'

    @property
    def return_param(self) -> PropertyRecord | None:
        for p in self.params:
            if p.flags & EPropertyFlags.ReturnParm:
                return p
        return None

    def to_json(self, *, nested: bool = False) -> dict:
        rp = self.return_param
        d = {}
        if not nested:
            d['kind'] = FunctionRecord.kind
            d['path'] = self.path
            d['name'] = self.name
            d['package'] = self.package
        d['flags'] = hexs(self.flags, 8)
        d['params_size'] = hexs(self.params_size)
        d['return'] = rp.name if rp is not None else None
        d['params'] = [p.to_json() for p in self.params]
        d['exec_rva'] = hexs(self.exec_rva) if self.exec_rva is not None else None
        return d

    @classmethod
    def from_json(cls, data: dict, *, path: str | None = None, name: str | None = None,
                  package: str | None = None) -> 'FunctionRecord':
        _require_dict(data, 'FunctionRecord')
        p = path if path is not None else _require_key(data, 'path', str)
        n = name if name is not None else _require_key(data, 'name', str)
        pkg = package if package is not None else _require_key(data, 'package', str)
        params_data = _require_key(data, 'params', list)
        exec_rva_raw = _require_key_nullable(data, 'exec_rva', str)
        return cls(
            path=p, name=n, package=pkg,
            flags=_hex_key(data, 'flags'),
            params_size=_hex_key(data, 'params_size'),
            params=[PropertyRecord.from_json(pd) for pd in params_data],
            exec_rva=unhex(exec_rva_raw) if exec_rva_raw is not None else None,
            address=None,
        )


@dataclasses.dataclass(slots=True)
class StructRecord:
    path: str
    name: str
    cpp_name: str
    package: str
    super: str | None
    size: int
    min_alignment: int
    properties: list[PropertyRecord]
    address: int | None = None
    kind: ClassVar[str] = 'struct'

    def to_json(self) -> dict:
        return {
            'kind': StructRecord.kind,
            'path': self.path,
            'name': self.name,
            'cpp_name': self.cpp_name,
            'package': self.package,
            'super': self.super,
            'size': hexs(self.size),
            'min_alignment': self.min_alignment,
            'properties': [p.to_json() for p in self.properties],
        }

    @classmethod
    def from_json(cls, data: dict) -> 'StructRecord':
        _require_dict(data, 'StructRecord')
        props_data = _require_key(data, 'properties', list)
        return cls(
            path=_require_key(data, 'path', str),
            name=_require_key(data, 'name', str),
            cpp_name=_require_key(data, 'cpp_name', str),
            package=_require_key(data, 'package', str),
            super=_require_key_nullable(data, 'super', str),
            size=_hex_key(data, 'size'),
            min_alignment=_require_key(data, 'min_alignment', int),
            properties=[PropertyRecord.from_json(pd) for pd in props_data],
            address=None,
        )


@dataclasses.dataclass(slots=True)
class InterfaceRecord:
    cls: str
    pointer_offset: int
    implemented_by_k2: bool

    def to_json(self) -> dict:
        return {
            'class': self.cls,
            'pointer_offset': hexs(self.pointer_offset),
            'implemented_by_k2': self.implemented_by_k2,
        }

    @classmethod
    def from_json(klass, data: dict) -> 'InterfaceRecord':
        _require_dict(data, 'InterfaceRecord')
        return klass(
            cls=_require_key(data, 'class', str),
            pointer_offset=_hex_key(data, 'pointer_offset'),
            implemented_by_k2=_require_key(data, 'implemented_by_k2', bool),
        )


@dataclasses.dataclass(slots=True)
class ClassRecord(StructRecord):
    cast_flags: int = 0
    cdo: str | None = None
    interfaces: list[InterfaceRecord] = dataclasses.field(default_factory=list)
    functions: dict[str, FunctionRecord] = dataclasses.field(default_factory=dict)
    kind: ClassVar[str] = 'class'

    def to_json(self) -> dict:
        return {
            'kind': ClassRecord.kind,
            'path': self.path,
            'name': self.name,
            'cpp_name': self.cpp_name,
            'package': self.package,
            'super': self.super,
            'size': hexs(self.size),
            'min_alignment': self.min_alignment,
            'cast_flags': hexs(self.cast_flags, 16),
            'cdo': self.cdo,
            'interfaces': [i.to_json() for i in self.interfaces],
            'properties': [p.to_json() for p in self.properties],
            'functions': {name: f.to_json(nested=True) for name, f in self.functions.items()},
        }

    @classmethod
    def from_json(cls, data: dict) -> 'ClassRecord':
        _require_dict(data, 'ClassRecord')
        path = _require_key(data, 'path', str)
        package = _require_key(data, 'package', str)
        props_data = _require_key(data, 'properties', list)
        interfaces_data = _require_key(data, 'interfaces', list)
        functions_data = _require_key(data, 'functions', dict)
        functions = {
            fname: FunctionRecord.from_json(fdata, path=f'{path}:{fname}', name=fname, package=package)
            for fname, fdata in functions_data.items()
        }
        return cls(
            path=path,
            name=_require_key(data, 'name', str),
            cpp_name=_require_key(data, 'cpp_name', str),
            package=package,
            super=_require_key_nullable(data, 'super', str),
            size=_hex_key(data, 'size'),
            min_alignment=_require_key(data, 'min_alignment', int),
            properties=[PropertyRecord.from_json(pd) for pd in props_data],
            address=None,
            cast_flags=_hex_key(data, 'cast_flags'),
            cdo=_require_key_nullable(data, 'cdo', str),
            interfaces=[InterfaceRecord.from_json(i) for i in interfaces_data],
            functions=functions,
        )


@dataclasses.dataclass(slots=True)
class EnumRecord:
    path: str
    name: str
    cpp_name: str
    package: str
    underlying_size: int
    underlying_size_from: str
    underlying_signed: bool | None
    values: list[tuple[str, int]]
    address: int | None = None
    kind: ClassVar[str] = 'enum'

    def __post_init__(self):
        if self.underlying_size not in (1, 2, 4, 8):
            raise ValueError(f'invalid underlying_size {self.underlying_size!r}')
        if self.underlying_size_from not in ENUM_SIZE_SOURCES:
            raise ValueError(f'invalid underlying_size_from {self.underlying_size_from!r}')

    def to_json(self) -> dict:
        return {
            'kind': EnumRecord.kind,
            'path': self.path,
            'name': self.name,
            'cpp_name': self.cpp_name,
            'package': self.package,
            'underlying_size': self.underlying_size,
            'underlying_size_from': self.underlying_size_from,
            'underlying_signed': self.underlying_signed,
            'values': [[n, v] for n, v in self.values],
        }

    @classmethod
    def from_json(cls, data: dict) -> 'EnumRecord':
        _require_dict(data, 'EnumRecord')
        values_data = _require_key(data, 'values', list)
        values = []
        for item in values_data:
            if (not isinstance(item, list) or len(item) != 2 or not isinstance(item[0], str)
                    or not isinstance(item[1], int) or isinstance(item[1], bool)):
                raise ValueError(f'invalid enum value entry {item!r}')
            values.append((item[0], item[1]))
        return cls(
            path=_require_key(data, 'path', str),
            name=_require_key(data, 'name', str),
            cpp_name=_require_key(data, 'cpp_name', str),
            package=_require_key(data, 'package', str),
            underlying_size=_require_key(data, 'underlying_size', int),
            underlying_size_from=_require_key(data, 'underlying_size_from', str),
            underlying_signed=_require_key_nullable(data, 'underlying_signed', bool),
            values=values,
            address=None,
        )


TypeRecord = StructRecord | ClassRecord | EnumRecord | FunctionRecord


def type_from_json(data: dict) -> TypeRecord:
    if not isinstance(data, dict):
        raise ValueError(f'type data must be a dict, got {type(data).__name__}')
    kind = data.get('kind')
    if kind == 'class':
        return ClassRecord.from_json(data)
    if kind == 'struct':
        return StructRecord.from_json(data)
    if kind == 'enum':
        return EnumRecord.from_json(data)
    if kind == 'function':
        return FunctionRecord.from_json(data)
    raise ValueError(f'unknown kind {kind!r}')


@dataclasses.dataclass(frozen=True, slots=True)
class ObjectRecord:
    index: int
    address: int
    flags: int
    class_index: int
    outer_index: int
    name: str
    vtable_rva: int | None = None

    def to_row(self) -> list:
        row = [self.index, hexs(self.address), hexs(self.flags, 8), self.class_index, self.outer_index, self.name]
        if self.vtable_rva is not None:
            row.append(hexs(self.vtable_rva))
        return row

    @classmethod
    def from_row(cls, row: list) -> 'ObjectRecord':
        if not isinstance(row, (list, tuple)) or len(row) not in (6, 7):
            raise ValueError(f'invalid object row {row!r}')
        index, address_hex, flags_hex, class_index, outer_index, name = row[:6]
        for v in (index, class_index, outer_index):
            if not isinstance(v, int) or isinstance(v, bool):
                raise ValueError(f'invalid object row {row!r}')
        if not isinstance(name, str):
            raise ValueError(f'invalid object row {row!r}')
        vtable_rva = unhex(row[6]) if len(row) == 7 else None
        return cls(index=index, address=unhex(address_hex), flags=unhex(flags_hex),
                   class_index=class_index, outer_index=outer_index, name=name, vtable_rva=vtable_rva)


class ObjectTable:
    def __init__(self, records: Iterable[ObjectRecord]):
        self._by_index: dict[int, ObjectRecord] = {}
        for rec in records:
            if not isinstance(rec, ObjectRecord):
                raise TypeError(f'expected ObjectRecord, got {type(rec).__name__}')
            if rec.index < 0:
                raise ValueError(f'negative index {rec.index}')
            if rec.index in self._by_index:
                raise ValueError(f'duplicate index {rec.index}')
            self._by_index[rec.index] = rec
        self._sorted_indices: list[int] = sorted(self._by_index)
        self._by_address: dict[int, ObjectRecord] = {}
        for idx in self._sorted_indices:
            rec = self._by_index[idx]
            self._by_address.setdefault(rec.address, rec)
        self._path_cache: dict[int, str] = {}
        self._index_of_path: dict[str, int] | None = None
        self._package_class = self._detect_package_class()

    def _detect_package_class(self) -> int:
        for idx in self._sorted_indices:
            rec = self._by_index[idx]
            if rec.name != 'Package':
                continue
            outer = self._by_index.get(rec.outer_index)
            if outer is not None and outer.name == '/Script/CoreUObject':
                return rec.index
        return -1

    def __getitem__(self, index: int) -> ObjectRecord:
        if not isinstance(index, int):
            raise TypeError(f'index must be int, got {type(index).__name__}')
        try:
            return self._by_index[index]
        except KeyError:
            raise KeyError(index) from None

    def get(self, index: int) -> ObjectRecord | None:
        if not isinstance(index, int):
            raise TypeError(f'index must be int, got {type(index).__name__}')
        return self._by_index.get(index)

    def __iter__(self) -> Iterator[ObjectRecord]:
        for i in self._sorted_indices:
            yield self._by_index[i]

    def __len__(self) -> int:
        return len(self._by_index)

    def __contains__(self, index: object) -> bool:
        return isinstance(index, int) and index in self._by_index

    def by_address(self, address: int) -> ObjectRecord | None:
        if not isinstance(address, int):
            raise TypeError(f'address must be int, got {type(address).__name__}')
        return self._by_address.get(address)

    def class_of(self, index: int) -> ObjectRecord | None:
        rec = self[index]
        return self.get(rec.class_index)

    def outer_of(self, index: int) -> ObjectRecord | None:
        rec = self[index]
        return self.get(rec.outer_index)

    def is_package(self, index: int) -> bool:
        rec = self[index]
        if self._package_class != -1:
            return rec.class_index == self._package_class
        return self.outer_of(index) is None

    def short_name(self, index: int) -> str:
        return strip_path(self[index].name)

    def _outer_chain(self, index: int) -> list[int]:
        """Ancestors of `index`, self first and the outermost (no-outer) object last."""
        chain = [index]
        seen = {index}
        current = index
        while True:
            outer = self.outer_of(current)
            if outer is None:
                return chain
            if outer.index in seen or len(chain) >= 257:
                raise ValueError(f'outer chain of object {index} is cyclic or longer than 256')
            chain.append(outer.index)
            seen.add(outer.index)
            current = outer.index

    def package_of(self, index: int) -> int:
        self[index]
        return self._outer_chain(index)[-1]

    def path(self, index: int) -> str:
        self[index]
        if index in self._path_cache:
            return self._path_cache[index]
        chain = self._outer_chain(index)
        cache_pos = next((pos for pos in range(1, len(chain)) if chain[pos] in self._path_cache), None)
        if cache_pos is not None:
            result = self._path_cache[chain[cache_pos]]
            start = cache_pos - 1
        else:
            root_idx = chain[-1]
            result = self._by_index[root_idx].name
            self._path_cache[root_idx] = result
            start = len(chain) - 2
        for pos in range(start, -1, -1):
            cur_idx = chain[pos]
            outer_idx = chain[pos + 1]
            oo = self.outer_of(outer_idx)
            sep = ':' if (not self.is_package(outer_idx) and oo is not None and self.is_package(oo.index)) else '.'
            result = f'{result}{sep}{self._by_index[cur_idx].name}'
            self._path_cache[cur_idx] = result
        return result

    def full_name(self, index: int) -> str:
        self[index]
        chain = self._outer_chain(index)
        prefix = ''.join(self.short_name(o) + '.' for o in reversed(chain[1:]))
        cls = self.class_of(index)
        cls_part = self.short_name(cls.index) if cls is not None else 'None'
        return f'{cls_part} {prefix}{self.short_name(index)}'

    def index_of_path(self, path: str) -> int | None:
        if not isinstance(path, str):
            raise TypeError(f'path must be str, got {type(path).__name__}')
        if self._index_of_path is None:
            mapping: dict[str, int] = {}
            for idx in self._sorted_indices:
                try:
                    p = self.path(idx)
                except ValueError:
                    continue
                mapping.setdefault(p, idx)
            self._index_of_path = mapping
        return self._index_of_path.get(path)
