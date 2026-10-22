"""The export records and property values of nylib.ue.assets: ExportInfo, Export, StructValue, MapValue and their parts."""
import collections
import operator
from collections.abc import Mapping
from dataclasses import dataclass, field

from ..errors import AbsentPropertyError, AmbiguousNameError, AssetError
from ._records import ReadStats

_PRESENT = ('serialized', 'zero')
_NO_CTX = (None, None, None)  # (package, export path after the package, container)


@dataclass(frozen=True, slots=True)
class ObjectRef:
    kind: str
    package: str | None
    name: str | None
    path: str | None
    _target: int = field(default=0, repr=False)

    def __bool__(self) -> bool:
        return self.kind != 'null'


@dataclass(frozen=True, slots=True)
class SoftObjectRef:
    package: str
    asset: str
    subpath: str
    path: str

    def __bool__(self) -> bool:
        return self.path != ''


@dataclass(frozen=True, slots=True)
class ExportInfo:
    package: str
    name: str
    path: str = field(repr=False)
    index: int
    class_name: str | None
    class_ref: ObjectRef = field(repr=False)
    super_ref: ObjectRef = field(repr=False)
    template_ref: ObjectRef = field(repr=False)
    outer: int | None
    flags: int
    size: int
    container: str


@dataclass(frozen=True, slots=True)
class Slot:
    index: int
    owner: str
    name: str
    type: str
    state: str
    position: int | None
    element: int = 0


@dataclass(frozen=True, slots=True)
class EnumValue:
    enum: str
    name: str | None
    value: int | None


@dataclass(frozen=True, slots=True)
class TextValue:
    history: str
    string: str | None
    namespace: str | None
    key: str | None
    table: str | None
    data: 'StructValue | None'


def _layout(slots: tuple) -> tuple:
    """((name, first slot position, slot count) per property in slot order, {name: positions in that tuple})."""
    props = []
    by_name = {}
    for pos, s in enumerate(slots):
        if s.element and props and props[-1][0] == s.name and slots[props[-1][1]].index == s.index - s.element:
            name, first, n = props[-1]
            props[-1] = (name, first, n + 1)
            continue
        by_name.setdefault(s.name, []).append(len(props))
        props.append((s.name, pos, 1))
    return tuple(props), {k: tuple(v) for k, v in by_name.items()}


def _first8(items) -> str:
    return ', '.join(str(i) for i in items[:8]) + (', ...' if len(items) > 8 else '')


def _int_key(value) -> int:
    if isinstance(value, bool):
        raise TypeError('a slot index must be an int, not bool')
    try:
        return operator.index(value)
    except TypeError:
        raise TypeError(f'a slot index must be an int, got {type(value).__name__}') from None


class StructValue(Mapping):
    """A struct's slots and values; a read-only Mapping from each unambiguous, present property name to its value."""
    __slots__ = ('_struct', '_native', '_slots', '_values', '_ctx', '_problem', '_props', '_by_name', '_keys', '_hash')

    def __new__(cls, *args, **kwargs):
        raise TypeError('StructValue cannot be constructed directly: read() builds it')

    @classmethod
    def _new(cls, struct: str, native: bool, slots: tuple, values: tuple, ctx: tuple = _NO_CTX, problem=None,
             layout: tuple | None = None) -> 'StructValue':
        """`values[i]` is slot i's value, None unless serialized or zero; `layout` is `_layout(slots)` when the caller has it."""
        self = object.__new__(cls)
        self._struct = struct
        self._native = native
        self._slots = slots
        self._values = values
        self._ctx = ctx
        self._problem = problem
        self._props, self._by_name = _layout(slots) if layout is None else layout
        self._keys = self._hash = None
        return self

    struct = property(lambda self: self._struct)
    native = property(lambda self: self._native)
    slots = property(lambda self: self._slots)

    def _pos(self, index: int) -> int | None:
        slots = self._slots
        if 0 <= index < len(slots) and slots[index].index == index:
            return index
        return next((i for i, s in enumerate(slots) if s.index == index), None)

    def _absent(self, slot: Slot) -> AbsentPropertyError:
        pkg, export, container = self._ctx
        return AbsentPropertyError(
            f'{self._struct} property {slot.index} is absent in {pkg}.{export}: it was not serialized, so its value is the '
            "archetype's, which this data does not hold", package=pkg, container=container, export=export,
            class_name=self._struct, property_index=slot.index, property_name=slot.name)

    def _property(self, name):
        """(first position, slot count) of the one property named `name`; KeyError or AmbiguousNameError otherwise."""
        found = self._by_name.get(name) if isinstance(name, str) else None
        if found is None:
            raise KeyError(f'{self._struct} has no property with that name')
        if len(found) > 1:
            indexes = tuple(self._slots[self._props[k][1]].index for k in found)
            pkg, export, _container = self._ctx
            raise AmbiguousNameError(f'{self._struct} has {len(indexes)} properties with that name (indexes {_first8(indexes)}); '
                                     'use the schema index', package=pkg, export=export, struct_name=self._struct,
                                     property_name=name, indexes=indexes)
        _name, first, n = self._props[found[0]]
        return first, n

    def __getitem__(self, name):
        first, n = self._property(name)
        slots = self._slots[first:first + n]
        if any(s.state == 'unread' for s in slots):
            raise self._problem
        if (absent := next((s for s in slots if s.state not in _PRESENT), None)) is not None:
            raise self._absent(absent)
        return self._values[first] if n == 1 else self._values[first:first + n]

    def _key_names(self) -> tuple:
        if self._keys is None:
            slots = self._slots
            self._keys = tuple(name for name, first, n in self._props if len(self._by_name[name]) == 1
                               and all(s.state in _PRESENT for s in slots[first:first + n]))
        return self._keys

    def __contains__(self, name) -> bool:
        return isinstance(name, str) and name in self._key_names()

    def get(self, name, default=None):
        try:
            return self[name]
        except KeyError:
            return default

    def __iter__(self):
        return iter(self._key_names())

    def __len__(self) -> int:
        return len(self._key_names())

    def at(self, index):
        """The value at schema index `index`; AbsentPropertyError when absent, the export's problem when unread."""
        index = _int_key(index)
        if (pos := self._pos(index)) is None:
            raise IndexError(f'{self._struct} has no slot {index}')
        slot = self._slots[pos]
        if slot.state == 'unread':
            raise self._problem
        if slot.state not in _PRESENT:
            raise self._absent(slot)
        return self._values[pos]

    def state(self, key) -> str:
        """The state of slot `key` (an int), or of the property `key` (a str) names."""
        if isinstance(key, str):
            first, n = self._property(key)
            states = {s.state for s in self._slots[first:first + n]}
            return next(s for s in ('unread', 'absent', 'serialized', 'zero') if s in states)
        index = _int_key(key)
        if (pos := self._pos(index)) is None:
            raise IndexError(f'{self._struct} has no slot {index}')
        return self._slots[pos].state

    def to_python(self) -> dict:
        """Plain data for json.dumps: properties in slot order, absent ones left out, shared names as name#index."""
        slots, values = self._slots, self._values
        if any(s.state == 'unread' for s in slots):
            raise self._problem
        out = {}
        for name, first, n in self._props:
            key = name if len(self._by_name[name]) == 1 else f'{name}#{slots[first].index}'
            present = [e for e in range(n) if slots[first + e].state in _PRESENT]
            if len(present) == n:
                out[key] = _plain(values[first]) if n == 1 else [_plain(v) for v in values[first:first + n]]
            else:
                for e in present:
                    out[f'{key}[{e}]'] = _plain(values[first + e])
        return out

    def _eq_key(self) -> tuple:
        slots, values = self._slots, self._values
        return (self._struct, self._native, tuple((s.index, s.element, s.owner, s.name, s.type, s.state) for s in slots),
                tuple(values[i] for i, s in enumerate(slots) if s.state in _PRESENT))

    def __eq__(self, other) -> bool:
        if not isinstance(other, StructValue):
            return NotImplemented
        return self is other or self._eq_key() == other._eq_key()

    def __hash__(self) -> int:
        if self._hash is None:
            self._hash = hash(self._eq_key())
        return self._hash

    def __repr__(self) -> str:
        if self._native:
            fields = ''.join(f', {s.name}={v!r}' for s, v in zip(self._slots, self._values))
            return f'StructValue({self._struct!r}{fields})'
        counts = collections.Counter(s.state for s in self._slots)
        unread = f", {counts['unread']} unread" if counts['unread'] else ''
        return (f"StructValue({self._struct!r}, {len(self._slots)} slots: {counts['serialized']} serialized, {counts['zero']} zero, "
                f"{counts['absent']} absent{unread})")

    def __reduce__(self):
        return _struct_value, (self._struct, self._native, self._slots, self._values, self._ctx, self._problem)


def _struct_value(struct, native, slots, values, ctx, problem) -> StructValue:
    return StructValue._new(struct, native, slots, values, ctx, problem)


class MapValue(Mapping):
    """A map's pairs in serialized order, repeated keys included; its Mapping view is dict(pairs), so a key's last pair wins."""
    __slots__ = ('_pairs', '_dict', '_hash')

    def __init__(self, pairs=()):
        self._pairs = tuple((k, v) for k, v in pairs)
        self._dict = dict(self._pairs)
        self._hash = None

    pairs = property(lambda self: self._pairs)

    def __getitem__(self, key):
        return self._dict[key]

    def __iter__(self):
        return iter(self._dict)

    def __len__(self) -> int:
        return len(self._dict)

    def __eq__(self, other) -> bool:
        if not isinstance(other, MapValue):
            return NotImplemented
        return self is other or self._pairs == other._pairs

    def __hash__(self) -> int:
        if self._hash is None:
            self._hash = hash(self._pairs)
        return self._hash

    def __repr__(self) -> str:
        return f'MapValue({len(self._pairs)} entries)'

    def __reduce__(self):
        return MapValue, (self._pairs,)


def _plain(v):
    """The to_python() form of one value."""
    if isinstance(v, StructValue):
        return v.to_python()
    if isinstance(v, MapValue):
        return [[_plain(k), _plain(x)] for k, x in v.pairs]
    if isinstance(v, tuple):
        return [_plain(x) for x in v]
    if isinstance(v, bytes):
        return list(v)
    if isinstance(v, ObjectRef):
        return {'kind': v.kind, 'package': v.package, 'name': v.name, 'path': v.path}
    if isinstance(v, SoftObjectRef):
        return {'package': v.package, 'asset': v.asset, 'subpath': v.subpath, 'path': v.path}
    if isinstance(v, EnumValue):
        return {'enum': v.enum, 'name': v.name, 'value': v.value}
    if isinstance(v, TextValue):
        return {'history': v.history, 'string': v.string, 'namespace': v.namespace, 'key': v.key, 'table': v.table,
                'data': None if v.data is None else v.data.to_python()}
    return v


def _problem_key(p) -> tuple | None:
    return None if p is None else (type(p), str(p))


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class Export:
    info: ExportInfo
    properties: StructValue
    native: object
    native_size: int
    exact: bool
    guid: str | None
    complete: bool
    problem: AssetError | None
    stats: ReadStats = field(repr=False, compare=False)

    def _fields(self) -> tuple:
        return self.info, self.properties, self.native, self.native_size, self.exact, self.guid, self.complete

    def __eq__(self, other) -> bool:
        if not isinstance(other, Export):
            return NotImplemented
        p, q = self.problem, other.problem
        return (self._fields() == other._fields() and _problem_key(p) == _problem_key(q)
                and (p is None or vars(p) == vars(q)))

    def __hash__(self) -> int:
        return hash((self._fields(), _problem_key(self.problem)))

    def __repr__(self) -> str:
        if self.exact:
            tail = 'exact'
        elif self.complete:
            tail = f'{self.native_size} B unparsed'
        else:
            tail = f'partial: {type(self.problem).__name__}'
        return f'Export({self.info.path}, {self.properties.struct}, {self.info.size} B, {tail})'
