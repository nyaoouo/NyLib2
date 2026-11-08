"""The `.usmap` coordination interface: `load_usmap()`, the immutable `Usmap`, schema views, type labels and recorded changes."""
import hashlib
import json
import operator
import os
import re

from collections.abc import Mapping
from dataclasses import dataclass, replace

from ..errors import InvalidMappingError
from . import _usmap
from ._keys import _check_path
from ._props import _lower, type_label
from ._usmap import PropertyType
from ._values import ExportInfo

_META_MAX = 64 << 20  # the largest meta.json load_usmap() reads
_META_SCHEMA = 'nylib.ue.snapshot'
_MAX_TYPE_DEPTH = _usmap._MAX_TYPE_DEPTH
_SIMPLE = {
    'Byte': 0, 'Bool': 1, 'Int': 2, 'Float': 3, 'Object': 4, 'Name': 5, 'Delegate': 6, 'Double': 7, 'Str': 10, 'Text': 11,
    'Interface': 12, 'MulticastDelegate': 13, 'WeakObject': 14, 'LazyObject': 15, 'AssetObject': 16, 'SoftObject': 17,
    'UInt64': 18, 'UInt32': 19, 'UInt16': 20, 'Int64': 21, 'Int16': 22, 'Int8': 23, 'FieldPath': 27, 'Unknown': 0xFF,
}
_WRAPS = {'Array': 8, 'Set': 25, 'Optional': 28}
_OBJECT_HEADS = frozenset({'Object', 'WeakObject', 'SoftObject', 'LazyObject', 'AssetObject', 'Interface'})
_NAME_STOPS = '<>,:'
_KINDS = ('add', 'retype', 'rename', 'count', 'record')
_DIGEST_TAG = b'nylib.ue.assets usmap digest v1\x00'
_CONTROL_RE = re.compile('[\x00-\x1f\x7f-\x9f]')
_NON_ASCII_RE = re.compile('[^\x20-\x7e]')


def _one_line(text: str) -> str:
    """`text` with each control character written as `\\x` and two lowercase hex digits."""
    return _CONTROL_RE.sub(lambda m: f'\\x{ord(m.group()):02x}', text)


def _ascii_form(text: str) -> str:
    """`text` with each character outside U+0020-U+007E written as `ascii()` writes it, without the quotes."""
    return _NON_ASCII_RE.sub(lambda m: ascii(m.group())[1:-1], text)


def _int(value, name: str) -> int:
    if isinstance(value, bool):
        raise TypeError(f'{name} must be an int, not bool')
    try:
        return operator.index(value)
    except TypeError:
        raise TypeError(f'{name} must be an int, got {type(value).__name__}') from None


def _plural(n: int, word: str) -> str:
    return word if n == 1 else word + 's'


# --- type labels -------------------------------------------------------------------------------------------------

class _ObjectLabel(Exception):
    pass


def _expect(text: str, pos: int, ch: str) -> int:
    if pos >= len(text) or text[pos] != ch:
        raise ValueError(f'not a type label: expected {ch!r} at {pos}')
    return pos + 1


def _label_name(text: str, pos: int, stop: str) -> tuple:
    """(name or None, position after `stop`) of the struct or enum name at `pos`; the text `None` is the absent name."""
    end = pos
    while end < len(text) and text[end] not in _NAME_STOPS:
        end += 1
    name = text[pos:end]
    if not name or _CONTROL_RE.search(name):
        raise ValueError(f'not a type label: bad name at {pos}')
    return (None if name == 'None' else name), _expect(text, end, stop)


def _label_at(text: str, pos: int, depth: int) -> tuple:
    if depth > _MAX_TYPE_DEPTH:
        raise ValueError('not a type label: nested too deeply')
    end = pos
    while end < len(text) and text[end] not in _NAME_STOPS:
        end += 1
    head = text[pos:end]
    if end < len(text) and text[end] == '<':
        q = end + 1
        if head == 'Struct':
            name, q = _label_name(text, q, '>')
            return PropertyType(9, struct_name=name), q
        if head == 'Enum':
            name, q = _label_name(text, q, ':')
            inner, q = _label_at(text, q, depth + 1)
            return PropertyType(26, inner=inner, enum_name=name), _expect(text, q, '>')
        if head in _WRAPS:
            inner, q = _label_at(text, q, depth + 1)
            return PropertyType(_WRAPS[head], inner=inner), _expect(text, q, '>')
        if head == 'Map':
            key, q = _label_at(text, q, depth + 1)
            q = _expect(text, q, ',')
            value, q = _label_at(text, q, depth + 1)
            return PropertyType(24, inner=key, value=value), _expect(text, q, '>')
        if head in _OBJECT_HEADS:
            raise _ObjectLabel
        raise ValueError('not a type label')
    if head in _SIMPLE:
        return PropertyType(_SIMPLE[head]), end
    raise ValueError('not a type label')


def _parse_label(text: str) -> PropertyType:
    """The type node of a 2b type label; ValueError for any other text, TypeError for a non-str."""
    if not isinstance(text, str):
        raise TypeError(f'a type label must be a str, got {type(text).__name__}')
    try:
        node, pos = _label_at(text, 0, 0)
    except _ObjectLabel:
        raise ValueError(f'{text!r}: a .usmap stores no class for an object property, so a class cannot be required or set') from None
    if pos != len(text):
        raise ValueError(f'not a type label: trailing text at {pos}')
    return node


# --- from_python helpers -----------------------------------------------------------------------------------------

def _join(path: str, key) -> str:
    return f'{path}[{key}]' if isinstance(key, int) else (f'{path}.{key}' if path else key)


def _data(data, path: str, keys: tuple, optional: tuple = ()) -> dict:
    """`data` as a dict with exactly `keys` (and maybe `optional`); TypeError or ValueError naming the key path."""
    if not isinstance(data, dict):
        raise TypeError(f'{path or "data"} must be a dict, got {type(data).__name__}')
    for key in keys:
        if key not in data:
            raise ValueError(f'{_join(path, key)}: missing key')
    for key in data:
        if key not in keys and key not in optional:
            raise ValueError(f'{path or "data"}: unknown key {key!r}')
    return data


def _val(data: dict, path: str, key: str, kind: str, none: bool = False):
    """data[key], which must be of JSON kind `kind` ('int', 'str', 'bool', 'list' or 'dict'), or None when `none`."""
    v = data[key]
    if v is None and none:
        return None
    ok = {'int': lambda: isinstance(v, int) and not isinstance(v, bool), 'str': lambda: isinstance(v, str),
          'bool': lambda: isinstance(v, bool), 'list': lambda: isinstance(v, list), 'dict': lambda: isinstance(v, dict)}[kind]()
    if not ok:
        raise ValueError(f'{_join(path, key)}: expected {kind}{" or null" if none else ""}')
    return v


# --- records -----------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class PropertyInfo:
    """One slot of a chain, as the effective mapping holds it; it has no value."""
    index: int
    element: int
    owner: str
    own_index: int
    name: str
    type: str
    array_dim: int

    def __post_init__(self):
        for key, lo, hi in (('index', 0, None), ('element', 0, None), ('own_index', 0, None), ('array_dim', 1, 255)):
            v = getattr(self, key)
            if type(v) is not int:
                object.__setattr__(self, key, v := _int(v, key))
            if v < lo or (hi is not None and v > hi):
                raise ValueError(f'{key} is out of range')
        if self.element >= self.array_dim:
            raise ValueError('element must be below array_dim')
        for key in ('owner', 'name', 'type'):
            if not isinstance(v := getattr(self, key), str):
                raise TypeError(f'{key} must be a str, got {type(v).__name__}')
        if not self.owner:
            raise ValueError('owner must not be empty')

    def to_python(self) -> dict:
        return {'index': self.index, 'element': self.element, 'owner': self.owner, 'own_index': self.own_index,
                'name': self.name, 'type': self.type, 'array_dim': self.array_dim}

    @classmethod
    def from_python(cls, data: dict) -> 'PropertyInfo':
        return _property_from(data, '')


_PROPERTY_KEYS = ('index', 'element', 'owner', 'own_index', 'name', 'type', 'array_dim')


def _property_from(data, path: str) -> PropertyInfo:
    d = _data(data, path, _PROPERTY_KEYS)
    args = {k: _val(d, path, k, 'int' if k in ('index', 'element', 'own_index', 'array_dim') else 'str') for k in _PROPERTY_KEYS}
    try:
        return PropertyInfo(**args)
    except (TypeError, ValueError) as e:
        raise ValueError(f'{path or "data"}: {e}') from None


def _prop(index: int, element: int, owner: str, own_index: int, name: str, label: str, array_dim: int) -> PropertyInfo:
    """A PropertyInfo from a mapping's own values, without validation."""
    p = object.__new__(PropertyInfo)
    for key, v in zip(_PROPERTY_KEYS, (index, element, owner, own_index, name, label, array_dim)):
        object.__setattr__(p, key, v)
    return p


@dataclass(frozen=True, slots=True)
class RecordInfo:
    name: str
    super: str | None
    count: int
    properties: tuple[PropertyInfo, ...]


@dataclass(frozen=True, slots=True)
class DumpInfo:
    """What `load_usmap(meta=)` read from a dump's meta.json."""
    created: str | None
    exe: str | None
    pe_timestamp: int | None
    quality: str | None
    reasons: tuple[str, ...]

    def __repr__(self) -> str:
        stamp = None if self.pe_timestamp is None else f'{self.pe_timestamp:#010x}'
        return (f'DumpInfo(created={self.created!r}, exe={self.exe!r}, pe_timestamp={stamp}, quality={self.quality!r}, '
                f'reasons={self.reasons!r})')

    def to_python(self) -> dict:
        return {'created': self.created, 'exe': self.exe, 'pe_timestamp': self.pe_timestamp, 'quality': self.quality,
                'reasons': list(self.reasons)}

    @classmethod
    def from_python(cls, data: dict) -> 'DumpInfo':
        return _dump_from(data, '')


def _dump_from(data, path: str) -> DumpInfo:
    d = _data(data, path, ('created', 'exe', 'pe_timestamp', 'quality', 'reasons'))
    stamp = _val(d, path, 'pe_timestamp', 'int', True)
    if stamp is not None and not 0 <= stamp <= 0xFFFFFFFF:
        raise ValueError(f'{_join(path, "pe_timestamp")}: out of range')
    reasons = _val(d, path, 'reasons', 'list')
    for i, r in enumerate(reasons):
        if not isinstance(r, str):
            raise ValueError(f'{_join(_join(path, "reasons"), i)}: expected str')
    return DumpInfo(_val(d, path, 'created', 'str', True), _val(d, path, 'exe', 'str', True), stamp,
                    _val(d, path, 'quality', 'str', True), tuple(reasons))


# --- MappingChange -----------------------------------------------------------------------------------------------

_INDEX_MAX = 65535
_CHANGE_KEYS = ('kind', 'struct', 'own_index', 'name', 'type', 'array_dim', 'count', 'super', 'properties', 'before', 'by', 'note')
_CHANGE_FIELDS = ('own_index', 'name', 'type', 'array_dim', 'count', 'super', 'before')
# per kind, how each of _CHANGE_FIELDS is checked: None means the field must be None, '?' that None is allowed
_CHANGE_RULES = {
    'add': ('index', 'name', 'label', 'dim', None, None, None),
    'retype': ('index', None, 'label', None, None, None, 'label?'),
    'rename': ('index', 'name', 'label?', None, None, None, 'name?'),
    'count': (None, None, None, None, 'count', None, 'count?'),
    'record': (None, None, None, None, 'count', 'name?', None),
}


def _ranged(value, key: str, lo: int, hi: int) -> int:
    value = _int(value, key)
    if not lo <= value <= hi:
        raise ValueError(f'{key} is out of range')
    return value


def _text(value, key: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f'{key} must be a str, got {type(value).__name__}')
    if not value:
        raise ValueError(f'{key} must not be empty')
    return value


def _change_field(value, key: str, rule, kind: str):
    if rule is None:
        if value is not None:
            raise ValueError(f'{key} must be None for a {kind} change')
        return None
    if rule.endswith('?') and value is None:
        return None
    rule = rule.rstrip('?')
    if rule in ('index', 'count'):
        return _ranged(value, key, 0, _INDEX_MAX)
    if rule == 'name':
        return _text(value, key)
    if rule == 'dim':
        return 1 if value is None else _ranged(value, key, 1, 255)
    _parse_label(value)
    return value


def _change_properties(value, count) -> tuple:
    """`record`'s properties as a tuple of (own_index, name, type, array_dim)."""
    if not isinstance(value, (tuple, list)):
        raise TypeError(f'properties must be a tuple or list, got {type(value).__name__}')
    out = []
    for n, item in enumerate(value):
        if not isinstance(item, (tuple, list)):
            raise TypeError(f'properties[{n}] must be a tuple or list, got {type(item).__name__}')
        if len(item) not in (3, 4):
            raise ValueError(f'properties[{n}] must hold 3 or 4 items')
        i = _ranged(item[0], f'properties[{n}][0]', 0, _INDEX_MAX)
        name = _text(item[1], f'properties[{n}][1]')
        _parse_label(item[2])
        dim = 1 if len(item) == 3 else _ranged(item[3], f'properties[{n}][3]', 1, 255)
        if i + dim > count:
            raise ValueError(f'properties[{n}] does not fit the count')
        out.append((i, name, item[2], dim))
    end = 0
    for i, _name, _label, dim in sorted(out, key=lambda p: p[0]):
        if i < end:
            raise ValueError('properties overlap')
        end = i + dim
    return tuple(out)


@dataclass(frozen=True, slots=True)
class MappingChange:
    """One record edit: the caller's input and the applied result alike; `own_index` is an index inside the record `struct`."""
    kind: str
    struct: str
    own_index: int | None = None
    name: str | None = None
    type: str | None = None
    array_dim: int | None = None
    count: int | None = None
    super: str | None = None
    properties: tuple[tuple[int, str, str, int], ...] = ()
    before: str | int | None = None
    by: str = 'patch'
    note: str | None = None

    def __post_init__(self):
        if not isinstance(self.kind, str):
            raise TypeError(f'kind must be a str, got {type(self.kind).__name__}')
        if self.kind not in _KINDS:
            raise ValueError(f'kind must be one of {", ".join(_KINDS)}')
        _text(self.struct, 'struct')
        if _CONTROL_RE.search(_text(self.by, 'by')):
            raise ValueError('by must not hold a control character')
        if self.note is not None and not isinstance(self.note, str):
            raise TypeError(f'note must be a str or None, got {type(self.note).__name__}')
        values = {key: _change_field(getattr(self, key), key, rule, self.kind)
                  for key, rule in zip(_CHANGE_FIELDS, _CHANGE_RULES[self.kind])}
        if self.kind == 'record':
            props = _change_properties(self.properties, values['count'])
        elif not isinstance(self.properties, (tuple, list)):
            raise TypeError(f'properties must be a tuple or list, got {type(self.properties).__name__}')
        elif self.properties:
            raise ValueError(f'properties must be empty for a {self.kind} change')
        else:
            props = ()
        for key, v in values.items():
            if v is not getattr(self, key):
                object.__setattr__(self, key, v)
        object.__setattr__(self, 'properties', props)

    @classmethod
    def add(cls, struct, own_index, name, type, *, array_dim=1, note=None) -> 'MappingChange':
        return cls('add', struct, own_index, name, type, array_dim, note=note)

    @classmethod
    def retype(cls, struct, own_index, type, *, before=None, note=None) -> 'MappingChange':
        return cls('retype', struct, own_index, type=type, before=before, note=note)

    @classmethod
    def rename(cls, struct, own_index, name, *, before=None, type=None, note=None) -> 'MappingChange':
        return cls('rename', struct, own_index, name, type, before=before, note=note)

    @classmethod
    def set_count(cls, struct, count, *, before=None, note=None) -> 'MappingChange':
        return cls('count', struct, count=count, before=before, note=note)

    @classmethod
    def record(cls, struct, *, super=None, count, properties=(), note=None) -> 'MappingChange':
        return cls('record', struct, count=count, super=super, properties=properties, note=note)

    def to_python(self) -> dict:
        return {'kind': self.kind, 'struct': self.struct, 'own_index': self.own_index, 'name': self.name, 'type': self.type,
                'array_dim': self.array_dim, 'count': self.count, 'super': self.super,
                'properties': [list(p) for p in self.properties], 'before': self.before, 'by': self.by, 'note': self.note}

    @classmethod
    def from_python(cls, data: dict) -> 'MappingChange':
        return _change_from(data, '')


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _change_from(data, path: str) -> MappingChange:
    d = _data(data, path, ('kind', 'struct'), _CHANGE_KEYS[2:])
    args = {'kind': _val(d, path, 'kind', 'str'), 'struct': _val(d, path, 'struct', 'str')}
    for key, kind in (('own_index', 'int'), ('array_dim', 'int'), ('count', 'int'), ('name', 'str'), ('type', 'str'),
                      ('super', 'str'), ('note', 'str')):
        if key in d:
            args[key] = _val(d, path, key, kind, True)
    if 'by' in d:
        args['by'] = _val(d, path, 'by', 'str')
    if 'before' in d:
        if not ((v := d['before']) is None or isinstance(v, str) or _is_int(v)):
            raise ValueError(f'{_join(path, "before")}: expected str, int or null')
        args['before'] = v
    if 'properties' in d:
        props = []
        for n, item in enumerate(_val(d, path, 'properties', 'list')):
            at = _join(_join(path, 'properties'), n)
            if not isinstance(item, list):
                raise ValueError(f'{at}: expected list')
            if len(item) not in (3, 4):
                raise ValueError(f'{at}: expected 3 or 4 items')
            for k, kind in enumerate(('int', 'str', 'str', 'int')[:len(item)]):
                if not (isinstance(item[k], str) if kind == 'str' else _is_int(item[k])):
                    raise ValueError(f'{_join(at, k)}: expected {kind}')
            props.append(tuple(item))
        args['properties'] = tuple(props)
    labels = [(_join(path, key), args.get(key)) for key in (('type', 'before') if args['kind'] == 'retype' else ('type',))]
    labels += [(_join(_join(_join(path, 'properties'), n), 2), p[2]) for n, p in enumerate(args.get('properties', ()))]
    for key, text in labels:
        if isinstance(text, str):
            try:
                _parse_label(text)
            except ValueError:
                raise ValueError(f'{key}: not a type label') from None
    try:
        return MappingChange(**args)
    except (TypeError, ValueError) as e:
        raise ValueError(f'{path or "data"}: {e}') from None


def _change_digest(sha256: str, changes: tuple) -> str:
    """`sha256` when there are no changes, else the SHA-256 over the file hash and the canonical form of each change."""
    if not changes:
        return sha256
    h = hashlib.sha256(_DIGEST_TAG + bytes.fromhex(sha256) + len(changes).to_bytes(4, 'little'))
    for c in changes:
        canon = json.dumps([c.kind, c.struct, c.own_index, c.name, c.type, c.array_dim, c.count, c.super,
                            [list(p) for p in c.properties], c.before], ensure_ascii=True, separators=(',', ':'),
                           allow_nan=False).encode('ascii')
        h.update(len(canon).to_bytes(8, 'little') + canon)
    return h.hexdigest()


# --- schema views ------------------------------------------------------------------------------------------------

def _local_slots(rec) -> list:
    """(own index, element, entry) of each slot `rec` builds, in own-index order (2b's Schema rules)."""
    local = {}
    for p in rec.properties:
        for e in range(p.array_dim):
            i = p.index + e
            if i < rec.property_count and i not in local:
                local[i] = (e, p)
    return [(i, *local[i]) for i in sorted(local)]


def _chain_slots(chain) -> tuple:
    """The PropertyInfo of every slot of `chain` (records, own first), numbered chain-wide."""
    out = []
    base = 0
    for rec in chain:
        labels = {}
        for i, e, p in _local_slots(rec):
            if (label := labels.get(id(p))) is None:
                label = labels[id(p)] = type_label(p.type)
            out.append(_prop(base + i, e, rec.name, p.index, p.name, label, p.array_dim))
        base += rec.property_count
    return tuple(out)


def _record_info(rec) -> RecordInfo:
    props = tuple(_prop(i, 0, rec.name, i, p.name, type_label(p.type), p.array_dim) for i, e, p in _local_slots(rec) if e == 0)
    return RecordInfo(rec.name, rec.super, rec.property_count, props)


def _resolve_chain(mappings, name: str) -> tuple:
    """(records, None) for `name`'s super chain, or (None, ('no record', missing name)) / (None, ('cycle', name))."""
    chain, seen, n = [], set(), name
    while n is not None:
        key = _lower(n)
        if key in seen:
            return None, ('cycle', name)
        seen.add(key)
        if (rec := mappings.record(n)) is None:
            return None, ('no record', n)
        chain.append(rec)
        n = rec.super
    return chain, None


# --- applying changes --------------------------------------------------------------------------------------------

def _refuse(u: 'Usmap', k: int, c: MappingChange, why: str, entry=None) -> InvalidMappingError:
    return InvalidMappingError(f'{u.file}: change {k} ({c.kind}) does not apply to {c.struct!r}: {why}', usmap=u.file,
                               reason='change does not apply', class_name=c.struct, property_index=c.own_index,
                               property_name=None if entry is None else entry.name,
                               property_type=None if entry is None else type_label(entry.type))


def _parsable(label: str) -> bool:
    try:
        _parse_label(label)
    except ValueError:
        return False
    return True


def _same_super(a: str | None, b: str | None) -> bool:
    return a is b or (a is not None and b is not None and _lower(a) == _lower(b))


def _apply_change(u: 'Usmap', structs: dict, c: MappingChange, k: int) -> MappingChange | None:
    """Apply `c` to the record dict `structs`; the change as recorded, or None when it is already in place."""
    key = _lower(c.struct)
    rec = structs.get(key)
    if c.kind == 'record':
        if rec is not None:
            if _same_super(rec.super, c.super) and rec.property_count == c.count:
                return None
            raise _refuse(u, k, c, f'the record exists with super {rec.super!r} and {rec.property_count} properties')
        props = tuple(_usmap._Property(i, d, n, _parse_label(t)) for i, n, t, d in c.properties)
        structs[key] = _usmap.StructRecord(c.struct, c.super, c.count, props)
        return c
    if rec is None:
        raise _refuse(u, k, c, 'it has no record')
    if c.kind == 'count':
        if rec.property_count == c.count:
            return None
        if c.before is not None and rec.property_count != c.before:
            raise _refuse(u, k, c, f'its property count is {rec.property_count}, not {c.before}')
        if outside := [max(p.index, c.count) for p in rec.properties if p.index + p.array_dim > c.count]:
            raise _refuse(u, k, c, f'a count of {c.count} would leave own index {min(outside)} outside')
        structs[key] = _usmap.StructRecord(rec.name, rec.super, c.count, rec.properties)
        return replace(c, struct=rec.name, before=rec.property_count)
    i = c.own_index
    entry = next((p for p in rec.properties if p.index == i), None)
    if c.kind == 'add':
        if entry is not None and entry.name == c.name and entry.array_dim == c.array_dim and type_label(entry.type) == c.type:
            return None
        end = i + c.array_dim
        if end > rec.property_count or any(i < p.index + p.array_dim and p.index < end for p in rec.properties):
            raise _refuse(u, k, c, f'own indexes {i}..{end - 1} are not free in its {rec.property_count} slots', entry)
        props = rec.properties + (_usmap._Property(i, c.array_dim, c.name, _parse_label(c.type)),)
        structs[key] = _usmap.StructRecord(rec.name, rec.super, rec.property_count, props)
        return replace(c, struct=rec.name)
    if entry is None:
        raise _refuse(u, k, c, f'it has no property at own index {i}')
    current = type_label(entry.type)
    if c.kind == 'retype':
        if current == c.type:
            return None
        if c.before is not None and current != c.before:
            raise _refuse(u, k, c, f'own index {i} is {_one_line(current)}, not {c.before}', entry)
        new = _usmap._Property(entry.index, entry.array_dim, entry.name, _parse_label(c.type))
        before = current if _parsable(current) else None
    else:
        if c.type is not None and current != c.type:
            raise _refuse(u, k, c, f'own index {i} is {_one_line(current)}, not {c.type}', entry)
        if entry.name == c.name:
            return None
        if c.before is not None and entry.name != c.before:
            raise _refuse(u, k, c, f"the name at own index {i} differs from the change's before", entry)
        new = _usmap._Property(entry.index, entry.array_dim, c.name, entry.type)
        before = entry.name or None
    structs[key] = _usmap.StructRecord(rec.name, rec.super, rec.property_count, tuple(new if p is entry else p for p in rec.properties))
    return replace(c, struct=rec.name, before=before)


# --- requirements, results and reports ---------------------------------------------------------------------------

_STATUSES = ('ok', 'resolved', 'missing', 'type mismatch', 'index mismatch', 'ambiguous')
_VERDICTS = ('usable', 'usable after apply', 'not usable')
_REPORT_FORMAT = 'nylib.ue.assets.MappingReport'
_PREFIX_MIN = 6  # shortest prefix unique_prefix_fallback matches on


@dataclass(frozen=True, slots=True)
class Requirement:
    """One thing a family reads: a record, and maybe a property by name, chain index and type label."""
    struct: str
    name: str | None = None
    index: int | None = None
    type: str | None = None

    def __post_init__(self):
        _text(self.struct, 'struct')
        if self.name is not None:
            _text(self.name, 'name')
        if self.index is not None:
            if (v := _int(self.index, 'index')) < 0:
                raise ValueError('index is out of range')
            if type(self.index) is not int:
                object.__setattr__(self, 'index', v)
        if self.type is not None:
            _parse_label(self.type)

    def to_python(self) -> dict:
        return {'struct': self.struct, 'name': self.name, 'index': self.index, 'type': self.type}

    @classmethod
    def from_python(cls, data: dict) -> 'Requirement':
        return _requirement_from(data, '')


def _requirement_from(data, path: str) -> Requirement:
    d = _data(data, path, ('struct', 'name', 'index', 'type'))
    label = _val(d, path, 'type', 'str', True)
    if label is not None:
        try:
            _parse_label(label)
        except ValueError:
            raise ValueError(f'{_join(path, "type")}: not a type label') from None
    try:
        return Requirement(_val(d, path, 'struct', 'str'), _val(d, path, 'name', 'str', True), _val(d, path, 'index', 'int', True), label)
    except (TypeError, ValueError) as e:
        raise ValueError(f'{path or "data"}: {e}') from None


@dataclass(frozen=True, slots=True)
class RequirementResult:
    family: str
    requirement: Requirement
    status: str
    found: PropertyInfo | None
    change: MappingChange | None
    by: str | None
    detail: str | None

    def to_python(self) -> dict:
        return {'family': self.family, 'requirement': self.requirement.to_python(), 'status': self.status,
                'found': None if self.found is None else self.found.to_python(),
                'change': None if self.change is None else self.change.to_python(), 'by': self.by, 'detail': self.detail}

    @classmethod
    def from_python(cls, data: dict) -> 'RequirementResult':
        return _result_from(data, '', None)


def _result_from(data, path: str, family) -> RequirementResult:
    d = _data(data, path, ('family', 'requirement', 'status', 'found', 'change', 'by', 'detail'))
    name = _val(d, path, 'family', 'str')
    if family is not None and name != family:
        raise ValueError(f'{_join(path, "family")}: differs from the family name')
    status = _val(d, path, 'status', 'str')
    if status not in _STATUSES:
        raise ValueError(f'{_join(path, "status")}: not a status')
    found = None if d['found'] is None else _property_from(d['found'], _join(path, 'found'))
    change = None if d['change'] is None else _change_from(d['change'], _join(path, 'change'))
    return RequirementResult(name, _requirement_from(d['requirement'], _join(path, 'requirement')), status, found, change,
                             _val(d, path, 'by', 'str', True), _val(d, path, 'detail', 'str', True))


@dataclass(frozen=True, slots=True)
class FamilyResult:
    name: str
    verdict: str
    items: tuple[RequirementResult, ...]

    @property
    def usable(self) -> bool:
        return self.verdict == 'usable'

    def to_python(self) -> dict:
        return {'name': self.name, 'verdict': self.verdict, 'items': [r.to_python() for r in self.items]}

    @classmethod
    def from_python(cls, data: dict) -> 'FamilyResult':
        return _family_from(data, '')


def _family_from(data, path: str) -> FamilyResult:
    d = _data(data, path, ('name', 'verdict', 'items'))
    name = _val(d, path, 'name', 'str')
    verdict = _val(d, path, 'verdict', 'str')
    if verdict not in _VERDICTS:
        raise ValueError(f'{_join(path, "verdict")}: not a verdict')
    at = _join(path, 'items')
    return FamilyResult(name, verdict, tuple(_result_from(item, _join(at, n), name) for n, item in enumerate(_val(d, path, 'items', 'list'))))


_REPORT_KEYS = ('format', 'format_version', 'file', 'sha256', 'digest', 'version', 'structs', 'enums', 'meta', 'build', 'paired',
                'families', 'covered', 'counts', 'proposed', 'changes', 'custom_serialization', 'summary')


@dataclass(frozen=True, slots=True)
class MappingReport:
    file: str
    sha256: str
    digest: str
    version: int
    structs: int
    enums: int
    meta: DumpInfo | None
    build: int | None
    families: tuple[FamilyResult, ...]
    proposed: tuple[MappingChange, ...]
    changes: tuple[MappingChange, ...]
    custom_serialization: tuple[str, ...]

    @property
    def paired(self) -> bool | None:
        if self.meta is None or self.meta.pe_timestamp is None or self.build is None:
            return None
        return self.meta.pe_timestamp == self.build

    @property
    def covered(self) -> tuple[str, ...]:
        return tuple(f.name for f in self.families if f.usable)

    @property
    def items(self) -> tuple[RequirementResult, ...]:
        return tuple(r for f in self.families for r in f.items)

    @property
    def counts(self) -> tuple[tuple[str, int], ...]:
        tally = dict.fromkeys(_STATUSES, 0)
        for f in self.families:
            for r in f.items:
                tally[r.status] += 1
        return tuple(tally.items())

    def family(self, name: str) -> FamilyResult:
        if not isinstance(name, str):
            raise TypeError(f'name must be a str, got {type(name).__name__}')
        for f in self.families:
            if f.name == name:
                return f
        raise KeyError('no family with that name')

    def __str__(self) -> str:
        nf, n, p, c = len(self.families), sum(c for _s, c in self.counts), len(self.proposed), len(self.changes)
        text = (f'{_ascii_form(self.file)} (sha256 {self.sha256[:8]}..., v{self.version}): {len(self.covered)} of {nf} '
                f'{"family" if nf == 1 else "families"} usable; {n} {_plural(n, "requirement")}: '
                f'{", ".join(f"{k} {s}" for s, k in self.counts if k)}')
        if p:
            text += f'; {p} proposed {_plural(p, "rename")}'
        text += f'; {c} {_plural(c, "change")}' if c else '; no changes'
        if self.meta is None:
            return text + '; no dump meta.json'
        text += '; dump meta.json'
        if self.meta.created is not None:
            text += ' ' + _ascii_form(self.meta.created[:10])
        if self.meta.quality is not None:
            text += ' ' + _ascii_form(self.meta.quality)
        if (paired := self.paired) is not None:
            text += f', build {self.build:#010x} {"paired" if paired else "not paired"}'
        return text

    def __repr__(self) -> str:
        return f'<MappingReport {self}>'

    def to_python(self) -> dict:
        return {'format': _REPORT_FORMAT, 'format_version': 1, 'file': self.file, 'sha256': self.sha256, 'digest': self.digest,
                'version': self.version, 'structs': self.structs, 'enums': self.enums,
                'meta': None if self.meta is None else self.meta.to_python(), 'build': self.build, 'paired': self.paired,
                'families': [f.to_python() for f in self.families], 'covered': list(self.covered), 'counts': dict(self.counts),
                'proposed': [c.to_python() for c in self.proposed], 'changes': [c.to_python() for c in self.changes],
                'custom_serialization': list(self.custom_serialization), 'summary': str(self)}

    @classmethod
    def from_python(cls, data: dict) -> 'MappingReport':
        return _report_from(data)


def _report_from(data) -> MappingReport:
    if not isinstance(data, dict):
        raise TypeError(f'data must be a dict, got {type(data).__name__}')
    if 'format' not in data:
        raise ValueError('format: missing key')
    if data['format'] != _REPORT_FORMAT or not isinstance(data['format'], str):
        raise ValueError('format: not a MappingReport archive')
    if 'format_version' not in data:
        raise ValueError('format_version: missing key')
    if not _is_int(v := data['format_version']):
        raise ValueError('format_version: expected int')
    if v != 1:
        raise ValueError(f'format_version {v} is not supported by this nylib version')
    d = _data(data, '', _REPORT_KEYS)
    build = _val(d, '', 'build', 'int', True)
    if build is not None and not 0 <= build <= 0xFFFFFFFF:
        raise ValueError('build: out of range')
    custom = _val(d, '', 'custom_serialization', 'list')
    for n, item in enumerate(custom):
        if not isinstance(item, str):
            raise ValueError(f'custom_serialization[{n}]: expected str')
    report = MappingReport(
        _val(d, '', 'file', 'str'), _val(d, '', 'sha256', 'str'), _val(d, '', 'digest', 'str'), _val(d, '', 'version', 'int'),
        _val(d, '', 'structs', 'int'), _val(d, '', 'enums', 'int'), None if d['meta'] is None else _dump_from(d['meta'], 'meta'), build,
        tuple(_family_from(f, f'families[{n}]') for n, f in enumerate(_val(d, '', 'families', 'list'))),
        tuple(_change_from(c, f'proposed[{n}]') for n, c in enumerate(_val(d, '', 'proposed', 'list'))),
        tuple(_change_from(c, f'changes[{n}]') for n, c in enumerate(_val(d, '', 'changes', 'list'))), tuple(custom))
    if _val(d, '', 'paired', 'bool', True) is not report.paired:
        raise ValueError('paired: differs from meta and build')
    covered = _val(d, '', 'covered', 'list')
    if not all(isinstance(c, str) for c in covered) or tuple(covered) != report.covered:
        raise ValueError('covered: differs from the families')
    counts = _val(d, '', 'counts', 'dict')
    if list(counts) != list(_STATUSES) or not all(_is_int(c) for c in counts.values()) or counts != dict(report.counts):
        raise ValueError('counts: differs from the families')
    _val(d, '', 'summary', 'str')
    return report


# --- the stock fallbacks -----------------------------------------------------------------------------------------

def _check_chain(requirement, chain) -> None:
    if not isinstance(requirement, Requirement):
        raise TypeError(f'requirement must be a Requirement, got {type(requirement).__name__}')
    if not isinstance(chain, tuple) or not all(isinstance(s, PropertyInfo) for s in chain):
        raise TypeError('chain must be a tuple of PropertyInfo')


def index_and_type_fallback(requirement: Requirement, chain: tuple[PropertyInfo, ...]) -> PropertyInfo | None:
    """The slot of `chain` at the requirement's index when its type is the required one; names are ignored."""
    _check_chain(requirement, chain)
    if requirement.index is None or requirement.type is None:
        return None
    s = next((s for s in chain if s.index == requirement.index), None)
    return s if s is not None and s.type == requirement.type else None


def unique_prefix_fallback(requirement: Requirement, chain: tuple[PropertyInfo, ...]) -> PropertyInfo | tuple[PropertyInfo, ...] | None:
    """The `_aaa` slots of `chain` whose name extends the requirement's name or is a prefix of it, the prefix at least 6 characters."""
    _check_chain(requirement, chain)
    n = requirement.name
    if n is None or not n.startswith('_aaa') or len(n) < _PREFIX_MIN:
        return None
    hits = []
    for s in chain:
        if s.element != 0 or not s.name.startswith('_aaa') or (requirement.type is not None and s.type != requirement.type):
            continue
        t = s.name.split('\0', 1)[0]
        if t.startswith(n) or (n.startswith(t) and len(t) >= _PREFIX_MIN):
            hits.append(s)
    return None if not hits else hits[0] if len(hits) == 1 else tuple(hits)


# --- check() -----------------------------------------------------------------------------------------------------

class _Chain:
    """One struct's resolved chain: its slots, and lookups by chain index and by name (element 0)."""
    __slots__ = ('slots', 'by_index', 'names', 'records')

    def __init__(self, records, slots):
        self.slots = slots
        self.by_index = {s.index: s for s in slots}
        self.names = {}
        for s in slots:
            if s.element == 0:
                self.names.setdefault(s.name, []).append(s)
        self.records = frozenset(_lower(r.name) for r in records)


class _Chains:
    """A per-call cache of a mapping's chains: struct -> (_Chain, None), or (None, the `missing` detail)."""

    def __init__(self, mappings):
        self._mappings = mappings
        self._cache = {}

    def get(self, struct: str) -> tuple:
        if (hit := self._cache.get(struct)) is None:
            records, why = _resolve_chain(self._mappings, struct)
            if records is None:
                text = f'no record for {_one_line(why[1])}' if why[0] == 'no record' else f'the super chain of {_one_line(struct)} cycles'
                hit = (None, text)
            else:
                hit = (_Chain(records, _chain_slots(records)), None)
            self._cache[struct] = hit
        return hit


def _evaluate(chains: _Chains, req: Requirement, ask) -> tuple:
    """(status or 'pass', found, detail, via, asked) of `req` on one mapping; `ask(req, chain)` is the fallback's validated answer tuple."""
    chain, why = chains.get(req.struct)
    if chain is None:
        return 'missing', None, why, None, False
    name, index, label = req.name, req.index, req.type
    if name is None:
        if index is None:
            if label is None:
                return 'pass', None, None, 'struct', False
            hits = [s for s in chain.slots if s.element == 0 and s.type == label]
            if not hits:
                return 'missing', None, f'no property of type {label}', 'type', False
            if len(hits) > 1:
                return 'ambiguous', None, f'{len(hits)} properties of type {label}', 'type', False
            return 'pass', hits[0], None, 'type', False
        if (s := chain.by_index.get(index)) is None:
            return 'missing', None, f'no property at index {index}', 'index', False
        if label is not None and s.type != label:
            return 'type mismatch', s, f'index {index} is a {_one_line(s.type)}', 'index', False
        return 'pass', s, None, 'index', False
    named = chain.names.get(name, ())
    if len(named) > 1:
        return 'ambiguous', None, f'{len(named)} properties have the name', 'name', False
    cand, via, asked = (named[0] if named else None), 'name', False
    if cand is None and ask is not None:
        asked = True
        answer = ask(req, chain)
        if len(answer) > 1:
            return 'ambiguous', None, f'the fallback found {len(answer)} candidates', 'fallback', True
        if answer:
            cand, via = answer[0], 'fallback'
    if cand is None and index is not None and (cand := chain.by_index.get(index)) is not None:
        via = 'index'
    if cand is None:
        return 'missing', None, 'no property has the name' + ('; the fallback found none' if asked else ''), 'name', asked
    if index is not None and cand.index != index:
        s = chain.by_index.get(index)
        if s is not None and s.owner == cand.owner and s.own_index == cand.own_index:
            cand = s
    if label is not None and cand.type != label:
        a = _one_line(cand.type)
        detail = f'the fallback answered index {cand.index}, a {a}' if via == 'fallback' else f'index {cand.index} is a {a}'
        return 'type mismatch', cand, detail, via, asked
    if index is not None and cand.index != index:
        detail = f'the name is at index {cand.index}' if via == 'name' else f'the fallback answered index {cand.index}'
        return 'index mismatch', cand, detail, via, asked
    if via == 'index':
        gap = 'the fallback found none; ' if asked else ''
        return 'index mismatch', cand, f'no property has the name; {gap}index {cand.index} has another name', via, asked
    return 'pass', cand, None, via, asked


def _answer(answer, chain: _Chain, family: str, n: int) -> tuple:
    """A fallback's answer as a tuple of slots of `chain`; ValueError for an answer the protocol refuses."""
    if answer is None:
        return ()
    many = (answer,) if isinstance(answer, PropertyInfo) else answer
    where = f'family {family!r}, position {n}'
    if not isinstance(many, tuple):
        raise ValueError(f'{where}: the fallback answered a {type(answer).__name__}, not None, a PropertyInfo or a tuple')
    if not all(isinstance(a, PropertyInfo) for a in many):
        raise ValueError(f'{where}: the fallback answered an item that is not a PropertyInfo')
    if len(set(many)) != len(many):
        raise ValueError(f'{where}: the fallback answered the same slot twice')
    if any(chain.by_index.get(a.index) != a for a in many):
        raise ValueError(f'{where}: the fallback answered a slot that is not in the chain')
    if any(not a.owner for a in many):
        raise ValueError(f'{where}: the fallback answered a slot with an empty owner')
    return many


def _families_of(requirements) -> tuple:
    """((family, requirements), ...) from check()'s first argument."""
    def items(value, family):
        if isinstance(value, (str, bytes, Requirement)):
            raise TypeError(f'family {family!r}: requirements must be an iterable of Requirement, got {type(value).__name__}')
        try:
            out = tuple(value)
        except TypeError:
            raise TypeError(f'family {family!r}: requirements must be an iterable of Requirement, got {type(value).__name__}') from None
        for n, r in enumerate(out):
            if not isinstance(r, Requirement):
                raise TypeError(f'family {family!r}: position {n} must be a Requirement, got {type(r).__name__}')
        if not out:
            raise ValueError(f'family {family!r} has no requirement')
        return out

    if isinstance(requirements, Mapping):
        out = []
        for key, value in requirements.items():
            if not isinstance(key, str):
                raise TypeError(f'a family name must be a str, got {type(key).__name__}')
            out.append((key, items(value, key)))
        if not out:
            raise ValueError('no family to check')
        return tuple(out)
    return (('', items(requirements, '')),)


def _responsible(by_struct: dict, found: PropertyInfo | None, chain: _Chain) -> MappingChange:
    """The applied change a resolved result names: the last one on `found`'s property, else the last one on the chain's records."""
    if found is not None:
        for _pos, c in reversed(by_struct.get(_lower(found.owner), ())):
            if c.kind == 'record' or (c.kind != 'count' and c.own_index == found.own_index):
                return c
    return max((by_struct[r][-1] for r in chain.records if r in by_struct), key=lambda p: p[0])[1]


class _Check:
    """The state of one check() call: claims, the fallback's memo and the pass over the families."""

    def __init__(self, fallback):
        self.fallback = fallback
        self.memo = {}

    def ask(self, req, chain, family, n):
        if req not in self.memo:
            self.memo[req] = self.fallback(req, chain.slots)
        return _answer(self.memo[req], chain, family, n)

    def run(self, chains: _Chains, families: tuple, fallback_on: bool) -> list:
        """Per family, per requirement: (status or 'pass', found, detail, via, asked), claims applied."""
        claims = {}
        out = []
        for family, reqs in families:
            rows = []
            for n, req in enumerate(reqs):
                ask = (lambda r, c, family=family, n=n: self.ask(r, c, family, n)) if fallback_on else None
                row = _evaluate(chains, req, ask)
                if row[0] == 'pass' and req.name is not None:
                    row = self.claim(claims, chains.get(req.struct)[0], req, row)
                rows.append(row)
            out.append(rows)
        return out

    @staticmethod
    def claim(claims: dict, chain: _Chain, req: Requirement, row: tuple) -> tuple:
        status, found, detail, via, asked = row
        key = (_lower(found.owner), found.own_index)
        if (prior := claims.get(key)) is not None and prior != req.name:
            return 'ambiguous', None, f'index {found.index} is claimed for another name by an earlier requirement', via, asked
        if via == 'fallback':
            for s in chain.slots:
                k = (_lower(s.owner), s.own_index)
                if s.element == 0 and k != key and claims.get(k) == req.name:
                    return 'ambiguous', None, f'the name is claimed for index {s.index} by an earlier requirement', via, asked
        claims[key] = req.name
        return row


# --- load_usmap and Usmap ----------------------------------------------------------------------------------------

def _meta_error(usmap: str, meta: str, why: str, reason: str) -> InvalidMappingError:
    return InvalidMappingError(f'{meta} is not a nylib dump meta.json: {why}', usmap=usmap, reason=reason)


def _dig(doc, *keys):
    for k in keys:
        doc = doc.get(k) if isinstance(doc, dict) else None
    return doc


def _str_or_none(v) -> str | None:
    return v if isinstance(v, str) else None


def _read_meta(path: str, usmap: str) -> DumpInfo:
    name = os.path.basename(path)
    try:
        with open(path, 'rb') as f:
            if os.fstat(f.fileno()).st_size > _META_MAX or len(raw := f.read(_META_MAX + 1)) > _META_MAX:
                raise _meta_error(usmap, name, f'it is larger than {_META_MAX} bytes', 'meta.json too large')
    except FileNotFoundError as e:
        raise InvalidMappingError(f'meta file {name} not found', usmap=usmap, reason='meta.json not found', path=path,
                                  errno=e.errno, winerror=getattr(e, 'winerror', None)) from None
    except OSError as e:
        raise InvalidMappingError(f'meta file {name} cannot be read', usmap=usmap, reason='meta.json unreadable', path=path,
                                  errno=e.errno, winerror=getattr(e, 'winerror', None)) from None
    try:
        doc = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _meta_error(usmap, name, 'it is not UTF-8 JSON', 'meta.json not JSON') from None
    schema = _dig(doc, 'schema')
    if not (isinstance(schema, dict) and schema.get('name') == _META_SCHEMA and isinstance(schema.get('version'), str)):
        raise _meta_error(usmap, name, f'its schema is not {_META_SCHEMA}', 'meta.json schema')
    stamp = _dig(doc, 'target', 'module', 'pe_timestamp')
    if isinstance(stamp, str):
        try:
            stamp = int(stamp, 16)
        except ValueError:
            stamp = None
        if stamp is not None and not 0 <= stamp <= 0xFFFFFFFF:
            stamp = None
    else:
        stamp = None
    reasons = _dig(doc, 'quality', 'reasons')
    if not (isinstance(reasons, list) and all(isinstance(r, str) for r in reasons)):
        reasons = []
    return DumpInfo(_str_or_none(_dig(doc, 'created')), _str_or_none(_dig(doc, 'target', 'exe')), stamp,
                    _str_or_none(_dig(doc, 'quality', 'verdict')), tuple(reasons))


def load_usmap(path: str | os.PathLike, *, meta: str | os.PathLike | None = None, custom_serialization=()) -> 'Usmap':
    """Parse a `.usmap` once into an immutable `Usmap`; `meta` names a dump's meta.json, `custom_serialization` the caller's classes."""
    usmap_path = _check_path(path, 'path')
    meta_path = None if meta is None else _check_path(meta, 'meta')
    if isinstance(custom_serialization, (str, bytes, bytearray)):
        raise TypeError(f'custom_serialization must be an iterable of str, got {type(custom_serialization).__name__}')
    try:
        custom = tuple(custom_serialization)
    except TypeError:
        raise TypeError(f'custom_serialization must be an iterable of str, got {type(custom_serialization).__name__}') from None
    for item in custom:
        if not isinstance(item, str):
            raise TypeError(f'custom_serialization items must be str, got {type(item).__name__}')
        if not item:
            raise ValueError('custom_serialization items must not be empty')
    mappings, digest = _usmap.read(usmap_path)
    info = None if meta_path is None else _read_meta(meta_path, mappings._usmap)
    sha256 = digest.hex()
    return Usmap._make(mappings, mappings, sha256, info, custom, (), sha256)


class Usmap:
    """An immutable, parsed `.usmap`; made by `load_usmap()`."""
    __slots__ = ('file', 'sha256', 'digest', 'version', 'structs', 'enums', 'meta', 'custom_serialization', 'changes',
                 '_file_map', '_eff')

    def __init__(self, *_args, **_kwargs):
        raise TypeError('Usmap cannot be constructed directly: call load_usmap()')

    @classmethod
    def _make(cls, file_map, eff, sha256: str, meta, custom: tuple, changes: tuple, digest: str) -> 'Usmap':
        """A Usmap over the file's `file_map` and the effective mappings `eff`."""
        self = object.__new__(cls)
        for key, v in (('file', file_map._usmap), ('sha256', sha256), ('digest', digest), ('version', file_map.version),
                       ('structs', len(eff._structs)), ('enums', len(eff._enums)), ('meta', meta),
                       ('custom_serialization', custom), ('changes', changes), ('_file_map', file_map), ('_eff', eff)):
            object.__setattr__(self, key, v)
        return self

    def __setattr__(self, name, value):
        raise AttributeError('Usmap is read-only')

    def __delattr__(self, name):
        raise AttributeError('Usmap is read-only')

    def __reduce_ex__(self, protocol):
        raise TypeError('Usmap cannot be pickled: send usmap.changes and call load_usmap in the other process')

    def __getstate__(self):
        raise TypeError('Usmap cannot be pickled: send usmap.changes and call load_usmap in the other process')

    def __repr__(self) -> str:
        n = len(self.changes)
        return (f'<Usmap {_ascii_form(self.file)} (sha256 {self.sha256[:8]}..., v{self.version}): {self.structs} structs, '
                f'{self.enums} enums, {n} {_plural(n, "change")}>')

    def record(self, name: str) -> RecordInfo | None:
        """The effective record named `name` (ASCII-case-insensitive), or None."""
        if not isinstance(name, str):
            raise TypeError(f'name must be a str, got {type(name).__name__}')
        return None if (rec := self._eff.record(name)) is None else _record_info(rec)

    def records(self):
        """Every effective record: the file's order of first occurrence, then injected records."""
        for rec in self._eff._structs.values():
            yield _record_info(rec)

    def properties(self, struct: str) -> tuple[PropertyInfo, ...] | None:
        """The slots of `struct`'s whole super chain in chain-index order; None when a record is missing or the chain cycles."""
        if not isinstance(struct, str):
            raise TypeError(f'struct must be a str, got {type(struct).__name__}')
        chain, _why = _resolve_chain(self._eff, struct)
        return None if chain is None else _chain_slots(chain)

    def with_changes(self, changes) -> 'Usmap':
        """A new `Usmap` with `changes` applied in order; one already in place is skipped, one that does not fit raises InvalidMappingError."""
        if isinstance(changes, (str, bytes, bytearray, dict, MappingChange)):
            raise TypeError(f'changes must be an iterable of MappingChange, got {type(changes).__name__}')
        try:
            items = tuple(changes)
        except TypeError:
            raise TypeError(f'changes must be an iterable of MappingChange, got {type(changes).__name__}') from None
        for k, c in enumerate(items):
            if not isinstance(c, MappingChange):
                raise TypeError(f'changes[{k}] must be a MappingChange, got {type(c).__name__}')
        structs = dict(self._eff._structs)
        applied = [done for k, c in enumerate(items) if (done := _apply_change(self, structs, c, k)) is not None]
        all_changes = self.changes + tuple(applied)
        eff = _usmap.Mappings(structs, self._eff._enums, self._eff._usmap, version=self._eff.version)
        return Usmap._make(self._file_map, eff, self.sha256, self.meta, self.custom_serialization, all_changes,
                           _change_digest(self.sha256, all_changes))

    def declared_custom(self, target: 'ExportInfo | str') -> str | None:
        """The first `custom_serialization` entry that names `target`'s class or one of its supers, as given; else None."""
        if isinstance(target, ExportInfo):
            name = target.class_name
        elif isinstance(target, str):
            name = target
        else:
            raise TypeError(f'target must be an ExportInfo or a str, got {type(target).__name__}')
        by_name = {}
        for entry in self.custom_serialization:
            by_name.setdefault(_lower(entry), entry)
        seen = set()
        while name is not None and (key := _lower(name)) not in seen:
            seen.add(key)
            if (entry := by_name.get(key)) is not None:
                return entry
            name = None if (rec := self._eff.record(name)) is None else rec.super
        return None

    def check(self, requirements, *, fallback=None, by: str | None = None, build: int | None = None) -> MappingReport:
        """Check requirement families against the effective mapping; a `fallback` only proposes renames, `with_changes()` applies them."""
        families = _families_of(requirements)
        if fallback is not None and not callable(fallback):
            raise TypeError(f'fallback must be callable, got {type(fallback).__name__}')
        if by is not None and not isinstance(by, str):
            raise TypeError(f'by must be a str, got {type(by).__name__}')
        if fallback is None and by is not None:
            raise ValueError('by needs a fallback')
        if fallback is not None:
            if by is None:
                raise TypeError('by must be a str naming the fallback, got NoneType')
            if not by or by == 'patch' or _CONTROL_RE.search(by):
                raise ValueError("by must be a non-empty label without control characters, and not 'patch'")
        if build is not None:
            build = _ranged(build, 'build', 0, 0xFFFFFFFF)
        state = _Check(fallback)
        chains = _Chains(self._eff)
        base = _Chains(self._file_map) if self.changes else chains
        rows = state.run(chains, families, fallback is not None)
        by_struct = None
        proposed = []
        results = []
        usable = []
        for (family, reqs), fam_rows in zip(families, rows):
            items = []
            clean = True
            for req, (status, found, detail, via, asked) in zip(reqs, fam_rows):
                change = None
                label = by if asked else None
                if status == 'pass' and via == 'fallback':
                    change = MappingChange('rename', found.owner, found.own_index, req.name, found.type if _parsable(found.type) else None,
                                           before=found.name or None, by=by)
                    if change not in proposed:
                        proposed.append(change)
                    status, detail = 'resolved', f'rename proposed by {by}'
                elif status == 'pass':
                    if not self.changes or ((b := _evaluate(base, req, None))[0] == 'pass' and b[1] == found):
                        status = 'ok'
                    else:
                        if by_struct is None:
                            by_struct = {}
                            for pos, c in enumerate(self.changes):
                                by_struct.setdefault(_lower(c.struct), []).append((pos, c))
                        change = _responsible(by_struct, found, chains.get(req.struct)[0])
                        status, label, detail = 'resolved', change.by, f'{change.kind} by {change.by}'
                items.append(RequirementResult(family, req, status, found, change, label, detail))
                clean = clean and (status == 'ok' or (status == 'resolved' and via != 'fallback'))
            results.append(items)
            usable.append(clean)
        after = None
        verdicts = []
        for n, items in enumerate(results):
            if usable[n]:
                verdicts.append('usable')
            elif not all(r.status in ('ok', 'resolved') for r in items):
                verdicts.append('not usable')
            else:
                if after is None:
                    after = _Check(None).run(_Chains(self.with_changes(proposed)._eff), families, False)
                verdicts.append('usable after apply' if all(row[0] == 'pass' for row in after[n]) else 'not usable')
        return MappingReport(self.file, self.sha256, self.digest, self.version, self.structs, self.enums, self.meta, build,
                             tuple(FamilyResult(f, v, tuple(items)) for (f, _r), v, items in zip(families, verdicts, results)),
                             tuple(proposed), self.changes, self.custom_serialization)
