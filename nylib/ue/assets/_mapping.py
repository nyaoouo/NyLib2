"""The `.usmap` coordination interface: `load_usmap()`, the immutable `Usmap`, schema views, type labels and recorded changes."""
import hashlib
import json
import operator
import os
import re

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
