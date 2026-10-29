"""The `.usmap` coordination interface: `load_usmap()`, the immutable `Usmap`, schema views and type labels."""
import json
import operator
import os
import re

from dataclasses import dataclass

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
