"""nylib.pdb content model: dataclasses, JSON v1 (de)serialization, validation, normalization.

Pure Python; never imports the compiled extension.
"""
import dataclasses
import json
import os
import pathlib
import re
import types
import typing

from . import _codeview
from .pe_info import SectionHeader

FORMAT = 'nylib.pdb.model'
VERSION = 1

MACHINES = {'x64': 0x8664, 'x86': 0x14C}
CALLING_CONVENTIONS = {'cdecl': 0x00, 'fastcall': 0x04, 'stdcall': 0x07, 'thiscall': 0x0B, 'vectorcall': 0x18}
ACCESS = {'private': 1, 'protected': 2, 'public': 3}
POINTER_MODES = {'pointer': 0, 'lvalue_ref': 1, 'rvalue_ref': 4}

# name -> (simple_kind, size); derived from _codeview's (ti, size, dia_bt, dia_size, enum_range) table.
BASE_TYPES = types.MappingProxyType(
    dict((name, (ti, size)) for name, (ti, size, *_rest) in _codeview.BASE_TYPES.items()))

enum_range = _codeview.enum_range  # re-export: (lo, hi) for an enum-capable base type name, else None

_MAX_NAME_BYTES = 0xF000
_MAX_DEPTH = 100

_ANON_EXACT = ('<unnamed-tag>', '__unnamed')
_ANON_SUFFIX = ('::<unnamed-tag>', '::__unnamed')


def is_anonymous_name(name: str) -> bool:
    """True iff name is the TPI-hash anonymous spelling, or ends with one qualified by scope."""
    return name in _ANON_EXACT or name.endswith(_ANON_SUFFIX)


class ModelError(ValueError):
    """Model content/parse error. ``path`` pinpoints the field, ``''`` for whole-model errors."""

    def __init__(self, path: str, message: str):
        self.path = path
        self.message = message
        super().__init__(f'{path}: {message}' if path else message)


def _check_bool(v, path):
    if type(v) is not bool:
        raise ModelError(path, f'expected boolean, got {v!r}')
    return v


def _check_str(v, path):
    if not isinstance(v, str):
        raise ModelError(path, f'expected string, got {v!r}')
    return v


def _check_int(v, path):
    if isinstance(v, bool) or not isinstance(v, int):
        raise ModelError(path, f'expected integer, got {v!r}')
    return v


def _check_list(v, path):
    if not isinstance(v, list):
        raise ModelError(path, f'expected a list, got {v!r}')
    return v


def _check_dict(v, path):
    if not isinstance(v, dict):
        raise ModelError(path, f'expected an object, got {v!r}')
    return v


def _check_list_of(lst, path, item_cls, cls_name=None):
    """``lst`` is a list and every item is an ``item_cls`` instance, else ``ModelError``."""
    _check_list(lst, path)
    name = cls_name or item_cls.__name__
    for i, item in enumerate(lst):
        if not isinstance(item, item_cls):
            raise ModelError(f'{path}[{i}]', f'expected {name}, got {item!r}')
    return lst


# TypeRef = str | Pointer | Array | Modifier | FunctionType | Udt | Enum (alias defined after the classes below)


@dataclasses.dataclass
class Pointer:
    to: 'TypeRef'
    mode: str = 'pointer'
    const: bool = False
    volatile: bool = False
    unaligned: bool = False
    size: 'int | None' = None


@dataclasses.dataclass
class Array:
    of: 'TypeRef'
    count: int


@dataclasses.dataclass
class Modifier:
    of: 'TypeRef'
    const: bool = False
    volatile: bool = False
    unaligned: bool = False


@dataclasses.dataclass
class FunctionType:
    returns: 'TypeRef' = 'void'
    args: 'list[TypeRef]' = dataclasses.field(default_factory=list)
    variadic: bool = False
    call: str = 'cdecl'


@dataclasses.dataclass
class Field:
    name: str
    type: 'TypeRef'
    offset: int
    bit_offset: 'int | None' = None
    bit_length: 'int | None' = None
    access: str = 'public'


@dataclasses.dataclass
class BaseClass:
    type: str
    offset: int = 0
    access: str = 'public'


@dataclasses.dataclass
class Udt:
    name: str = '<unnamed-tag>'
    size: int = 0
    kind: str = 'struct'
    fields: 'list[Field]' = dataclasses.field(default_factory=list)
    bases: 'list[BaseClass]' = dataclasses.field(default_factory=list)
    opaque: bool = False


@dataclasses.dataclass
class Enum:
    name: str = '<unnamed-tag>'
    underlying: str = 'int'
    values: 'dict[str, int]' = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class Typedef:
    name: str
    type: 'TypeRef'


@dataclasses.dataclass
class Function:
    name: str
    rva: int
    length: int
    type: 'TypeRef | None' = None
    static: bool = False


@dataclasses.dataclass
class Data:
    name: str
    rva: int
    type: 'TypeRef | None' = None
    static: bool = False


@dataclasses.dataclass
class Public:
    name: str
    rva: int
    function: 'bool | None' = None


@dataclasses.dataclass
class Image:
    machine: str = 'x64'
    guid: 'str | None' = None
    age: 'int | None' = None
    sections: 'list[SectionHeader]' = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class PdbModel:
    image: Image = dataclasses.field(default_factory=Image)
    types: 'list[Udt | Enum]' = dataclasses.field(default_factory=list)
    typedefs: 'list[Typedef]' = dataclasses.field(default_factory=list)
    functions: 'list[Function]' = dataclasses.field(default_factory=list)
    data: 'list[Data]' = dataclasses.field(default_factory=list)
    publics: 'list[Public]' = dataclasses.field(default_factory=list)

    # -- JSON v1 -----------------------------------------------------------

    def to_dict(self) -> dict:
        seen = set()
        if not isinstance(self.image, Image):
            raise ModelError('image', f'expected an Image, got {self.image!r}')
        _check_list_of(self.types, 'types', (Udt, Enum), 'Udt or Enum')
        _check_list_of(self.typedefs, 'typedefs', Typedef)
        _check_list_of(self.functions, 'functions', Function)
        _check_list_of(self.data, 'data', Data)
        _check_list_of(self.publics, 'publics', Public)
        d = {'format': FORMAT, 'version': VERSION}
        img = _dump_image(self.image)
        if img:
            d['image'] = img
        if self.types:
            d['types'] = [_dump_udt_or_enum(t, f'types[{i}]', 0, seen) for i, t in enumerate(self.types)]
        if self.typedefs:
            d['typedefs'] = [_dump_typedef(t, f'typedefs[{i}]', seen) for i, t in enumerate(self.typedefs)]
        if self.functions:
            d['functions'] = [_dump_function(f, f'functions[{i}]', seen) for i, f in enumerate(self.functions)]
        if self.data:
            d['data'] = [_dump_data(x, f'data[{i}]', seen) for i, x in enumerate(self.data)]
        if self.publics:
            d['publics'] = [_dump_public(p, f'publics[{i}]') for i, p in enumerate(self.publics)]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> 'PdbModel':
        _obj(d, '', {'format', 'version', 'image', 'types', 'typedefs', 'functions', 'data', 'publics'},
             {'format', 'version'})
        if d['format'] != FORMAT:
            raise ModelError('format', f'expected {FORMAT!r}, got {d["format"]!r}')
        if type(d['version']) is not int or d['version'] != VERSION:
            raise ModelError('version', f'expected version {VERSION}, got {d["version"]!r}')
        raw_types, raw_typedefs = d.get('types', []), d.get('typedefs', [])
        raw_functions, raw_data, raw_publics = d.get('functions', []), d.get('data', []), d.get('publics', [])
        for name, raw in (('types', raw_types), ('typedefs', raw_typedefs), ('functions', raw_functions),
                          ('data', raw_data), ('publics', raw_publics)):
            _check_list(raw, name)
        types = [_load_type_item(t, f'types[{i}]') for i, t in enumerate(raw_types)]
        typedefs = [_load_typedef(t, f'typedefs[{i}]') for i, t in enumerate(raw_typedefs)]
        functions = [_load_function(f, f'functions[{i}]') for i, f in enumerate(raw_functions)]
        data = [_load_data(x, f'data[{i}]') for i, x in enumerate(raw_data)]
        publics = [_load_public(p, f'publics[{i}]') for i, p in enumerate(raw_publics)]
        return cls(image=_load_image(d.get('image', {}), 'image'), types=types, typedefs=typedefs,
                   functions=functions, data=data, publics=publics)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=1, ensure_ascii=False) + '\n'

    @classmethod
    def from_json(cls, text: str) -> 'PdbModel':
        try:
            data = json.loads(text, object_pairs_hook=_dup_checked_object)
        except RecursionError:
            raise ModelError('', 'JSON nesting too deep') from None
        return cls.from_dict(data)

    def save(self, path) -> None:
        try:
            data = self.to_json().encode('utf-8')
        except UnicodeEncodeError as e:
            raise ModelError('', f'model text is not valid UTF-8: {e}') from None
        path = pathlib.Path(path)
        tmp = path.with_name(path.name + '.tmp')
        tmp.write_bytes(data)
        os.replace(tmp, path)

    @classmethod
    def load(cls, path) -> 'PdbModel':
        return cls.from_json(pathlib.Path(path).read_text(encoding='utf-8'))

    # -- validation ----------------------------------------------------------

    def validate(self, sections: 'typing.Sequence[SectionHeader] | None' = None) -> None:
        _validate_model(self, sections)

    # -- normalization ---------------------------------------------------------

    def normalized(self) -> 'PdbModel':
        return _normalize_model(self)


TypeRef = typing.Union[str, Pointer, Array, Modifier, FunctionType, Udt, Enum]

__all__ = [
    'FORMAT', 'VERSION', 'MACHINES', 'CALLING_CONVENTIONS', 'ACCESS', 'POINTER_MODES', 'BASE_TYPES', 'enum_range',
    'is_anonymous_name', 'ModelError', 'TypeRef', 'Pointer', 'Array', 'Modifier', 'FunctionType', 'Field',
    'BaseClass', 'Udt', 'Enum', 'Typedef', 'Function', 'Data', 'Public', 'Image', 'PdbModel', 'SectionHeader',
]


# ===== JSON dump helpers =====================================================================

_HEX_SAVE_KEYS = frozenset(
    {'rva', 'length', 'virtual_address', 'virtual_size', 'raw_size', 'raw_pointer', 'characteristics'})


def _dump_int(key: str, v: int, path: str):
    _check_int(v, path)
    return f'{v:#x}' if key in _HEX_SAVE_KEYS else v


def _enter(obj, path, depth, seen):
    if depth > _MAX_DEPTH:
        raise ModelError(path, f'TypeRef nesting exceeds {_MAX_DEPTH} levels')
    if id(obj) in seen:
        raise ModelError(path, 'inline type contains itself')
    seen.add(id(obj))


def _dump_typeref(tr, path, depth, seen):
    if depth > _MAX_DEPTH:
        raise ModelError(path, f'TypeRef nesting exceeds {_MAX_DEPTH} levels')
    if isinstance(tr, str):
        return tr
    if isinstance(tr, Pointer):
        _enter(tr, path, depth, seen)
        _check_str(tr.mode, path + '.mode')
        _check_bool(tr.const, path + '.const')
        _check_bool(tr.volatile, path + '.volatile')
        _check_bool(tr.unaligned, path + '.unaligned')
        d = {'kind': 'pointer', 'to': _dump_typeref(tr.to, path + '.to', depth + 1, seen)}
        if tr.mode != 'pointer':
            d['mode'] = tr.mode
        if tr.const:
            d['const'] = True
        if tr.volatile:
            d['volatile'] = True
        if tr.unaligned:
            d['unaligned'] = True
        if tr.size is not None:
            d['size'] = _check_int(tr.size, path + '.size')
        seen.discard(id(tr))
        return d
    if isinstance(tr, Array):
        _enter(tr, path, depth, seen)
        _check_int(tr.count, path + '.count')
        d = {'kind': 'array', 'of': _dump_typeref(tr.of, path + '.of', depth + 1, seen), 'count': tr.count}
        seen.discard(id(tr))
        return d
    if isinstance(tr, Modifier):
        _enter(tr, path, depth, seen)
        _check_bool(tr.const, path + '.const')
        _check_bool(tr.volatile, path + '.volatile')
        _check_bool(tr.unaligned, path + '.unaligned')
        d = {'kind': 'modifier', 'of': _dump_typeref(tr.of, path + '.of', depth + 1, seen)}
        if tr.const:
            d['const'] = True
        if tr.volatile:
            d['volatile'] = True
        if tr.unaligned:
            d['unaligned'] = True
        seen.discard(id(tr))
        return d
    if isinstance(tr, FunctionType):
        _enter(tr, path, depth, seen)
        _check_bool(tr.variadic, path + '.variadic')
        _check_str(tr.call, path + '.call')
        _check_list(tr.args, path + '.args')
        d = {'kind': 'function'}
        if tr.returns != 'void':
            d['returns'] = _dump_typeref(tr.returns, path + '.returns', depth + 1, seen)
        if tr.args:
            d['args'] = [_dump_typeref(a, f'{path}.args[{i}]', depth + 1, seen) for i, a in enumerate(tr.args)]
        if tr.variadic:
            d['variadic'] = True
        if tr.call != 'cdecl':
            d['call'] = tr.call
        seen.discard(id(tr))
        return d
    if isinstance(tr, (Udt, Enum)):
        return _dump_udt_or_enum(tr, path, depth, seen)
    raise ModelError(path, f'not a TypeRef: {tr!r}')


def _dump_udt_or_enum(obj, path, depth, seen):
    _enter(obj, path, depth, seen)
    _check_str(obj.name, path + '.name')
    if isinstance(obj, Enum):
        _check_str(obj.underlying, path + '.underlying')
        _check_dict(obj.values, path + '.values')
        for k, v in obj.values.items():
            _check_str(k, path + '.values')
            _check_int(v, f'{path}.values[{k!r}]')
        d = {'kind': 'enum'}
        if obj.name != '<unnamed-tag>':
            d['name'] = obj.name
        if obj.underlying != 'int':
            d['underlying'] = obj.underlying
        if obj.values:
            d['values'] = dict(obj.values)
        seen.discard(id(obj))
        return d
    _check_str(obj.kind, path + '.kind')
    if obj.kind not in _UDT_KINDS:
        raise ModelError(path + '.kind', f'invalid kind: {obj.kind!r}')
    _check_int(obj.size, path + '.size')
    _check_list_of(obj.fields, path + '.fields', Field)
    _check_list_of(obj.bases, path + '.bases', BaseClass)
    _check_bool(obj.opaque, path + '.opaque')
    d = {'kind': obj.kind}
    if obj.name != '<unnamed-tag>':
        d['name'] = obj.name
    if obj.size:
        d['size'] = obj.size
    if obj.fields:
        d['fields'] = [_dump_field(f, f'{path}.fields[{i}]', depth + 1, seen) for i, f in enumerate(obj.fields)]
    if obj.bases:
        d['bases'] = [_dump_base(b, f'{path}.bases[{i}]') for i, b in enumerate(obj.bases)]
    if obj.opaque:
        d['opaque'] = True
    seen.discard(id(obj))
    return d


def _dump_field(f, path, depth, seen):
    _check_str(f.name, path + '.name')
    _check_int(f.offset, path + '.offset')
    _check_str(f.access, path + '.access')
    d = {'name': f.name, 'type': _dump_typeref(f.type, path + '.type', depth, seen), 'offset': f.offset}
    if f.bit_offset is not None:
        d['bit_offset'] = _check_int(f.bit_offset, path + '.bit_offset')
    if f.bit_length is not None:
        d['bit_length'] = _check_int(f.bit_length, path + '.bit_length')
    if f.access != 'public':
        d['access'] = f.access
    return d


def _dump_base(b, path):
    _check_str(b.type, path + '.type')
    _check_int(b.offset, path + '.offset')
    _check_str(b.access, path + '.access')
    d = {'type': b.type}
    if b.offset:
        d['offset'] = b.offset
    if b.access != 'public':
        d['access'] = b.access
    return d


def _dump_section(s, path):
    _check_str(s.name, path + '.name')
    _check_int(s.raw_size, path + '.raw_size')
    _check_int(s.raw_pointer, path + '.raw_pointer')
    d = {'name': s.name, 'virtual_address': _dump_int('virtual_address', s.virtual_address, path + '.virtual_address'),
         'virtual_size': _dump_int('virtual_size', s.virtual_size, path + '.virtual_size'),
         'characteristics': _dump_int('characteristics', s.characteristics, path + '.characteristics')}
    if s.raw_size:
        d['raw_size'] = _dump_int('raw_size', s.raw_size, path + '.raw_size')
    if s.raw_pointer:
        d['raw_pointer'] = _dump_int('raw_pointer', s.raw_pointer, path + '.raw_pointer')
    return d


def _dump_image(img):
    _check_str(img.machine, 'image.machine')
    d = {}
    if img.machine != 'x64':
        d['machine'] = img.machine
    if img.guid is not None:
        d['guid'] = _check_str(img.guid, 'image.guid')
    if img.age is not None:
        d['age'] = _check_int(img.age, 'image.age')
    _check_list_of(img.sections, 'image.sections', SectionHeader)
    if img.sections:
        d['sections'] = [_dump_section(s, f'image.sections[{i}]') for i, s in enumerate(img.sections)]
    return d


def _dump_typedef(t, path, seen):
    _check_str(t.name, path + '.name')
    return {'name': t.name, 'type': _dump_typeref(t.type, path + '.type', 0, seen)}


def _dump_function(f, path, seen):
    _check_str(f.name, path + '.name')
    _check_bool(f.static, path + '.static')
    d = {'name': f.name, 'rva': _dump_int('rva', f.rva, path + '.rva'), 'length': _dump_int('length', f.length, path + '.length')}
    if f.type is not None:
        d['type'] = _dump_typeref(f.type, path + '.type', 0, seen)
    if f.static:
        d['static'] = True
    return d


def _dump_data(x, path, seen):
    _check_str(x.name, path + '.name')
    _check_bool(x.static, path + '.static')
    d = {'name': x.name, 'rva': _dump_int('rva', x.rva, path + '.rva')}
    if x.type is not None:
        d['type'] = _dump_typeref(x.type, path + '.type', 0, seen)
    if x.static:
        d['static'] = True
    return d


def _dump_public(p, path):
    _check_str(p.name, path + '.name')
    if p.function is not None:
        _check_bool(p.function, path + '.function')
    d = {'name': p.name, 'rva': _dump_int('rva', p.rva, path + '.rva')}
    if p.function is not None:
        d['function'] = p.function
    return d


# ===== JSON load helpers =====================================================================

_HEX_RE = re.compile(r'-?0x[0-9A-Fa-f]+$')


def _dup_checked_object(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ModelError('', f'duplicate key {k!r}')
        d[k] = v
    return d


def _obj(d, path, allowed, required=frozenset()):
    if not isinstance(d, dict):
        raise ModelError(path, f'expected object, got {d!r}')
    extra = d.keys() - allowed
    if extra:
        raise ModelError(path, f'unknown key(s): {sorted(extra)}')
    missing = required - d.keys()
    if missing:
        raise ModelError(path, f'missing key(s): {sorted(missing)}')
    return d


def _load_int(v, path):
    if isinstance(v, bool) or not isinstance(v, (int, str)):
        raise ModelError(path, f'expected integer, got {v!r}')
    if isinstance(v, int):
        return v
    if not _HEX_RE.fullmatch(v):
        raise ModelError(path, f'invalid hex integer string {v!r}')
    return int(v, 16)


def _load_bool(v, path):
    if not isinstance(v, bool):
        raise ModelError(path, f'expected boolean, got {v!r}')
    return v


def _load_str(v, path):
    if not isinstance(v, str):
        raise ModelError(path, f'expected string, got {v!r}')
    return v


_TYPEREF_SHAPES = {
    'pointer': ({'kind', 'to', 'mode', 'const', 'volatile', 'unaligned', 'size'}, {'kind', 'to'}),
    'array': ({'kind', 'of', 'count'}, {'kind', 'of', 'count'}),
    'modifier': ({'kind', 'of', 'const', 'volatile', 'unaligned'}, {'kind', 'of'}),
    'function': ({'kind', 'returns', 'args', 'variadic', 'call'}, {'kind'}),
}
_UDT_KINDS = ('struct', 'class', 'union')


def _load_typeref(v, path, depth=0):
    if depth > _MAX_DEPTH:
        raise ModelError(path, f'TypeRef nesting exceeds {_MAX_DEPTH} levels')
    if isinstance(v, str):
        return v
    if not isinstance(v, dict) or not isinstance(v.get('kind'), str):
        raise ModelError(path, f'expected a TypeRef object with a "kind" key, got {v!r}')
    kind = v['kind']
    if kind in _TYPEREF_SHAPES:
        allowed, required = _TYPEREF_SHAPES[kind]
        _obj(v, path, allowed, required)
        if kind == 'pointer':
            return Pointer(to=_load_typeref(v['to'], path + '.to', depth + 1),
                           mode=_load_str(v.get('mode', 'pointer'), path + '.mode'),
                           const=_load_bool(v.get('const', False), path + '.const'),
                           volatile=_load_bool(v.get('volatile', False), path + '.volatile'),
                           unaligned=_load_bool(v.get('unaligned', False), path + '.unaligned'),
                           size=None if 'size' not in v else _load_int(v['size'], path + '.size'))
        if kind == 'array':
            return Array(of=_load_typeref(v['of'], path + '.of', depth + 1),
                         count=_load_int(v['count'], path + '.count'))
        if kind == 'modifier':
            return Modifier(of=_load_typeref(v['of'], path + '.of', depth + 1),
                             const=_load_bool(v.get('const', False), path + '.const'),
                             volatile=_load_bool(v.get('volatile', False), path + '.volatile'),
                             unaligned=_load_bool(v.get('unaligned', False), path + '.unaligned'))
        args = v.get('args', [])
        _check_list(args, path + '.args')
        return FunctionType(returns=_load_typeref(v.get('returns', 'void'), path + '.returns', depth + 1),
                             args=[_load_typeref(a, f'{path}.args[{i}]', depth + 1) for i, a in enumerate(args)],
                             variadic=_load_bool(v.get('variadic', False), path + '.variadic'),
                             call=_load_str(v.get('call', 'cdecl'), path + '.call'))
    if kind in _UDT_KINDS or kind == 'enum':
        return _load_udt_or_enum(v, path, depth)
    raise ModelError(path, f'unknown kind {kind!r}')


def _load_udt_or_enum(v, path, depth=0):
    if depth > _MAX_DEPTH:
        raise ModelError(path, f'TypeRef nesting exceeds {_MAX_DEPTH} levels')
    kind = v.get('kind')
    if kind == 'enum':
        _obj(v, path, {'kind', 'name', 'underlying', 'values'}, {'kind'})
        values = v.get('values', {})
        _check_dict(values, path + '.values')
        return Enum(name=_load_str(v.get('name', '<unnamed-tag>'), path + '.name'),
                    underlying=_load_str(v.get('underlying', 'int'), path + '.underlying'),
                    values={_load_str(k, path + '.values'): _load_int(val, f'{path}.values[{k!r}]')
                            for k, val in values.items()})
    _obj(v, path, {'kind', 'name', 'size', 'fields', 'bases', 'opaque'}, {'kind'})
    fields, bases = v.get('fields', []), v.get('bases', [])
    _check_list(fields, path + '.fields')
    _check_list(bases, path + '.bases')
    return Udt(kind=kind,
               name=_load_str(v.get('name', '<unnamed-tag>'), path + '.name'),
               size=_load_int(v.get('size', 0), path + '.size'),
               fields=[_load_field(f, f'{path}.fields[{i}]', depth + 1) for i, f in enumerate(fields)],
               bases=[_load_base(b, f'{path}.bases[{i}]') for i, b in enumerate(bases)],
               opaque=_load_bool(v.get('opaque', False), path + '.opaque'))


def _load_type_item(v, path):
    if not isinstance(v, dict) or v.get('kind') not in ('struct', 'class', 'union', 'enum'):
        raise ModelError(path, f'expected a struct/class/union/enum object, got {v!r}')
    return _load_udt_or_enum(v, path)


def _load_field(v, path, depth=0):
    _obj(v, path, {'name', 'type', 'offset', 'bit_offset', 'bit_length', 'access'}, {'name', 'type', 'offset'})
    bo, bl = v.get('bit_offset'), v.get('bit_length')
    return Field(name=_load_str(v['name'], path + '.name'),
                 type=_load_typeref(v['type'], path + '.type', depth),
                 offset=_load_int(v['offset'], path + '.offset'),
                 bit_offset=None if bo is None else _load_int(bo, path + '.bit_offset'),
                 bit_length=None if bl is None else _load_int(bl, path + '.bit_length'),
                 access=_load_str(v.get('access', 'public'), path + '.access'))


def _load_base(v, path):
    _obj(v, path, {'type', 'offset', 'access'}, {'type'})
    return BaseClass(type=_load_str(v['type'], path + '.type'),
                      offset=_load_int(v.get('offset', 0), path + '.offset'),
                      access=_load_str(v.get('access', 'public'), path + '.access'))


def _load_typedef(v, path):
    _obj(v, path, {'name', 'type'}, {'name', 'type'})
    return Typedef(name=_load_str(v['name'], path + '.name'), type=_load_typeref(v['type'], path + '.type'))


def _load_function(v, path):
    _obj(v, path, {'name', 'rva', 'length', 'type', 'static'}, {'name', 'rva', 'length'})
    t = v.get('type')
    return Function(name=_load_str(v['name'], path + '.name'),
                     rva=_load_int(v['rva'], path + '.rva'),
                     length=_load_int(v['length'], path + '.length'),
                     type=None if t is None else _load_typeref(t, path + '.type'),
                     static=_load_bool(v.get('static', False), path + '.static'))


def _load_data(v, path):
    _obj(v, path, {'name', 'rva', 'type', 'static'}, {'name', 'rva'})
    t = v.get('type')
    return Data(name=_load_str(v['name'], path + '.name'),
                rva=_load_int(v['rva'], path + '.rva'),
                type=None if t is None else _load_typeref(t, path + '.type'),
                static=_load_bool(v.get('static', False), path + '.static'))


def _load_public(v, path):
    _obj(v, path, {'name', 'rva', 'function'}, {'name', 'rva'})
    f = v.get('function')
    return Public(name=_load_str(v['name'], path + '.name'),
                  rva=_load_int(v['rva'], path + '.rva'),
                  function=None if f is None else _load_bool(f, path + '.function'))


def _load_section(v, path):
    _obj(v, path, {'name', 'virtual_address', 'virtual_size', 'characteristics', 'raw_size', 'raw_pointer'},
         {'name', 'virtual_address', 'virtual_size', 'characteristics'})
    return SectionHeader(name=_load_str(v['name'], path + '.name'),
                          virtual_address=_load_int(v['virtual_address'], path + '.virtual_address'),
                          virtual_size=_load_int(v['virtual_size'], path + '.virtual_size'),
                          characteristics=_load_int(v['characteristics'], path + '.characteristics'),
                          raw_size=_load_int(v.get('raw_size', 0), path + '.raw_size'),
                          raw_pointer=_load_int(v.get('raw_pointer', 0), path + '.raw_pointer'))


def _load_image(v, path):
    _obj(v, path, {'machine', 'guid', 'age', 'sections'})
    g, a, sections = v.get('guid'), v.get('age'), v.get('sections', [])
    _check_list(sections, path + '.sections')
    return Image(machine=_load_str(v.get('machine', 'x64'), path + '.machine'),
                 guid=None if g is None else _load_str(g, path + '.guid'),
                 age=None if a is None else _load_int(a, path + '.age'),
                 sections=[_load_section(s, f'{path}.sections[{i}]') for i, s in enumerate(sections)])


# ===== validation =====================================================================

_GUID_RE = re.compile(r'[0-9A-Fa-f]{32}')


def _is_guid(s):
    if not isinstance(s, str):
        return False
    t = s
    if t.startswith('{') and t.endswith('}'):
        t = t[1:-1]
    return bool(_GUID_RE.fullmatch(t.replace('-', '')))


def _check_name(name, path, *, allow_empty=False, allow_anonymous=True, allow_base_type=True):
    if not isinstance(name, str):
        raise ModelError(path, f'expected string, got {name!r}')
    if '\0' in name:
        raise ModelError(path, 'name contains NUL')
    try:
        length = len(name.encode('utf-8'))
    except UnicodeEncodeError:
        raise ModelError(path, f'name is not valid UTF-8: {name!r}') from None
    if length > _MAX_NAME_BYTES:
        raise ModelError(path, f'name exceeds {_MAX_NAME_BYTES:#x} UTF-8 bytes')
    if not allow_empty and name == '':
        raise ModelError(path, 'name is empty')
    if not allow_anonymous and is_anonymous_name(name):
        raise ModelError(path, f'name is anonymous: {name!r}')
    if not allow_base_type and name in BASE_TYPES:
        raise ModelError(path, f'name collides with a base type: {name!r}')


class _Ctx:
    __slots__ = ('names', 'size_cache', 'resolve_cache')

    def __init__(self):
        self.names = {}  # name -> ('type', Udt|Enum) | ('typedef', Typedef)
        self.size_cache = {}  # name -> byte size, memoized across _sizeof calls
        self.resolve_cache = {}  # name -> resolved base-type name or Udt/Enum object, memoized across _resolve_ref calls


def _resolve_ref(ref, ctx, path):
    """Follow typedef names (never through pointers) to a base-type name, a Udt/Enum object, or an inline object."""
    if not isinstance(ref, str):
        return ref
    cache = ctx.resolve_cache
    chain = []  # typedef names visited this walk, in order (for caching once resolved)
    chain_set = set()
    cur = ref
    while isinstance(cur, str):
        if cur in BASE_TYPES:
            result = cur
            break
        if cur in cache:
            result = cache[cur]
            break
        kind = ctx.names.get(cur)
        if kind is None:
            raise ModelError(path, f'unknown type name: {cur!r}')
        if cur in chain_set:
            raise ModelError(path, f'typedef cycle: {cur!r}')
        chain.append(cur)
        chain_set.add(cur)
        if kind[0] == 'type':
            result = kind[1]
            break
        cur = kind[1].type
    else:
        result = cur
    for name in chain:
        cache[name] = result
    return result


def _strip_modifiers(ref, ctx, path):
    """Resolve through typedefs, then through one Modifier wrapper if the result is one."""
    resolved = _resolve_ref(ref, ctx, path)
    if isinstance(resolved, Modifier):
        resolved = _resolve_ref(resolved.of, ctx, path)
    return resolved


def _sizeof(ref, ctx, path):
    """Byte size of ``ref``; iterative and memoized by name (no Python recursion, no re-walking a chain)."""
    cache = ctx.size_cache
    chain = []  # ('name', name) | ('array', count) steps from ref to the terminal node, in that order
    local_seen = set()
    cur = ref
    while True:
        if isinstance(cur, str):
            if cur in BASE_TYPES:
                size = BASE_TYPES[cur][1]
                break
            if cur in cache:
                size = cache[cur]
                break
            if cur in local_seen:
                raise ModelError(path, f'typedef cycle: {cur!r}')
            local_seen.add(cur)
            kind = ctx.names.get(cur)
            if kind is None:
                raise ModelError(path, f'unknown type name: {cur!r}')
            chain.append(('name', cur))
            cur = kind[1] if kind[0] == 'type' else kind[1].type
            continue
        if isinstance(cur, Enum):
            _check_str(cur.underlying, path)
            size = BASE_TYPES.get(cur.underlying, (0, 0))[1]
            break
        if isinstance(cur, Udt):
            _check_int(cur.size, path)
            size = cur.size
            break
        if isinstance(cur, Pointer):
            if cur.size is not None:
                _check_int(cur.size, path)
            size = cur.size if cur.size is not None else 8
            break
        if isinstance(cur, Array):
            _check_int(cur.count, path)
            chain.append(('array', cur.count))
            cur = cur.of
            continue
        if isinstance(cur, Modifier):
            cur = cur.of
            continue
        size = 0  # FunctionType: callers exclude this case before calling _sizeof
        break
    for step, val in reversed(chain):
        if step == 'array':
            size *= val
        else:
            cache[val] = size
    return size


def _check_complete_sized(ref, ctx, path):
    resolved = _strip_modifiers(ref, ctx, path)
    if resolved == 'void':
        raise ModelError(path, 'void is not a complete type')
    if isinstance(resolved, FunctionType):
        raise ModelError(path, 'a function type is not a complete type')
    if isinstance(resolved, Udt):
        _check_bool(resolved.opaque, path)
        if resolved.opaque:
            raise ModelError(path, 'an opaque type is not complete')
    return resolved


def _check_typeref(ref, path, ctx, depth, seen):
    """Shape/range checks for any TypeRef position."""
    if depth > _MAX_DEPTH:
        raise ModelError(path, f'TypeRef nesting exceeds {_MAX_DEPTH} levels')
    if isinstance(ref, str):
        _resolve_ref(ref, ctx, path)
        return
    if isinstance(ref, (Udt, Enum)):
        _check_udt_or_enum(ref, path, ctx, depth, seen, is_top=False)
        return
    if id(ref) in seen:
        raise ModelError(path, 'inline type contains itself')
    seen = seen | {id(ref)}
    if isinstance(ref, Pointer):
        _check_str(ref.mode, path + '.mode')
        if ref.mode not in POINTER_MODES:
            raise ModelError(path + '.mode', f'invalid pointer mode: {ref.mode!r}')
        _check_bool(ref.const, path + '.const')
        _check_bool(ref.volatile, path + '.volatile')
        _check_bool(ref.unaligned, path + '.unaligned')
        if ref.size is not None and (type(ref.size) is not int or ref.size not in (4, 8)):
            raise ModelError(path + '.size', f'invalid pointer size: {ref.size!r}')
        _check_typeref(ref.to, path + '.to', ctx, depth + 1, seen)
    elif isinstance(ref, Array):
        _check_int(ref.count, path + '.count')
        if not (0 <= ref.count <= 2 ** 32 - 1):
            raise ModelError(path + '.count', f'array count out of range: {ref.count!r}')
        _check_complete_sized(ref.of, ctx, path + '.of')
        _check_typeref(ref.of, path + '.of', ctx, depth + 1, seen)
        elem_size = _sizeof(ref.of, ctx, path + '.of')
        if elem_size == 0:
            if ref.count != 0:
                raise ModelError(path + '.count', 'non-zero count with a zero-size element')
        elif ref.count * elem_size > 2 ** 63 - 1:
            raise ModelError(path + '.count', 'array total size exceeds 2**63-1')
    elif isinstance(ref, Modifier):
        _check_bool(ref.const, path + '.const')
        _check_bool(ref.volatile, path + '.volatile')
        _check_bool(ref.unaligned, path + '.unaligned')
        if not (ref.const or ref.volatile or ref.unaligned):
            raise ModelError(path, 'modifier has no flag set')
        if isinstance(ref.of, (Pointer, Modifier, Array, FunctionType)):
            raise ModelError(path + '.of', 'modifier operand is a pointer/modifier/array/function object')
        resolved = _resolve_ref(ref.of, ctx, path + '.of')
        if not isinstance(resolved, (str, Udt, Enum, Pointer)):
            raise ModelError(path + '.of', f'modifier operand resolves to an invalid kind: {resolved!r}')
        _check_typeref(ref.of, path + '.of', ctx, depth + 1, seen)
    elif isinstance(ref, FunctionType):
        _check_str(ref.call, path + '.call')
        if ref.call not in CALLING_CONVENTIONS:
            raise ModelError(path + '.call', f'invalid calling convention: {ref.call!r}')
        resolved_returns = _resolve_ref(ref.returns, ctx, path + '.returns')
        if isinstance(resolved_returns, (Array, FunctionType)):
            raise ModelError(path + '.returns', 'return type is an array or function type')
        _check_typeref(ref.returns, path + '.returns', ctx, depth + 1, seen)
        _check_bool(ref.variadic, path + '.variadic')
        _check_list(ref.args, path + '.args')
        if len(ref.args) + ref.variadic > 16318:
            raise ModelError(path + '.args', 'argument list exceeds 16318 entries')
        for i, a in enumerate(ref.args):
            resolved_a = _strip_modifiers(a, ctx, f'{path}.args[{i}]')
            if resolved_a == 'void' or isinstance(resolved_a, (Array, FunctionType)):
                raise ModelError(f'{path}.args[{i}]', 'argument is void, an array or a function type')
            _check_typeref(a, f'{path}.args[{i}]', ctx, depth + 1, seen)
    else:
        raise ModelError(path, f'not a TypeRef: {ref!r}')


def _check_field(f, path, ctx, depth, seen):
    _check_name(f.name, path + '.name', allow_empty=True)
    _check_int(f.offset, path + '.offset')
    if not (0 <= f.offset <= 2 ** 31 - 1):
        raise ModelError(path + '.offset', f'field offset out of range: {f.offset!r}')
    _check_str(f.access, path + '.access')
    if f.access not in ACCESS:
        raise ModelError(path + '.access', f'invalid access: {f.access!r}')
    if (f.bit_offset is None) != (f.bit_length is None):
        raise ModelError(path, 'bit_offset and bit_length must both be set or both be None')
    _check_complete_sized(f.type, ctx, path + '.type')
    _check_typeref(f.type, path + '.type', ctx, depth, seen)
    if f.bit_offset is not None:
        resolved = _strip_modifiers(f.type, ctx, path + '.type')
        is_integral = isinstance(resolved, str) and _codeview.is_integral(resolved)
        is_enum = isinstance(resolved, Enum)
        if not (is_integral or is_enum):
            raise ModelError(path, 'bitfield type is not integral or an enum')
        _check_int(f.bit_length, path + '.bit_length')
        if not (1 <= f.bit_length <= 64):
            raise ModelError(path + '.bit_length', f'bit_length out of range: {f.bit_length!r}')
        _check_int(f.bit_offset, path + '.bit_offset')
        if not (0 <= f.bit_offset <= 63):
            raise ModelError(path + '.bit_offset', f'bit_offset out of range: {f.bit_offset!r}')
        if f.bit_offset + f.bit_length > 8 * _sizeof(f.type, ctx, path + '.type'):
            raise ModelError(path, 'bitfield exceeds its storage unit')


def _check_base(b, path, ctx):
    _check_str(b.type, path + '.type')
    _check_int(b.offset, path + '.offset')
    if not (0 <= b.offset <= 2 ** 31 - 1):
        raise ModelError(path + '.offset', f'base offset out of range: {b.offset!r}')
    _check_str(b.access, path + '.access')
    if b.access not in ACCESS:
        raise ModelError(path + '.access', f'invalid access: {b.access!r}')
    resolved = _resolve_ref(b.type, ctx, path + '.type')
    if isinstance(resolved, Udt):
        _check_bool(resolved.opaque, path + '.type')
    if not isinstance(resolved, Udt) or resolved.kind == 'union' or resolved.opaque:
        raise ModelError(path + '.type', f'base is not a complete non-union struct/class: {b.type!r}')


def _check_udt_or_enum(obj, path, ctx, depth, seen, is_top):
    if id(obj) in seen:
        raise ModelError(path, 'inline type contains itself')
    seen = seen | {id(obj)}
    if not is_top:
        _check_name(obj.name, path + '.name', allow_empty=True)
        if not is_anonymous_name(obj.name):
            raise ModelError(path + '.name', f'inline type has a non-anonymous name: {obj.name!r}')
    if isinstance(obj, Enum):
        _check_str(obj.underlying, path + '.underlying')
        _check_dict(obj.values, path + '.values')
        if enum_range(obj.underlying) is None:
            raise ModelError(path + '.underlying', f'not an enum-capable base type: {obj.underlying!r}')
        lo, hi = enum_range(obj.underlying)
        if len(obj.values) > 0xFFFF:
            raise ModelError(path + '.values', 'more than 0xFFFF enumerators')
        for name, value in obj.values.items():
            _check_name(name, f'{path}.values[{name!r}]', allow_anonymous=True, allow_base_type=True)
            _check_int(value, f'{path}.values[{name!r}]')
            if not (lo <= value <= hi):
                raise ModelError(f"{path}.values[{name!r}]", f'enumerator value out of range: {value!r}')
        return
    _check_str(obj.kind, path + '.kind')
    if obj.kind not in ('struct', 'class', 'union'):
        raise ModelError(path + '.kind', f'invalid kind: {obj.kind!r}')
    _check_int(obj.size, path + '.size')
    if not (0 <= obj.size <= 2 ** 63 - 1):
        raise ModelError(path + '.size', f'size out of range: {obj.size!r}')
    _check_list_of(obj.fields, path + '.fields', Field)
    _check_list_of(obj.bases, path + '.bases', BaseClass)
    _check_bool(obj.opaque, path + '.opaque')
    if obj.opaque:
        if obj.size or obj.fields or obj.bases:
            raise ModelError(path, 'opaque type has a size, fields or bases')
        if not is_top:
            raise ModelError(path, 'inline type cannot be opaque')
        return
    if obj.kind == 'union' and obj.bases:
        raise ModelError(path + '.bases', 'a union cannot have bases')
    if len(obj.fields) + len(obj.bases) > 0xFFFF:
        raise ModelError(path, 'fields + bases exceed 0xFFFF')
    for i, f in enumerate(obj.fields):
        _check_field(f, f'{path}.fields[{i}]', ctx, depth + 1, seen)
    for i, b in enumerate(obj.bases):
        _check_base(b, f'{path}.bases[{i}]', ctx)


def _v17_children(node, ctx, objs):
    """V17 graph successors of ``node``: typedef-name hops and inline TypeRef nodes (pointers/functions included).

    Base types, top-level Udt/Enum names (by name or by identity) and unknown names end the walk.
    """
    if node[0] == 'td':
        refs = [ctx.names[node[1]][1].type]
    else:
        obj = objs[node[1]]
        if isinstance(obj, Pointer):
            refs = [obj.to]
        elif isinstance(obj, (Array, Modifier)):
            refs = [obj.of]
        elif isinstance(obj, FunctionType):
            refs = [obj.returns] + list(obj.args)
        elif isinstance(obj, Udt):
            refs = [b.type for b in obj.bases] + [f.type for f in obj.fields]
        else:
            refs = []  # inline Enum: no further TypeRefs
    out = []
    for r in refs:
        if isinstance(r, str):
            if r in BASE_TYPES:
                continue
            kind = ctx.names.get(r)
            if kind is None or kind[0] == 'type':
                continue  # unknown name (V16 elsewhere) or a named Udt/Enum: ends the walk
            out.append(('td', r))
        elif isinstance(r, (Udt, Enum)):
            top = ctx.names.get(r.name)
            if top is not None and top[0] == 'type' and top[1] is r:
                continue  # identity match with a registered top-level type: ends the walk
            objs[id(r)] = r
            out.append(('obj', id(r)))
        else:  # Pointer, Array, Modifier, FunctionType
            objs[id(r)] = r
            out.append(('obj', id(r)))
    return out


def _check_typedef_v17(model, ctx):
    """V17: a typedef reaching itself through typedef names/inline objects, or a >100 inline-hop chain.

    Runs over all typedefs before the per-type checks.
    """
    if not model.typedefs:
        return
    tdnames = {t.name: i for i, t in enumerate(model.typedefs)}
    objs = {}
    roots = [('td', t.name) for t in model.typedefs]

    # Pass 1: cycle detection (iterative Tarjan SCC, including self-loops).
    index, low, on_stack, stack, counter, cyclic = {}, {}, set(), [], [0], set()
    for start in roots:
        if start in index:
            continue
        work = [(start, iter(_v17_children(start, ctx, objs)))]
        index[start] = low[start] = counter[0]; counter[0] += 1
        stack.append(start); on_stack.add(start)
        self_loop = set()
        while work:
            v, it = work[-1]
            advanced = False
            for w in it:
                if w == v:
                    self_loop.add(v)
                if w not in index:
                    index[w] = low[w] = counter[0]; counter[0] += 1
                    stack.append(w); on_stack.add(w)
                    work.append((w, iter(_v17_children(w, ctx, objs))))
                    advanced = True
                    break
                if w in on_stack:
                    low[v] = min(low[v], index[w])
            if advanced:
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[v])
            if low[v] == index[v]:
                comp = []
                while True:
                    w = stack.pop(); on_stack.discard(w); comp.append(w)
                    if w == v:
                        break
                if len(comp) > 1 or v in self_loop:
                    cyclic.update(tdnames[n[1]] for n in comp if n[0] == 'td')
    if cyclic:
        i = min(cyclic)
        raise ModelError(f'typedefs[{i}]', f'typedef cycle: {model.typedefs[i].name!r}')

    # Pass 2 (acyclic): a chain of more than 100 inline-object hops breaks the writer's recursive lowering.
    memo = {}
    for start in roots:
        if start in memo:
            continue
        work = [(start, iter(_v17_children(start, ctx, objs)))]
        on_path = {start}
        while work:
            node, it = work[-1]
            for child in it:
                if child not in memo and child not in on_path:
                    on_path.add(child)
                    work.append((child, iter(_v17_children(child, ctx, objs))))
                    break
            else:
                work.pop()
                on_path.discard(node)
                best = max((memo.get(c, 0) for c in _v17_children(node, ctx, objs)), default=0)
                memo[node] = best + (1 if node[0] == 'obj' else 0)
    worst = max(memo[r] for r in roots)
    if worst > 100:
        i = min(j for j, r in enumerate(roots) if memo[r] == worst)
        raise ModelError(f'typedefs[{i}]', 'typedef-name chain exceeds 100 hops')


def _value_children(ref, ctx):
    """Names/inline-objects reachable by value from ref (stops at Pointer/FunctionType)."""
    resolved = ref if not isinstance(ref, str) else ctx.names.get(ref, (None, None))[1]
    if isinstance(ref, str) and ref in BASE_TYPES:
        return []
    if resolved is None:
        return []
    if isinstance(resolved, Typedef):
        return [resolved.type]
    if isinstance(resolved, Udt):
        if resolved.opaque:
            return []
        return [b.type for b in resolved.bases] + [f.type for f in resolved.fields]
    if isinstance(resolved, Array):
        return [resolved.of]
    if isinstance(resolved, Modifier):
        return [resolved.of]
    return []  # Enum, Pointer, FunctionType: no by-value children


def _named_children(name, ctx):
    """Named by-value children reachable from ``name``, walking through inline objects (iterative)."""
    out = []
    stack, local_seen = list(_value_children(name, ctx)), set()
    while stack:
        c = stack.pop()
        if isinstance(c, str):
            if c not in BASE_TYPES:
                out.append(c)
            continue
        if id(c) in local_seen:
            continue
        local_seen.add(id(c))
        stack.extend(_value_children(c, ctx))
    return out


def _check_by_value_cycles(ctx, top_names, name_to_path):
    """By-value containment cycle check: iterative DFS (explicit stack, grey/black coloring)."""
    color = {}  # name -> 'grey' | 'black'
    for start in top_names:
        if start in color:
            continue
        path_stack = [start]  # grey names, in DFS order (also the path from start to the current frame)
        color[start] = 'grey'
        frames = [iter(_named_children(start, ctx))]
        while frames:
            try:
                child = next(frames[-1])
            except StopIteration:
                frames.pop()
                color[path_stack.pop()] = 'black'
                continue
            st = color.get(child)
            if st == 'grey':
                cycle = path_stack[path_stack.index(child):] + [child]
                raise ModelError(name_to_path[path_stack[-1]],
                                  f"by-value containment cycle: {' -> '.join(cycle)}")
            if st is None:
                color[child] = 'grey'
                path_stack.append(child)
                frames.append(iter(_named_children(child, ctx)))


def _validate_model(model, sections):
    if sections is not None:
        _check_list_of(sections, 'sections', SectionHeader)
    ctx = _Ctx()
    if not isinstance(model.image, Image):
        raise ModelError('image', f'expected an Image, got {model.image!r}')
    img = model.image
    _check_str(img.machine, 'image.machine')
    if img.machine not in MACHINES:
        raise ModelError('image.machine', f'invalid machine: {img.machine!r}')
    if img.guid is not None and not _is_guid(img.guid):
        raise ModelError('image.guid', f'not a GUID: {img.guid!r}')
    if img.age is not None:
        _check_int(img.age, 'image.age')
        if not (0 <= img.age <= 0xFFFFFFFF):
            raise ModelError('image.age', f'age out of range: {img.age!r}')
    _check_list_of(img.sections, 'image.sections', SectionHeader)
    if len(img.sections) > 0xFFFE:
        raise ModelError('image.sections', 'more than 0xFFFE sections')
    prev_va = -1
    for i, s in enumerate(img.sections):
        p = f'image.sections[{i}]'
        _check_str(s.name, p + '.name')
        try:
            s.name.encode('latin-1')
        except UnicodeEncodeError:
            raise ModelError(p + '.name', f'section name is not latin-1: {s.name!r}') from None
        if '\0' in s.name or len(s.name.encode('latin-1')) > 8:
            raise ModelError(p + '.name', f'invalid section name: {s.name!r}')
        for field_name in ('virtual_address', 'virtual_size', 'characteristics', 'raw_size', 'raw_pointer'):
            v = getattr(s, field_name)
            if isinstance(v, bool) or not isinstance(v, int) or not (0 <= v <= 0xFFFFFFFF):
                raise ModelError(f'{p}.{field_name}', f'out of range: {v!r}')
        if s.virtual_address <= prev_va:
            raise ModelError(p + '.virtual_address', 'virtual_address is not strictly ascending')
        prev_va = s.virtual_address

    _check_list_of(model.types, 'types', (Udt, Enum), 'Udt or Enum')
    _check_list_of(model.typedefs, 'typedefs', Typedef)
    _check_list_of(model.functions, 'functions', Function)
    _check_list_of(model.data, 'data', Data)
    _check_list_of(model.publics, 'publics', Public)

    def register(name, path, kind, obj):
        _check_str(name, path)
        if name in ctx.names:
            raise ModelError(path, f'name defined twice: {name!r}')
        ctx.names[name] = (kind, obj)

    for i, t in enumerate(model.types):
        register(t.name, f'types[{i}].name', 'type', t)
    for i, t in enumerate(model.typedefs):
        register(t.name, f'typedefs[{i}].name', 'typedef', t)

    _check_typedef_v17(model, ctx)  # V17 runs over all typedefs before the per-type checks

    for i, t in enumerate(model.types):
        _check_name(t.name, f'types[{i}].name', allow_anonymous=False, allow_base_type=False)
        _check_udt_or_enum(t, f'types[{i}]', ctx, 0, set(), is_top=True)
    for i, t in enumerate(model.typedefs):
        p = f'typedefs[{i}]'
        _check_name(t.name, p + '.name', allow_anonymous=False, allow_base_type=False)
        _check_typeref(t.type, p + '.type', ctx, 0, set())

    top_names = [t.name for t in model.types] + [t.name for t in model.typedefs]
    name_to_path = dict(zip(
        [t.name for t in model.types] + [t.name for t in model.typedefs],
        [f'types[{i}]' for i in range(len(model.types))] +
        [f'typedefs[{i}]' for i in range(len(model.typedefs))]))
    _check_by_value_cycles(ctx, top_names, name_to_path)

    seen_fn = set()
    for i, f in enumerate(model.functions):
        p = f'functions[{i}]'
        _check_name(f.name, p + '.name')
        _check_int(f.rva, p + '.rva')
        if not (1 <= f.rva <= 0xFFFFFFFF):
            raise ModelError(p + '.rva', f'rva out of range: {f.rva!r}')
        _check_int(f.length, p + '.length')
        if f.length < 0 or f.rva + f.length > 2 ** 32:
            raise ModelError(p + '.length', f'length out of range: {f.length!r}')
        if f.type is not None:
            resolved = _resolve_ref(f.type, ctx, p + '.type')
            if not isinstance(resolved, FunctionType):
                raise ModelError(p + '.type', f'function type does not resolve to a function type: {f.type!r}')
            _check_typeref(f.type, p + '.type', ctx, 0, set())
        _check_bool(f.static, p + '.static')
        key = (f.name, f.rva, f.length, f.static, _type_key(f.type))
        if key in seen_fn:
            raise ModelError(p, f'exact duplicate function: {f.name!r}')
        seen_fn.add(key)
        _check_rva_in_sections(f.rva, f.length, sections, img, p)

    seen_data = set()
    for i, x in enumerate(model.data):
        p = f'data[{i}]'
        _check_name(x.name, p + '.name')
        _check_int(x.rva, p + '.rva')
        if not (1 <= x.rva <= 0xFFFFFFFF):
            raise ModelError(p + '.rva', f'rva out of range: {x.rva!r}')
        if x.type is not None:
            resolved = _strip_modifiers(x.type, ctx, p + '.type')
            if resolved == 'void' or isinstance(resolved, FunctionType):
                raise ModelError(p + '.type', f'invalid data type: {x.type!r}')
            _check_typeref(x.type, p + '.type', ctx, 0, set())
        _check_bool(x.static, p + '.static')
        key = (x.name, x.rva, x.static, _type_key(x.type))
        if key in seen_data:
            raise ModelError(p, f'exact duplicate data: {x.name!r}')
        seen_data.add(key)
        _check_rva_in_sections(x.rva, None, sections, img, p)

    seen_pub_names = set()
    for i, pub in enumerate(model.publics):
        p = f'publics[{i}]'
        _check_name(pub.name, p + '.name')
        _check_int(pub.rva, p + '.rva')
        if not (1 <= pub.rva <= 0xFFFFFFFF):
            raise ModelError(p + '.rva', f'rva out of range: {pub.rva!r}')
        if pub.function is not None:
            _check_bool(pub.function, p + '.function')
        if pub.name in seen_pub_names:
            raise ModelError(p + '.name', f'duplicate public name: {pub.name!r}')
        seen_pub_names.add(pub.name)
        _check_rva_in_sections(pub.rva, None, sections, img, p)


def _type_key(tr):
    if tr is None:
        return ''
    return json.dumps(_dump_typeref(tr, '', 0, set()), sort_keys=True)


def _effective_sections(sections, img):
    if sections is not None:
        return sections
    return img.sections or None


def _check_rva_in_sections(rva, length, sections, img, path):
    secs = _effective_sections(sections, img)
    if not secs:
        return
    for s in secs:
        lo = s.virtual_address
        hi = lo + max(s.virtual_size, s.raw_size)
        if lo <= rva < hi:
            if length is not None and rva + length > hi:
                raise ModelError(path, 'function does not end inside its section')
            return
    raise ModelError(path, f'rva {rva:#x} is not inside any section')


# ===== normalization =========================================================================

def _normalize_guid(guid):
    if guid is None:
        return None
    t = guid
    if t.startswith('{') and t.endswith('}'):
        t = t[1:-1]
    return t.replace('-', '').upper()


def _normalize_model(model):
    """Deep copy in canonical order (copied through to_dict/from_dict)."""
    copied = PdbModel.from_dict(model.to_dict())
    image = Image(machine=copied.image.machine, guid=_normalize_guid(copied.image.guid), age=copied.image.age,
                  sections=copied.image.sections)
    types = sorted(copied.types, key=lambda t: t.name)
    typedefs = sorted(copied.typedefs, key=lambda t: t.name)
    functions = sorted(copied.functions, key=lambda f: (f.rva, f.name, f.length, f.static, _type_key(f.type)))
    data = sorted(copied.data, key=lambda x: (x.rva, x.name, x.static, _type_key(x.type)))
    publics = sorted(copied.publics, key=lambda p: (p.rva, p.name))
    return PdbModel(image=image, types=types, typedefs=typedefs, functions=functions, data=data, publics=publics)
