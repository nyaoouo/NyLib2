"""The typed reader of unversioned export properties: slots over a struct's super chain, values by kind, partial results."""
import contextlib
import string
import struct
import threading

from ..errors import InvalidMappingError, UnsupportedAssetError
from . import _natives
from ._values import EnumValue, MapValue, ObjectRef, Slot, SoftObjectRef, StructValue, TextValue, _layout

_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
_MAX_LEVEL = 16  # struct nesting, nested FTexts included
_MAX_DEPTH = 64  # value depth: struct levels plus container steps
_BUDGET = 65536  # decode units one read may spend beyond its export's size
_MAX_SLOTS = 1 << 16  # schema slots one unversioned header may describe
_MAX_ZERO_SIZE_COUNT = 65536  # elements of a container whose element type can take 0 bytes
_CHECK_EVERY = 4096  # decoded values, built slots or payloads between two checkpoints
_CDO = 0x10  # RF_ClassDefaultObject: no object trailer
_NULL_REF = ObjectRef('null', None, None, None)
_ZERO_TEXT = TextValue('None', None, None, None, None, None)
_EMPTY_MAP = MapValue()
_PROBLEMS = (InvalidMappingError, UnsupportedAssetError)
_NO_LOCK = contextlib.nullcontext()  # the lock of a per-read schema, which no other thread sees
_LABELS = {
    0: 'Byte', 1: 'Bool', 2: 'Int', 3: 'Float', 4: 'Object', 5: 'Name', 6: 'Delegate', 7: 'Double', 10: 'Str', 11: 'Text',
    12: 'Interface', 13: 'MulticastDelegate', 14: 'WeakObject', 15: 'LazyObject', 16: 'AssetObject', 17: 'SoftObject',
    18: 'UInt64', 19: 'UInt32', 20: 'UInt16', 21: 'Int64', 22: 'Int16', 23: 'Int8', 27: 'FieldPath', 0xFF: 'Unknown',
}
_SCALARS = {code: struct.Struct(fmt) for code, fmt in
            ((0, '<B'), (2, '<i'), (3, '<f'), (7, '<d'), (18, '<Q'), (19, '<I'), (20, '<H'), (21, '<q'), (22, '<h'), (23, '<b'))}
_ZEROS = {0: 0, 1: False, 2: 0, 3: 0.0, 4: _NULL_REF, 5: 'None', 7: 0.0, 10: '', 11: _ZERO_TEXT, 12: _NULL_REF, 13: (),
          14: _NULL_REF, 15: '0' * 32, 16: '', 17: _natives.EMPTY_SOFT, 18: 0, 19: 0, 20: 0, 21: 0, 22: 0, 23: 0, 24: _EMPTY_MAP,
          25: (), 28: None}
_U16, _I32, _U32, _I8, _I64, _U64, _F32, _F64 = (struct.Struct(f) for f in ('<H', '<i', '<I', '<b', '<q', '<Q', '<f', '<d'))
_NAME = struct.Struct('<ii')
_GUID = struct.Struct('<IIII')
_HISTORIES = {-1: 'None', 0: 'Base', 1: 'NamedFormat', 2: 'OrderedFormat', 3: 'ArgumentFormat', 4: 'AsNumber', 5: 'AsPercent',
              6: 'AsCurrency', 7: 'AsDate', 8: 'AsTime', 9: 'AsDateTime', 10: 'Transform', 11: 'StringTableEntry', 12: 'TextGenerator'}
_ARGUMENTS = {1: 'Map<Str,Struct<FormatArgumentValue>>', 2: 'Array<Struct<FormatArgumentValue>>', 3: 'Array<Struct<FormatArgumentData>>'}
_ARG_TYPES = {0: ('Int', 'Int64', _I64), 1: ('UInt', 'UInt64', _U64), 2: ('Float', 'Float', _F32), 3: ('Double', 'Double', _F64)}
_STYLES = {7: ('DateStyle',), 8: ('TimeStyle',), 9: ('DateStyle', 'TimeStyle')}


def _lower(s: str) -> str:
    return s.translate(_LOWER)


def _signed(v: int) -> int:
    """`v` as a signed 64-bit integer (two's complement)."""
    return v - (1 << 64) if v >= 1 << 63 else v


def _kept(e: Exception) -> Exception:
    """`e` with no traceback along its context chain, so a kept problem holds none of the reader's frames."""
    x = e
    while x is not None:
        x.__traceback__ = None
        x = x.__context__
    return e


def type_label(t) -> str:
    """The type label of a mapping type node: `Array<T>`, `Map<K,V>`, `Enum<E:U>`, `Struct<S>`, ..."""
    code = t.code
    if code == 9:
        return f'Struct<{t.struct_name}>'
    if code == 26:
        return f'Enum<{t.enum_name}:{type_label(t.inner)}>'
    if code == 8:
        return f'Array<{type_label(t.inner)}>'
    if code == 25:
        return f'Set<{type_label(t.inner)}>'
    if code == 28:
        return f'Optional<{type_label(t.inner)}>'
    if code == 24:
        return f'Map<{type_label(t.inner)},{type_label(t.value)}>'
    return _LABELS[code]


def _zero_size(t) -> bool:
    """True iff a value of type `t` can take 0 bytes."""
    if t.code == 24:
        return _zero_size(t.inner) and _zero_size(t.value)
    return t.code == 9 and t.struct_name == 'KeyHandleMap'


class Schema:
    """The slots of one struct's whole super chain, own properties first; templates[pos] is
    (index, element, owner, name, label, type)."""
    __slots__ = ('templates', 'where', 'absent', 'zero', 'nones', 'layout', '_unread', '_lock')

    def __init__(self, chain: tuple, lock):
        templates = []
        base = 0
        for rec in chain:
            local = {}
            for p in rec.properties:
                label = None
                for e in range(p.array_dim):
                    i = p.index + e
                    if i < rec.property_count and i not in local:
                        label = label or type_label(p.type)
                        local[i] = (base + i, e, rec.name, p.name, label, p.type)
            templates.extend(local[i] for i in sorted(local))
            base += rec.property_count
        self._build(tuple(templates), lock)

    @classmethod
    def of(cls, templates: tuple) -> 'Schema':
        """The schema of slot `templates` in index order, such as a property bag's descriptors."""
        self = object.__new__(cls)
        self._build(templates, _NO_LOCK)
        return self

    def _build(self, templates: tuple, lock) -> None:
        self.templates = templates
        self.where = {t[0]: pos for pos, t in enumerate(templates)}
        self.absent = tuple(Slot(i, owner, name, label, 'absent', None, e) for i, e, owner, name, label, _t in templates)
        self.zero = tuple(Slot(i, owner, name, label, 'zero', None, e) for i, e, owner, name, label, _t in templates)
        self.nones = (None,) * len(templates)
        self.layout = _layout(self.absent)
        self._unread = None
        self._lock = lock

    @property
    def unread(self) -> tuple:
        """Every slot of the chain 'unread'; built on first use."""
        if (u := self._unread) is None:
            with self._lock:
                if (u := self._unread) is None:
                    u = self._unread = tuple(Slot(i, owner, name, label, 'unread', None, e)
                                             for i, e, owner, name, label, _t in self.templates)
        return u


class _SchemaError(Exception):
    def __init__(self, reason: str, name: str):
        self.reason = reason
        self.name = name


class Schemas:
    """One installation's cache of struct schemas, enum member tables and native slot layouts, built under its lock."""

    def __init__(self, mappings):
        self._mappings = mappings
        self._lock = threading.Lock()
        self._schemas = {}
        self._enums = {}
        self._layouts = {}

    def get(self, name: str) -> Schema:
        """The schema of `name`; _SchemaError when a record of its chain is missing or the chain cycles."""
        key = _lower(name)
        if (s := self._schemas.get(key)) is not None:
            return s
        with self._lock:
            if (s := self._schemas.get(key)) is None:
                chain, seen, n = [], set(), name
                while n is not None:
                    k = _lower(n)
                    if k in seen:
                        raise _SchemaError('super chain cycle', name)
                    seen.add(k)
                    if (rec := self._mappings.record(n)) is None:
                        raise _SchemaError('no record', n)
                    chain.append(rec)
                    n = rec.super
                s = self._schemas[key] = Schema(tuple(chain), self._lock)
            return s

    def enum(self, name):
        """({value: first member name}, {member name: first value}) of enum `name`, values signed, or None without a record."""
        if name is None:
            return None
        if (e := self._enums.get(name)) is None:
            with self._lock:
                if (e := self._enums.get(name)) is None:
                    if (rec := self._mappings.enum(name)) is None:
                        return None
                    by_value, by_name = {}, {}
                    for value, member in rec.members:
                        value = _signed(value)
                        by_value.setdefault(value, member)
                        by_name.setdefault(member, value)
                    e = self._enums[name] = (by_value, by_name)
        return e

    def layout(self, key: tuple, slots: tuple) -> tuple:
        """The shared _layout of a native's `slots`; `key` is (native name, field names)."""
        if (layout := self._layouts.get(key)) is None:
            with self._lock:
                if (layout := self._layouts.get(key)) is None:
                    layout = self._layouts[key] = _layout(slots)
        return layout


def _render(path: list, cls: str) -> str:
    out = ''
    for s in path:
        if type(s) is int:
            out += f'[{s}]'
        elif len(s) == 2:
            out += f'[{s[0]} {s[1]}]'
        else:
            out += f"{'.' if out else ''}{s[0]}#{s[1]}"
    return out or cls


class PropertyReader:
    """Reads one export's unversioned property block and object trailer; `ref(v)` maps an FPackageIndex to an ObjectRef,
    or None when `v` is outside the export and import maps; `resolve(ref)` names the export a package import ref names;
    `check()` is the closed and cancel checkpoint."""

    def __init__(self, *, schemas: Schemas, names: tuple, ref, resolve, usmap: str, package: str, export: str, container: str,
                 size: int, class_name: str, check):
        self.schemas = schemas
        self.names = names
        self.ref = ref
        self.resolve = resolve
        self.usmap = usmap
        self.package = package
        self.export = export
        self.container = container
        self.size = size
        self.cls = class_name
        self.check = check
        self.ctx = (package, export, container)
        self.path = []  # (struct, index, name, label) slot steps, element indexes, ('key'|'value'|'row', n) steps
        self.native = None  # the native struct being read, for failures
        self.row = None
        self.n = 0
        self.units = 0  # decode units spent: decoded values and built slots
        self.slots = 0  # slots built, for their checkpoint
        self.payloads = 0  # InstancedStruct-family payloads read after their type items, for their checkpoint
        self.budget = size + _BUDGET
        self.data = b''
        self.pos = self.end = 0
        self._zeros = {}  # struct name -> (zero value, nesting depth below it)
        self._empty = {}  # fieldless native name -> its one value
        self._resolving = None  # the error of naming a package import, which partial=True still raises

    # ---- failures -----------------------------------------------------------------------------------------------

    def _attrs(self, pos, struct_name) -> dict:
        steps, last = [], None
        for s in self.path:
            if type(s) is tuple and len(s) == 4:
                steps.append(s[:2])
                last = s
            else:
                steps.append(s)
        return dict(package=self.package, container=self.container, export=self.export, property_path=tuple(steps),
                    class_name=self.cls if last is None else last[0], property_index=None if last is None else last[1],
                    property_name=None if last is None else last[2], property_type=None if last is None else last[3],
                    position=pos, struct_name=struct_name, row=self.row)

    def _mapping_error(self, message: str, reason: str, pos, struct_name=None, **extra) -> InvalidMappingError:
        attrs = self._attrs(pos, struct_name)
        attrs.update(extra)
        return InvalidMappingError(message, usmap=self.usmap, reason=reason, **attrs)

    def fail(self, reason: str, pos: int, struct_name=None):
        """Raise the walk-failure InvalidMappingError for a read that began at `pos`."""
        message = (f'{self.usmap} does not fit {self.package}.{self.export}: {_render(self.path, self.cls)} cannot be read at '
                   f'{pos:#x} ({reason}; export is {self.size} bytes)')
        raise self._mapping_error(message, reason, pos, self.native if struct_name is None else struct_name)

    def unsupported(self, what: str, pos: int, struct_name=None):
        """Raise the variant UnsupportedAssetError: a value form this nylib version does not read."""
        attrs = self._attrs(pos, self.native if struct_name is None else struct_name)
        raise UnsupportedAssetError(f'{self.package}.{self.export}: {_render(self.path, self.cls)} is {what}, which this nylib '
                                    f'version does not read (at {pos:#x})', feature=what, **attrs)

    def _unsupported_native(self, name: str, pos: int):
        attrs = self._attrs(pos, name)
        raise UnsupportedAssetError(f'{self.package}.{self.export}: {_render(self.path, self.cls)} is a {name}, a native struct '
                                    f'this nylib version does not read (at {pos:#x})', feature=f'native struct {name}', **attrs)

    def _schema_error(self, e: _SchemaError) -> InvalidMappingError:
        what = f'it has no record for {e.name}' if e.reason == 'no record' else f'the super chain of {e.name} cycles'
        return self._mapping_error(f'{self.usmap} cannot read {self.package}.{self.export}: {what}', e.reason, self.pos,
                                   class_name=e.name)

    def _slot_error(self, reason: str, text: str):
        a = self._attrs(self.pos, None)
        raise self._mapping_error(f"{self.usmap} cannot read {self.package}.{self.export}: {a['class_name']} {text}", reason, self.pos)

    def schema(self, name: str) -> Schema:
        """The schema of struct `name`; InvalidMappingError ('no record', 'super chain cycle') otherwise."""
        try:
            return self.schemas.get(name)
        except _SchemaError as e:
            raise self._schema_error(e) from None

    # ---- primitives ---------------------------------------------------------------------------------------------

    def tick(self) -> None:
        """One decoded value read outside value(): the checkpoint every 4,096 values, and one decode unit."""
        self.n += 1
        if not self.n % _CHECK_EVERY:
            self.check()
        self.spend(1, self.pos)

    def built(self, n: int) -> None:
        """`n` more slots built: the checkpoint every 4,096 built slots, which costs no decode unit."""
        k = self.slots // _CHECK_EVERY
        self.slots += n
        for _ in range(self.slots // _CHECK_EVERY - k):
            self.check()

    def payload(self) -> None:
        """One InstancedStruct-family payload read after its type items: the checkpoint every 4,096, which costs no decode unit."""
        self.payloads += 1
        if not self.payloads % _CHECK_EVERY:
            self.check()

    def spend(self, units: int, pos: int) -> None:
        """Charge `units` decode units for the value or block that begins at `pos`; past the budget, the walk failure."""
        self.units += units
        if self.units > self.budget:
            self.fail('decode budget', pos)

    def need(self, n: int) -> int:
        """The position of the next `n` bytes, which it consumes."""
        p = self.pos
        if n > self.end - p:
            self.fail('read past the export end', p)
        self.pos = p + n
        return p

    def i32(self) -> int:
        return _I32.unpack_from(self.data, self.need(4))[0]

    def count(self, unit: int, what: str) -> tuple:
        """(position, n) of an i32 count of items of at least `unit` bytes each; `what` names the failure."""
        p = self.need(4)
        n = _I32.unpack_from(self.data, p)[0]
        if n < 0 or n * unit > self.end - self.pos:
            self.fail(f'{what} {n}', p)
        return p, n

    def _items(self, t, what: str) -> tuple:
        p = self.need(4)
        n = _I32.unpack_from(self.data, p)[0]
        if n < 0 or (n > _MAX_ZERO_SIZE_COUNT if _zero_size(t) else n > self.end - self.pos):
            self.fail(f'{what} {n}', p)
        return p, n

    def bool32(self) -> bool:
        p = self.need(4)
        v = _U32.unpack_from(self.data, p)[0]
        if v > 1:
            self.fail(f'bool value {v}', p)
        return v == 1

    def fname(self) -> str:
        p = self.need(8)
        idx, num = _NAME.unpack_from(self.data, p)
        if not 0 <= idx < len(self.names):
            self.fail(f'name index {idx}', p)
        if num < 0:
            self.fail(f'name index {num}', p)
        s = self.names[idx]
        return s if num == 0 else f'{s}_{num - 1}'

    def fstring(self) -> str:
        p = self.need(4)
        n = _I32.unpack_from(self.data, p)[0]
        if n == 0:
            return ''
        m = n if n > 0 else -2 * n
        if m > self.end - self.pos:
            self.fail('bad string', p)
        q = self.pos
        b = self.data[q:q + m]
        self.pos = q + m
        if n > 0:
            if b[-1] != 0:
                self.fail('bad string', p)
            return b[:-1].decode('latin-1')
        if b[-2:] != b'\0\0':
            self.fail('bad string', p)
        return b[:-2].decode('utf-16-le', 'surrogatepass')

    def utf8(self) -> str:
        p = self.need(4)
        n = _I32.unpack_from(self.data, p)[0]
        if n < 0 or n > self.end - self.pos:
            self.fail('bad string', p)
        q = self.pos
        self.pos = q + n
        return self.data[q:q + n].decode('utf-8', 'surrogateescape')

    def object(self) -> ObjectRef:
        p = self.need(4)
        v = _I32.unpack_from(self.data, p)[0]
        if (r := self.ref(v)) is None:
            self.fail(f'object index {v}', p)
        return r

    def soft(self) -> SoftObjectRef:
        package, asset, sub = self.fname(), self.fname(), self.utf8()
        package = '' if package == 'None' else package
        asset = '' if asset == 'None' else asset
        path = '' if not package else package if not asset else f'{package}.{asset}' + (f':{sub}' if sub else '')
        return SoftObjectRef(package, asset, sub, path)

    def named(self, ref: ObjectRef) -> str:
        """The name of the struct a non-null ObjectRef names; a package import's is read from its package's cooked header."""
        if ref.kind != 'import':
            return ref.name
        try:
            return self.resolve(ref)
        except _PROBLEMS as e:
            self._resolving = e
            raise

    def nat(self, name: str, fields: tuple) -> StructValue:
        """A native StructValue of `fields`, each (name, label, position, value)."""
        key = (name, tuple(f[0] for f in fields))
        slots = tuple(Slot(i, name, f, label, 'serialized', pos) for i, (f, label, pos, _v) in enumerate(fields))
        return StructValue._new(name, True, slots, tuple(f[3] for f in fields), self.ctx, None, self.schemas.layout(key, slots))

    def _zero_nat(self, name: str, fields: tuple) -> StructValue:
        key = (name, tuple(f[0] for f in fields))
        slots = tuple(Slot(i, name, f, label, 'zero', None) for i, (f, label, _v) in enumerate(fields))
        return StructValue._new(name, True, slots, tuple(f[2] for f in fields), self.ctx, None, self.schemas.layout(key, slots))

    # ---- blocks ---------------------------------------------------------------------------------------------------

    def _header_frags(self) -> tuple:
        """(fragments, zero-bitmask, total entry count) of an unversioned header; bounded by the header's own
        bytes, not by how many slots it lists."""
        frags, zero_num, span, total = [], 0, 0, 0
        while True:
            p = self.pos
            if self.end - p < 2:
                self.fail('bad property header', p)
            packed = _U16.unpack_from(self.data, p)[0]
            self.pos = p + 2
            skip, has_zero, value_num, last = packed & 0x7F, packed & 0x80, packed >> 9, packed & 0x100
            span += skip + value_num
            if span > _MAX_SLOTS or (not last and skip + value_num == 0):
                self.fail('bad property header', p)
            frags.append((skip, has_zero, value_num))
            total += value_num
            if has_zero:
                zero_num += value_num
            if last:
                break
        mask = b''
        if zero_num:
            n = 1 if zero_num <= 8 else 2 if zero_num <= 16 else 4 * ((zero_num + 31) // 32)
            p = self.pos
            if self.end - p < n:
                self.fail('bad property header', p)
            mask = self.data[p:p + n]
            self.pos = p + n
        return frags, mask, total

    @staticmethod
    def _header_entries(frags: list, mask: bytes, skip: int = 0):
        """(schema index, serialized) of each header entry in index order, lazily, so a header costs its
        fragments only; `skip` drops the first `skip` entries (resuming after a failure)."""
        index = zi = n = 0
        for frag_skip, has_zero, value_num in frags:
            index += frag_skip
            for _ in range(value_num):
                nonzero = True
                if has_zero:
                    nonzero = not (mask[zi >> 3] >> (zi & 7)) & 1
                    zi += 1
                if n >= skip:
                    yield index, nonzero
                index += 1
                n += 1

    def _entry(self, schema: Schema, name: str, index: int, nonzero: bool, level: int, depth: int) -> tuple:
        """(slot position, Slot, value) of header entry `index` of struct `name`, whose block sits at `level` and `depth`."""
        pos = schema.where.get(index)
        if pos is None:
            self.path.append((name, index, None, None))
            self._slot_error('no property', f'has no property at index {index} ({_render(self.path, self.cls)})')
        _i, element, owner, pname, label, t = schema.templates[pos]
        self.path.append((name, index, pname, label))
        if t.code == 0xFF:
            self._unknown()
        if nonzero:
            start = self.pos
            value = self.value(t, False, level, depth)
            slot = Slot(index, owner, pname, label, 'serialized', start, element)
        else:
            value = self.zero(t, level, depth)
            slot = schema.zero[pos]
        self.path.pop()
        return pos, slot, value

    def _unknown(self):
        self._slot_error('unknown type', f'property {self._attrs(None, None)["property_index"]} has an unknown type '
                                         f'({_render(self.path, self.cls)})')

    def _struct_none(self):
        self._slot_error("struct 'None'", f"property {self._attrs(None, None)['property_index']} is a StructProperty of struct "
                                          "'None' (size unknown)")

    def block(self, schema: Schema, name: str, level: int, depth: int) -> StructValue:
        """The reflected StructValue of struct `name` at `level` and `depth`, read from its unversioned block."""
        native, self.native = self.native, None
        start = self.pos
        frags, mask, total = self._header_frags()
        if not total:
            self.native = native
            return StructValue._new(name, False, schema.absent, schema.nones, self.ctx, None, schema.layout)
        self.spend(len(schema.templates), start)
        self.built(max(0, len(schema.templates) - total))
        slots, values = list(schema.absent), list(schema.nones)
        for index, nonzero in self._header_entries(frags, mask):
            self.slots += 1
            if not self.slots % _CHECK_EVERY:
                self.check()
            pos, slot, value = self._entry(schema, name, index, nonzero, level, depth)
            slots[pos], values[pos] = slot, value
        self.native = native
        return StructValue._new(name, False, tuple(slots), tuple(values), self.ctx, None, schema.layout)

    def reflected(self, name: str, level: int, depth: int) -> StructValue:
        """The reflected block of struct `name` that a native's layout names, one level below `level` and one deeper than `depth`."""
        if depth >= _MAX_DEPTH:
            self.fail('value nesting', self.pos)
        if level >= _MAX_LEVEL:
            self.fail('struct nesting', self.pos)
        return self.block(self.schema(name), name, level + 1, depth + 1)

    @staticmethod
    def bag_schema(templates: tuple) -> Schema:
        return Schema.of(templates)

    def read(self, data: bytes, schema: Schema, flags: int, partial: bool) -> tuple:
        """(properties, native_size, guid, complete, problem) of the export's bytes `data`, whose class has `schema`."""
        self.data, self.pos, self.end = data, 0, len(data)
        name = self.cls
        try:
            frags, mask, total = self._header_frags()
            self.spend(len(schema.templates), 0)
        except _PROBLEMS as e:
            if not partial:
                raise
            _kept(e)
            return StructValue._new(name, False, schema.unread, schema.nones, self.ctx, e, schema.layout), 0, None, False, e
        self.built(max(0, len(schema.templates) - total))
        slots, values = list(schema.absent), list(schema.nones)
        for k, (index, nonzero) in enumerate(self._header_entries(frags, mask)):
            self.slots += 1
            if not self.slots % _CHECK_EVERY:
                self.check()
            try:
                pos, slot, value = self._entry(schema, name, index, nonzero, 0, 0)
            except _PROBLEMS as e:
                if not partial or e is self._resolving:
                    raise
                for later, _nz in self._header_entries(frags, mask, skip=k):
                    if (p := schema.where.get(later)) is not None:
                        slots[p], values[p] = schema.unread[p], None
                del self.path[:]
                self.native = None
                _kept(e)
                return StructValue._new(name, False, tuple(slots), tuple(values), self.ctx, e, schema.layout), 0, None, False, e
            slots[pos], values[pos] = slot, value
        properties = StructValue._new(name, False, tuple(slots), tuple(values), self.ctx, None, schema.layout)
        guid = None
        if not flags & _CDO:
            end = self.pos
            has_guid = _U32.unpack_from(data, end)[0] if self.end - end >= 4 else None
            if has_guid is None or has_guid > 1 or (has_guid and self.end - end < 20):
                e = self._mapping_error(f'{self.usmap} does not fit {self.package}.{self.export}: the {name} properties end at '
                                        f'{end:#x}, where the object trailer is not valid (export is {self.size} bytes)',
                                        'object trailer', end)
                if not partial:
                    raise e
                return properties, 0, None, False, _kept(e)
            self.pos = end + 4
            if has_guid:
                guid = '{:08X}{:08X}{:08X}{:08X}'.format(*_GUID.unpack_from(data, self.pos))
                self.pos += 16
        return properties, self.end - self.pos, guid, True, None

    # ---- values ---------------------------------------------------------------------------------------------------

    def value(self, t, inside: bool, level: int, depth: int):
        """One decoded value of type `t`; `inside` is True inside a container, `level` is its holder's nesting level and
        `depth` the value's depth before the level step a struct adds."""
        self.n += 1
        if not self.n % _CHECK_EVERY:
            self.check()
        self.units += 1
        if self.units > self.budget:
            self.fail('decode budget', self.pos)
        if depth > _MAX_DEPTH:
            self.fail('value nesting', self.pos)
        code = t.code
        if (fmt := _SCALARS.get(code)) is not None:
            return fmt.unpack_from(self.data, self.need(fmt.size))[0]
        if code == 9:
            return self.struct(t.struct_name, level, depth)
        if code == 5:
            return self.fname()
        if code == 26:
            return self._enum(t, inside, level, depth)
        if code == 1:
            p = self.need(1)
            if (b := self.data[p]) > 1:
                self.fail(f'bool value {b}', p)
            return b == 1
        if code in (4, 12, 14):
            return self.object()
        if code == 8:
            return self._array(t.inner, level, depth)
        if code in (10, 16):
            return self.fstring()
        if code == 17:
            return self.soft()
        if code == 24:
            return self._map(t, level, depth)
        if code == 25:
            return self._set(t.inner, level, depth)
        if code == 28:
            return self.value(t.inner, True, level, depth + 1) if self.bool32() else None
        if code == 11:
            return self.text(level, depth)
        if code == 6:
            return self._delegate()
        if code == 13:
            p, n = self.count(1, 'array count')
            out = []
            self.path.append(0)
            for k in range(n):
                self.path[-1] = k
                self.tick()
                if depth >= _MAX_DEPTH:
                    self.fail('value nesting', self.pos)
                out.append(self._delegate())
            self.path.pop()
            return tuple(out)
        if code == 27:
            p, n = self.count(1, 'array count')
            names = []
            for _ in range(n):
                self.tick()
                names.append(self.fname())
            q = self.pos
            owner = self.object()
            return self.nat('FieldPath', (('Path', 'Array<Name>', p, () if names == ['None'] else tuple(names)),
                                          ('Owner', 'Object', q, owner)))
        if code == 15:
            return '{:08X}{:08X}{:08X}{:08X}'.format(*_GUID.unpack_from(self.data, self.need(16)))
        self._unknown()

    def _delegate(self) -> StructValue:
        p = self.pos
        obj = self.object()
        return self.nat('Delegate', (('Object', 'Object', p, obj), ('FunctionName', 'Name', p + 4, self.fname())))

    def _enum(self, t, inside: bool, level: int, depth: int) -> EnumValue:
        members = self.schemas.enum(t.enum_name)
        enum = 'None' if t.enum_name is None else t.enum_name
        if inside:
            name = self.fname()
            if name.startswith(prefix := f'{enum}::'):
                name = name[len(prefix):]
            return EnumValue(enum, name, None if members is None else members[1].get(name))
        inner = t.inner
        v = fmt.unpack_from(self.data, self.need(fmt.size))[0] if (fmt := _SCALARS.get(inner.code)) is not None else \
            self.value(inner, False, level, depth + 1)
        return EnumValue(enum, None if members is None else members[0].get(_signed(v) if type(v) is int else v), v)

    def _array(self, inner, level: int, depth: int):
        p, n = self._items(inner, 'array count')
        if inner.code == 0:
            q = self.pos
            self.pos = q + n
            return self.data[q:q + n]
        out = []
        self.path.append(0)
        for k in range(n):
            self.path[-1] = k
            out.append(self.value(inner, True, level, depth + 1))
        self.path.pop()
        return tuple(out)

    def _set(self, inner, level: int, depth: int) -> tuple:
        for _removed in (True, False):
            _p, n = self._items(inner, 'set count')
            out = []
            self.path.append(0)
            for k in range(n):
                self.path[-1] = k
                out.append(self.value(inner, True, level, depth + 1))
            self.path.pop()
        return tuple(out)

    def _map(self, t, level: int, depth: int) -> MapValue:
        key, val = t.inner, t.value
        _p, n = self._items(key, 'map count')
        self.path.append(None)
        for k in range(n):
            self.path[-1] = ('key', k)
            self.value(key, True, level, depth + 1)
        self.path.pop()
        _p, n = self._items(t, 'map count')
        pairs = []
        self.path.append(None)
        for k in range(n):
            self.path[-1] = ('key', k)
            kv = self.value(key, True, level, depth + 1)
            self.path[-1] = ('value', k)
            pairs.append((kv, self.value(val, True, level, depth + 1)))
        self.path.pop()
        return MapValue(pairs)

    def struct(self, name, level: int, depth: int):
        """The value of struct `name`, one level below `level` and one deeper than `depth`: a native's value, or a reflected block."""
        pos = self.pos
        if name is None or name == 'None':
            self._struct_none()
        if depth >= _MAX_DEPTH:
            self.fail('value nesting', pos)
        if level >= _MAX_LEVEL:
            self.fail('struct nesting', pos)
        if (spec := _natives.FIXED.get(name)) is not None:
            if spec.size > self.end - pos:
                self.fail('read past the export end', pos, name)
            self.pos = pos + spec.size
            if not spec.size:  # a fieldless native: one shared value per read
                if (empty := self._empty.get(name)) is None:
                    empty = self._empty[name] = spec.read(self.data, pos, self.ctx)
                return empty
            return spec.read(self.data, pos, self.ctx)
        if (fn := _natives.VARIABLE.get(name)) is not None:
            native, self.native = self.native, name
            v = fn(self, level + 1, depth + 1)
            self.native = native
            return v
        if name in _natives.UNSUPPORTED:
            self._unsupported_native(name, pos)
        return self.block(self.schema(name), name, level + 1, depth + 1)

    # ---- zero values ----------------------------------------------------------------------------------------------

    def zero(self, t, level: int, depth: int):
        """The zero value of type `t` in a block at `level` and `depth`."""
        code = t.code
        if code in _ZEROS:
            return _ZEROS[code]
        if code == 8:
            return b'' if t.inner.code == 0 else ()
        if code == 9:
            return self._zero_struct(t.struct_name, level, depth)[0]
        if code == 26:
            members = self.schemas.enum(t.enum_name)
            return EnumValue('None' if t.enum_name is None else t.enum_name, None if members is None else members[0].get(0), 0)
        if code == 6:
            return self._zero_nat('Delegate', (('Object', 'Object', _NULL_REF), ('FunctionName', 'Name', 'None')))
        if code == 27:
            return self._zero_nat('FieldPath', (('Path', 'Array<Name>', ()), ('Owner', 'Object', _NULL_REF)))
        self._unknown()

    def _zero_struct(self, name, level: int, depth: int, reflected: bool = False) -> tuple:
        """(the all-zero value of struct `name` one level below `level` and one deeper than `depth`, the levels below it);
        `reflected` takes the zero of `name`'s reflected block even when `name` is a native."""
        if name is None or name == 'None':
            self._struct_none()
        key = (name,) if reflected and _natives.is_native(name) else name
        if (hit := self._zeros.get(key)) is not None:
            if depth + 1 + hit[1] > _MAX_DEPTH:
                self.fail('value nesting', self.pos)
            if level + 1 + hit[1] > _MAX_LEVEL:
                self.fail('struct nesting', self.pos)
            return hit
        if depth >= _MAX_DEPTH:
            self.fail('value nesting', self.pos)
        if level >= _MAX_LEVEL:
            self.fail('struct nesting', self.pos)
        if not reflected and (spec := _natives.FIXED.get(name)) is not None:
            hit = (spec.zero(self.ctx), 0)
        elif not reflected and (zero := _natives.ZEROS.get(name)) is not None:
            hit = zero(self, level + 1, depth + 1)
        elif not reflected and name in _natives.UNSUPPORTED:
            self._unsupported_native(name, self.pos)
        else:
            schema = self.schema(name)
            self.spend(len(schema.templates), self.pos)
            values, deepest = [], 0
            for index, _e, _owner, pname, label, t in schema.templates:
                self.slots += 1
                if not self.slots % _CHECK_EVERY:
                    self.check()
                self.path.append((name, index, pname, label))
                if t.code == 0xFF:
                    self._unknown()
                if t.code == 9:
                    v, below = self._zero_struct(t.struct_name, level + 1, depth + 1)
                    deepest = max(deepest, below + 1)
                else:
                    v = self.zero(t, level + 1, depth + 1)
                values.append(v)
                self.path.pop()
            hit = (StructValue._new(name, False, schema.zero, tuple(values), self.ctx, None, schema.layout), deepest)
        self._zeros[key] = hit
        return hit

    # ---- FText ----------------------------------------------------------------------------------------------------

    def text(self, level: int, depth: int) -> TextValue:
        """An FText whose own nesting level is `level` and whose depth is `depth`."""
        if depth > _MAX_DEPTH:
            self.fail('value nesting', self.pos)
        if level > _MAX_LEVEL:
            self.fail('struct nesting', self.pos)
        p = self.need(5)
        h = _I8.unpack_from(self.data, p + 4)[0]
        if h == -1:
            return TextValue('None', self.fstring() if self.bool32() else None, None, None, None, None)
        if h == 0:
            namespace, key, source = self.fstring(), self.fstring(), self.fstring()
            return TextValue('Base', source, namespace, key, None, None)
        if h == 11:
            table = self.fname()
            return TextValue('StringTableEntry', None, None, self.fstring(), table, None)
        if (history := _HISTORIES.get(h)) is None:
            self.unsupported(f'Text history {h}', p + 4)
        if h in (1, 2, 3):
            q = self.pos
            source = self.text(level + 1, depth + 1)
            r, n = self.count(1, 'map count' if h == 1 else 'array count')
            args = []
            for _ in range(n):
                self.tick()
                if h == 2:
                    args.append(self._argument(level, depth))
                    continue
                a = self.pos
                arg_name = self.fstring()
                b = self.pos
                value = self._argument(level, depth)
                args.append((arg_name, value) if h == 1 else
                            self.nat('FormatArgumentData', (('ArgumentName', 'Str', a, arg_name),
                                                            ('ArgumentValue', 'Struct<FormatArgumentValue>', b, value))))
            fields = (('SourceFmt', 'Text', q, source), ('Arguments', _ARGUMENTS[h], r, MapValue(args) if h == 1 else tuple(args)))
        elif h in (4, 5, 6):
            fields = ()
            if h == 6:
                q = self.pos
                fields = (('CurrencyCode', 'Str', q, self.fstring()),)
            q = self.pos
            fields += (('SourceValue', 'Struct<FormatArgumentValue>', q, self._argument(level, depth)),)
            q = self.pos
            options = self._number_options() if self.bool32() else None
            fields += (('FormatOptions', 'Optional<Struct<NumberFormattingOptions>>', None if options is None else q, options),)
            q = self.pos
            fields += (('TargetCulture', 'Str', q, self.fstring()),)
        elif h in (7, 8, 9):
            q = self.need(8)
            fields = (('SourceDateTime', 'Struct<DateTime>', q, _natives.FIXED['DateTime'].read(self.data, q, self.ctx)),)
            for style in _STYLES[h]:
                q = self.need(1)
                fields += ((style, 'Int8', q, _I8.unpack_from(self.data, q)[0]),)
            q = self.pos
            fields += (('TimeZone', 'Str', q, self.fstring()),)
            q = self.pos
            fields += (('TargetCulture', 'Str', q, self.fstring()),)
        elif h == 10:
            q = self.pos
            source = self.text(level + 1, depth + 1)
            r = self.need(1)
            fields = (('SourceText', 'Text', q, source), ('TransformType', 'Byte', r, self.data[r]))
        else:
            q = self.pos
            if (generator := self.fname()) != 'None':
                self.unsupported('Text history TextGenerator', q)
            fields = (('GeneratorTypeID', 'Name', q, generator),)
        return TextValue(history, None, None, None, None, self.nat(history, fields))

    def _argument(self, level: int, depth: int) -> StructValue:
        p = self.need(1)
        ty = _I8.unpack_from(self.data, p)[0]
        q = self.pos
        if ty == 4:
            return self.nat('FormatArgumentValue', (('Type', 'Str', p, 'Text'), ('Value', 'Text', q, self.text(level + 1, depth + 1))))
        if (form := _ARG_TYPES.get(ty)) is None:
            self.unsupported(f'Text argument type {ty}', p)
        type_name, label, fmt = form
        return self.nat('FormatArgumentValue', (('Type', 'Str', p, type_name),
                                                ('Value', label, q, fmt.unpack_from(self.data, self.need(fmt.size))[0])))

    def _number_options(self) -> StructValue:
        a = self.pos
        always_sign = self.bool32()
        use_grouping = self.bool32()
        r = self.need(17)
        rounding, = _I8.unpack_from(self.data, r)
        digits = struct.unpack_from('<iiii', self.data, r + 1)
        return self.nat('NumberFormattingOptions', (
            ('AlwaysSign', 'Bool', a, always_sign), ('UseGrouping', 'Bool', a + 4, use_grouping), ('RoundingMode', 'Int8', r, rounding),
            *((f, 'Int', r + 1 + 4 * k, d) for k, (f, d) in enumerate(zip(('MinimumIntegralDigits', 'MaximumIntegralDigits',
                                                                          'MinimumFractionalDigits', 'MaximumFractionalDigits'), digits)))))
