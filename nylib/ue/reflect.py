"""The reflection core: stage-4 wrappers to F8 records, and the streaming three-pass snapshot walk (stage 6, R2)."""
import dataclasses
import itertools
import time
import typing
from typing import Callable, Iterable

from .engine.accessor import view
from .engine.containers import FImplementedInterface
from .engine.unreal import (
    UEArrayProperty, UEByteProperty, UEClass, UEClassProperty, UEDelegateProperty, UEEnum, UEEnumProperty, UEFieldPathProperty,
    UEFunction, UEMapProperty, UEObject, UEObjectProperty, UEOptionalProperty, UEProperty, UESetProperty, UEStruct,
    UEStructProperty,
)
from .errors import DetectionError, MemoryReadError, TargetError
from .flags import EClassCastFlags as CF, EObjectFlags
from .model import (
    ClassRecord, EnumRecord, FunctionRecord, InterfaceRecord, ObjectRecord, ObjectTable, PropertyRecord, PropType, StructRecord,
    TypeRecord,
)
from .snapshot import write_snapshot

if typing.TYPE_CHECKING:
    from .engine.context import EngineContext
    from .engine.core import Engine

ISSUE_KINDS = ('unreadable_object', 'index_mismatch', 'unresolved_class', 'unresolved_outer', 'cyclic_outer', 'unreadable_fields',
               'unreadable_type', 'duplicate_path', 'unresolved_reference', 'enum_names_unsupported', 'enum_size_invalid', 'orphan_function',
               'unreadable_name', 'unreadable_interfaces')
DEAD_TARGET_RUN = 1000
PROGRESS_EVERY = 4096
PROPERTY_KIND_ORDER: tuple[tuple[int, str], ...] = tuple((int(bit), kind) for bit, kind in (
    (CF.ClassProperty, 'ClassProperty'), (CF.SoftClassProperty, 'SoftClassProperty'), (CF.ObjectProperty, 'ObjectProperty'),
    (CF.WeakObjectProperty, 'WeakObjectProperty'), (CF.LazyObjectProperty, 'LazyObjectProperty'),
    (CF.SoftObjectProperty, 'SoftObjectProperty'), (CF.InterfaceProperty, 'InterfaceProperty'),
    (CF.StructProperty, 'StructProperty'), (CF.ArrayProperty, 'ArrayProperty'), (CF.SetProperty, 'SetProperty'),
    (CF.MapProperty, 'MapProperty'), (CF.OptionalProperty, 'OptionalProperty'),
    (CF.EnumProperty, 'EnumProperty'), (CF.ByteProperty, 'ByteProperty'), (CF.BoolProperty, 'BoolProperty'),
    (CF.MulticastInlineDelegateProperty, 'MulticastInlineDelegateProperty'),
    (CF.MulticastSparseDelegateProperty, 'MulticastSparseDelegateProperty'), (CF.DelegateProperty, 'DelegateProperty'),
    (CF.MulticastDelegateProperty, 'MulticastInlineDelegateProperty'), (CF.FieldPathProperty, 'FieldPathProperty'),
    (CF.TextProperty, 'TextProperty'), (CF.StrProperty, 'StrProperty'), (CF.Utf8StrProperty, 'Utf8StrProperty'),
    (CF.AnsiStrProperty, 'AnsiStrProperty'), (CF.NameProperty, 'NameProperty'),
    (CF.DoubleProperty, 'DoubleProperty'), (CF.LargeWorldCoordinatesRealProperty, 'DoubleProperty'),
    (CF.FloatProperty, 'FloatProperty'), (CF.Int8Property, 'Int8Property'), (CF.Int16Property, 'Int16Property'),
    (CF.IntProperty, 'IntProperty'), (CF.Int64Property, 'Int64Property'), (CF.UInt16Property, 'UInt16Property'),
    (CF.UInt32Property, 'UInt32Property'), (CF.UInt64Property, 'UInt64Property'),
))

_U32 = 0xFFFFFFFF
_U64 = 0xFFFFFFFFFFFFFFFF
_MAX_NESTING = 8
_MAX_OUTERS = 256
_SAMPLE_LIMIT = 200
_MAX_INTERFACES = 4096  # live TArray cap for UClass.ImplementedInterfaces
_FIELD_PATH = int(CF.FieldPathProperty)
_OBJECT_KINDS = frozenset({'ObjectProperty', 'WeakObjectProperty', 'LazyObjectProperty', 'SoftObjectProperty', 'InterfaceProperty'})
_CLASS_KINDS = frozenset({'ClassProperty', 'SoftClassProperty'})
_DELEGATE_KINDS = frozenset({'MulticastInlineDelegateProperty', 'MulticastSparseDelegateProperty', 'DelegateProperty'})
_COUNT_KEYS = ('objects', 'packages', 'classes', 'structs', 'enums', 'functions')
# per-slot kind bits of the walk
_ROW, _CDO, _PACKAGE, _STRUCT, _CLASS, _FUNCTION, _ENUM = 1, 2, 4, 8, 16, 32, 64
_TYPE_CAST_FLAGS = int(CF.Package | CF.Struct | CF.Class | CF.Function | CF.Enum)  # a row is type-relevant for the quality verdict
QUALITY_THRESHOLDS = {'unreadable_type': 0, 'unreadable_fields': 0, 'unreadable_name': 0, 'unreadable_interfaces': 0,
                      'index_mismatch_type_ratio': 0.001}


def kind_of(cast_flags: int, objptr_instead_of_fieldpath: bool) -> str:
    """The first PROPERTY_KIND_ORDER kind whose bit is in `cast_flags`, or 'unknown'."""
    if not isinstance(cast_flags, int):
        raise TypeError(f'cast_flags must be an int, got {type(cast_flags).__name__}')
    for bit, kind in PROPERTY_KIND_ORDER:
        if cast_flags & bit:
            return 'ObjectProperty' if bit == _FIELD_PATH and objptr_instead_of_fieldpath else kind
    return 'unknown'


def enum_size_for_values(values: Iterable[tuple[str, int]]) -> int:
    """EnumManager::InitInternal's max-value rule @ ea0dab3 (SetEnumSizeForValue over the non-`_MAX` values)."""
    max_value = 0
    for item in values:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise TypeError(f'enum value must be a (name, value) pair, got {item!r}')
        name, value = item
        if not isinstance(name, str) or not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f'enum value must be a (str, int) pair, got {item!r}')
        if not name.endswith('_MAX'):
            max_value = max(max_value, value & _U64)
    if max_value > 0xFFFFFFFF:
        return 8
    if max_value > 0xFFFF:
        return 4
    if max_value > 0xFF:
        return 2
    return 1


def _check_address(address) -> None:
    if not isinstance(address, int):
        raise TypeError(f'address must be an int, got {type(address).__name__}')


class TableResolver:
    """Paths of object addresses through a walked ObjectTable."""

    def __init__(self, table: ObjectTable):
        self.table = table

    def _index(self, address: int) -> int | None:
        _check_address(address)
        if not address or (rec := self.table.by_address(address)) is None:
            return None
        return rec.index

    def path(self, address: int) -> str | None:
        if (index := self._index(address)) is None:
            return None
        try:
            return self.table.path(index)
        except ValueError:
            return None

    def package(self, address: int) -> str | None:
        if (index := self._index(address)) is None:
            return None
        try:
            return self.table.path(self.table.package_of(index))
        except ValueError:
            return None


class LiveResolver:
    """Paths of object addresses walked live through get_outer(), with ObjectTable.path's separator rule."""

    def __init__(self, e: 'Engine'):
        self.e = e
        self._package_class: dict[int, bool] = {}

    def _chain(self, address: int) -> list[int] | None:
        _check_address(address)
        if not address:
            return None
        chain = [address]
        while outer := UEObject(self.e, chain[-1]).get_outer().address:
            if outer in chain or len(chain) > _MAX_OUTERS:
                return None
            chain.append(outer)
        return chain

    def _is_package(self, address: int) -> bool:
        cls = UEObject(self.e, address).get_class().address
        if (result := self._package_class.get(cls)) is None:
            result = self._package_class[cls] = bool(cls and UEClass(self.e, cls).get_cast_flags() & CF.Package)
        return result

    def _name(self, address: int) -> str:
        return UEObject(self.e, address).get_fname().to_raw_string()

    def path(self, address: int) -> str | None:
        if (chain := self._chain(address)) is None:
            return None
        result = self._name(chain[-1])
        for pos in range(len(chain) - 2, -1, -1):
            outer = chain[pos + 1]
            outer_outer = chain[pos + 2] if pos + 2 < len(chain) else None
            sep = ':' if not self._is_package(outer) and outer_outer is not None and self._is_package(outer_outer) else '.'
            result = f'{result}{sep}{self._name(chain[pos])}'
        return result

    def package(self, address: int) -> str | None:
        if (chain := self._chain(address)) is None:
            return None
        return self._name(chain[-1])


def _check_wrapper(obj) -> None:
    if obj.address == 0:
        raise ValueError('null object')


class Reflection:
    """Builds F8 records from an engine's wrappers; paths come from `resolver`."""

    def __init__(self, e: 'Engine', resolver, *, issue: Callable[[str, str], None] | None = None):
        self.e = e
        self.resolver = resolver
        self._issue = issue

    def _report(self, kind: str, sample: str) -> None:
        if self._issue is not None:
            self._issue(kind, sample)

    def _path(self, obj) -> str | None:
        return self.resolver.path(obj.address)

    def _nested(self, prop: UEProperty, depth: int) -> PropType | None:
        return self._prop_type(prop, depth + 1) if prop.address else None

    def _prop_type(self, prop: UEProperty, depth: int) -> PropType:
        if depth > _MAX_NESTING:
            raise MemoryReadError(prop.address, 0, f'property type nesting at {prop.address:#x} exceeds {_MAX_NESTING} levels')
        kind = kind_of(prop.get_cast_flags(), self.e.settings.Internal.bIsObjPtrInsteadOfFieldPathProperty)
        t = PropType(prop=prop.get_prop_class_name(), kind=kind)
        if kind in _CLASS_KINDS:
            p = prop.cast(UEClassProperty)
            t.cls, t.meta_class = self._path(p.get_property_class()), self._path(p.get_meta_class())
        elif kind in _OBJECT_KINDS:
            t.cls = self._path(prop.cast(UEObjectProperty).get_property_class())
        elif kind == 'StructProperty':
            t.struct = self._path(prop.cast(UEStructProperty).get_underlaying_struct())
        elif kind == 'ArrayProperty':
            t.inner = self._nested(prop.cast(UEArrayProperty).get_inner_property(), depth)
        elif kind == 'SetProperty':
            t.element = self._nested(prop.cast(UESetProperty).get_element_property(), depth)
        elif kind == 'MapProperty':
            p = prop.cast(UEMapProperty)
            t.key, t.value = self._nested(p.get_key_property(), depth), self._nested(p.get_value_property(), depth)
        elif kind == 'OptionalProperty':
            t.value = self._nested(prop.cast(UEOptionalProperty).get_value_property(), depth)
        elif kind == 'EnumProperty':
            p = prop.cast(UEEnumProperty)
            t.enum, t.underlying = self._path(p.get_enum()), self._nested(p.get_underlaying_property(), depth)
        elif kind == 'ByteProperty':
            t.enum = self._path(prop.cast(UEByteProperty).get_enum())
        elif kind == 'BoolProperty':
            base, mem = prop.address + self.e.off.BoolProperty.Base, self.e.mem
            t.field_size, t.byte_offset, t.byte_mask, t.field_mask = mem.u8(base), mem.u8(base + 1), mem.u8(base + 2), mem.u8(base + 3)
        elif kind in _DELEGATE_KINDS:
            t.signature = self._path(prop.cast(UEDelegateProperty).get_signature_function())
        elif kind == 'FieldPathProperty':
            field_class = prop.cast(UEFieldPathProperty).get_field_class()
            t.field_class = field_class.get_name() if field_class.address else None
        return t

    def prop_type(self, prop: UEProperty) -> PropType:
        _check_wrapper(prop)
        return self._prop_type(prop, 0)

    def property_record(self, prop: UEProperty) -> PropertyRecord:
        _check_wrapper(prop)
        return PropertyRecord(name=prop.get_name(), offset=prop.get_offset(), size=prop.get_size(), array_dim=prop.get_array_dim(),
                              flags=prop.get_property_flags() & _U64, type=self._prop_type(prop, 0), address=prop.address)

    def _struct_fields(self, obj: UEStruct) -> dict:
        return dict(path=self.resolver.path(obj.address), name=obj.get_fname().to_raw_string(), cpp_name=obj.get_cpp_name(),
                    package=self.resolver.package(obj.address), super=self._path(obj.get_super()), size=obj.get_struct_size(),
                    min_alignment=obj.get_min_alignment(), properties=[self.property_record(p) for p in obj.get_properties()])

    def struct_record(self, obj: UEStruct) -> StructRecord:
        _check_wrapper(obj)
        return StructRecord(**self._struct_fields(obj.cast(UEStruct)))

    def function_record(self, fn: UEFunction) -> FunctionRecord:
        _check_wrapper(fn)
        fn = fn.cast(UEFunction)
        exec_rva = None
        if self.e.off.UFunction.ExecFunction > 0 and (exec_function := fn.get_exec_function()):
            exec_rva = exec_function - self.e.platform.get_module_base()
        return FunctionRecord(path=self.resolver.path(fn.address), name=fn.get_fname().to_raw_string(),
                              package=self.resolver.package(fn.address), flags=fn.get_function_flags() & _U32,
                              params_size=fn.get_struct_size(), params=[self.property_record(p) for p in fn.get_properties()],
                              exec_rva=exec_rva)

    def _class_record(self, cls: UEClass) -> tuple[ClassRecord, list[int]]:
        """The record and the addresses of the functions it lists."""
        _check_wrapper(cls)
        cls = cls.cast(UEClass)
        fields = self._struct_fields(cls)
        interfaces = []
        if self.e.off.UClass.ImplementedInterfaces >= 0:
            try:
                data, num = cls.get_implemented_interfaces().checked(_MAX_INTERFACES)
            except MemoryReadError as err:
                self._report('unreadable_interfaces', f'implemented interfaces header: {err}')
                data, num = 0, 0
            for i in range(num):
                item = view(FImplementedInterface, data + i * 0x10, self.e.acc)
                if (path := self.resolver.path(item.InterfaceClass)) is None:
                    self._report('unresolved_reference', f'implemented interface class {item.InterfaceClass:#x} does not resolve')
                    continue
                interfaces.append(InterfaceRecord(cls=path, pointer_offset=item.PointerOffset, implemented_by_k2=bool(item.bImplementedByK2)))
        functions, listed = {}, []
        for fn in cls.get_functions():
            name = fn.get_fname().to_raw_string()
            if name not in functions:
                functions[name] = self.function_record(fn)
                listed.append(fn.address)
        record = ClassRecord(**fields, cast_flags=cls.get_cast_flags(), cdo=self._path(cls.get_default_object()),
                             interfaces=interfaces, functions=functions)
        return record, listed

    def class_record(self, cls: UEClass) -> ClassRecord:
        return self._class_record(cls)[0]

    def enum_record(self, enum: UEEnum, size: int | None = None) -> EnumRecord:
        _check_wrapper(enum)
        enum = enum.cast(UEEnum)
        if size is not None and (isinstance(size, bool) or size not in (1, 2, 4, 8)):
            raise ValueError(f'invalid enum underlying size {size!r}')
        try:
            pairs = enum.get_name_value_pairs()
        except DetectionError as err:  # DV10
            self._report('enum_names_unsupported', err.detail)
            pairs = []
        valid_name = enum.get_valid_name()
        if size is None:
            underlying = (enum_size_for_values([(name.to_wstring(), value) for name, value in pairs]), 'max_value')
        else:
            underlying = (size, 'property')
        return EnumRecord(path=self.resolver.path(enum.address), name=enum.get_fname().to_raw_string(),
                          cpp_name=valid_name if valid_name[:1] == 'E' else 'E' + valid_name,  # UEEnum::GetEnumPrefixedName @ ea0dab3
                          package=self.resolver.package(enum.address), underlying_size=underlying[0], underlying_size_from=underlying[1],
                          underlying_signed=None, values=[(name.to_string(), value) for name, value in pairs])

    def type_record(self, obj: UEObject) -> TypeRecord | None:
        _check_wrapper(obj)
        if obj.get_flags() & EObjectFlags.ClassDefaultObject:  # as the walk: no type record for a CDO
            return None
        cast_flags = obj.get_class().get_cast_flags()
        if cast_flags & CF.Class:
            return self.class_record(obj.cast(UEClass))
        if cast_flags & CF.Function:
            return self.function_record(obj.cast(UEFunction))
        if cast_flags & CF.Struct:
            return self.struct_record(obj.cast(UEStruct))
        if cast_flags & CF.Enum:
            return self.enum_record(obj.cast(UEEnum))
        return None


@dataclasses.dataclass(frozen=True)
class WalkResult:
    partial: str
    counts: dict[str, int]
    issues: list[dict]
    walked: int
    unreadable: int
    seconds: float
    written: dict
    quality: dict


class _Issues:
    def __init__(self):
        self.entries: dict[str, dict] = {}

    def add(self, kind: str, index: int, name: str, detail) -> None:
        sample = f'{index} {name}: {detail}'.replace('\r', ' ').replace('\n', ' ')[:_SAMPLE_LIMIT]
        if (entry := self.entries.get(kind)) is None:
            self.entries[kind] = {'kind': kind, 'count': 1, 'first': sample, 'last': sample}
        else:
            entry['count'] += 1
            entry['last'] = sample

    def to_list(self) -> list[dict]:
        return [dict(entry) for entry in self.entries.values()]


class _Walk:
    """One walk's state; write_snapshot consumes objects(), fields(), types() in that order."""

    def __init__(self, e: 'Engine', check_alive, progress):
        self.e = e
        self.check_alive = check_alive
        self.progress = progress
        self.module_name = e.mem.main_module.name
        self.issues = _Issues()
        self.counts = dict.fromkeys(_COUNT_KEYS, 0)
        self.bits = bytearray()
        self.sizes: dict[int, int] = {}
        self.table: ObjectTable | None = None
        self.reflection: Reflection | None = None
        self.walked = self.unreadable = 0
        self.type_objects = self.type_mismatch = 0
        self.done = self.total = 0
        self.run = 0
        self.current = (-1, '?')
        self.reported_names = 0

    def _ok(self) -> None:
        self.run = 0

    def _fail(self) -> None:
        self.run += 1
        if self.run >= DEAD_TARGET_RUN and self.check_alive is not None:
            self.run = 0
            if not self.check_alive():
                raise TargetError(self.module_name, 'process exited during the walk')

    def _tick(self, k: int = 1) -> None:
        before = self.done // PROGRESS_EVERY
        self.done += k
        if self.progress is not None and self.done // PROGRESS_EVERY != before and self.done != self.total:
            self.progress(self.done, self.total)

    def _report_names(self, index: int, name: str) -> None:
        """One `unreadable_name` for each CompIdx the NameArray could not resolve since the last call."""
        if (new := len(unresolved := self.e.names.unresolved) - self.reported_names) > 0:
            for comp_idx in reversed(list(itertools.islice(reversed(unresolved), new))):  # only the new tail, in first-seen order
                self.issues.add('unreadable_name', index, name, f'CompIdx {comp_idx}')
            self.reported_names = len(unresolved)

    def _unreadable_object(self, index: int, name: str, err) -> None:
        self.unreadable += 1
        self.issues.add('unreadable_object', index, name, err)
        self._fail()

    def objects(self):
        e = self.e
        e.names.unresolved.clear()
        n = e.objects.num()
        slots, first_slot = [], {}
        for i in range(n):
            try:
                address = e.objects.get_by_index(i).address
            except MemoryReadError as err:
                self.walked += 1
                self._unreadable_object(i, '?', err)
                continue
            self._ok()
            if address:
                slots.append((i, address))
                first_slot.setdefault(address, i)
        self.walked += len(slots)
        self.total = 3 * self.walked
        self.bits = bytearray(max(n, 0))
        self._tick(self.unreadable)
        base = e.platform.get_module_base()
        class_cast_flags: dict[int, int] = {}
        records = []
        for i, address in slots:
            obj, name = UEObject(e, address), '?'
            try:
                name = obj.get_fname().to_raw_string()
                flags = obj.get_flags() & _U32
                stored_index = obj.get_index()
                cls, outer = obj.get_class().address, obj.get_outer().address
                if (cast_flags := class_cast_flags.get(cls)) is None:
                    cast_flags = class_cast_flags[cls] = UEClass(e, cls).get_cast_flags() if cls else 0
                vtable_rva = obj.get_vft() - base if flags & EObjectFlags.ClassDefaultObject else None
            except MemoryReadError as err:
                self._unreadable_object(i, name, err)
                self._tick()
                continue
            finally:
                self._report_names(i, name)
            self._ok()
            # a Package CDO is still counted (as `counts.packages` already does); any other CDO is not a type row
            type_relevant = bool(cast_flags & _TYPE_CAST_FLAGS) and (cast_flags & CF.Package or not flags & EObjectFlags.ClassDefaultObject)
            if type_relevant:
                self.type_objects += 1
            if stored_index != i:
                self.issues.add('index_mismatch', i, name, f'stored index {stored_index}')
                if type_relevant:
                    self.type_mismatch += 1
            class_index, outer_index = first_slot.get(cls, -1), first_slot.get(outer, -1)
            if cls and class_index < 0:
                self.issues.add('unresolved_class', i, name, f'class {cls:#x} is not in GObjects')
            if outer and outer_index < 0:
                self.issues.add('unresolved_outer', i, name, f'outer {outer:#x} is not in GObjects')
            bits = _ROW | (_CDO if flags & EObjectFlags.ClassDefaultObject else 0)
            for bit, flag in ((_PACKAGE, CF.Package), (_STRUCT, CF.Struct), (_CLASS, CF.Class), (_FUNCTION, CF.Function), (_ENUM, CF.Enum)):
                if cast_flags & flag:
                    bits |= bit
            self.bits[i] = bits
            record = ObjectRecord(index=i, address=address, flags=flags, class_index=class_index, outer_index=outer_index, name=name,
                                  vtable_rva=vtable_rva)
            records.append(record)
            self.counts['objects'] += 1
            self.counts['packages'] += bool(bits & _PACKAGE)
            self._tick()
            yield record
        self.table = ObjectTable(records)
        self.reflection = Reflection(e, TableResolver(self.table), issue=self._reflection_issue)

    def _reflection_issue(self, kind: str, sample: str) -> None:
        self.issues.add(kind, *self.current, sample)

    def fields(self):
        if self.table is None:
            raise RuntimeError('the objects stream must be consumed before the fields stream')
        e = self.e
        self._tick(self.unreadable)
        for rec in self.table:
            bits = self.bits[rec.index]
            if not bits & _STRUCT:
                self._tick()
                continue
            try:
                props = UEStruct(e, rec.address).get_properties()
                addresses = [p.address for p in props]
                sizes = []
                if not bits & _CDO:  # EnumManager::InitInternal @ ea0dab3
                    for prop in props:
                        cast_flags = prop.get_cast_flags()
                        if cast_flags & CF.EnumProperty:
                            enum = prop.cast(UEEnumProperty).get_enum()
                            if not prop.cast(UEEnumProperty).get_underlaying_property():
                                continue
                        elif cast_flags & CF.ByteProperty:
                            enum = prop.cast(UEByteProperty).get_enum()
                        else:
                            continue
                        if not enum:
                            continue
                        sizes.append((enum.get_index(), prop.get_size() & 0xFF))
            except MemoryReadError as err:
                self.issues.add('unreadable_fields', rec.index, rec.name, err)
                self._fail()
                self._tick()
                continue
            self._ok()
            self.sizes.update(sizes)
            self._tick()
            if addresses:
                yield rec.index, addresses

    def _type_record(self, rec: ObjectRecord, bits: int) -> tuple[TypeRecord, list[int]]:
        r, e = self.reflection, self.e
        if bits & _CLASS:
            return r._class_record(UEClass(e, rec.address))
        if bits & _FUNCTION:
            return r.function_record(UEFunction(e, rec.address)), []
        if bits & _STRUCT:
            return r.struct_record(UEStruct(e, rec.address)), []
        enum = UEEnum(e, rec.address)
        if (size := self.sizes.get(enum.get_index())) is not None and size not in (1, 2, 4, 8):  # DV14
            self.issues.add('enum_size_invalid', rec.index, rec.name, f'underlying size {size} from a property; max-value rule used')
            size = None
        return r.enum_record(enum, size), []

    def _emit(self, rec: ObjectRecord, bits: int, *emitted: set) -> tuple[str, TypeRecord, list[int]] | None:
        """(path, record, listed function addresses), or None after the cyclic_outer / duplicate_path / unreadable_type issue."""
        try:
            path = self.table.path(rec.index)
        except ValueError as err:
            self.issues.add('cyclic_outer', rec.index, rec.name, err)
            return None
        if any(path in s for s in emitted):
            self.issues.add('duplicate_path', rec.index, rec.name, f'path {path!r} already emitted')
            return None
        self.current = (rec.index, rec.name)
        try:
            record, functions = self._type_record(rec, bits)
        except MemoryReadError as err:
            self.issues.add('unreadable_type', rec.index, rec.name, err)
            self._fail()
            return None
        finally:
            self._report_names(rec.index, rec.name)
        self._ok()
        return path, record, functions

    def types(self):
        if self.reflection is None:
            raise RuntimeError('the objects stream must be consumed before the types stream')
        table, counts = self.table, self.counts
        emitted, nested, listed, class_functions = set(), set(), set(), []
        self._tick(self.unreadable)
        for rec in table:
            bits = self.bits[rec.index]
            if bits & _CDO or not bits & (_CLASS | _FUNCTION | _STRUCT | _ENUM):  # ea0dab3's managers skip every CDO
                self._tick()
                continue
            if bits & _FUNCTION and not bits & _CLASS and (outer := table.get(rec.outer_index)) is not None and self.bits[outer.index] & _CLASS:
                class_functions.append(rec)
                self._tick()
                continue
            if (got := self._emit(rec, bits, emitted)) is None:
                self._tick()
                continue
            path, record, functions = got
            emitted.add(path)
            listed.update(functions)
            if isinstance(record, ClassRecord):
                counts['classes'] += 1
                counts['functions'] += len(record.functions)
                nested.update(fn.path for fn in record.functions.values())
            elif isinstance(record, FunctionRecord):
                counts['functions'] += 1
            elif isinstance(record, StructRecord):
                counts['structs'] += 1
            else:
                counts['enums'] += 1
            self._tick()
            yield record
        for rec in class_functions:  # orphans: no progress tick, each row was visited above
            if rec.address in listed:
                continue
            self.issues.add('orphan_function', rec.index, rec.name, 'no emitted class lists this function')
            if (got := self._emit(rec, self.bits[rec.index], emitted, nested)) is not None:
                emitted.add(got[0])
                counts['functions'] += 1
                yield got[1]
        if self.progress is not None:
            self.progress(self.done, self.total)


def _quality(w: '_Walk') -> dict:
    """The export quality verdict from one walk's final issue and type-relevance counts.

    `degraded` when `unreadable_type`, `unreadable_fields`, `unreadable_name` or `unreadable_interfaces` is nonzero,
    or when `index_mismatch` over type-relevant rows exceeds `index_mismatch_type_ratio` of the type-relevant row count.
    """
    issue_counts = {kind: w.issues.entries.get(kind, {}).get('count', 0) for kind in ISSUE_KINDS}
    reasons = []
    for kind in ('unreadable_type', 'unreadable_fields', 'unreadable_name', 'unreadable_interfaces'):
        if issue_counts[kind] > QUALITY_THRESHOLDS[kind]:
            reasons.append(f'{kind} {issue_counts[kind]} > {QUALITY_THRESHOLDS[kind]}')
    ratio = QUALITY_THRESHOLDS['index_mismatch_type_ratio']
    if w.type_objects and w.type_mismatch > ratio * w.type_objects:
        reasons.append(f'index_mismatch {w.type_mismatch}/{w.type_objects} type-relevant rows > {ratio:.1%}')
    return {'verdict': 'degraded' if reasons else 'complete', 'reasons': reasons, 'counts': issue_counts,
            'type_counts': {'index_mismatch': w.type_mismatch}, 'objects': w.counts['objects'],
            'type_objects': w.type_objects, 'thresholds': dict(QUALITY_THRESHOLDS)}


def walk(ctx: 'EngineContext', folder, *, meta: dict, offsets: dict,
         check_alive: Callable[[], bool] | None = None, progress: Callable[[int, int], None] | None = None,
         generator: dict | None = None) -> WalkResult:
    """Stream the engine's objects, FField addresses and types into `<folder>.partial` (write_snapshot), with counts and issues in meta.json.

    Never renames or exports; any exception leaves `<folder>.partial` without meta.json.
    """
    if not isinstance(meta, dict):
        raise TypeError(f'meta must be a dict, got {type(meta).__name__}')
    if not isinstance(offsets, dict):
        raise TypeError(f'offsets must be a dict, got {type(offsets).__name__}')
    if check_alive is not None and not callable(check_alive):
        raise TypeError(f'check_alive must be callable or None, got {type(check_alive).__name__}')
    if progress is not None and not callable(progress):
        raise TypeError(f'progress must be callable or None, got {type(progress).__name__}')
    e = ctx.engine
    if not e.settings.Internal.bUseFProperty:
        raise DetectionError('reflect.walk', 'engines with UProperty reflection (UE < 4.25) are not supported yet')
    start = time.perf_counter()
    w = _Walk(e, check_alive, progress)
    written = write_snapshot(folder, lambda: {**meta, 'counts': dict(w.counts), 'issues': w.issues.to_list(), 'quality': _quality(w)},
                             offsets, w.objects(), w.types(), w.fields(), generator=generator)
    return WalkResult(partial=written['partial'], counts=dict(w.counts), issues=w.issues.to_list(), walked=w.walked,
                      unreadable=w.unreadable, seconds=time.perf_counter() - start, written=written, quality=_quality(w))
