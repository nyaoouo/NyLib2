"""Port gate: run stages 4-6 on one captured session and compare the result with its Dumper-7 oracle."""
import argparse
import collections
import dataclasses
import datetime
import json
import math
import os
import pathlib
import re
import sys
import tempfile
import time
import traceback

from .. import reflect
from ..capture import ImageSource
from ..engine.context import ENGINE_CORE_STEPS, EngineContext, init_engine_core
from ..engine.core import Engine
from ..engine.gnames import FNameEntry
from ..engine.unreal import UEEnum
from ..errors import MemoryReadError
from ..exports import run_export
from ..flags import EFunctionFlags, EObjectFlags, EPropertyFlags
from ..model import ClassRecord, EnumRecord, FunctionRecord, StructRecord
from ..names import make_name_valid, strip_path
from ..snapshot import Snapshot
from . import real
from .oracle import (DriftResult, GObjectsDump, compare_gobjects, compare_idmap, compare_offsets, flatten_oracle_offsets,
                     parse_basic_offsets, parse_gobjects_dump, parse_idmap, parse_offsets_info, parse_predefined_members)

CAPTURE_RESIDENT_BYTES = 1 << 30
K14_REASON = ("K14 (root Q30 = A): the oracle's GNames is Dumper-7 ea0dab3's first FNamePool candidate, which it never "
              "validates and which holds zeros in this capture; nylib.ue uses the pool that InitializeNamePool accepts")
# (target, check, item) -> recorded reason. Items: offsets = flattened key, gobjects / gobjects-props / props-exact /
# cdo-types = row index as '%08X', idmap = record name, names = name component, enums = enum name, dumpspace = oracle type key.
ACCEPTED: dict[tuple[str, str, str], str] = {        # (target, check, item) -> recorded reason; 6-G.2 adds entries, the review checks them
    ('pal', 'offsets', 'Offsets.GNames'): K14_REASON,             # pre-declared under Q30 = A; empty under Q30 = B
    ('pal', 'offsets', 'OffsetsInfo.OFFSET_GNAMES'): K14_REASON,
    ('fb', 'offsets', 'Offsets.GNames'): K14_REASON,
    ('fb', 'offsets', 'OffsetsInfo.OFFSET_GNAMES'): K14_REASON,
}
ORACLE_KEY_CATALOGUE: tuple[str, ...] = (
    'Offsets.GObjects', 'Offsets.AppendString', 'Offsets.GetNameEntry', 'Offsets.GNames', 'Offsets.GWorld', 'Offsets.ProcessEvent',
    'Offsets.ProcessEventIdx',
    'FUObjectItem.Object',
    'TUObjectArray.Objects', 'TUObjectArray.MaxElements', 'TUObjectArray.NumElements', 'TUObjectArray.MaxChunks', 'TUObjectArray.NumChunks',
    'FName.ComparisonIndex', 'FName.Number', 'FName.DisplayIndex',
    'TPersistentObjectPtr.TagAtLastTest', 'TPersistentObjectPtr.ObjectID',
    'FFieldPath.InitialFieldClass', 'FFieldPath.FieldPathSerialNumber', 'FFieldPath.ResolvedOwner', 'FFieldPath.Path',
    'TMulticastInlineDelegate.InvocationList',
    'FFieldClass.Name', 'FFieldClass.Id', 'FFieldClass.CastFlags', 'FFieldClass.ClassFlags', 'FFieldClass.SuperClass',
    'FFieldVariant.bIsUObject',
    'FField.VTable', 'FField.ClassPrivate', 'FField.Owner', 'FField.Next', 'FField.Name', 'FField.ObjFlags',
    'FProperty.ArrayDim', 'FProperty.ElementSize', 'FProperty.PropertyFlags', 'FProperty.Offset',
    'FByteProperty.Enum', 'FBoolProperty.FieldSize', 'FBoolProperty.ByteOffset', 'FBoolProperty.ByteMask', 'FBoolProperty.FieldMask',
    'FObjectPropertyBase.PropertyClass', 'FClassProperty.MetaClass', 'FStructProperty.Struct', 'FArrayProperty.InnerProperty',
    'FDelegateProperty.SignatureFunction', 'FMapProperty.KeyProperty', 'FMapProperty.ValueProperty', 'FSetProperty.ElementProperty',
    'FEnumProperty.UnderlayingProperty', 'FEnumProperty.Enum', 'FFieldPathProperty.FieldClass', 'FOptionalProperty.ValueProperty',
    'UObject.VTable', 'UObject.Flags', 'UObject.Index', 'UObject.Class', 'UObject.Name', 'UObject.Outer',
    'UField.Next',
    'UStruct.SuperStruct', 'UStruct.Children', 'UStruct.ChildProperties', 'UStruct.Size', 'UStruct.MinAlignment',
    'UFunction.FunctionFlags', 'UFunction.ExecFunction',
    'UClass.CastFlags', 'UClass.ClassDefaultObject',
    'UEnum.Names',
    'OffsetsInfo.OFFSET_GOBJECTS', 'OffsetsInfo.OFFSET_APPENDSTRING', 'OffsetsInfo.OFFSET_TOSTRING', 'OffsetsInfo.OFFSET_GNAMES',
    'OffsetsInfo.OFFSET_GWORLD', 'OffsetsInfo.OFFSET_PROCESSEVENT', 'OffsetsInfo.INDEX_PROCESSEVENT',
)
NAME_MISS_FLOOR = 10
NAME_MISS_SHARE = 0.0001
NAME_MIN_COMPONENTS = 10000
DUMPSPACE_MIN_TYPES = 1000
DUMPSPACE_MIN_MEMBERS = 10000
DUMPSPACE_DRIFT_BOUND = 0.01

CHECKS = ('offsets', 'gobjects', 'gobjects-props', 'idmap', 'stem', 'names', 'counts', 'enums', 'props-exact', 'cdo-types', 'dumpspace')
EXTRA_CHECKS = ('extra:from_snapshot', 'extra:live_resolver')
OFFSETS_MIN_VALUES = 25
IDMAP_MIN_RECORDS = 1000
ENUMS_MIN_COMPARED = 500
ENUMS_DRIFT_BOUND = 0.01
PROPS_EXACT_MIN_KEYS = 10000
CDO_TYPES_MIN_ROWS = 1000
EXTRA_NAME_SAMPLES = 1000
EXTRA_TYPE_SAMPLES = 200
_NAME_MISS_LISTED = 200
_U64 = (1 << 64) - 1
_ENUM_TYPE_SIZES = {'uint8': 1, 'uint16': 2, 'uint32': 4, 'uint64': 8}
_CATALOGUE = frozenset(ORACLE_KEY_CATALOGUE)


@dataclasses.dataclass(frozen=True)
class DumpspaceTypes:
    """Parsed Dumpspace StructsInfo.json + ClassesInfo.json and FunctionsInfo.json (6-G.4, review I4)."""
    types: dict[str, list[list]]          # key -> one body per occurrence (file order; StructsInfo then ClassesInfo)
    functions: dict[str, list[list]]      # class key -> one FunctionsInfo body per occurrence


@dataclasses.dataclass
class PortStep:
    name: str
    seconds: float | None = None
    status: str = 'not run'                  # ok | drift | skipped | error | not run
    detail: str = ''


@dataclasses.dataclass
class PortRun:
    """One session's port-gate run: steps, the walk result, one DriftResult per check; no engine, context or image."""
    session_id: str
    target: str
    dir: str
    steps: list[PortStep]
    walk: object = None                      # reflect.WalkResult
    checks: dict[str, DriftResult] = dataclasses.field(default_factory=dict)
    skipped: dict[str, str] = dataclasses.field(default_factory=dict)
    notes: list[str] = dataclasses.field(default_factory=list)
    error: str | None = None                 # '<step>: <Type>: <message>' of the step that stopped the run
    trace: str | None = None

    def step(self, name: str) -> PortStep:
        for s in self.steps:
            if s.name == name:
                return s
        self.steps.append(s := PortStep(name))
        return s

    @property
    def ok(self) -> bool:
        return all(s.status in ('ok', 'skipped') for s in self.steps)

    def report(self) -> str:
        lines = [f'session {self.target}/{os.path.basename(self.dir)} ({self.session_id})']
        for s in self.steps:
            secs = '' if s.seconds is None else f'{s.seconds:9.2f}s'
            lines.append(f'  {s.name:<26}{secs:>11}  {s.status:<8}{s.detail}')
            if (dr := self.checks.get(s.name.removeprefix('check:'))) is not None and s.name.startswith(('check:', 'extra:')):
                lines.extend(f'      {x}' for x in dr.samples)
        if self.walk is not None:
            lines.append(f'  walk: {self.walk.seconds:.2f}s, walked {self.walk.walked}, unreadable {self.walk.unreadable}, counts {self.walk.counts}')
        lines.extend(f'  note: {n}' for n in self.notes)
        if self.error:
            lines.append(f'  error: {self.error}')
        return '\n'.join(lines)


def _one_line(exc: BaseException) -> str:
    return f'{type(exc).__name__}: {exc}'.replace('\r', '').replace('\n', ' | ')


def _accepted(target: str, check: str) -> set[str]:
    return {item for (t, c, item) in ACCEPTED if t == target and c == check}


def _oracle_dir(session: real.Session) -> pathlib.Path:
    return pathlib.Path(session.dir) / 'oracle' / session.data['oracle']['folder']


def oracle_offsets(session: real.Session) -> dict[str, int]:
    """flatten_oracle_offsets of the session's Basic.hpp, CoreUObject_classes.hpp and OffsetsInfo.json."""
    d = _oracle_dir(session)
    basic_text = (d / 'CppSDK' / 'SDK' / 'Basic.hpp').read_text(encoding='utf-8-sig')
    members = parse_predefined_members(basic_text)
    core = parse_predefined_members((d / 'CppSDK' / 'SDK' / 'CoreUObject_classes.hpp').read_text(encoding='utf-8-sig'))
    if both := members.keys() & core.keys():
        raise ValueError(f'predefined members in both Basic.hpp and CoreUObject_classes.hpp: {sorted(both)}')
    return flatten_oracle_offsets(parse_basic_offsets(basic_text), {**members, **core}, parse_offsets_info(d / 'Dumpspace' / 'OffsetsInfo.json'))


def _doc_value(doc: dict, key: str):
    v = doc
    for part in key.split('.'):
        v = v[part]
    if isinstance(v, str):
        return int(v, 16)  # hexs: '0x..' or '-0x..'
    return v


def oracle_keys(offsets: dict, meta: dict) -> dict[str, int]:
    """Our values under the flattened oracle key grammar, read from offsets.json and meta.json (ORACLE_KEY_CATALOGUE)."""
    g = lambda key: _doc_value(offsets, key)
    eng = meta['engine']
    gobjects, append, gnames = g('Off.InSDK.ObjArray.GObjects'), g('Off.InSDK.Name.AppendNameToString'), g('Off.InSDK.NameArray.GNames')
    gworld, pe_offset, pe_index = g('Off.InSDK.World.GWorld'), g('Off.InSDK.ProcessEvent.PEOffset'), g('Off.InSDK.ProcessEvent.PEIndex')
    k = {'Offsets.GObjects': max(gobjects, 0), 'Offsets.AppendString': max(append, 0)}
    if g('Off.InSDK.Name.bIsAppendStringInlinedAndUsed'):
        k['Offsets.GetNameEntry'] = g('Off.InSDK.Name.GetNameEntryFromName')
    k.update({'Offsets.GNames': max(gnames, 0), 'Offsets.GWorld': max(gworld, 0), 'Offsets.ProcessEvent': max(pe_offset, 0),
              'Offsets.ProcessEventIdx': pe_index})

    k['FUObjectItem.Object'] = g('Off.InSDK.ObjArray.FUObjectItemInitialOffset')
    if g('Off.FUObjectArray.bIsChunked'):
        lay = g('Off.FUObjectArray.ChunkedFixedLayout')
        k.update({'TUObjectArray.Objects': int(lay['ObjectsOffset'], 16), 'TUObjectArray.MaxElements': int(lay['MaxElementsOffset'], 16),
                  'TUObjectArray.NumElements': int(lay['NumElementsOffset'], 16), 'TUObjectArray.MaxChunks': int(lay['MaxChunksOffset'], 16),
                  'TUObjectArray.NumChunks': int(lay['NumChunksOffset'], 16)})
    else:
        lay = g('Off.FUObjectArray.FixedLayout')
        k.update({'TUObjectArray.Objects': int(lay['ObjectsOffset'], 16), 'TUObjectArray.MaxElements': int(lay['MaxObjectsOffset'], 16),
                  'TUObjectArray.NumElements': int(lay['NumObjectsOffset'], 16)})

    number = g('Off.FName.Number')
    k['FName.ComparisonIndex'] = g('Off.FName.CompIdx')
    if not eng['outline_number_name']:
        k['FName.Number'] = number
    if eng['case_preserving_name']:
        k['FName.DisplayIndex'] = 0x8 if number == 4 else 0x4

    if not eng['weak_object_ptr_without_tag']:
        k['TPersistentObjectPtr.TagAtLastTest'] = 0x8
    k['TPersistentObjectPtr.ObjectID'] = 0x8 if eng['weak_object_ptr_without_tag'] else 0xC

    fprop = eng['use_fproperty']
    if fprop:
        if g('PropertySizes.FieldPathProperty') > 0x20:
            k.update({'FFieldPath.InitialFieldClass': 0x8, 'FFieldPath.FieldPathSerialNumber': 0x10,
                      'FFieldPath.ResolvedOwner': 0x14, 'FFieldPath.Path': 0x1C})
        else:
            k.update({'FFieldPath.ResolvedOwner': 0x8, 'FFieldPath.Path': 0x10})
    k['TMulticastInlineDelegate.InvocationList'] = g('PropertySizes.MulticastInlineDelegateProperty') - 0x10
    if fprop and not eng['mask_for_field_owner']:
        k['FFieldVariant.bIsUObject'] = 0x8

    if fprop:
        for member in ('Name', 'Id', 'CastFlags', 'ClassFlags', 'SuperClass'):
            k[f'FFieldClass.{member}'] = g(f'Off.FFieldClass.{member}')
        for member, field in (('VTable', 'Vft'), ('ClassPrivate', 'Class'), ('Owner', 'Owner'), ('Next', 'Next'), ('Name', 'Name'), ('ObjFlags', 'Flags')):
            k[f'FField.{member}'] = g(f'Off.FField.{field}')
        for member, field in (('ArrayDim', 'ArrayDim'), ('ElementSize', 'ElementSize'), ('PropertyFlags', 'PropertyFlags'), ('Offset', 'Offset_Internal')):
            k[f'FProperty.{member}'] = g(f'Off.Property.{field}')
        bool_base, map_base, enum_base = g('Off.BoolProperty.Base'), g('Off.MapProperty.Base'), g('Off.EnumProperty.Base')
        k.update({
            'FByteProperty.Enum': g('Off.ByteProperty.Enum'),
            'FBoolProperty.FieldSize': bool_base, 'FBoolProperty.ByteOffset': bool_base + 1,
            'FBoolProperty.ByteMask': bool_base + 2, 'FBoolProperty.FieldMask': bool_base + 3,
            'FObjectPropertyBase.PropertyClass': g('Off.ObjectProperty.PropertyClass'),
            'FClassProperty.MetaClass': g('Off.ClassProperty.MetaClass'),
            'FStructProperty.Struct': g('Off.StructProperty.Struct'),
            'FArrayProperty.InnerProperty': g('Off.ArrayProperty.Inner'),
            'FDelegateProperty.SignatureFunction': g('Off.DelegateProperty.SignatureFunction'),
            'FMapProperty.KeyProperty': map_base, 'FMapProperty.ValueProperty': map_base + 8,
            'FSetProperty.ElementProperty': g('Off.SetProperty.ElementProp'),
            'FEnumProperty.UnderlayingProperty': enum_base, 'FEnumProperty.Enum': enum_base + 8,
            'FFieldPathProperty.FieldClass': g('Off.FieldPathProperty.FieldClass'),
            'FOptionalProperty.ValueProperty': g('Off.OptionalProperty.ValueProperty'),
        })

    for member, field in (('VTable', 'Vft'), ('Flags', 'Flags'), ('Index', 'Index'), ('Class', 'Class'), ('Name', 'Name'), ('Outer', 'Outer')):
        k[f'UObject.{member}'] = g(f'Off.UObject.{field}')
    k['UField.Next'] = g('Off.UField.Next')
    for member in ('SuperStruct', 'Children', 'Size', 'MinAlignment'):
        k[f'UStruct.{member}'] = g(f'Off.UStruct.{member}')
    if fprop:
        k['UStruct.ChildProperties'] = g('Off.UStruct.ChildProperties')
    k['UFunction.FunctionFlags'] = g('Off.UFunction.FunctionFlags')
    k['UFunction.ExecFunction'] = g('Off.UFunction.ExecFunction')
    k['UClass.CastFlags'] = g('Off.UClass.CastFlags')
    k['UClass.ClassDefaultObject'] = g('Off.UClass.ClassDefaultObject')
    k['UEnum.Names'] = g('Off.UEnum.Names')

    k['OffsetsInfo.OFFSET_GOBJECTS'] = gobjects & _U64
    k['OffsetsInfo.OFFSET_APPENDSTRING' if g('Off.InSDK.Name.bIsUsingAppendStringOverToString') else 'OffsetsInfo.OFFSET_TOSTRING'] = append & _U64
    k['OffsetsInfo.OFFSET_GNAMES'] = gnames & _U64
    k['OffsetsInfo.OFFSET_GWORLD'] = gworld & _U64
    k['OffsetsInfo.OFFSET_PROCESSEVENT'] = pe_offset & _U64
    k['OffsetsInfo.INDEX_PROCESSEVENT'] = pe_index & _U64
    if stray := k.keys() - _CATALOGUE:
        raise AssertionError(f'oracle_keys produced keys outside ORACLE_KEY_CATALOGUE: {sorted(stray)}')
    return k


def compare_offset_keys(ours: dict, oracle: dict, *, target: str) -> DriftResult:
    """compare_offsets after removing ACCEPTED items, plus symmetric presence over the catalogue."""
    accepted = _accepted(target, 'offsets')
    ours = {k: v for k, v in ours.items() if k not in accepted}
    oracle = {k: v for k, v in oracle.items() if k not in accepted}
    base = compare_offsets(ours, oracle, min_values=OFFSETS_MIN_VALUES)
    missing = [k for k in oracle if k in _CATALOGUE and k not in ours]
    extra = [k for k in ours if k not in oracle]
    reasons = [base.reason] if base.reason else []
    if missing:
        reasons.append(f'catalogue keys missing from ours: {missing}')
    if extra:
        reasons.append(f'keys of ours not in the oracle: {extra}')
    samples = base.samples + tuple(f'{k}: missing from ours (oracle={oracle[k]:#x})' for k in missing) + \
        tuple(f'{k}: not in the oracle (ours={ours[k]:#x})' for k in extra)
    return dataclasses.replace(base, ok=base.ok and not missing and not extra, reason='; '.join(reasons), samples=samples)


def compare_gobjects_capture(ours: GObjectsDump, oracle: GObjectsDump, *, target: str, check: str) -> DriftResult:
    """compare_gobjects after dropping ACCEPTED rows, failing on any changed key (6-G.4, review I3: no allowance on a capture)."""
    if check not in ('gobjects', 'gobjects-props'):
        raise ValueError(f"check must be 'gobjects' or 'gobjects-props', got {check!r}")
    accepted = _accepted(target, check)
    dr = compare_gobjects(_drop_rows(ours, accepted), _drop_rows(oracle, accepted), compare_props=(check == 'gobjects-props'))
    if dr.changed > 0:
        reason = f'{dr.changed} changed keys (no allowance on a capture)'
        dr = dataclasses.replace(dr, ok=False, reason='; '.join(filter(None, (reason, dr.reason))))
    return dr


class _PoolStrings(set):
    read_errors = 0


def pool_strings(e) -> set[str] | None:
    """Every FNamePool entry decoded by E6's FNameEntry.get_string(); None on an outline-number or non-pool engine."""
    s, names, o = e.settings.Internal, e.names, e.off
    if s.bUseOutlineNumberName or not s.bUseNamePool or not names.GNames:
        return None
    stride = names.NameEntryStride
    block_size = stride << names.FNameBlockOffsetBits
    last, cursor = names.get_num_chunks(), names.get_byte_cursor()
    hdr_off, str_off, shift = o.FNameEntry.NamePool.HeaderOffset, o.FNameEntry.NamePool.StringOffset, names.FNameEntryLengthShiftCount
    out = _PoolStrings()
    for b in range(last + 1):
        end = cursor if b == last else block_size
        try:
            block = e.mem.ptr(names.GNames + o.NameArray.ChunksStart + 8 * b)
            pos = 0
            while pos < end:
                header = e.mem.u16(block + pos + hdr_off)
                if not (length := header >> shift):
                    break
                out.add(FNameEntry(e, block + pos).get_string())
                size = str_off + length * (2 if header & 1 else 1)
                pos += -(-size // stride) * stride
        except MemoryReadError:
            out.read_errors += 1
    return out


def name_components(dump: GObjectsDump, props_dump: GObjectsDump) -> set[str]:
    """The oracle's name components: object class and '.'-separated outer chain parts, property class and name."""
    comps = set()
    for d in (dump, props_dump):
        for _index, _address, full_name in d.rows:
            cls, _, rest = full_name.partition(' ')
            comps.add(cls)
            comps.update(rest.split('.'))
    for rows in props_dump.props.values():
        for _offset, _address, prop, name in rows:
            comps.add(prop)
            comps.add(name)
    comps.discard('')
    return comps


def _covered(component: str, base: set[str]) -> bool:
    if component in base:
        return True
    head, sep, n = component.rpartition('_')
    return bool(sep) and (n == '0' or (n[:1] in '123456789' and n.isascii() and n.isdigit())) and head in base


def compare_names(pool: set[str], components: set[str], *, target: str) -> DriftResult:
    """The churn-free name check: every oracle name component must be in the pool, up to the expected churn."""
    comps = set(components) - _accepted(target, 'names')
    base = {s.rsplit('/', 1)[-1] for s in pool}
    misses = sorted(c for c in comps if not _covered(c, base))
    limit = max(NAME_MISS_FLOOR, math.ceil(NAME_MISS_SHARE * len(comps)))
    non_ascii = [m for m in misses if not m.isascii()]
    reasons = []
    if len(comps) < NAME_MIN_COMPONENTS:
        reasons.append(f'too few name components ({len(comps)} < {NAME_MIN_COMPONENTS})')
    if len(misses) > limit:
        reasons.append(f'{len(misses)} misses exceed the limit {limit}')
    if non_ascii:
        reasons.append(f'{len(non_ascii)} non-ASCII misses')
    samples = [f'miss: {m!r}' for m in misses[:_NAME_MISS_LISTED]]
    if len(misses) > _NAME_MISS_LISTED:
        samples.append(f'... and {len(misses) - _NAME_MISS_LISTED} more misses')
    samples.append(f'pool: {len(pool)} strings, {getattr(pool, "read_errors", 0)} block read errors; components: {len(comps)}; limit: {limit}')
    return DriftResult(ok=not reasons, matched=len(comps) - len(misses), changed=len(misses),
                       drift=len(misses) / max(1, len(comps)), reason='; '.join(reasons), samples=tuple(samples))


def _oracle_enums(path) -> dict[str, list[tuple[int | None, list[int]]]]:
    """Dumpspace EnumsInfo.json: name -> [(underlying size or None, sorted unsigned 64-bit values)] per occurrence."""
    doc = json.loads(pathlib.Path(path).read_text(encoding='utf-8'))
    data = doc.get('data') if isinstance(doc, dict) else None
    if not isinstance(data, list):
        raise ValueError(f"{path}: 'data' must be a JSON array")
    out = {}
    for i, item in enumerate(data):
        if not isinstance(item, dict) or len(item) != 1:
            raise ValueError(f'{path}: data[{i}] must be a one-key object')
        (name, body), = item.items()
        if not (isinstance(body, list) and len(body) == 2 and isinstance(body[0], list) and isinstance(body[1], str)):
            raise ValueError(f'{path}: data[{i}] {name!r} must be [members, type]')
        values = []
        for m in body[0]:
            if not isinstance(m, dict) or len(m) != 1:
                raise ValueError(f'{path}: data[{i}] {name!r} has a malformed member {m!r}')
            (_, v), = m.items()
            if not isinstance(v, int) or isinstance(v, bool):
                raise ValueError(f'{path}: data[{i}] {name!r} has a non-integer value {v!r}')
            values.append(v & _U64)
        out.setdefault(name, []).append((_ENUM_TYPE_SIZES.get(body[1]), sorted(values)))
    return out


def _our_enums(snapshot) -> dict[str, list[tuple[int, list[int]]]]:
    out = {}
    for rec in snapshot.types():
        if rec.kind == 'enum':
            # 6-G.4 (review M3): the oracle's EnumsInfo.json stores values as C++ int; truncate ours the same way first.
            out.setdefault(rec.cpp_name, []).append(
                (rec.underlying_size, sorted(((v + 2**31) % 2**32 - 2**31) & _U64 for _, v in rec.values)))
    return out


def _compare_enums(ours: dict, oracle: dict, *, target: str) -> DriftResult:
    """Enums with unique names on both sides: underlying size and sorted values (F6.1 = A)."""
    accepted = _accepted(target, 'enums')
    o_unique = {n: v[0] for n, v in oracle.items() if len(v) == 1 and '::' not in n and n not in accepted}
    u_unique = {n: v[0] for n, v in ours.items() if len(v) == 1 and n not in accepted}
    common = [n for n in o_unique if n in u_unique]
    samples, changed = [], 0
    for n in common:
        (osize, ovals), (usize, uvals) = o_unique[n], u_unique[n]
        if osize != usize or ovals != uvals:
            changed += 1
            if len(samples) < 5:
                what = f'size ours={usize} oracle={osize}' if osize != usize else f'values ours={uvals[:8]} oracle={ovals[:8]}'
                samples.append(f'{n}: {what}')
    oracle_only = [n for n in o_unique if n not in ours and n not in accepted]
    ours_only = [n for n in u_unique if n not in oracle and n not in accepted]
    samples += [f'{n}: oracle-only' for n in oracle_only[:max(0, 5 - len(samples))]]
    samples += [f'{n}: ours-only' for n in ours_only[:max(0, 5 - len(samples))]]
    drift = (changed + len(oracle_only) + len(ours_only)) / max(1, len(o_unique))
    reasons = []
    if len(common) < ENUMS_MIN_COMPARED:
        reasons.append(f'too few enums compared ({len(common)} < {ENUMS_MIN_COMPARED})')
    if drift > ENUMS_DRIFT_BOUND:
        reasons.append(f'drift {drift:.4f} exceeds {ENUMS_DRIFT_BOUND} (changed {changed}, oracle-only {len(oracle_only)}, ours-only {len(ours_only)})')
    return DriftResult(ok=not reasons, matched=len(common) - changed, changed=changed, drift=drift,
                       reason='; '.join(reasons), samples=tuple(samples))


# ---- dumpspace (6-G.4, review I4) -------------------------------------------------------------

def _ds_one_key(obj, *, where: str):
    if not isinstance(obj, dict) or len(obj) != 1:
        raise ValueError(f'{where} must be a one-key object')
    return next(iter(obj.items()))


def _ds_file(folder, name: str):
    p = pathlib.Path(folder) / name
    doc = json.loads(p.read_text(encoding='utf-8'))
    if not isinstance(doc, dict) or not isinstance(doc.get('data'), list):
        raise ValueError(f"{p}: 'data' must be a JSON array")
    return p, doc['data']


def parse_dumpspace(folder: str | os.PathLike) -> DumpspaceTypes:
    """Parse a Dumper-7 Dumpspace folder's StructsInfo.json + ClassesInfo.json and FunctionsInfo.json."""
    if not isinstance(folder, (str, os.PathLike)):
        raise TypeError(f'folder must be str or os.PathLike, got {type(folder).__name__}')
    types: dict[str, list] = {}
    for fname in ('StructsInfo.json', 'ClassesInfo.json'):
        p, data = _ds_file(folder, fname)
        for i, item in enumerate(data):
            key, body = _ds_one_key(item, where=f'{p}: data[{i}]')
            if not (isinstance(body, list) and len(body) >= 2):
                raise ValueError(f'{p}: data[{i}] {key!r} must be a list of at least 2 entries')
            h0, h1 = body[0], body[1]
            if not (isinstance(h0, dict) and list(h0) == ['__InheritInfo'] and isinstance(h0['__InheritInfo'], list)
                    and all(isinstance(s, str) for s in h0['__InheritInfo'])):
                raise ValueError(f'{p}: data[{i}] {key!r} missing a valid __InheritInfo header')
            if not (isinstance(h1, dict) and list(h1) == ['__MDKClassSize']
                    and isinstance(h1['__MDKClassSize'], int) and not isinstance(h1['__MDKClassSize'], bool)):
                raise ValueError(f'{p}: data[{i}] {key!r} missing a valid __MDKClassSize header')
            for j, m in enumerate(body[2:], start=2):
                mname, mval = _ds_one_key(m, where=f'{p}: data[{i}] {key!r} member[{j}]')
                if not (isinstance(mval, list) and len(mval) in (4, 5)):
                    raise ValueError(f'{p}: data[{i}] {key!r} member {mname!r} must be a 4- or 5-element list')
            types.setdefault(key, []).append(body)
    p, data = _ds_file(folder, 'FunctionsInfo.json')
    functions: dict[str, list] = {}
    for i, item in enumerate(data):
        key, body = _ds_one_key(item, where=f'{p}: data[{i}]')
        if not isinstance(body, list):
            raise ValueError(f'{p}: data[{i}] {key!r} must be a list')
        for j, fn in enumerate(body):
            fname, fval = _ds_one_key(fn, where=f'{p}: data[{i}] {key!r} function[{j}]')
            if not (isinstance(fval, list) and len(fval) == 4 and isinstance(fval[1], list)):
                raise ValueError(f'{p}: data[{i}] {key!r} function {fname!r} must be [return, params, offset, flags]')
        functions.setdefault(key, []).append(body)
    return DumpspaceTypes(types=types, functions=functions)


class _DsUnresolved(Exception):
    """A referenced path or name has no record: a difference, not a skip."""


class _DsNonUnique(Exception):
    """A referenced name occurs more than once: the rendering is skipped and counted."""


def _ds_align(size: int, alignment: int) -> int:
    return size if alignment <= 0 else -(-size // alignment) * alignment


# ea0dab3 Enums.h StringifyFunctionFlags: display string per flag, in declaration order. A literal typo in that C++
# source ("HasOutParams") diverges from the EFunctionFlags member name ("HasOutParms"); kept verbatim for parity.
_FUNCTION_FLAG_DISPLAY = {f.name: f.name for f in EFunctionFlags} | {'HasOutParms': 'HasOutParams'}


def _stringify_function_flags(flags: int) -> str:
    """ea0dab3 Enums.h StringifyFunctionFlags(flags, '|'): its 30 names, in declaration order."""
    return '|'.join(_FUNCTION_FLAG_DISPLAY[f.name] for f in EFunctionFlags if flags & f)


_DIGIT_SUFFIX_RE = re.compile(r'(.+)_(\d+)')


def _ds_name_candidates(oracle_name: str, *, prefix: str | None = None, name_suffix: str | None = None) -> list[str]:
    """Possible base names after CollisionManager's optional trailing `_<digits>`, optional `_<name_suffix>`, optional leading
    `prefix`, most-specific (least stripped) first: an exact match must win over a stripped one (6-G.4 debugging)."""
    variants = [oracle_name]
    m = _DIGIT_SUFFIX_RE.fullmatch(oracle_name)
    no_digits = m.group(1) if m else oracle_name
    if no_digits not in variants:
        variants.append(no_digits)
    if name_suffix:
        suffix = f'_{name_suffix}'
        for v in list(variants):
            if v.endswith(suffix) and len(v) > len(suffix) and v[:-len(suffix)] not in variants:
                variants.append(v[:-len(suffix)])
    if prefix:
        for v in list(variants):
            if v.startswith(prefix) and len(v) > len(prefix) and v[len(prefix):] not in variants:
                variants.append(v[len(prefix):])
    return variants


def _ds_pair_by_name(oracle_items, our_items, *, key_of_our, candidates_of_oracle):
    """FIFO pairing by name: oracle_items = [(name, value), ...]; returns (pairs, unpaired_oracle, unpaired_ours)."""
    queues: dict[str, collections.deque] = {}
    for obj in our_items:
        queues.setdefault(key_of_our(obj), collections.deque()).append(obj)
    pairs, unpaired_oracle = [], []
    for name, value in oracle_items:
        found = None
        for cand in candidates_of_oracle(name):
            q = queues.get(cand)
            if q:
                found = q.popleft()
                break
        if found is None:
            unpaired_oracle.append((name, value))
        else:
            pairs.append((name, value, found))
    unpaired_ours = [o for q in queues.values() for o in q]
    return pairs, unpaired_oracle, unpaired_ours


_DS_SIMPLE_TYPE_NAMES = {
    'UInt16Property': 'uint16', 'UInt32Property': 'uint32', 'UInt64Property': 'uint64',
    'Int8Property': 'int8', 'Int16Property': 'int16', 'IntProperty': 'int32', 'Int64Property': 'int64',
    'FloatProperty': 'float', 'DoubleProperty': 'double',
    'NameProperty': 'FName', 'StrProperty': 'FString', 'TextProperty': 'FText',
}


def _ds_struct_node(path: str | None, by_path: dict, name_counts: collections.Counter, *, default_name: str | None, default_et: str = 'C'):
    """ea0dab3 DumpspaceGenerator::GetMemberType(const StructWrapper&): [cpp_name, 'C'|'S', '*' or '', []]."""
    if path is None:
        if default_name is None:
            raise _DsUnresolved
        return [default_name, default_et, '*' if default_et == 'C' else '', []]
    rec = by_path.get(path)
    if rec is None:
        raise _DsUnresolved
    if name_counts.get(rec.cpp_name, 0) != 1:
        raise _DsNonUnique
    et = 'C' if rec.kind == 'class' else 'S'
    return [rec.cpp_name, et, '*' if et == 'C' else '', []]


def _ds_compare_node(ptype, flags: int, oracle, *, top_level: bool, by_path: dict, name_counts: collections.Counter) -> bool:
    """Compare our PropType against one oracle `<type>` node (ea0dab3 DumpspaceGenerator::GetMember{EType,TypeStr})."""
    if not (isinstance(oracle, list) and len(oracle) == 4):
        return False
    o_name, o_et, o_ext, o_sub = oracle
    kind = ptype.kind

    def nested(sub_ptype, sub_oracle) -> bool:
        return _ds_compare_node(sub_ptype, 0, sub_oracle, top_level=False, by_path=by_path, name_counts=name_counts)

    if kind == 'ByteProperty':
        if ptype.enum is not None:
            rec = by_path.get(ptype.enum)
            if rec is None:
                raise _DsUnresolved
            if name_counts.get(rec.cpp_name, 0) != 1:
                raise _DsNonUnique
            return oracle == [rec.cpp_name, 'E', '', []]
        return oracle == ['uint8', 'D', '', []]
    if kind in _DS_SIMPLE_TYPE_NAMES:
        return oracle == [_DS_SIMPLE_TYPE_NAMES[kind], 'D', '', []]
    if kind == 'ClassProperty':  # FClassProperty : FObjectProperty -> IsA(ObjectProperty) -> ET_Class
        if top_level:
            if flags & EPropertyFlags.UObjectWrapper:
                return oracle == ['TSubclassOf', 'C', '', [_ds_struct_node(ptype.meta_class, by_path, name_counts, default_name=None)]]
            return oracle == ['UClass', 'C', '*', []]
        # Nested (array/map/set/optional element): UObjectWrapper isn't recorded on a nested PropType (R2), so
        # either rendering matches (6-G.4, review I4: "a nested class property ... matches either").
        if o_name == 'TSubclassOf':
            return oracle == ['TSubclassOf', 'C', '', [_ds_struct_node(ptype.meta_class, by_path, name_counts, default_name=None)]]
        return oracle == ['UClass', 'C', '*', []]
    if kind == 'SoftClassProperty':
        return oracle == ['TSoftClassPtr', 'D', '', [_ds_struct_node(ptype.cls, by_path, name_counts, default_name='UClass')]]
    if kind == 'ObjectProperty':
        if ptype.cls is not None:
            rec = by_path.get(ptype.cls)
            if rec is None:
                raise _DsUnresolved
            if name_counts.get(rec.cpp_name, 0) != 1:
                raise _DsNonUnique
            et = 'C' if rec.kind == 'class' else 'S'
            return oracle == [rec.cpp_name, et, '*', []]
        return oracle == ['UObject', 'C', '*', []]
    if kind == 'WeakObjectProperty':
        return oracle == ['TWeakObjectPtr', 'D', '', [_ds_struct_node(ptype.cls, by_path, name_counts, default_name='UObject')]]
    if kind == 'LazyObjectProperty':
        return oracle == ['TLazyObjectPtr', 'D', '', [_ds_struct_node(ptype.cls, by_path, name_counts, default_name='UObject')]]
    if kind == 'SoftObjectProperty':
        return oracle == ['TSoftObjectPtr', 'D', '', [_ds_struct_node(ptype.cls, by_path, name_counts, default_name='UObject')]]
    if kind == 'InterfaceProperty':
        return oracle == ['TScriptInterface', 'D', '', [_ds_struct_node(ptype.cls, by_path, name_counts, default_name='IInterface')]]
    if kind == 'StructProperty':
        if ptype.struct is None:
            raise _DsUnresolved
        rec = by_path.get(ptype.struct)
        if rec is None:
            raise _DsUnresolved
        if name_counts.get(rec.cpp_name, 0) != 1:
            raise _DsNonUnique
        return oracle == [rec.cpp_name, 'S', '', []]
    if kind == 'ArrayProperty':
        if ptype.inner is None or len(o_sub) != 1:
            return False
        return [o_name, o_et, o_ext] == ['TArray', 'C', ''] and nested(ptype.inner, o_sub[0])
    if kind == 'SetProperty':
        if ptype.element is None or len(o_sub) != 1:
            return False
        return [o_name, o_et, o_ext] == ['TSet', 'C', ''] and nested(ptype.element, o_sub[0])
    if kind == 'MapProperty':
        if ptype.key is None or ptype.value is None or len(o_sub) != 2:
            return False
        return ([o_name, o_et, o_ext] == ['TMap', 'C', ''] and nested(ptype.key, o_sub[0]) and nested(ptype.value, o_sub[1]))
    if kind == 'EnumProperty':
        if ptype.enum is not None:
            rec = by_path.get(ptype.enum)
            if rec is None:
                raise _DsUnresolved
            if name_counts.get(rec.cpp_name, 0) != 1:
                raise _DsNonUnique
            return oracle == [rec.cpp_name, 'E', '', []]
        return oracle == ['NamelessEnumIGuessIdkWhatToPutHereWithRegardsTheGuyFromDumper7', 'E', '', []]
    if kind == 'BoolProperty':
        native = ptype.field_mask == 0xFF
        return oracle == (['bool', 'D', '', []] if native else ['uint8', 'D', '', []])
    if kind == 'FieldPathProperty':
        sub = [f'F{ptype.field_class}', 'S', '', []] if ptype.field_class is not None else ['FField', 'S', '', []]
        return oracle == ['TFieldPath', 'D', '', [sub]]
    if kind == 'OptionalProperty':
        if ptype.value is None or len(o_sub) != 1:
            return False
        return [o_name, o_et, o_ext] == ['TOptional', 'D', ''] and nested(ptype.value, o_sub[0])
    # Delegate kinds, Utf8Str/AnsiStr, unknown: ea0dab3's unknown-property fallback (Class.GetCppName() + '_')
    return oracle == [f'F{ptype.prop}_', 'D', '', []]


# ea0dab3 StructManager::InitAlignmentsAndNames hardcodes a '2' onto whichever single class
# ObjectArray::FindClassFast("OnlineEngineInterfaceImpl") matches, on every target, whether or not a
# real second class of that name exists there (StructManager.cpp, grep "Hardcoded fix for two"); PAL
# has exactly one such class (00000219), so the oracle's rename is cosmetic, not a true collision.
_ORACLE_HARDCODED_RENAME = {'UOnlineEngineInterfaceImpl2': 'UOnlineEngineInterfaceImpl'}


def _ds_build_index(types) -> tuple[dict, collections.Counter, list, list, list]:
    by_path: dict[str, object] = {}
    name_counts = collections.Counter()
    classes, structs, enums = [], [], []
    for rec in types:
        if not isinstance(rec, (StructRecord, ClassRecord, EnumRecord, FunctionRecord)):
            raise TypeError(f'expected a TypeRecord, got {type(rec).__name__}')
        if isinstance(rec, FunctionRecord):
            continue  # not addressable by a property reference
        by_path[rec.path] = rec
        name_counts[rec.cpp_name] += 1
        (classes if isinstance(rec, ClassRecord) else structs if isinstance(rec, StructRecord) else enums).append(rec)
    return by_path, name_counts, classes, structs, enums


def _ds_inherit_chain(rec, by_path: dict) -> list[str] | None:
    chain, seen, cur = [], set(), rec
    while cur.super is not None:
        if cur.super in seen:
            return None
        seen.add(cur.super)
        nxt = by_path.get(cur.super)
        if nxt is None:
            return None
        chain.append(nxt.cpp_name)
        cur = nxt
    return chain


def _ds_size_ok(oracle_size: int, rec) -> bool:
    if oracle_size == rec.size or oracle_size == _ds_align(rec.size, rec.min_alignment):
        return True
    if oracle_size == 0:
        is_interface = isinstance(rec, ClassRecord) and rec.cpp_name.startswith('I')
        is_empty = rec.size == 1 and not rec.properties
        return is_interface or is_empty
    return False


def _ds_compare_members(rec, oracle_members: list, by_path: dict, name_counts: collections.Counter) -> tuple[bool, int, int, int]:
    """Returns (any_difference, pairs_compared, renamed_pairs, skipped_renderings)."""
    usable = [(name, val) for name, val in oracle_members if val[0][0] != 'Unsupported_Predefined_Member']
    # CollisionManager's suffix is Struct.GetValidName(): the plain valid name, without the U/A/I/F/E cpp_name prefix.
    valid_name = make_name_valid(strip_path(rec.name))
    pairs, unpaired_o, unpaired_u = _ds_pair_by_name(
        usable, rec.properties, key_of_our=lambda p: make_name_valid(p.name),
        candidates_of_oracle=lambda n: _ds_name_candidates(n, name_suffix=valid_name))
    differs = bool(unpaired_o or unpaired_u)
    skipped = renamed = 0
    for name, val, prop in pairs:
        if name != make_name_valid(prop.name):
            renamed += 1
        otype, ooffset, osize, oarraydim, *obit = val
        if prop.offset != ooffset or prop.size * prop.array_dim != osize or prop.array_dim != oarraydim:
            differs = True
        our_bit = prop.type.bit
        if bool(obit) != (our_bit is not None) or (obit and our_bit != obit[0]):
            differs = True
        try:
            if not _ds_compare_node(prop.type, prop.flags, otype, top_level=True, by_path=by_path, name_counts=name_counts):
                differs = True
        except _DsNonUnique:
            skipped += 1
        except _DsUnresolved:
            differs = True
    return differs, len(pairs), renamed, skipped


def _ds_compare_functions(rec, oracle_fn_bodies: list | None, by_path: dict, name_counts: collections.Counter) -> tuple[bool, int, int, int]:
    """Returns (any_difference, functions_compared, parameters_compared, skipped_renderings)."""
    if oracle_fn_bodies is None or len(oracle_fn_bodies) != 1:
        return False, 0, 0, 0
    oracle_fns = [_ds_one_key(item, where='FunctionsInfo member') for item in oracle_fn_bodies[0]]
    pairs, unpaired_o, unpaired_u = _ds_pair_by_name(
        oracle_fns, list(rec.functions.values()), key_of_our=lambda f: make_name_valid(strip_path(f.name)),
        candidates_of_oracle=lambda n: _ds_name_candidates(n, prefix='Func_'))
    differs = bool(unpaired_o or unpaired_u)
    skipped = 0
    params_compared = 0
    for _name, val, fn in pairs:
        oret, oparams, ooffset, oflags = val
        if _stringify_function_flags(fn.flags) != oflags:
            differs = True
        want_offset = (fn.exec_rva & _U64) if fn.exec_rva is not None else None
        if want_offset is None:
            if not (isinstance(ooffset, int) and ooffset >= 2**63):
                differs = True
        elif ooffset != want_offset:
            differs = True
        rp = fn.return_param
        try:
            if rp is None:
                if oret != ['void', 'D', '', []]:
                    differs = True
            elif not _ds_compare_node(rp.type, rp.flags, oret, top_level=True, by_path=by_path, name_counts=name_counts):
                differs = True
        except _DsNonUnique:
            skipped += 1
        except _DsUnresolved:
            differs = True
        ours_params = sorted((p for p in fn.params if p.flags & EPropertyFlags.Parm and not p.flags & EPropertyFlags.ReturnParm),
                             key=lambda p: (p.offset, p.type.bit if p.type.bit is not None else -1))
        param_pairs, param_unpaired_o, param_unpaired_u = _ds_pair_by_name(
            [(oparam[2], oparam) for oparam in oparams], ours_params, key_of_our=lambda p: make_name_valid(p.name),
            candidates_of_oracle=lambda n: _ds_name_candidates(n, prefix='Param_'))
        if param_unpaired_o or param_unpaired_u:
            differs = True
        # "They must come in the same order": the oracle-order pairing must also be monotonic in our offset-sorted order.
        last_idx = -1
        for _pname, _oparam, our_p in param_pairs:
            idx = ours_params.index(our_p)
            if idx <= last_idx:
                differs = True
            last_idx = idx
        for _pname, oparam, our_p in param_pairs:
            params_compared += 1
            otype, oref, _oname = oparam
            if oref != '':
                differs = True
            try:
                if not _ds_compare_node(our_p.type, our_p.flags, otype, top_level=True, by_path=by_path, name_counts=name_counts):
                    differs = True
            except _DsNonUnique:
                skipped += 1
            except _DsUnresolved:
                differs = True
    return differs, len(pairs), params_compared, skipped


def compare_dumpspace(types, oracle: DumpspaceTypes, *, target: str,
                      min_types: int = DUMPSPACE_MIN_TYPES, min_members: int = DUMPSPACE_MIN_MEMBERS) -> DriftResult:
    """Compare our struct/class/function records with a Dumpspace oracle (6-G.4, review I4)."""
    if not isinstance(target, str):
        raise TypeError('target must be a str')
    for name, value in (('min_types', min_types), ('min_members', min_members)):
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f'{name} must be an int')
        if value < 0:
            raise ValueError(f'{name} must be >= 0')
    accepted = _accepted(target, 'dumpspace')
    types = list(types)
    by_path, name_counts, classes, structs, _enums = _ds_build_index(types)
    ours_by_key = {}
    for rec in (*classes, *structs):
        if name_counts[rec.cpp_name] == 1:
            ours_by_key.setdefault(rec.cpp_name, rec)
    oracle_qualified = {k for k, v in oracle.types.items() if '::' not in k and len(v) == 1}
    # Map each oracle key to the name we'd compare it under, applying _ORACLE_HARDCODED_RENAME unless
    # that would collide with a genuine, distinct oracle key already claiming the renamed form.
    oracle_logical: dict[str, str] = {}
    for k in oracle_qualified:
        logical = _ORACLE_HARDCODED_RENAME.get(k, k)
        if logical in oracle_logical and oracle_logical[logical] != k:
            continue
        oracle_logical[logical] = k

    compared = sorted((oracle_logical.keys() & ours_by_key.keys()) - accepted)
    oracle_only = (oracle_logical.keys() - ours_by_key.keys()) - accepted
    ours_only = (ours_by_key.keys() - oracle_logical.keys()) - accepted
    qualifying_oracle = len(oracle_logical.keys() - accepted)

    matched = changed = 0
    member_pairs_total = function_pairs_total = param_pairs_total = skipped_total = renamed_total = 0
    samples = []
    for key in compared:
        rec = ours_by_key[key]
        oracle_key = oracle_logical[key]
        body = oracle.types[oracle_key][0]
        inherit_diff = _ds_inherit_chain(rec, by_path) != body[0]['__InheritInfo']
        size_diff = not _ds_size_ok(body[1]['__MDKClassSize'], rec)
        members_diff, pairs_n, mem_renamed, mem_skipped = _ds_compare_members(
            rec, [_ds_one_key(m, where=f'{key} member') for m in body[2:]], by_path, name_counts)
        fn_bodies = oracle.functions.get(oracle_key) if isinstance(rec, ClassRecord) else None
        fn_diff, fn_n, param_n, fn_skipped = _ds_compare_functions(rec, fn_bodies, by_path, name_counts) if isinstance(rec, ClassRecord) else (False, 0, 0, 0)
        member_pairs_total += pairs_n
        renamed_total += mem_renamed
        function_pairs_total += fn_n
        param_pairs_total += param_n
        skipped_total += mem_skipped + fn_skipped
        is_changed = inherit_diff or size_diff or members_diff or fn_diff
        if is_changed:
            changed += 1
            if len(samples) < 5:
                what = []
                if inherit_diff:
                    what.append('__InheritInfo')
                if size_diff:
                    what.append('__MDKClassSize')
                if members_diff:
                    what.append('members')
                if fn_diff:
                    what.append('functions')
                samples.append(f'{key}: {", ".join(what)} differ')
        else:
            matched += 1
    samples += [f'{k}: oracle-only' for k in sorted(oracle_only)[:max(0, 5 - len(samples))]]
    samples += [f'{k}: ours-only' for k in sorted(ours_only)[:max(0, 5 - len(samples))]]

    one_sided = len(oracle_only) + len(ours_only)
    drift = one_sided / max(1, qualifying_oracle)
    reasons = []
    if changed:
        reasons.append(f'{changed} keys differ (no allowance)')
    if drift > DUMPSPACE_DRIFT_BOUND:
        reasons.append(f'drift {drift:.4f} exceeds {DUMPSPACE_DRIFT_BOUND}')
    if len(compared) < min_types:
        reasons.append(f'too few keys compared ({len(compared)} < {min_types})')
    if member_pairs_total < min_members:
        reasons.append(f'too few member pairs compared ({member_pairs_total} < {min_members})')
    samples.append(f'keys: {len(compared)}, members: {member_pairs_total} ({renamed_total} renamed), '
                   f'functions: {function_pairs_total}, parameters: {param_pairs_total}, skipped renderings: {skipped_total}')
    return DriftResult(ok=not reasons, matched=matched, changed=changed, drift=drift, reason='; '.join(reasons), samples=tuple(samples))


def _drop_rows(dump: GObjectsDump, indices: set[str]) -> GObjectsDump:
    if not indices:
        return dump
    return dataclasses.replace(dump, rows=[r for r in dump.rows if f'{r[0]:08X}' not in indices],
                               props={i: p for i, p in dump.props.items() if f'{i:08X}' not in indices})


def _check_idmap(ours: list, oracle: list, *, target: str) -> DriftResult:
    accepted = _accepted(target, 'idmap')
    ours = [r for r in ours if r[1] not in accepted]
    oracle = [r for r in oracle if r[1] not in accepted]
    dr = compare_idmap(ours, oracle)
    if dr.ok and len(oracle) < IDMAP_MIN_RECORDS:
        return dataclasses.replace(dr, ok=False, reason=f'too few idmap records ({len(oracle)} < {IDMAP_MIN_RECORDS})')
    return dr


def _props_exact(ours: GObjectsDump, oracle: GObjectsDump) -> DriftResult:
    """Property rows of every object whose key and full name are equal in both WithProperties dumps; no drift allowance."""
    o_names = {(i, a): n for i, a, n in oracle.rows}
    matched, bad = 0, []
    for i, a, n in ours.rows:
        if o_names.get((i, a)) != n:
            continue
        if (u := ours.props.get(i, [])) == (o := oracle.props.get(i, [])):
            matched += 1
        else:
            bad.append(f'[{i:08X}] {n}: ours {len(u)} property rows, oracle {len(o)}')
    compared = matched + len(bad)
    reasons = ([f'{len(bad)} objects differ in their property rows'] if bad else []) +         ([f'too few keys compared ({compared} < {PROPS_EXACT_MIN_KEYS})'] if compared < PROPS_EXACT_MIN_KEYS else [])
    return DriftResult(ok=not reasons, matched=matched, changed=len(bad), drift=len(bad) / max(1, compared),
                       reason='; '.join(reasons), samples=tuple(bad[:5]))


def _cdo_types(snap, *, target: str) -> DriftResult:
    """No ClassDefaultObject row has a type record (a cyclic path is skipped)."""
    accepted = _accepted(target, 'cdo-types')
    checked, bad = 0, []
    for row in snap.objects:
        if not row.flags & EObjectFlags.ClassDefaultObject or f'{row.index:08X}' in accepted:
            continue
        try:
            path = snap.objects.path(row.index)
        except ValueError:
            continue
        checked += 1
        if (rec := snap.type(path)) is not None:
            bad.append(f'[{row.index:08X}] {path}: {rec.kind} record')
    reasons = ([f'{len(bad)} ClassDefaultObject rows have a type record'] if bad else []) +         ([f'too few ClassDefaultObject rows checked ({checked} < {CDO_TYPES_MIN_ROWS})'] if checked < CDO_TYPES_MIN_ROWS else [])
    return DriftResult(ok=not reasons, matched=checked - len(bad), changed=len(bad), drift=len(bad) / max(1, checked),
                       reason='; '.join(reasons), samples=tuple(bad[:5]))


def _check_equal(pairs: list[tuple[str, object, object]]) -> DriftResult:
    bad = [f'{what}: ours={a!r} oracle={b!r}' for what, a, b in pairs if a != b]
    return DriftResult(ok=not bad, matched=len(pairs) - len(bad), changed=len(bad), drift=len(bad) / max(1, len(pairs)),
                       reason='; '.join(bad), samples=tuple(bad))


def _gnames_valid(image, rva: int) -> tuple[bool, str]:
    try:
        ok = Engine(image).names.try_init_override(rva, True)
    except Exception as exc:
        return False, f'rejected ({_one_line(exc)})'
    return ok, 'accepted by InitializeNamePool' if ok else 'rejected by InitializeNamePool'


def _k14_diagnosis(image, oracle_rva: int | None, our_rva: int | None) -> tuple[bool, str]:
    """Initialise both GNames candidates on fresh engines; confirmed = the oracle's is rejected and ours is accepted."""
    if oracle_rva is None:
        return False, 'K14: the oracle has no OFFSET_GNAMES'
    o_ok, o_text = _gnames_valid(image, oracle_rva)
    parts = [f'oracle GNames {oracle_rva:#x} {o_text}']
    u_ok = False
    if our_rva:
        u_ok, u_text = _gnames_valid(image, our_rva)
        parts.append(f'ours {our_rva:#x} {u_text}')
    else:
        parts.append('ours: none recorded')
    confirmed = not o_ok and u_ok and our_rva != oracle_rva
    return confirmed, f'K14: {"; ".join(parts)} -> {"confirmed" if confirmed else "not confirmed"}'


def _is_within(path: str, folder: str) -> bool:
    path, folder = os.path.normcase(os.path.abspath(path)), os.path.normcase(os.path.abspath(folder))
    try:
        return os.path.commonpath([path, folder]) == folder
    except ValueError:  # different drives
        return False


class _StepFailed(Exception):
    pass


class _Steps:
    def __init__(self, run: PortRun):
        self.run = run

    def fail(self, step: PortStep, exc: BaseException) -> None:
        step.status, step.detail = 'error', _one_line(exc)
        self.run.error = f'{step.name}: {step.detail}'
        self.run.trace = ''.join(traceback.format_exception(exc))

    def call(self, name: str, fn, *args):
        step, t0 = self.run.step(name), time.perf_counter()
        try:
            result = fn(*args)
        except Exception as exc:
            step.seconds = time.perf_counter() - t0
            self.fail(step, exc)
            raise _StepFailed from None
        step.seconds = time.perf_counter() - t0
        if step.status == 'not run':
            step.status = 'ok'
        return result

    def check(self, name: str, fn, *args) -> None:
        step = self.run.step(name)
        dr = self.call(name, fn, *args)
        if dr is None:
            return
        self.run.checks[name.removeprefix('check:')] = dr
        step.status = 'ok' if dr.ok else 'drift'
        step.detail = f'matched={dr.matched} changed={dr.changed} drift={dr.drift:.4f}' + (f' -- {dr.reason}' if dr.reason else '')


def _step_names(extra: bool) -> list[str]:
    return (['check_session', 'load', *ENGINE_CORE_STEPS, 'walk', 'export', 'oracle'] + [f'check:{c}' for c in CHECKS]
            + (list(EXTRA_CHECKS) if extra else []))


def _init_engine(run: PortRun, steps: _Steps, e, image, oracle_off: dict):
    marks = []
    t_end = None
    try:
        return init_engine_core(e, on_step=lambda name: marks.append((name, time.perf_counter())))
    except Exception as exc:
        t_end = time.perf_counter()
        failed = marks[-1][0] if marks else ENGINE_CORE_STEPS[0]
        steps.fail(run.step(failed), exc)
        if failed == 'FName::Init':
            _, line = _k14_diagnosis(image, oracle_off.get('OffsetsInfo.OFFSET_GNAMES'), e.off.InSDK.NameArray.GNames)
            run.notes.append(line)
            run.step(failed).detail += f' [{line}]'
        raise _StepFailed from None
    finally:
        t_end = t_end or time.perf_counter()
        for i, (name, t) in enumerate(marks):
            step = run.step(name)
            step.seconds = (marks[i + 1][1] if i + 1 < len(marks) else t_end) - t
            if step.status == 'not run':
                step.status = 'ok'


def _extra_from_snapshot(ctx, snap, image) -> DriftResult:
    ctx2 = EngineContext.from_snapshot(snap.meta, snap.offsets, image)
    bad = []
    if (a := ctx2.to_offsets()) != (b := ctx.to_offsets()):
        diff = [k for k in sorted(a.keys() | b.keys()) if a.get(k) != b.get(k)]
        bad.append(f'to_offsets() differs in {diff}')
    rows = list(snap.objects)
    sample = rows[::max(1, len(rows) // EXTRA_NAME_SAMPLES)][:EXTRA_NAME_SAMPLES]
    for row in sample:
        obj = ctx2.engine.objects.get_by_index(row.index)
        got = (obj.address, obj.get_fname().to_raw_string() if obj else None)
        if got != (row.address, row.name):
            bad.append(f'[{row.index:08X}] re-attached {got!r} != snapshot {(row.address, row.name)!r}')
    reasons = ([f'{len(bad)} differences'] if bad else []) + \
        ([f'only {len(sample)} rows sampled'] if not sample or len(sample) < min(EXTRA_NAME_SAMPLES, len(rows)) else [])
    return DriftResult(ok=not reasons, matched=len(sample) - len(bad), changed=len(bad),
                       drift=len(bad) / max(1, len(sample)), reason='; '.join(reasons), samples=tuple(bad[:5]))


def _extra_live_resolver(ctx, snap) -> DriftResult:
    e = ctx.engine
    refl = reflect.Reflection(e, reflect.LiveResolver(e))
    rows = list(snap.objects)
    stride = max(1, len(rows) // (EXTRA_TYPE_SAMPLES * 20))
    compared, bad = 0, []
    for row in rows[::stride]:
        if compared >= EXTRA_TYPE_SAMPLES:
            break
        if (rec := snap.type_of_object(row.index)) is None:
            continue
        compared += 1
        obj = e.objects.get_by_index(row.index)
        if rec.kind == 'enum' and rec.underlying_size_from == 'property':  # the size comes from the walk's enum-size map
            live = refl.enum_record(obj.cast(UEEnum), rec.underlying_size)
        else:
            live = refl.type_record(obj)
        if live is None or live.to_json() != rec.to_json():
            bad.append(f'[{row.index:08X}] {rec.path}: live record differs' + (' (None)' if live is None else ''))
    reasons = ([f'{len(bad)} live records differ'] if bad else []) + \
        ([f'only {compared} type objects sampled (< {EXTRA_TYPE_SAMPLES})'] if compared < EXTRA_TYPE_SAMPLES else [])
    return DriftResult(ok=not reasons, matched=compared - len(bad), changed=len(bad), drift=len(bad) / max(1, compared),
                       reason='; '.join(reasons), samples=tuple(bad[:5]))


def run_port(session: real.Session, work_dir: str, *, extra: bool = False) -> PortRun:
    """Run the port on one session into <work_dir>/<session_id>/ and compare it with the session's oracle."""
    if not isinstance(session, real.Session):
        raise TypeError(f'session must be a real.Session, got {type(session).__name__}')
    if not isinstance(work_dir, (str, os.PathLike)):
        raise TypeError(f'work_dir must be str or os.PathLike, got {type(work_dir).__name__}')
    store = os.path.dirname(os.path.dirname(os.path.abspath(session.dir)))
    if _is_within(os.fspath(work_dir), store):
        raise ValueError(f'work_dir {os.fspath(work_dir)!r} lies inside the capture store {store!r}')
    work = os.path.join(os.path.abspath(os.fspath(work_dir)), session.session_id)
    run = PortRun(session_id=session.session_id, target=session.target, dir=session.dir, steps=[PortStep(n) for n in _step_names(extra)])
    steps = _Steps(run)
    image = snap = ctx = None
    try:
        def _check_session():
            real.check_session(session)
            return oracle_offsets(session)
        oracle_off = steps.call('check_session', _check_session)

        def _load():
            nonlocal image
            image = ImageSource.load(os.path.join(session.dir, 'capture.zip'), max_resident_bytes=CAPTURE_RESIDENT_BYTES)
            return Engine(image)
        e = steps.call('load', _load)
        ctx = _init_engine(run, steps, e, image, oracle_off)

        def _walk():
            meta = ctx.to_meta()
            meta['created'] = datetime.datetime.now().astimezone().isoformat(timespec='seconds')
            meta['mode'] = 'capture'
            meta['remote_calls'] = []
            meta['target']['exe'] = os.path.basename(session.data['target']['shipping_exe'].replace('\\', '/'))
            return reflect.walk(ctx, os.path.join(work, 'snap'), meta=meta, offsets=ctx.to_offsets())
        run.walk = steps.call('walk', _walk)

        def _export():
            nonlocal snap
            snap = Snapshot.load(run.walk.partial, _partial=True)
            out = os.path.join(work, 'exports')
            return {fmt: run_export(fmt, snap, out) for fmt in ('gobjects', 'gobjects-props', 'idmap')}
        paths = steps.call('export', _export)
        od = _oracle_dir(session)

        def _parse():
            return (parse_gobjects_dump(od / 'GObjects-Dump.txt'), parse_gobjects_dump(od / 'GObjects-Dump-WithProperties.txt', with_properties=True),
                    parse_gobjects_dump(pathlib.Path(paths['gobjects'])), parse_gobjects_dump(pathlib.Path(paths['gobjects-props']), with_properties=True))
        o_dump, o_props, u_dump, u_props = steps.call('oracle', _parse)
        t = session.target

        def _offsets():
            ours = oracle_keys(snap.offsets, snap.meta)
            dr = compare_offset_keys(ours, oracle_off, target=t)
            k14_items = {item for (tt, c, item), r in ACCEPTED.items() if tt == t and c == 'offsets' and r == K14_REASON}
            if ours.get('Offsets.GNames') != oracle_off.get('Offsets.GNames') or k14_items:
                confirmed, line = _k14_diagnosis(image, oracle_off.get('OffsetsInfo.OFFSET_GNAMES'), ours.get('OffsetsInfo.OFFSET_GNAMES'))
                run.notes.append(line)
                if k14_items and not confirmed:
                    dr = dataclasses.replace(dr, ok=False, reason='; '.join(filter(None, [dr.reason, f'ACCEPTED K14 entries not confirmed ({line})'])))
            return dr
        steps.check('check:offsets', _offsets)
        steps.check('check:gobjects', lambda: compare_gobjects_capture(u_dump, o_dump, target=t, check='gobjects'))
        steps.check('check:gobjects-props', lambda: compare_gobjects_capture(u_props, o_props, target=t, check='gobjects-props'))
        idmaps = [rel for rel in session.data['oracle']['files'] if rel.startswith('IDAMappings/') and rel.endswith('.idmap')]
        steps.check('check:idmap', lambda: _check_idmap(parse_idmap(pathlib.Path(paths['idmap'])), parse_idmap(od.joinpath(*idmaps[0].split('/'))), target=t))
        steps.check('check:stem', lambda: _check_equal([('meta.target.stem', snap.meta['target']['stem'], session.data['oracle']['stem']),
                                                         ('GObjects dump line 3', u_dump.stem, o_dump.stem)]))

        def _names():
            pool = pool_strings(ctx.engine)
            if pool is None:
                run.skipped['names'] = 'outline-number or non-pool engine: no FNamePool to walk'
                run.step('check:names').status = 'skipped'
                run.step('check:names').detail = run.skipped['names']
                return None
            return compare_names(pool, name_components(o_dump, o_props), target=t)
        steps.check('check:names', _names)

        def _counts():
            counts = snap.meta.get('counts')
            counts = counts if isinstance(counts, dict) else {}
            written, table = run.walk.written['objects'], len(snap.objects)
            n_classes = n_structs = n_enums = n_functions = 0
            for rec in snap.types():
                if rec.kind == 'class':
                    n_classes += 1
                    n_functions += len(rec.functions)
                elif rec.kind == 'struct':
                    n_structs += 1
                elif rec.kind == 'enum':
                    n_enums += 1
                elif rec.kind == 'function':
                    n_functions += 1
            # 6-G.4 (review M4): the recount over snapshot.types() proves meta() ran after the types stream.
            dr = _check_equal([
                ('meta.counts.objects vs rows written', counts.get('objects'), written),
                ('rows written vs objects.jsonl rows', written, table),
                ('meta.counts.classes vs recount', counts.get('classes'), n_classes),
                ('meta.counts.structs vs recount', counts.get('structs'), n_structs),
                ('meta.counts.enums vs recount', counts.get('enums'), n_enums),
                ('meta.counts.functions vs recount', counts.get('functions'), n_functions),
            ])
            return dr if written > 0 else dataclasses.replace(dr, ok=False, reason='no object rows written')
        steps.check('check:counts', _counts)
        steps.check('check:enums', lambda: _compare_enums(_our_enums(snap), _oracle_enums(od / 'Dumpspace' / 'EnumsInfo.json'), target=t))
        steps.check('check:dumpspace', lambda: compare_dumpspace(snap.types(), parse_dumpspace(od / 'Dumpspace'), target=t))
        steps.check('check:props-exact', lambda: _props_exact(_drop_rows(u_props, _accepted(t, 'props-exact')), _drop_rows(o_props, _accepted(t, 'props-exact'))))
        steps.check('check:cdo-types', lambda: _cdo_types(snap, target=t))

        if extra:
            steps.check('extra:from_snapshot', _extra_from_snapshot, ctx, snap, image)
            steps.check('extra:live_resolver', _extra_live_resolver, ctx, snap)
    except _StepFailed:
        pass
    finally:
        ctx = None
        if snap is not None:
            snap.close()
        if image is not None:
            image.close()
    return run


def _load_session(folder: str) -> real.Session:
    folder = os.path.abspath(folder)
    with open(os.path.join(folder, 'session.json'), 'rb') as f:
        data = json.loads(f.read().decode('utf-8'))
    real.validate_session(data, short=os.path.basename(os.path.dirname(folder)))
    return real.Session(dir=folder, data=data, target=data['target']['short'], state=data['state'], session_id=data['session_id'])


def main(argv: list[str] | None = None) -> int:
    """python -m nylib.ue.tests.port --session DIR [--work DIR] [--extra]; exit 0 when every step and check passes."""
    ap = argparse.ArgumentParser(prog='python -m nylib.ue.tests.port', description='Run the nylib.ue port gate on one capture session.')
    ap.add_argument('--session', required=True, help='a capture session folder (<store>/<target>/<folder>)')
    ap.add_argument('--work', help='keep the snapshot and exports in this folder (default: a temporary folder)')
    ap.add_argument('--extra', action='store_true', help='also run the from_snapshot round trip and the LiveResolver check')
    args = ap.parse_args(argv)
    session = _load_session(args.session)
    if args.work:
        run = run_port(session, args.work, extra=args.extra)
    else:
        with tempfile.TemporaryDirectory(prefix='nylib-ue-port-', ignore_cleanup_errors=True) as tmp:
            run = run_port(session, tmp, extra=args.extra)
    print(run.report())
    if run.trace:
        print(run.trace, file=sys.stderr)
    return 0 if run.ok else 1


if __name__ == '__main__':
    sys.exit(main())
