"""Port gate: run stages 4-6 on one captured session and compare the result with its Dumper-7 oracle."""
import argparse
import dataclasses
import datetime
import json
import math
import os
import pathlib
import sys
import tempfile
import time
import traceback

from .. import reflect
from ..capture import ImageSource
from ..engine.context import ENGINE_CORE_STEPS, EngineContext, init_engine_core
from ..engine.core import Engine
from ..engine.gnames import FNameEntry
from ..errors import MemoryReadError
from ..exports import run_export
from ..snapshot import Snapshot
from . import real
from .oracle import (DriftResult, GObjectsDump, compare_gobjects, compare_idmap, compare_offsets, flatten_oracle_offsets,
                     parse_basic_offsets, parse_gobjects_dump, parse_idmap, parse_offsets_info, parse_predefined_members)

CAPTURE_RESIDENT_BYTES = 1 << 30
K14_REASON = ("K14 (root Q30 = A): the oracle's GNames is Dumper-7 ea0dab3's first FNamePool candidate, which it never "
              "validates and which holds zeros in this capture; nylib.ue uses the pool that InitializeNamePool accepts")
# (target, check, item) -> recorded reason. Items: offsets = flattened key, gobjects / gobjects-props = row index as
# '%08X', idmap = record name, names = name component, enums = enum name.
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

CHECKS = ('offsets', 'gobjects', 'gobjects-props', 'idmap', 'stem', 'names', 'counts', 'enums')
EXTRA_CHECKS = ('extra:from_snapshot', 'extra:live_resolver')
OFFSETS_MIN_VALUES = 25
IDMAP_MIN_RECORDS = 1000
ENUMS_MIN_COMPARED = 500
ENUMS_DRIFT_BOUND = 0.01
EXTRA_NAME_SAMPLES = 1000
EXTRA_TYPE_SAMPLES = 200
_NAME_MISS_LISTED = 200
_U64 = (1 << 64) - 1
_ENUM_TYPE_SIZES = {'uint8': 1, 'uint16': 2, 'uint32': 4, 'uint64': 8}
_CATALOGUE = frozenset(ORACLE_KEY_CATALOGUE)


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
            out.setdefault(rec.cpp_name, []).append((rec.underlying_size, sorted(v & _U64 for _, v in rec.values)))
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
        live = refl.type_record(e.objects.get_by_index(row.index))
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
        steps.check('check:gobjects', lambda: compare_gobjects(_drop_rows(u_dump, _accepted(t, 'gobjects')), _drop_rows(o_dump, _accepted(t, 'gobjects'))))
        steps.check('check:gobjects-props', lambda: compare_gobjects(_drop_rows(u_props, _accepted(t, 'gobjects-props')),
                                                                    _drop_rows(o_props, _accepted(t, 'gobjects-props')), compare_props=True))
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
            n = counts.get('objects') if isinstance(counts, dict) else None
            written, table = run.walk.written['objects'], len(snap.objects)
            dr = _check_equal([('meta.counts.objects vs rows written', n, written), ('rows written vs objects.jsonl rows', written, table)])
            return dr if written > 0 else dataclasses.replace(dr, ok=False, reason='no object rows written')
        steps.check('check:counts', _counts)
        steps.check('check:enums', lambda: _compare_enums(_our_enums(snap), _oracle_enums(od / 'Dumpspace' / 'EnumsInfo.json'), target=t))

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
