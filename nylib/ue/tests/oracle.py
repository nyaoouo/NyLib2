"""Parsers for real Dumper-7 output, an offsets-flattening helper, and
drift-tolerant comparisons between two parses. Pure text/binary parsing: no
memory access, no dependency on the rest of nylib.ue.
"""
import dataclasses
import json
import os
import re
import struct
from collections import Counter


def _load_text(data, *, kind):
    """Normalize a bytes/str/PathLike parser argument to decoded text content."""
    if isinstance(data, str):
        return data
    if isinstance(data, (bytes, bytearray, memoryview)):
        raw = bytes(data)
    elif isinstance(data, os.PathLike):
        with open(data, 'rb') as f:
            raw = f.read()
    else:
        raise TypeError(f'{kind} expects bytes, str or os.PathLike, got {type(data).__name__}')
    return raw.decode('utf-8')  # a UnicodeDecodeError is a ValueError subclass


def _load_idmap_bytes(data):
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    if isinstance(data, os.PathLike):
        with open(data, 'rb') as f:
            return f.read()
    raise TypeError(f'parse_idmap expects bytes or os.PathLike, got {type(data).__name__}')


@dataclasses.dataclass(frozen=True)
class GObjectsDump:
    line1: str
    stem: str                                                # '' for Dumper-7's 5-line header
    count: int
    rows: list[tuple[int, int, str]]                         # (index, address, full_name), file order
    props: dict[int, list[tuple[int, int, str, str]]]        # index -> [(offset, address, prop, name)]


_OBJECT_ROW_RE = re.compile(r'\[([0-9A-F]{8})\] \{0x([0-9a-f]+)\} (\S.*)')
_PROPERTY_ROW_RE = re.compile(r'\[([0-9A-F]{8})\] \{0x([0-9a-f]+)\}     (\S+) (.*)')
_COUNT_LINE_RE = re.compile(r'Count: (\d+)')


def parse_gobjects_dump(data: bytes | str | os.PathLike, *, with_properties: bool = False) -> GObjectsDump:
    """Parse a Dumper-7 GObjects dump (5- or 7-line header) into a GObjectsDump.

    Raises ValueError on any malformed line, naming the 1-based file line number.
    """
    text = _load_text(data, kind='parse_gobjects_dump')
    elems = text.split('\r\n')
    for lineno, e in enumerate(elems, start=1):
        if '\n' in e:
            raise ValueError(f'bare LF at line {lineno}')
    if not elems or elems[-1] != '':
        raise ValueError('file does not end with a final CRLF')
    elems = elems[:-1]
    if not elems or not elems[0]:
        raise ValueError('missing or empty line 1')
    line1 = elems[0]
    if len(elems) < 2 or elems[1] != '':
        raise ValueError('line 2 must be blank')

    m5 = _COUNT_LINE_RE.fullmatch(elems[2]) if len(elems) > 2 else None
    if m5:
        if len(elems) < 4 or elems[3] != '':
            raise ValueError('line 4 must be blank')
        if len(elems) < 5 or elems[4] != '':
            raise ValueError('line 5 must be blank')
        stem = ''
        count = int(m5.group(1))
        body_start = 5
    else:
        if len(elems) < 3:
            raise ValueError('missing line 3 (stem)')
        stem = elems[2]
        if len(elems) < 4 or elems[3] != '':
            raise ValueError('line 4 must be blank')
        if len(elems) < 5:
            raise ValueError('missing line 5 (Count:)')
        m7 = _COUNT_LINE_RE.fullmatch(elems[4])
        if not m7:
            raise ValueError(f'expected a Count: line at line 5, got {elems[4]!r}')
        if len(elems) < 6 or elems[5] != '':
            raise ValueError('line 6 must be blank')
        if len(elems) < 7 or elems[6] != '':
            raise ValueError('line 7 must be blank')
        count = int(m7.group(1))
        body_start = 7

    rows = []
    props = {}
    seen_indices = set()
    last_index = None
    for lineno, e in enumerate(elems[body_start:], start=body_start + 1):
        pm = _PROPERTY_ROW_RE.fullmatch(e) if with_properties else None
        if pm is not None:
            if last_index is None:
                raise ValueError(f'property row before the first object row at line {lineno}')
            offset = int(pm.group(1), 16)
            address = int(pm.group(2), 16)
            props.setdefault(last_index, []).append((offset, address, pm.group(3), pm.group(4)))
            continue
        om = _OBJECT_ROW_RE.fullmatch(e)
        if om is None:
            raise ValueError(f'line matches neither enabled pattern at line {lineno}: {e!r}')
        index = int(om.group(1), 16)
        if index in seen_indices:
            raise ValueError(f'repeated object index at line {lineno}: {index:08X}')
        seen_indices.add(index)
        rows.append((index, int(om.group(2), 16), om.group(3)))
        last_index = index
    return GObjectsDump(line1=line1, stem=stem, count=count, rows=rows, props=props)


def parse_idmap(data: bytes | os.PathLike) -> list[tuple[int, str]]:
    """Parse an IDAMappingGenerator V1 stream into [(rva, name)] in file order."""
    raw = _load_idmap_bytes(data)
    pos = 0
    n = len(raw)
    records = []
    while pos < n:
        if pos + 6 > n:
            raise ValueError(f'truncated record header at offset {pos}')
        rva, name_len = struct.unpack_from('<IH', raw, pos)
        pos += 6
        if pos + name_len > n:
            raise ValueError(f'record name overruns buffer at offset {pos}')
        name = raw[pos:pos + name_len].decode('utf-8')
        pos += name_len
        records.append((rva, name))
    return records


def parse_offsets_info(data: bytes | str | os.PathLike) -> dict[str, int]:
    """Parse a Dumpspace OffsetsInfo.json 'data' array, 'Dumper' format marker included."""
    text = _load_text(data, kind='parse_offsets_info')
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f'invalid JSON: {e}') from e
    if not isinstance(doc, dict):
        raise ValueError('OffsetsInfo document must be a JSON object')
    pairs = doc.get('data')
    if not isinstance(pairs, list):
        raise ValueError("OffsetsInfo 'data' must be a JSON array")
    result = {}
    for i, pair in enumerate(pairs):
        if (not isinstance(pair, list) or len(pair) != 2 or not isinstance(pair[0], str)
                or not isinstance(pair[1], int) or isinstance(pair[1], bool)):
            raise ValueError(f'malformed data pair at index {i}: {pair!r}')
        name, value = pair
        if name in result:
            raise ValueError(f'repeated offset name {name!r}')
        result[name] = value
    return result


_OFFSETS_NAMESPACE_RE = re.compile(r'constexpr\s+int32\s+(\w+)\s*=\s*(0x[0-9A-Fa-f]+)\s*;')


def parse_basic_offsets(text: str) -> dict[str, int]:
    """Parse Basic.hpp's `namespace Offsets { constexpr int32 X = 0x..; }` block."""
    if not isinstance(text, str):
        raise TypeError('parse_basic_offsets expects str')
    lines = text.splitlines()
    start = next((i for i, l in enumerate(lines) if l.strip() == 'namespace Offsets'), None)
    if start is None:
        raise ValueError('no namespace Offsets block found')
    end = next((i for i in range(start + 1, len(lines)) if lines[i] == '}'), None)
    if end is None:
        raise ValueError('namespace Offsets block is not closed')
    result = {}
    for l in lines[start:end]:
        m = _OFFSETS_NAMESPACE_RE.search(l)
        if m:
            name = m.group(1)
            if name in result:
                raise ValueError(f'repeated offset name {name!r}')
            result[name] = int(m.group(2), 16)
    return result


_TYPE_HEADER_RE = re.compile(
    r'^(?:template\s*<.*>\s*)?(?:class|struct|union)\s+(?:alignas\(\w+\)\s+)?(\w+)'
    r'(?:\s+final)?(?:\s*:\s*public\s+[\w:<>, ]+)?\s*$'
)
_PREDEFINED_MEMBER_RE = re.compile(
    r'^\s*(?!static\b)\S.*?\b([A-Za-z_]\w*)(?:\s*=\s*[^;]*)?;\s*// 0x([0-9A-Fa-f]+)\(0x([0-9A-Fa-f]+)\)\(NOT AUTO-GENERATED PROPERTY\)'
)
# Dumper-7's GNames-fallback / outline-number Basic.hpp emits array members (`Name[0x..];`) and
# bitfield members (`Name : N;`), which have no single-offset layout; skipped like `static`.
_ARRAY_OR_BITFIELD_MEMBER_RE = re.compile(r'(?:\[0x[0-9A-Fa-f]+\]|:\s*\d+)\s*;\s*//')


def parse_predefined_members(text: str) -> dict[tuple[str, str], tuple[int, int]]:
    """Parse the `(NOT AUTO-GENERATED PROPERTY)` members of a Dumper-7 SDK header.

    Reflected members, `static` members, array members and bitfield members are skipped;
    `(Type, Member)` -> `(offset, size)`.
    """
    if not isinstance(text, str):
        raise TypeError('parse_predefined_members expects str')
    lines = text.splitlines()
    current_type = None
    result = {}
    for lineno, l in enumerate(lines, start=1):
        hm = _TYPE_HEADER_RE.match(l)
        if hm:
            current_type = hm.group(1)
            continue
        if not l.rstrip().endswith('(NOT AUTO-GENERATED PROPERTY)') or l.strip().startswith('static'):
            continue
        if _ARRAY_OR_BITFIELD_MEMBER_RE.search(l):
            continue
        mm = _PREDEFINED_MEMBER_RE.match(l)
        if mm is None:
            raise ValueError(f'unparsable predefined-member line at line {lineno}: {l!r}')
        if current_type is None:
            raise ValueError(f'predefined-member line before any type header at line {lineno}')
        key = (current_type, mm.group(1))
        if key in result:
            raise ValueError(f'repeated predefined member {key!r}')
        result[key] = (int(mm.group(2), 16), int(mm.group(3), 16))
    return result


def flatten_oracle_offsets(basic: dict[str, int], members: dict[tuple[str, str], tuple[int, int]],
                           offsets_info: dict[str, int]) -> dict[str, int]:
    """Flatten the three offset sources into one `Offsets.*` / `Type.Member` / `OffsetsInfo.*` namespace.

    The `OffsetsInfo.Dumper` format marker is dropped; a key produced by two sources raises ValueError.
    """
    if not isinstance(basic, dict) or not isinstance(members, dict) or not isinstance(offsets_info, dict):
        raise TypeError('flatten_oracle_offsets expects three dicts')
    result = {}

    def _put(key, value):
        if key in result:
            raise ValueError(f'duplicate flattened offset key {key!r}')
        result[key] = value

    for name, value in basic.items():
        _put(f'Offsets.{name}', value)
    for (type_name, member), (offset, _size) in members.items():
        _put(f'{type_name}.{member}', offset)
    for name, value in offsets_info.items():
        if name == 'Dumper':
            continue
        _put(f'OffsetsInfo.{name}', value)
    return result


@dataclasses.dataclass(frozen=True)
class DriftResult:
    ok: bool
    matched: int
    changed: int
    drift: float
    reason: str                     # '' when ok, else the first failing condition
    samples: tuple[str, ...]        # up to 5 one-line examples, filled even when ok


def _keyed_gobjects_rows(dump):
    keyed = {}
    for index, address, name in dump.rows:
        key = (index, address)
        if key in keyed:
            raise ValueError(f'repeated key {key!r} in gobjects dump')
        keyed[key] = name
    return keyed


def compare_gobjects(ours: GObjectsDump, oracle: GObjectsDump, *, min_matched: int = 10000,
                      drift_bound: float = 0.01, compare_props: bool = False) -> DriftResult:
    """Compare two GObjects dumps under the root §8 drift rules (a changed row never matches)."""
    if not isinstance(ours, GObjectsDump) or not isinstance(oracle, GObjectsDump):
        raise TypeError('compare_gobjects expects GObjectsDump instances')
    if not isinstance(min_matched, int):
        raise TypeError('min_matched must be an int')
    if min_matched < 0:
        raise ValueError('min_matched must be >= 0')
    if not isinstance(drift_bound, (int, float)):
        raise TypeError('drift_bound must be a real number')
    if not (0.0 <= drift_bound <= 1.0):
        raise ValueError('drift_bound must be within [0, 1]')

    ours_keyed = _keyed_gobjects_rows(ours)
    oracle_keyed = _keyed_gobjects_rows(oracle)

    matched = 0
    changed = 0
    samples = []
    for key, oracle_name in oracle_keyed.items():
        if key not in ours_keyed:
            continue
        our_name = ours_keyed[key]
        same = our_name == oracle_name
        if same and compare_props:
            same = ours.props.get(key[0], []) == oracle.props.get(key[0], [])
        if same:
            matched += 1
        else:
            changed += 1
            if len(samples) < 5:
                samples.append(f'[{key[0]:08X}] changed: ours={our_name!r} oracle={oracle_name!r}')

    oracle_only = [k for k in oracle_keyed if k not in ours_keyed]
    ours_only = [k for k in ours_keyed if k not in oracle_keyed]
    one_sided = len(oracle_only) + len(ours_only)
    for k in oracle_only:
        if len(samples) >= 5:
            break
        samples.append(f'[{k[0]:08X}] oracle-only: {oracle_keyed[k]!r}')
    for k in ours_only:
        if len(samples) >= 5:
            break
        samples.append(f'[{k[0]:08X}] ours-only: {ours_keyed[k]!r}')

    total_oracle = len(oracle.rows)
    drift = 1.0 if total_oracle == 0 else (changed + one_sided) / total_oracle
    ok = matched >= min_matched and drift <= drift_bound
    reason = '' if ok else ('too few matched rows' if matched < min_matched else 'drift exceeds bound')
    return DriftResult(ok=ok, matched=matched, changed=changed, drift=drift, reason=reason, samples=tuple(samples))


def compare_idmap(ours: list[tuple[int, str]], oracle: list[tuple[int, str]]) -> DriftResult:
    """Compare two idmap record lists: identical order passes; else a multiset/order drift."""
    ours = list(ours)
    oracle = list(oracle)
    for lst, label in ((ours, 'ours'), (oracle, 'oracle')):
        for item in lst:
            if not (isinstance(item, tuple) and len(item) == 2
                    and isinstance(item[0], int) and isinstance(item[1], str)):
                raise TypeError(f'{label} idmap elements must be (int, str) pairs')

    if ours == oracle:
        return DriftResult(ok=True, matched=len(oracle), changed=0, drift=0.0, reason='', samples=())

    prefix = 0
    for a, b in zip(ours, oracle):
        if a != b:
            break
        prefix += 1

    ours_ms, oracle_ms = Counter(ours), Counter(oracle)
    missing, extra = oracle_ms - ours_ms, ours_ms - oracle_ms
    sym_diff_size = sum(missing.values()) + sum(extra.values())
    drift = sym_diff_size / max(1, len(oracle))

    samples = []
    if prefix < len(ours) and prefix < len(oracle):
        samples.append(f'first divergence at record {prefix}: ours={ours[prefix]!r} oracle={oracle[prefix]!r}')
    elif len(ours) != len(oracle):
        samples.append(f'length differs: ours={len(ours)} oracle={len(oracle)}')
    for rec, count in missing.items():
        if len(samples) >= 5:
            break
        samples.append(f'missing from ours: {rec!r} (x{count})')
    for rec, count in extra.items():
        if len(samples) >= 5:
            break
        samples.append(f'extra in ours: {rec!r} (x{count})')
    reason = 'idmap multiset differs' if (missing or extra) else 'idmap record order differs'
    return DriftResult(ok=False, matched=prefix, changed=0, drift=drift, reason=reason, samples=tuple(samples[:5]))


def compare_offsets(ours: dict[str, int], oracle: dict[str, int], *, min_values: int = 25) -> DriftResult:
    """Compare two flattened offset namespaces on their common keys, with a min-values floor."""
    if not isinstance(ours, dict) or not isinstance(oracle, dict):
        raise TypeError('compare_offsets expects dict[str, int]')
    for d, label in ((ours, 'ours'), (oracle, 'oracle')):
        for k, v in d.items():
            if not isinstance(k, str) or not isinstance(v, int):
                raise TypeError(f'{label} must be dict[str, int]')
    if not isinstance(min_values, int):
        raise TypeError('min_values must be an int')
    if min_values < 0:
        raise ValueError('min_values must be >= 0')

    common = [k for k in oracle if k in ours]
    changed_keys = [k for k in common if ours[k] != oracle[k]]
    changed = len(changed_keys)
    matched = len(common) - changed
    missing = len(oracle) - len(common)
    drift = missing / max(1, len(oracle))
    ok = changed == 0 and (matched + changed) >= min_values
    reason = '' if ok else ('unequal values' if changed else 'too few compared keys')

    samples = [f'{k}: ours={ours[k]!r} oracle={oracle[k]!r}' for k in changed_keys[:5]]
    if len(samples) < 5:
        for k in (k for k in oracle if k not in ours):
            if len(samples) >= 5:
                break
            samples.append(f'{k}: missing from ours (oracle={oracle[k]!r})')
    return DriftResult(ok=ok, matched=matched, changed=changed, drift=drift, reason=reason, samples=tuple(samples))
