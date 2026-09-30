"""Versioned 2A snapshot I/O: a streaming writer, a lazy loader, and the in-memory `Snapshot`
container every exporter and pipeline stage reads through. Addresses are per-launch (root §6);
`types.jsonl` never carries one, so two dumps of the same build produce identical type files.
"""
import collections.abc
import importlib.metadata
import json
import os
import re
import tempfile

from .errors import SnapshotError, SchemaError  # re-exported
from .model import (
    ClassRecord, EnumRecord, FunctionRecord, ObjectRecord, ObjectTable, StructRecord, TypeRecord,
    hexs, type_from_json, unhex,
)

SCHEMA_NAME = 'nylib.ue.snapshot'
SCHEMA_VERSION = '1.0'
SCHEMA_MAJOR = int(SCHEMA_VERSION.split('.')[0])
OFFSETS_SCHEMA = 'nylib.ue.offsets'
OBJECTS_SCHEMA = 'nylib.ue.objects'
FIELDS_SCHEMA = 'nylib.ue.fields'
OBJECT_COLUMNS = ['index', 'address', 'flags', 'class', 'outer', 'name']
TYPE_CACHE_SIZE = 256  # parsed top-level records a loaded Snapshot keeps (LRU)


def _package_version() -> str:
    try:
        return importlib.metadata.version('nylib')
    except importlib.metadata.PackageNotFoundError:
        return '0+unknown'


GENERATOR_DEFAULT = {'tool': 'nylib.ue', 'version': _package_version(), 'reference': 'Dumper-7@ea0dab3'}

_ADDRESS_LIMIT = 1 << 64
_LONE_SURROGATE_RE = re.compile('[\ud800-\udfff]')
_SCHEMA_VERSION_RE = re.compile(r'\d+\.\d+')


def _in_range(value: int) -> bool:
    return 0 <= value < _ADDRESS_LIMIT


def _dump(obj) -> str:
    """JSON-encode one value the way every file in this module is written.

    Compact separators, `ensure_ascii=False`; a lone surrogate (a wide FName) is escaped so the
    result always encodes as UTF-8. `TypeError`/`ValueError` from `json.dumps` propagate.
    """
    text = json.dumps(obj, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
    if _LONE_SURROGATE_RE.search(text):
        text = _LONE_SURROGATE_RE.sub(lambda m: f'\\u{ord(m.group()):04X}', text)
    return text


def _check_path(value, what: str):
    if not isinstance(value, (str, os.PathLike)):
        raise TypeError(f'{what} must be str or os.PathLike, got {type(value).__name__}')


def _write_objects_jsonl(path, objects) -> int:
    written = 0
    prev_index = -1
    header = _dump({'schema': {'name': OBJECTS_SCHEMA, 'version': SCHEMA_VERSION}, 'columns': OBJECT_COLUMNS})
    with open(path, 'wb') as f:
        f.write(header.encode('utf-8') + b'\n')
        for rec in objects:
            if not isinstance(rec, ObjectRecord):
                raise TypeError(f'object element must be an ObjectRecord, got {type(rec).__name__}')
            for field_name in ('index', 'address', 'flags', 'class_index', 'outer_index'):
                if not isinstance(getattr(rec, field_name), int):
                    raise TypeError(f'object {field_name} must be an int, got '
                                     f'{type(getattr(rec, field_name)).__name__}')
            if not isinstance(rec.name, str):
                raise TypeError(f'object name must be a str, got {type(rec.name).__name__}')
            if rec.vtable_rva is not None and not isinstance(rec.vtable_rva, int):
                raise TypeError(f'object vtable_rva must be int or None, got {type(rec.vtable_rva).__name__}')
            if rec.index < 0:
                raise ValueError(f'object index {rec.index} is negative')
            if rec.index <= prev_index:
                raise ValueError(f'object index {rec.index} does not increase past {prev_index}')
            if not _in_range(rec.address):
                raise ValueError(f'object address out of range: {rec.address:#x}')
            prev_index = rec.index
            row = rec.to_row()
            row[0], row[3], row[4] = int(row[0]), int(row[3]), int(row[4])  # bool is an int subtype (F1)
            f.write(_dump(row).encode('utf-8') + b'\n')
            written += 1
    return written


def _write_fields_jsonl(path, fields) -> int:
    written = 0
    prev_owner = -1
    header = _dump({'schema': {'name': FIELDS_SCHEMA, 'version': SCHEMA_VERSION}})
    with open(path, 'wb') as f:
        f.write(header.encode('utf-8') + b'\n')
        for item in fields:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                raise TypeError(f'field item must be a 2-tuple or 2-list, got {item!r}')
            owner, addresses = item
            if not isinstance(owner, int):
                raise TypeError(f'field owner must be an int, got {type(owner).__name__}')
            if not isinstance(addresses, (tuple, list)):
                raise TypeError(f'field addresses must be a list or tuple, got {type(addresses).__name__}')
            for a in addresses:
                if not isinstance(a, int):
                    raise TypeError(f'field address must be an int, got {type(a).__name__}')
            if owner < 0:
                raise ValueError(f'field owner {owner} is negative')
            if owner <= prev_owner:
                raise ValueError(f'field owner {owner} does not increase past {prev_owner}')
            for a in addresses:
                if not _in_range(a):
                    raise ValueError(f'field address out of range: {a:#x}')
            prev_owner = owner
            f.write(_dump([int(owner), [hexs(a) for a in addresses]]).encode('utf-8') + b'\n')
            written += 1
    return written


def _write_types_files(partial, types) -> int:
    spool = tempfile.NamedTemporaryFile(dir=partial, delete=False)
    try:
        entries = []
        for rec in types:
            to_json = getattr(rec, 'to_json', None)
            path_attr = getattr(rec, 'path', None)
            if not callable(to_json) or not isinstance(path_attr, str):
                raise TypeError(f'type element must have to_json()/path str, got {type(rec).__name__}')
            line = _dump(to_json()).encode('utf-8')
            offset = spool.tell()
            spool.write(line + b'\n')
            entries.append((path_attr, offset, len(line)))
        spool.flush()
        # Sort/dedupe by the read-back form: a lone-surrogate pair and its combined astral code
        # point serialise to the same JSON text, so they must collide here, not silently
        # overwrite one idx entry after a reload.
        entries.sort(key=lambda e: json.loads(_dump(e[0])))
        for i in range(1, len(entries)):
            if json.loads(_dump(entries[i][0])) == json.loads(_dump(entries[i - 1][0])):
                raise ValueError(f'duplicate type path {entries[i][0]!r}')
        idx = {}
        written = 0
        out_offset = 0
        with open(os.path.join(partial, 'types.jsonl'), 'wb') as out:
            for path_attr, spool_offset, length in entries:
                spool.seek(spool_offset)
                data = spool.read(length)
                out.write(data + b'\n')
                idx[path_attr] = [out_offset, length]
                out_offset += length + 1
                written += 1
        with open(os.path.join(partial, 'types.idx.json'), 'wb') as f:
            f.write(_dump(idx).encode('utf-8') + b'\n')
        return written
    finally:
        spool.close()
        try:
            os.remove(spool.name)
        except OSError:
            pass


def write_snapshot(folder, meta: dict, offsets: dict, objects, types, fields, *, generator: dict | None = None) -> dict:
    """Stream a 2A snapshot into `<folder>.partial` and return counts; the caller renames it.

    Every argument is validated before any file is opened or deleted; an exception while streaming
    leaves `partial` without `meta.json`, so an interrupted write never loads as complete.
    """
    _check_path(folder, 'folder')
    folder_str = os.fspath(folder)
    if folder_str == '':
        raise ValueError('folder must not be empty')
    base = os.path.basename(os.path.normpath(folder_str))
    if base.lower().endswith('.partial'):
        raise ValueError(f'folder name must not end in .partial: {folder_str!r}')
    if not isinstance(meta, dict):
        raise TypeError(f'meta must be a dict, got {type(meta).__name__}')
    if not isinstance(offsets, dict):
        raise TypeError(f'offsets must be a dict, got {type(offsets).__name__}')
    if generator is not None and not isinstance(generator, dict):
        raise TypeError(f'generator must be a dict or None, got {type(generator).__name__}')

    offsets_doc = {'schema': {'name': OFFSETS_SCHEMA, 'version': SCHEMA_VERSION},
                   **{k: v for k, v in offsets.items() if k != 'schema'}}
    meta_doc = {**meta, 'schema': {'name': SCHEMA_NAME, 'version': SCHEMA_VERSION},
                'generator': dict(generator) if generator is not None else dict(GENERATOR_DEFAULT)}
    try:
        offsets_line = _dump(offsets_doc)
    except (TypeError, ValueError) as e:
        raise ValueError(f'offsets is not serialisable: {e}') from e
    try:
        meta_line = _dump(meta_doc)
    except (TypeError, ValueError) as e:
        raise ValueError(f'meta is not serialisable: {e}') from e

    partial = os.path.abspath(folder_str) + '.partial'
    os.makedirs(partial, exist_ok=True)
    meta_path = os.path.join(partial, 'meta.json')
    if os.path.exists(meta_path):
        os.remove(meta_path)  # BEFORE any other file is opened

    with open(os.path.join(partial, 'offsets.json'), 'wb') as f:
        f.write(offsets_line.encode('utf-8') + b'\n')
    objects_written = _write_objects_jsonl(os.path.join(partial, 'objects.jsonl'), objects)
    fields_written = _write_fields_jsonl(os.path.join(partial, 'fields.jsonl'), fields)
    types_written = _write_types_files(partial, types)
    with open(meta_path, 'wb') as f:
        f.write(meta_line.encode('utf-8') + b'\n')

    return {'partial': partial, 'objects': objects_written, 'types': types_written, 'fields': fields_written}


def _read_text(path, folder, missing_reason: str) -> str:
    if not os.path.isfile(path):
        raise SnapshotError(folder, missing_reason)
    with open(path, 'rb') as f:
        data = f.read()
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError as e:
        raise SnapshotError(folder, f'{os.path.basename(path)} is not valid utf-8') from e


def _json_loads_or_error(text: str, folder, label: str):
    try:
        return json.loads(text)
    except (ValueError, RecursionError) as e:  # json.JSONDecodeError, a huge int, or deep nesting
        raise SnapshotError(folder, f'{label} is not valid json') from e


def _split_jsonl(text: str, folder, label: str) -> list[str]:
    if not text.endswith('\n'):
        raise SnapshotError(folder, f'{label} does not end with a newline')
    lines = text.split('\n')[:-1]
    if any(line == '' for line in lines):
        raise SnapshotError(folder, f'{label} contains an empty line')
    return lines


def _check_header_schema(doc, folder, expected_name: str, label: str):
    if not isinstance(doc, dict):
        raise SnapshotError(folder, f'{label} is not a json object')
    schema = doc.get('schema')
    if not isinstance(schema, dict) or schema.get('name') != expected_name:
        raise SnapshotError(folder, f'{label}.schema is missing or invalid')


def _load_meta(folder, folder_str: str) -> dict:
    meta_path = os.path.join(folder_str, 'meta.json')
    text = _read_text(meta_path, folder, 'not a completed snapshot')
    meta = _json_loads_or_error(text, folder, 'meta.json')
    _check_header_schema(meta, folder, SCHEMA_NAME, 'meta.json')
    version = meta['schema'].get('version')
    if not isinstance(version, str) or not _SCHEMA_VERSION_RE.fullmatch(version):
        raise SnapshotError(folder, 'meta.json.schema.version is missing or invalid')
    try:
        major = int(version.split('.', 1)[0])
    except ValueError as e:  # the int-string conversion limit on an absurdly long digit run
        raise SnapshotError(folder, 'meta.json.schema.version is missing or invalid') from e
    if major != SCHEMA_MAJOR:
        generator = meta.get('generator')
        writer_version = generator.get('version') if isinstance(generator, dict) else None
        if not isinstance(writer_version, str):
            writer_version = 'unknown'
        raise SchemaError(folder, f'{meta_path} has schema {version}; this reader understands {SCHEMA_MAJOR}.x. '
                                   f'Update nylib, or read it with the nylib.ue version that wrote it ({writer_version}).')
    return meta


def _load_offsets(folder, folder_str: str) -> dict:
    path = os.path.join(folder_str, 'offsets.json')
    text = _read_text(path, folder, 'missing offsets.json')
    doc = _json_loads_or_error(text, folder, 'offsets.json')
    _check_header_schema(doc, folder, OFFSETS_SCHEMA, 'offsets.json')
    return doc


def _load_objects(folder, folder_str: str) -> ObjectTable:
    path = os.path.join(folder_str, 'objects.jsonl')
    text = _read_text(path, folder, 'missing objects.jsonl')
    lines = _split_jsonl(text, folder, 'objects.jsonl')
    header = _json_loads_or_error(lines[0], folder, 'objects.jsonl header')
    _check_header_schema(header, folder, OBJECTS_SCHEMA, 'objects.jsonl')
    records = []
    prev_index = -1
    for line in lines[1:]:
        row = _json_loads_or_error(line, folder, 'objects.jsonl row')
        try:
            rec = ObjectRecord.from_row(row)
        except ValueError as e:
            raise SnapshotError(folder, str(e)) from e
        if not _in_range(rec.address):
            raise SnapshotError(folder, f'objects.jsonl address out of range: {rec.address:#x}')
        if rec.index <= prev_index:
            raise SnapshotError(folder, f'objects.jsonl index {rec.index} does not increase past {prev_index}')
        prev_index = rec.index
        records.append(rec)
    try:
        return ObjectTable(records)
    except (TypeError, ValueError) as e:
        raise SnapshotError(folder, str(e)) from e


def _load_fields(folder, folder_str: str) -> dict:
    path = os.path.join(folder_str, 'fields.jsonl')
    if not os.path.isfile(path):
        return {}
    text = _read_text(path, folder, 'missing fields.jsonl')
    lines = _split_jsonl(text, folder, 'fields.jsonl')
    header = _json_loads_or_error(lines[0], folder, 'fields.jsonl header')
    _check_header_schema(header, folder, FIELDS_SCHEMA, 'fields.jsonl')
    result = {}
    prev_owner = -1
    for line in lines[1:]:
        row = _json_loads_or_error(line, folder, 'fields.jsonl row')
        if not isinstance(row, list) or len(row) != 2:
            raise SnapshotError(folder, f'invalid fields.jsonl row {row!r}')
        owner, addr_hexes = row
        if not isinstance(owner, int) or isinstance(owner, bool):
            raise SnapshotError(folder, f'invalid fields.jsonl owner {owner!r}')
        if owner < 0 or owner <= prev_owner:
            raise SnapshotError(folder, f'fields.jsonl owner {owner} does not increase past {prev_owner}')
        if not isinstance(addr_hexes, list):
            raise SnapshotError(folder, 'fields.jsonl addresses must be a list')
        addresses = []
        for h in addr_hexes:
            if not isinstance(h, str):
                raise SnapshotError(folder, f'invalid fields.jsonl address {h!r}')
            try:
                a = unhex(h)
            except ValueError as e:
                raise SnapshotError(folder, str(e)) from e
            if not _in_range(a):
                raise SnapshotError(folder, f'fields.jsonl address out of range: {h}')
            addresses.append(a)
        result[owner] = addresses
        prev_owner = owner
    return result


def _load_types_index(folder, folder_str: str):
    jsonl_path = os.path.join(folder_str, 'types.jsonl')
    if not os.path.isfile(jsonl_path):
        raise SnapshotError(folder, 'missing types.jsonl')
    size = os.path.getsize(jsonl_path)
    idx_path = os.path.join(folder_str, 'types.idx.json')
    text = _read_text(idx_path, folder, 'missing types.idx.json')
    doc = _json_loads_or_error(text, folder, 'types.idx.json')
    if not isinstance(doc, dict):
        raise SnapshotError(folder, 'types.idx.json is not a json object')
    idx = {}
    for path_key, value in doc.items():
        if not isinstance(value, list) or len(value) != 2:
            raise SnapshotError(folder, f'invalid types.idx.json entry for {path_key!r}')
        offset, length = value
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise SnapshotError(folder, f'invalid types.idx.json offset for {path_key!r}')
        if not isinstance(length, int) or isinstance(length, bool) or length < 1:
            raise SnapshotError(folder, f'invalid types.idx.json length for {path_key!r}')
        if offset + length + 1 > size:
            raise SnapshotError(folder, f'types.idx.json entry for {path_key!r} is out of bounds')
        idx[path_key] = (offset, length)
    return idx, jsonl_path


def _build_fields_map(fields) -> dict:
    items = fields.items() if isinstance(fields, collections.abc.Mapping) else fields
    result = {}
    for item in items:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise TypeError(f'field item must be a 2-tuple or 2-list, got {item!r}')
        owner, addresses = item
        if not isinstance(owner, int):
            raise TypeError(f'field owner must be an int, got {type(owner).__name__}')
        if owner < 0:
            raise ValueError(f'field owner {owner} is negative')
        if not isinstance(addresses, (tuple, list)):
            raise TypeError(f'field addresses must be a list or tuple, got {type(addresses).__name__}')
        for a in addresses:
            if not isinstance(a, int):
                raise TypeError(f'field address must be an int, got {type(a).__name__}')
            if not _in_range(a):
                raise ValueError(f'field address out of range: {a:#x}')
        if owner in result:
            raise ValueError(f'duplicate field owner {owner}')
        result[owner] = list(addresses)
    return result


class Snapshot:
    """An in-memory or lazily-loaded 2A snapshot: objects, per-launch field addresses and types.

    In-memory (`Snapshot(...)`) holds every type record; `Snapshot.load` keeps `types.jsonl` open
    and parses a type only when first resolved, with an LRU of `TYPE_CACHE_SIZE` records.
    """

    def __init__(self, meta: dict, offsets: dict, objects: ObjectTable, types, *, fields=()):
        if not isinstance(meta, dict):
            raise TypeError(f'meta must be a dict, got {type(meta).__name__}')
        if not isinstance(offsets, dict):
            raise TypeError(f'offsets must be a dict, got {type(offsets).__name__}')
        if not isinstance(objects, ObjectTable):
            raise TypeError(f'objects must be an ObjectTable, got {type(objects).__name__}')
        self.meta = meta
        self.offsets = offsets
        self.objects = objects
        self.path = None
        self._loaded = False
        self._closed = False
        types_map = {}
        for rec in types:
            if not isinstance(rec, TypeRecord):
                raise TypeError(f'type element must be a TypeRecord, got {type(rec).__name__}')
            types_map.setdefault(rec.path, rec)
        self._types = types_map
        self._fields = _build_fields_map(fields)

    @property
    def stem(self) -> str:
        target = self.meta.get('target')
        if isinstance(target, dict):
            s = target.get('stem')
            if isinstance(s, str):
                return s
        return ''

    def _type_exact(self, path: str):
        if not self._loaded:
            return self._types.get(path)
        if path in self._cache:
            self._cache.move_to_end(path)
            return self._cache[path]
        entry = self._idx.get(path)
        if entry is None:
            return None
        offset, length = entry
        self._file.seek(offset)
        data = self._file.read(length)
        if len(data) != length:
            raise SnapshotError(self.path, f'short read for type {path!r}')
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError as e:
            raise SnapshotError(self.path, f'type {path!r} is not valid utf-8') from e
        try:
            loaded = json.loads(text)
        except (ValueError, RecursionError) as e:  # bad JSON, a huge int, or deep nesting
            raise SnapshotError(self.path, f'type {path!r} is not valid json') from e
        if not isinstance(loaded, dict):
            raise SnapshotError(self.path, f'type {path!r} is not a json object')
        if loaded.get('path') != path:
            raise SnapshotError(self.path, f'index entry for {path!r} points at {loaded.get("path")!r}')
        try:
            rec = type_from_json(loaded)
        except (ValueError, RecursionError) as e:
            raise SnapshotError(self.path, str(e)) from e
        self._cache[path] = rec
        if len(self._cache) > TYPE_CACHE_SIZE:
            self._cache.popitem(last=False)
        return rec

    def type(self, path: str):
        if not isinstance(path, str):
            raise TypeError(f'path must be a str, got {type(path).__name__}')
        if self._loaded and self._closed:
            raise ValueError('snapshot is closed')
        rec = self._type_exact(path)
        if rec is not None:
            return rec
        if ':' in path:
            class_path, _, fn_name = path.rpartition(':')
            class_rec = self._type_exact(class_path)
            if isinstance(class_rec, ClassRecord):
                return class_rec.functions.get(fn_name)
            return None
        return None

    def types(self):
        if self._loaded and self._closed:
            raise ValueError('snapshot is closed')
        if not self._loaded:
            paths = sorted(self._types)
            return (self._types[p] for p in paths)
        paths = list(self._idx)
        return (self.type(p) for p in paths)

    def type_of_object(self, index: int):
        if not isinstance(index, int):
            raise TypeError(f'index must be an int, got {type(index).__name__}')
        if index not in self.objects:
            raise KeyError(index)
        if self._loaded and self._closed:
            raise ValueError('snapshot is closed')
        try:
            p = self.objects.path(index)
        except ValueError:
            return None
        return self.type(p)

    def field_addresses(self, owner_index: int) -> list[int] | None:
        if not isinstance(owner_index, int):
            raise TypeError(f'owner_index must be an int, got {type(owner_index).__name__}')
        row = self._fields.get(owner_index)
        return list(row) if row is not None else None

    def close(self) -> None:
        if self._loaded and not self._closed:
            self._file.close()
            self._cache.clear()
            self._closed = True

    def __enter__(self) -> 'Snapshot':
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @classmethod
    def load(cls, folder, *, _partial: bool = False) -> 'Snapshot':
        _check_path(folder, 'folder')
        folder_str = os.fspath(folder)
        # rstrip: Windows silently drops trailing dots/spaces from a directory name, so a caller
        # passing them still names the `.partial` folder the filesystem actually created.
        name = os.path.basename(os.path.normpath(folder_str)).rstrip('. ')
        if not _partial and name.lower().endswith('.partial'):
            raise SnapshotError(folder, 'not a completed snapshot')

        meta = _load_meta(folder, folder_str)
        offsets = _load_offsets(folder, folder_str)
        objects = _load_objects(folder, folder_str)
        fields = _load_fields(folder, folder_str)
        idx, jsonl_path = _load_types_index(folder, folder_str)

        self = cls.__new__(cls)
        self.meta = meta
        self.offsets = offsets
        self.objects = objects
        self.path = folder_str
        self._fields = fields
        self._loaded = True
        self._closed = False
        self._idx = idx
        self._file = open(jsonl_path, 'rb')
        self._cache = collections.OrderedDict()
        return self
