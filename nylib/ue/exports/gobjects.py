"""Dumper-7-compatible GObjects text dumps: parity with ObjectArray.cpp @ ea0dab3.

Files are written in binary-safe text mode (`newline=''`) with explicit `\\r\\n`, so the header's
and rows' embedded CRLF survive untouched; no `\\n` is ever emitted on its own.
"""
import os

from ..model import FunctionRecord, StructRecord

_LINE1 = 'Object dump by nylib.ue (Dumper-7 format)'


def _check_out_dir(out_dir):
    if not isinstance(out_dir, (str, os.PathLike)):
        raise TypeError(f'out_dir must be str or os.PathLike, got {type(out_dir).__name__}')


def _count(snapshot) -> int:
    globals_ = snapshot.meta.get('globals')
    if isinstance(globals_, dict):
        gobjects = globals_.get('GObjects')
        if isinstance(gobjects, dict):
            n = gobjects.get('num_elements')
            if isinstance(n, int) and not isinstance(n, bool):
                return n
    return len(snapshot.objects)


def _header(snapshot) -> str:
    stem = snapshot.stem
    count = _count(snapshot)
    stem_part = f'{stem}\r\n\r\n' if stem else ''
    return f'{_LINE1}\r\n\r\n{stem_part}Count: {count}\r\n\r\n\r\n'


def _object_row(snapshot, rec) -> str:
    try:
        full_name = snapshot.objects.full_name(rec.index)
    except ValueError:
        full_name = '<cyclic>'
    return f'[{rec.index:08X}] {{{rec.address:#x}}} {full_name}\r\n'


def _properties_of(type_rec):
    if isinstance(type_rec, FunctionRecord):
        return type_rec.params
    if isinstance(type_rec, StructRecord):  # covers ClassRecord too
        return type_rec.properties
    return None


def _property_rows(snapshot, rec) -> str:
    type_rec = snapshot.type_of_object(rec.index)
    props = _properties_of(type_rec)
    if not props:
        return ''
    addresses = snapshot.field_addresses(rec.index)
    if not addresses:
        return ''
    # zip() stops at the shorter of the two: the `min(len_addrs, len_props)` rule of S2.
    return ''.join(
        f'[{prop.offset:08X}] {{{addr:#x}}}     {prop.type.prop} {prop.name}\r\n'
        for prop, addr in zip(props, addresses)
    )


def _open_target(out_dir, filename) -> str:
    path = os.path.join(os.fspath(out_dir), filename)
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    return path


def write_objects(snapshot, out_dir) -> str:
    """Write `<out_dir>/GObjects-Dump.txt`: index-ordered object rows, no property rows."""
    _check_out_dir(out_dir)
    path = _open_target(out_dir, 'GObjects-Dump.txt')
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write(_header(snapshot))
        for rec in snapshot.objects:
            f.write(_object_row(snapshot, rec))
    return os.path.abspath(path)


def write_objects_with_properties(snapshot, out_dir) -> str:
    """Write `<out_dir>/GObjects-Dump-WithProperties.txt`: object rows plus property rows.

    A struct/class/function object's property rows follow it; a shorter field-address row than
    its property list prints the shorter (min) count.
    """
    _check_out_dir(out_dir)
    path = _open_target(out_dir, 'GObjects-Dump-WithProperties.txt')
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write(_header(snapshot))
        for rec in snapshot.objects:
            f.write(_object_row(snapshot, rec))
            f.write(_property_rows(snapshot, rec))
    return os.path.abspath(path)
