"""Dumper-7 idmap V1 stream: literal port of IDAMappingGenerator.cpp @ ea0dab3.

No header, no `ReadMe.txt`. Vtable records are not deduplicated by RVA (only the super-CDO-vtable
skip filters them); exec records are deduplicated globally by RVA, first wins.
"""
import os
import struct

from ..flags import EFunctionFlags, EObjectFlags
from ..model import ClassRecord
from ..names import make_name_valid, mangle_exec, strip_path, valid_file_name


def _check_out_dir(out_dir):
    if not isinstance(out_dir, (str, os.PathLike)):
        raise TypeError(f'out_dir must be str or os.PathLike, got {type(out_dir).__name__}')


def _cdo_record(snapshot, o):
    class_obj = snapshot.objects.class_of(o.index)
    class_rec = snapshot.type_of_object(class_obj.index) if class_obj is not None else None
    if not isinstance(class_rec, ClassRecord) or o.vtable_rva is None:
        return None
    super_rec = snapshot.type(class_rec.super) if class_rec.super is not None else None
    super_cdo = None
    if isinstance(super_rec, ClassRecord) and super_rec.cdo is not None:
        super_cdo = snapshot.objects.index_of_path(super_rec.cdo)
    super_vtable = snapshot.objects[super_cdo].vtable_rva if super_cdo is not None else None
    if super_rec is not None and super_vtable is not None and super_vtable == o.vtable_rva:
        return None  # Super && GetVft() == Super.GetDefaultObject().GetVft()
    return o.vtable_rva & 0xFFFFFFFF, class_rec.cpp_name + '_VFT'


def _class_records(snapshot, cr, seen_exec_rvas):
    for fn in cr.functions.values():
        if not (fn.flags & EFunctionFlags.Native):
            continue
        if fn.exec_rva is None:
            continue
        rva = fn.exec_rva & 0xFFFFFFFF
        if rva in seen_exec_rvas:
            continue
        seen_exec_rvas.add(rva)
        yield rva, mangle_exec(cr.cpp_name, make_name_valid(strip_path(fn.name)))


def _records(snapshot):
    seen_exec_rvas = set()
    for o in snapshot.objects:
        if o.flags & EObjectFlags.ClassDefaultObject:
            rec = _cdo_record(snapshot, o)
            if rec is not None:
                yield rec
            continue
        type_rec = snapshot.type_of_object(o.index)
        if isinstance(type_rec, ClassRecord):
            yield from _class_records(snapshot, type_rec, seen_exec_rvas)


def write(snapshot, out_dir) -> str:
    """Write `<out_dir>/IDAMappings/<file stem>.idmap`: `struct.pack('<IH', rva, len(nb)) + nb` records."""
    _check_out_dir(out_dir)
    stem = valid_file_name(snapshot.stem) if snapshot.stem else 'unknown'
    path = os.path.join(os.fspath(out_dir), 'IDAMappings', f'{stem}.idmap')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        for rva, name in _records(snapshot):
            nb = name.encode('utf-8')
            f.write(struct.pack('<IH', rva, len(nb) & 0xFFFF) + nb)
    return os.path.abspath(path)
