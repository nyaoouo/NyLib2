"""Export dispatch registry: format name -> relative path and writer (P13)."""
import dataclasses
import os
from typing import Callable

from ..names import valid_file_name
from . import gobjects, idmap, usmap


def _check_out_dir(out_dir):
    if not isinstance(out_dir, (str, os.PathLike)):
        raise TypeError(f'out_dir must be str or os.PathLike, got {type(out_dir).__name__}')


def _stem(snapshot) -> str:
    s = snapshot.stem
    return valid_file_name(s) if s else 'unknown'


@dataclasses.dataclass(frozen=True, slots=True)
class ExportSpec:
    fmt: str
    rel_path: Callable[[object], str]
    writer: Callable[[object, object], str]


EXPORT_SPECS: dict[str, ExportSpec] = {
    'gobjects': ExportSpec('gobjects', lambda snap: 'GObjects-Dump.txt', gobjects.write_objects),
    'gobjects-props': ExportSpec(
        'gobjects-props', lambda snap: 'GObjects-Dump-WithProperties.txt', gobjects.write_objects_with_properties),
    'idmap': ExportSpec('idmap', lambda snap: f'IDAMappings/{_stem(snap)}.idmap', idmap.write),
    'usmap': ExportSpec('usmap', lambda snap: f'Mappings/{_stem(snap)}.usmap', usmap.write),
}
DEFAULT_EXPORTS = ('idmap', 'gobjects', 'gobjects-props', 'usmap')  # the snapshot exports of dump's default (P13); pipeline.DEFAULT_DUMP_EXPORTS adds 'image'


def _spec(fmt: str) -> ExportSpec:
    if not isinstance(fmt, str):
        raise TypeError(f'fmt must be a str, got {type(fmt).__name__}')
    spec = EXPORT_SPECS.get(fmt)
    if spec is None:
        raise ValueError(f'unknown export format {fmt!r}')
    return spec


def export_path(fmt: str, snapshot) -> str:
    return _spec(fmt).rel_path(snapshot)


def run_export(fmt: str, snapshot, out_dir) -> str:
    spec = _spec(fmt)
    _check_out_dir(out_dir)
    return spec.writer(snapshot, out_dir)
