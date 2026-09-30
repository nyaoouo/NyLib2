"""Test helper: map a PE file from disk into an ImageSource, the way the Windows loader maps it at its preferred base."""
import os
import struct

from ..capture import ImageSource
from ..memory import Module

_SECTION_STRUCT = struct.Struct('<8sIIIIIIHHI')  # matches nylib.ue.pe._SECTION_STRUCT


def align_up(value: int, alignment: int) -> int:
    return value if alignment <= 1 else (value + alignment - 1) & ~(alignment - 1)


def map_pe_file(path: str) -> ImageSource:
    """Map a PE32+ AMD64 file at its preferred ImageBase: headers, then each section's raw data at its
    VirtualAddress, zero-filled up to align_up(VirtualSize, SectionAlignment); no relocations applied
    (correct at the preferred base). Creates one Module for the file."""
    with open(path, 'rb') as f:
        data = f.read()
    nt = struct.unpack_from('<I', data, 0x3C)[0]
    num_sections, = struct.unpack_from('<H', data, nt + 6)
    size_opt, = struct.unpack_from('<H', data, nt + 20)
    opt = nt + 24
    image_base, = struct.unpack_from('<Q', data, opt + 0x18)
    section_alignment, = struct.unpack_from('<I', data, opt + 0x20)
    size_image, = struct.unpack_from('<I', data, opt + 0x38)
    size_headers, = struct.unpack_from('<I', data, opt + 0x3C)

    segments = [(image_base, bytes(data[:size_headers]))]
    sec_table = opt + size_opt
    for i in range(num_sections):
        entry = data[sec_table + i * _SECTION_STRUCT.size: sec_table + (i + 1) * _SECTION_STRUCT.size]
        _name, virt_size, virt_addr, raw_size, ptr_raw, *_rest = _SECTION_STRUCT.unpack(entry)
        size = align_up(virt_size, section_alignment)
        if size == 0:
            continue
        copy_len = min(raw_size, virt_size, max(len(data) - ptr_raw, 0)) if raw_size else 0
        raw = data[ptr_raw:ptr_raw + copy_len] if copy_len > 0 else b''
        segments.append((image_base + virt_addr, raw + bytes(size - len(raw))))

    module = Module(os.path.basename(path), image_base, size_image, path)
    return ImageSource(segments, [module])
