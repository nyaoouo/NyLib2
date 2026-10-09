"""Pure-Python PE Debug Directory reader.

Extracts PDB name / GUID / age from a PE's ``IMAGE_DEBUG_TYPE_CODEVIEW`` entry
(RSDS record), plus the ImageBase / SizeOfImage so callers can wire up
``Session.load_address``. No ctypes.windll; safe to run on any platform.
"""
import ntpath
import struct
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

IMAGE_DEBUG_TYPE_CODEVIEW = 2
IMAGE_DIRECTORY_ENTRY_DEBUG = 6
RSDS_MAGIC = b'RSDS'


@dataclass
class PdbInfo:
    pdb_name: str          # sanitized bare basename (never the raw recorded path)
    guid: str              # 32 hex chars, uppercase, no dashes - msdl URL form
    age: int               # int; msdl URL uses hex-upper
    image_base: int        # ImageBase from Optional Header
    size_of_image: int     # SizeOfImage from Optional Header
    is_pe32_plus: bool     # True for PE32+ (x64), False for PE32 (x86)


@dataclass(frozen=True)
class SectionHeader:
    name: str              # latin-1, NUL-stripped, <= 8 bytes
    virtual_address: int
    virtual_size: int
    characteristics: int
    raw_size: int = 0
    raw_pointer: int = 0


@dataclass(frozen=True)
class ImageInfo:
    machine: int           # COFF Machine
    time_date_stamp: int
    image_base: int
    size_of_image: int
    is_pe32_plus: bool
    sections: tuple[SectionHeader, ...]


def _read_at(data: bytes, off: int, fmt: str):
    return struct.unpack_from(fmt, data, off)


def _rva_to_offset(rva: int, sections) -> int | None:
    """Map an RVA to a file offset using the section table."""
    for s in sections:
        if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
            return s.raw_pointer + (rva - s.virtual_address)
    return None


def _parse_coff_and_optional_header(data: bytes):
    """Shared COFF + Optional Header parse (no section table, no debug directory).

    Returns (machine, time_date_stamp, image_base, size_of_image, is_pe32_plus,
    num_rva, data_dir_off, sect_off, num_sections).
    """
    (e_lfanew,) = _read_at(data, 0x3C, '<I')
    if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        raise ValueError(f'PE signature missing at {e_lfanew:#x}')

    # COFF file header: 20 bytes after "PE\0\0"
    coff_off = e_lfanew + 4
    (machine, num_sections, time_date_stamp, _psym, _nsym, size_of_opt_hdr, _chars) = _read_at(
        data, coff_off, '<HHIIIHH')
    opt_off = coff_off + 20

    (magic,) = _read_at(data, opt_off, '<H')
    if magic == 0x20B:
        is_pe32_plus = True
    elif magic == 0x10B:
        is_pe32_plus = False
    else:
        raise ValueError(f'unknown OptionalHeader magic {magic:#x}')

    if is_pe32_plus:
        # PE32+: ImageBase at +24 (u64); SizeOfImage at +56 (u32);
        # NumberOfRvaAndSizes at +108; DataDirectory starts at +112.
        (image_base,) = _read_at(data, opt_off + 24, '<Q')
        (size_of_image,) = _read_at(data, opt_off + 56, '<I')
        (num_rva,) = _read_at(data, opt_off + 108, '<I')
        data_dir_off = opt_off + 112
    else:
        # PE32: ImageBase at +28 (u32); SizeOfImage at +56 (u32);
        # NumberOfRvaAndSizes at +92; DataDirectory starts at +96.
        (image_base,) = _read_at(data, opt_off + 28, '<I')
        (size_of_image,) = _read_at(data, opt_off + 56, '<I')
        (num_rva,) = _read_at(data, opt_off + 92, '<I')
        data_dir_off = opt_off + 96

    sect_off = opt_off + size_of_opt_hdr
    return (machine, time_date_stamp, image_base, size_of_image, is_pe32_plus,
            num_rva, data_dir_off, sect_off, num_sections)


def _parse_sections(data: bytes, sect_off: int, num_sections: int, full: bool = True) -> list[SectionHeader]:
    """Parse the section table.

    ``full=False`` reads only the bytes master's ``read_debug_info`` ever read
    (``vs, va, raw_sz, raw_off`` at ``+8``), to keep that path's struct.error
    offsets/messages unchanged; name and characteristics come back empty/0.
    """
    sections = []
    for i in range(num_sections):
        so = sect_off + i * 40
        # Name(8), VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, ...
        if full:
            (name_raw,) = _read_at(data, so, '<8s')
            vs, va, raw_sz, raw_off = _read_at(data, so + 8, '<IIII')
            (chars,) = _read_at(data, so + 36, '<I')
            name = name_raw.split(b'\0', 1)[0].decode('latin-1')
        else:
            vs, va, raw_sz, raw_off = _read_at(data, so + 8, '<IIII')
            name, chars = '', 0
        sections.append(SectionHeader(name=name, virtual_address=va, virtual_size=vs,
                                       characteristics=chars, raw_size=raw_sz, raw_pointer=raw_off))
    return sections


def _basename(raw_name: str) -> str:
    """Reduce a recorded PDB path to its last path component.

    Real PEs record absolute build paths (e.g. ``C:\\build\\x.pdb``); the
    result still needs ``_validate_bare_name`` before use.
    """
    return raw_name.replace('\\', '/').split('/')[-1]


def _is_reserved_name(name: str) -> bool:
    if hasattr(ntpath, 'isreserved'):
        return ntpath.isreserved(name)
    return PureWindowsPath(name).is_reserved()


def _validate_bare_name(name: str) -> None:
    """Reject a basename unsafe to use as a path component.

    Blocks drive-relative/escaping/ADS/separator tricks and Windows reserved
    device names (``CON``, ``AUX.pdb``, ...).
    """
    if not name or name in ('.', '..') or ':' in name or '/' in name or '\\' in name:
        raise ValueError(f'unsafe PDB name in debug record: {name!r}')
    if PureWindowsPath(name).name != name:
        raise ValueError(f'unsafe PDB name in debug record: {name!r}')
    if _is_reserved_name(name):
        raise ValueError(f'unsafe PDB name in debug record: {name!r}')


def read_debug_info(pe_path) -> PdbInfo:
    """Parse ``pe_path`` and return the RSDS CodeView PDB reference."""
    p = Path(pe_path)
    data = p.read_bytes()

    if len(data) < 0x40 or data[:2] != b'MZ':
        raise ValueError(f'not a PE image: {p}')

    try:
        return _parse_debug_info(data)
    except struct.error as e:
        raise ValueError(f'malformed PE headers in {p}: {e}') from e


def _parse_debug_info(data: bytes) -> PdbInfo:
    (_machine, _tds, image_base, size_of_image, is_pe32_plus,
     num_rva, data_dir_off, sect_off, num_sections) = _parse_coff_and_optional_header(data)

    if num_rva <= IMAGE_DIRECTORY_ENTRY_DEBUG:
        raise ValueError('PE has no Debug Directory')

    dbg_dir_off = data_dir_off + IMAGE_DIRECTORY_ENTRY_DEBUG * 8
    dbg_rva, dbg_size = _read_at(data, dbg_dir_off, '<II')
    if dbg_rva == 0 or dbg_size == 0:
        raise ValueError('empty Debug Directory')

    # Section table follows the optional header; master never read name/characteristics here.
    sections = _parse_sections(data, sect_off, num_sections, full=False)

    dbg_off = _rva_to_offset(dbg_rva, sections)
    if dbg_off is None:
        raise ValueError('debug dir RVA outside sections')

    # Debug Directory entries are 28 bytes each.
    num_entries = dbg_size // 28
    for i in range(num_entries):
        eo = dbg_off + i * 28
        # Characteristics(u32), TimeDateStamp(u32), MajorVer(u16), MinorVer(u16),
        # Type(u32), SizeOfData(u32), AddressOfRawData(RVA u32), PointerToRawData(u32)
        (_, _, _, _, dtype, size_of_data, addr_of_raw, ptr_to_raw) = _read_at(
            data, eo, '<IIHHIIII')
        if dtype != IMAGE_DEBUG_TYPE_CODEVIEW:
            continue

        rec_off = ptr_to_raw or _rva_to_offset(addr_of_raw, sections)
        if rec_off is None or rec_off + 4 > len(data):
            continue

        magic4 = data[rec_off:rec_off + 4]
        if magic4 != RSDS_MAGIC:
            # NB0*/other formats predate PDB 7.0. Skip; a modern binary always
            # has an RSDS entry alongside.
            continue

        # RSDS: DWORD magic, GUID (16), DWORD age, char name[]
        (d1, d2, d3) = _read_at(data, rec_off + 4, '<IHH')
        d4 = data[rec_off + 12:rec_off + 20]
        (age,) = _read_at(data, rec_off + 20, '<I')
        # PDB name is NUL-terminated ASCII/UTF-8.
        name_end = data.find(b'\x00', rec_off + 24)
        if name_end == -1:
            name_end = rec_off + 24 + min(260, len(data) - rec_off - 24)
        raw_name = data[rec_off + 24:name_end].decode('utf-8', errors='replace')
        pdb_name = _basename(raw_name)
        _validate_bare_name(pdb_name)

        guid_hex = f'{d1:08X}{d2:04X}{d3:04X}' + ''.join(f'{b:02X}' for b in d4)
        return PdbInfo(
            pdb_name=pdb_name,
            guid=guid_hex,
            age=age,
            image_base=image_base,
            size_of_image=size_of_image,
            is_pe32_plus=is_pe32_plus,
        )

    raise ValueError('no CodeView (RSDS) debug entry found')


def read_image_info(pe_path) -> ImageInfo:
    """Parse ``pe_path`` and return its COFF machine/base and section layout.

    Unlike ``read_debug_info``, no Debug Directory or RSDS entry is required.
    """
    p = Path(pe_path)
    data = p.read_bytes()

    if len(data) < 0x40 or data[:2] != b'MZ':
        raise ValueError(f'not a PE image: {p}')

    try:
        (machine, time_date_stamp, image_base, size_of_image, is_pe32_plus,
         _num_rva, _data_dir_off, sect_off, num_sections) = _parse_coff_and_optional_header(data)
        sections = _parse_sections(data, sect_off, num_sections)
    except struct.error as e:
        raise ValueError(f'malformed PE headers in {p}: {e}') from e

    return ImageInfo(machine=machine, time_date_stamp=time_date_stamp, image_base=image_base,
                      size_of_image=size_of_image, is_pe32_plus=is_pe32_plus, sections=tuple(sections))


def read_load_address(pe_path) -> int:
    """Convenience wrapper: ImageBase, suitable for Session.load_address."""
    return read_debug_info(pe_path).image_base
