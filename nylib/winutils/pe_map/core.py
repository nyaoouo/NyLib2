"""Validate PE file bytes and describe image layout without touching a process."""

import dataclasses
import hashlib
import struct


class PEFormatError(ValueError):
    pass


class UnsupportedImageError(PEFormatError):
    pass


@dataclasses.dataclass(frozen=True)
class DataDirectory:
    rva: int
    size: int


@dataclasses.dataclass(frozen=True)
class SectionPlan:
    name: str
    source_offset: int
    source_size: int
    target_rva: int
    virtual_size: int
    mapped_size: int
    characteristics: int
    protection: int
    discardable: bool

    @property
    def zero_rva(self) -> int:
        return self.target_rva + self.source_size

    @property
    def zero_size(self) -> int:
        return self.mapped_size - self.source_size


@dataclasses.dataclass(frozen=True)
class RelocFixup:
    target_rva: int
    width: int
    delta: int


@dataclasses.dataclass(frozen=True)
class ImportSymbol:
    thunk_rva: int
    name: str | None
    ordinal: int | None


@dataclasses.dataclass(frozen=True)
class ImportRequest:
    module: str
    symbols: tuple[ImportSymbol, ...]
    delay: bool = False
    module_handle_rva: int = 0


@dataclasses.dataclass(frozen=True)
class ExportSymbol:
    name: str | None
    ordinal: int
    rva: int
    forwarder: str | None = None


@dataclasses.dataclass(frozen=True)
class TlsPlan:
    template_rva: int
    template_size: int
    index_rva: int
    callbacks: tuple[int, ...]
    zero_fill: int


@dataclasses.dataclass(frozen=True)
class UnwindEntry:
    begin_rva: int
    end_rva: int
    info_rva: int


@dataclasses.dataclass(frozen=True)
class LoadConfigPlan:
    size: int
    security_cookie_rva: int | None
    guard_flags: int


@dataclasses.dataclass(frozen=True)
class ParsedImage:
    source_size: int
    source_sha256: bytes
    machine: int
    pointer_size: int
    preferred_base: int
    size_of_image: int
    size_of_headers: int
    entry_rva: int
    section_alignment: int
    file_alignment: int
    characteristics: int
    dll_characteristics: int
    directories: tuple[DataDirectory, ...]
    sections: tuple[SectionPlan, ...]
    relocation_entries: tuple[tuple[int, int], ...]
    imports: tuple[ImportRequest, ...]
    delay_imports: tuple[ImportRequest, ...]
    exports: tuple[ExportSymbol, ...]
    tls: TlsPlan | None
    unwind: tuple[UnwindEntry, ...]
    load_config: LoadConfigPlan | None


@dataclasses.dataclass(frozen=True)
class ImagePlan:
    image: ParsedImage
    target_base: int
    relocations: tuple[RelocFixup, ...]

    @property
    def entry_point(self) -> int:
        return self.target_base + self.image.entry_rva if self.image.entry_rva else 0


_MAX_IMAGE_SIZE = 0x40000000
_MAX_SECTIONS = 96
_MAX_ARRAY_ENTRIES = 0x10000
_MAX_STRING_SIZE = 0x1000
_DIRECTORY_COUNT = 16


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _power_of_two(value: int) -> bool:
    return value > 0 and not value & (value - 1)


def _protection(flags: int) -> int:
    executable = bool(flags & 0x20000000)
    readable = bool(flags & 0x40000000)
    writable = bool(flags & 0x80000000)
    if executable: return 0x40 if writable else 0x20 if readable else 0x10
    return 0x04 if writable else 0x02 if readable else 0x01


class _Reader:
    def __init__(self, image: bytes | bytearray | memoryview):
        self.data = memoryview(image).cast('B')
        self.sections: tuple[SectionPlan, ...] = ()
        self.headers_size = 0
        self.image_size = 0
        self.preferred_base = 0
        self.pointer_size = 0

    def unpack(self, offset: int, fmt: str):
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(self.data):
            raise PEFormatError(f'truncated PE data at file offset {offset:#x}')
        return struct.unpack_from(fmt, self.data, offset)

    def offset(self, rva: int, size: int = 1) -> int:
        if size < 0 or rva < 0 or rva + size > self.image_size:
            raise PEFormatError(f'RVA {rva:#x}+{size:#x} is outside the image')
        if rva < self.headers_size and rva + size <= self.headers_size:
            if rva + size > len(self.data):
                raise PEFormatError(f'truncated PE headers at RVA {rva:#x}')
            return rva
        for section in self.sections:
            if section.target_rva <= rva and rva + size <= section.target_rva + section.source_size:
                return section.source_offset + rva - section.target_rva
        raise PEFormatError(f'RVA {rva:#x}+{size:#x} has no file-backed data')

    def at_rva(self, rva: int, fmt: str):
        return self.unpack(self.offset(rva, struct.calcsize(fmt)), fmt)

    def string(self, rva: int) -> str:
        offset = self.offset(rva)
        for size in range(1, _MAX_STRING_SIZE + 1):
            self.offset(rva, size)
            if self.data[offset + size - 1] == 0:
                try:
                    return self.data[offset:offset + size - 1].tobytes().decode('ascii')
                except UnicodeDecodeError as e:
                    raise PEFormatError(f'non-ASCII PE string at RVA {rva:#x}') from e
        raise PEFormatError(f'unterminated PE string at RVA {rva:#x}')

    def va_to_rva(self, va: int, size: int = 1) -> int:
        rva = va - self.preferred_base
        if va == 0 or rva < 0 or rva + size > self.image_size:
            raise PEFormatError(f'VA {va:#x} is outside the preferred image')
        return rva

    def pointer_array(self, rva: int, *, require_mapped: bool = False) -> tuple[int, ...]:
        fmt = '<Q' if self.pointer_size == 8 else '<I'
        values = []
        for index in range(_MAX_ARRAY_ENTRIES):
            slot_rva = rva + index * self.pointer_size
            value, = self.at_rva(slot_rva, fmt)
            if value == 0: return tuple(values)
            if require_mapped:
                self.va_to_rva(value)
            values.append(value)
        raise PEFormatError(f'unterminated pointer array at RVA {rva:#x}')


def parse_image(image: bytes | bytearray | memoryview) -> ParsedImage:
    """Parse a PE DLL from bytes and return source-independent metadata."""
    reader = _Reader(image)
    data = reader.data
    if len(data) < 0x40 or data[:2].tobytes() != b'MZ':
        raise PEFormatError('missing DOS signature')
    pe_offset, = reader.unpack(0x3c, '<I')
    if reader.unpack(pe_offset, '<I')[0] != 0x4550:
        raise PEFormatError('missing PE signature')
    machine, section_count, _, _, _, optional_size, characteristics = reader.unpack(pe_offset + 4, '<HHIIIHH')
    if not 0 < section_count <= _MAX_SECTIONS:
        raise PEFormatError(f'invalid section count {section_count}')
    if not characteristics & 0x2000:
        raise UnsupportedImageError('only DLL images are supported')
    optional_offset = pe_offset + 24
    if optional_offset + optional_size > len(data):
        raise PEFormatError('truncated optional header')
    magic, = reader.unpack(optional_offset, '<H')
    if (machine, magic) == (0x8664, 0x20b):
        pointer_size, min_optional_size, directory_offset = 8, 112, 112
        preferred_base, = reader.unpack(optional_offset + 24, '<Q')
        directory_count, = reader.unpack(optional_offset + 108, '<I')
    elif (machine, magic) == (0x14c, 0x10b):
        pointer_size, min_optional_size, directory_offset = 4, 96, 96
        preferred_base, = reader.unpack(optional_offset + 28, '<I')
        directory_count, = reader.unpack(optional_offset + 92, '<I')
    else:
        raise UnsupportedImageError(f'unsupported PE machine/magic {machine:#x}/{magic:#x}')
    if optional_size < min_optional_size or directory_count > _DIRECTORY_COUNT or optional_size < directory_offset + directory_count * 8:
        raise PEFormatError('invalid optional header directory size')
    entry_rva, = reader.unpack(optional_offset + 16, '<I')
    section_alignment, file_alignment = reader.unpack(optional_offset + 32, '<II')
    size_of_image, size_of_headers = reader.unpack(optional_offset + 56, '<II')
    dll_characteristics, = reader.unpack(optional_offset + 70, '<H')
    if not _power_of_two(section_alignment) or not _power_of_two(file_alignment) or section_alignment < file_alignment:
        raise PEFormatError('invalid PE alignments')
    if not size_of_image or size_of_image > _MAX_IMAGE_SIZE or size_of_image % section_alignment:
        raise PEFormatError(f'invalid SizeOfImage {size_of_image:#x}')
    table_end = optional_offset + optional_size + section_count * 40
    if not size_of_headers or size_of_headers > len(data) or size_of_headers > size_of_image or table_end > size_of_headers:
        raise PEFormatError('invalid SizeOfHeaders or truncated section table')
    if entry_rva >= size_of_image:
        raise PEFormatError('entry point is outside the image')
    directories = [DataDirectory(0, 0) for _ in range(_DIRECTORY_COUNT)]
    for index in range(directory_count):
        rva, size = reader.unpack(optional_offset + directory_offset + index * 8, '<II')
        if bool(rva) != bool(size):
            raise PEFormatError(f'incomplete data directory {index}')
        if rva and (rva + size > (len(data) if index == 4 else size_of_image)):
            raise PEFormatError(f'data directory {index} is out of range')
        directories[index] = DataDirectory(rva, size)
    sections = []
    table_offset = optional_offset + optional_size
    last_end = _align_up(size_of_headers, section_alignment)
    for index in range(section_count):
        offset = table_offset + index * 40
        name = data[offset:offset + 8].tobytes().split(b'\0', 1)[0].decode('ascii', 'replace')
        virtual_size, target_rva, raw_size, raw_offset = reader.unpack(offset + 8, '<IIII')
        section_flags, = reader.unpack(offset + 36, '<I')
        if target_rva % section_alignment or target_rva < last_end:
            raise PEFormatError(f'section {name!r} overlaps headers or another section')
        mapped_size = _align_up(max(virtual_size, raw_size), section_alignment)
        if not mapped_size or target_rva + mapped_size > size_of_image:
            raise PEFormatError(f'section {name!r} exceeds SizeOfImage')
        if raw_size and (raw_offset % file_alignment or raw_offset + raw_size > len(data)):
            raise PEFormatError(f'section {name!r} has invalid raw data')
        sections.append(SectionPlan(name, raw_offset, raw_size, target_rva, virtual_size, mapped_size,
                                    section_flags, _protection(section_flags), bool(section_flags & 0x02000000)))
        last_end = target_rva + mapped_size
    reader.sections = tuple(sections)
    reader.headers_size = size_of_headers
    reader.image_size = size_of_image
    reader.preferred_base = preferred_base
    reader.pointer_size = pointer_size
    dirs = tuple(directories)
    for index, directory in enumerate(dirs):
        if directory.rva and index != 4:
            reader.offset(directory.rva, directory.size)
    relocations = _parse_relocations(reader, dirs[5], machine)
    imports = _parse_imports(reader, dirs[1], False)
    delay_imports = _parse_imports(reader, dirs[13], True)
    exports = _parse_exports(reader, dirs[0])
    tls = _parse_tls(reader, dirs[9])
    unwind = _parse_unwind(reader, dirs[3], machine)
    load_config = _parse_load_config(reader, dirs[10], pointer_size)
    return ParsedImage(len(data), hashlib.sha256(data).digest(), machine, pointer_size, preferred_base,
                       size_of_image, size_of_headers, entry_rva, section_alignment, file_alignment,
                       characteristics, dll_characteristics, dirs, reader.sections, relocations,
                       imports, delay_imports, exports, tls, unwind, load_config)


def _parse_relocations(reader: _Reader, directory: DataDirectory, machine: int) -> tuple[tuple[int, int], ...]:
    if not directory.rva: return ()
    result = []
    rva, end = directory.rva, directory.rva + directory.size
    expected_type, width = (10, 8) if machine == 0x8664 else (3, 4)
    while rva < end:
        page_rva, block_size = reader.at_rva(rva, '<II')
        if block_size < 8 or block_size % 2 or rva + block_size > end:
            raise PEFormatError(f'invalid relocation block at RVA {rva:#x}')
        for slot in range((block_size - 8) // 2):
            value, = reader.at_rva(rva + 8 + slot * 2, '<H')
            kind, target = value >> 12, page_rva + (value & 0xfff)
            if kind == 0: continue
            if kind != expected_type:
                raise UnsupportedImageError(f'unsupported relocation type {kind} at RVA {target:#x}')
            if target + width > reader.image_size:
                raise PEFormatError(f'relocation target {target:#x} exceeds image')
            result.append((target, width))
        rva += block_size
    return tuple(result)


def _parse_thunks(reader: _Reader, source_rva: int, iat_rva: int) -> tuple[ImportSymbol, ...]:
    symbols = []
    width = reader.pointer_size
    fmt = '<Q' if width == 8 else '<I'
    ordinal_flag = 1 << (width * 8 - 1)
    for index in range(_MAX_ARRAY_ENTRIES):
        thunk, = reader.at_rva(source_rva + index * width, fmt)
        reader.offset(iat_rva + index * width, width)
        if thunk == 0: return tuple(symbols)
        name, ordinal = None, None
        if thunk & ordinal_flag:
            if thunk & ~(ordinal_flag | 0xffff):
                raise PEFormatError(f'invalid ordinal thunk at RVA {source_rva + index * width:#x}')
            ordinal = thunk & 0xffff
        else:
            hint_name_rva = thunk
            reader.offset(hint_name_rva, 2)
            name = reader.string(hint_name_rva + 2)
        symbols.append(ImportSymbol(iat_rva + index * width, name, ordinal))
    raise PEFormatError(f'unterminated import thunks at RVA {source_rva:#x}')


def _parse_imports(reader: _Reader, directory: DataDirectory, delay: bool) -> tuple[ImportRequest, ...]:
    if not directory.rva: return ()
    descriptor_size = 32 if delay else 20
    if directory.size < descriptor_size:
        raise PEFormatError('import directory is too short')
    imports = []
    terminated = False
    for index in range(directory.size // descriptor_size):
        rva = directory.rva + index * descriptor_size
        if delay:
            fields = reader.at_rva(rva, '<8I')
            if not any(fields): terminated = True; break
            attrs, name_rva, handle_rva, iat_rva, int_rva, _, _, _ = fields
            if attrs & ~1:
                raise UnsupportedImageError(f'unsupported delay-import attributes {attrs:#x}')
            if not attrs:
                if reader.pointer_size == 8:
                    raise UnsupportedImageError('VA-based delay imports are unsupported in PE32+')
                name_rva, iat_rva, int_rva = (reader.va_to_rva(value) if value else 0 for value in (name_rva, iat_rva, int_rva))
                handle_rva = reader.va_to_rva(handle_rva, reader.pointer_size) if handle_rva else 0
            if handle_rva: reader.offset(handle_rva, reader.pointer_size)
            source_rva = int_rva or iat_rva
        else:
            fields = reader.at_rva(rva, '<5I')
            if not any(fields):
                terminated = True; break
            original_rva, _, _, name_rva, iat_rva = fields
            source_rva = original_rva or iat_rva
            handle_rva = 0
        if not name_rva or not iat_rva or not source_rva:
            raise PEFormatError(f'incomplete import descriptor at RVA {rva:#x}')
        imports.append(ImportRequest(reader.string(name_rva), _parse_thunks(reader, source_rva, iat_rva), delay, handle_rva))
    if not terminated:
        raise PEFormatError('unterminated import directory')
    return tuple(imports)


def _parse_exports(reader: _Reader, directory: DataDirectory) -> tuple[ExportSymbol, ...]:
    if not directory.rva: return ()
    if directory.size < 40: raise PEFormatError('export directory is too short')
    _, _, _, _, _, ordinal_base, count, name_count, funcs_rva, names_rva, ordinals_rva = reader.at_rva(directory.rva, '<IIHHIIIIIII')
    if count > _MAX_ARRAY_ENTRIES or name_count > count:
        raise PEFormatError('invalid export table counts')
    names = {}
    for index in range(name_count):
        name_rva, = reader.at_rva(names_rva + index * 4, '<I')
        ordinal_index, = reader.at_rva(ordinals_rva + index * 2, '<H')
        if ordinal_index >= count: raise PEFormatError('export name ordinal exceeds function table')
        names[ordinal_index] = reader.string(name_rva)
    exports = []
    for index in range(count):
        rva, = reader.at_rva(funcs_rva + index * 4, '<I')
        if not rva: continue
        if rva >= reader.image_size: raise PEFormatError(f'export RVA {rva:#x} exceeds image')
        forwarder = reader.string(rva) if directory.rva <= rva < directory.rva + directory.size else None
        exports.append(ExportSymbol(names.get(index), ordinal_base + index, rva, forwarder))
    return tuple(exports)


def _parse_tls(reader: _Reader, directory: DataDirectory) -> TlsPlan | None:
    if not directory.rva: return None
    if reader.pointer_size == 8:
        if directory.size < 40: raise PEFormatError('TLS directory is too short')
        start, end, index, callbacks, zero_fill, _ = reader.at_rva(directory.rva, '<QQQQII')
    else:
        if directory.size < 24: raise PEFormatError('TLS directory is too short')
        start, end, index, callbacks, zero_fill, _ = reader.at_rva(directory.rva, '<6I')
    if bool(start) != bool(end) or end < start:
        raise PEFormatError('invalid TLS template range')
    template_size = end - start
    template_rva = reader.va_to_rva(start, template_size) if start else 0
    if template_size: reader.offset(template_rva, template_size)
    if not index: raise PEFormatError('TLS directory has no index slot')
    index_rva = reader.va_to_rva(index, 4)
    callbacks_rva = reader.va_to_rva(callbacks, reader.pointer_size) if callbacks else 0
    callback_vas = reader.pointer_array(callbacks_rva, require_mapped=True) if callbacks_rva else ()
    return TlsPlan(template_rva, template_size, index_rva,
                   tuple(reader.va_to_rva(va) for va in callback_vas), zero_fill)


def _parse_unwind(reader: _Reader, directory: DataDirectory, machine: int) -> tuple[UnwindEntry, ...]:
    if not directory.rva: return ()
    if machine != 0x8664:
        raise UnsupportedImageError('exception directory is unsupported for PE32')
    if directory.size % 12: raise PEFormatError('exception directory has a partial entry')
    entries = []
    for offset in range(0, directory.size, 12):
        begin, end, info = reader.at_rva(directory.rva + offset, '<III')
        if not begin < end <= reader.image_size or info >= reader.image_size:
            raise PEFormatError('invalid x64 runtime function entry')
        entries.append(UnwindEntry(begin, end, info))
    return tuple(entries)


def _parse_load_config(reader: _Reader, directory: DataDirectory, width: int) -> LoadConfigPlan | None:
    if not directory.rva: return None
    if directory.size < 4: raise PEFormatError('load configuration directory is too short')
    declared_size, = reader.at_rva(directory.rva, '<I')
    if declared_size < 4 or declared_size > directory.size:
        raise PEFormatError('invalid load configuration size')
    cookie_offset = 0x58 if width == 8 else 0x3c
    guard_offset = 0x90 if width == 8 else 0x58
    cookie_rva = None
    if declared_size >= cookie_offset + width:
        value, = reader.at_rva(directory.rva + cookie_offset, '<Q' if width == 8 else '<I')
        if value: cookie_rva = reader.va_to_rva(value, width)
    guard_flags = reader.at_rva(directory.rva + guard_offset, '<I')[0] if declared_size >= guard_offset + 4 else 0
    return LoadConfigPlan(declared_size, cookie_rva, guard_flags)


def build_plan(image: ParsedImage, target_base: int) -> ImagePlan:
    """Bind a parsed image to a target base and compute relocation deltas."""
    if target_base < 0 or target_base + image.size_of_image > 1 << (image.pointer_size * 8):
        raise ValueError(f'target base {target_base:#x} is outside the address space')
    delta = target_base - image.preferred_base
    if delta and not image.relocation_entries:
        raise UnsupportedImageError('image cannot be rebased without base relocations')
    return ImagePlan(image, target_base, tuple(RelocFixup(rva, width, delta) for rva, width in image.relocation_entries))
