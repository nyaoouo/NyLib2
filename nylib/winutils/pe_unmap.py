import struct

_IMAGE_DOS_SIGNATURE = 0x5A4D            # 'MZ'
_IMAGE_NT_SIGNATURE = 0x00004550         # 'PE\0\0'
_IMAGE_FILE_MACHINE_AMD64 = 0x8664
_IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B
_SECTION_HEADER_SIZE = 40


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) & ~(alignment - 1)


def pe_unmap(image: bytes) -> bytes | None:
    """Convert a full-`SizeOfImage` in-memory dump to on-disk PE layout.

    Returns the rebuilt bytes, or None if the buffer is not a recognized
    64-bit PE (caller should then fall back to a raw dump).
    """
    if len(image) < 0x40:
        return None
    if struct.unpack_from("<H", image, 0)[0] != _IMAGE_DOS_SIGNATURE:
        return None
    e_lfanew = struct.unpack_from("<I", image, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 0x18 > len(image):
        return None
    if struct.unpack_from("<I", image, e_lfanew)[0] != _IMAGE_NT_SIGNATURE:
        return None

    machine, num_sections = struct.unpack_from("<HH", image, e_lfanew + 4)
    size_of_opt_header = struct.unpack_from("<H", image, e_lfanew + 0x14)[0]
    if machine != _IMAGE_FILE_MACHINE_AMD64:
        return None

    opt_offset = e_lfanew + 0x18
    if opt_offset + size_of_opt_header > len(image):
        return None
    opt_magic = struct.unpack_from("<H", image, opt_offset)[0]
    if opt_magic != _IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        return None

    file_alignment = struct.unpack_from("<I", image, opt_offset + 0x24)[0]
    size_of_headers = struct.unpack_from("<I", image, opt_offset + 0x3C)[0]
    if file_alignment == 0:
        file_alignment = 0x200
    if size_of_headers == 0 or size_of_headers > len(image):
        return None

    sections_offset = opt_offset + size_of_opt_header
    if sections_offset + num_sections * _SECTION_HEADER_SIZE > len(image):
        return None

    out = bytearray(image[:size_of_headers])

    for i in range(num_sections):
        sh = sections_offset + i * _SECTION_HEADER_SIZE
        virtual_size = struct.unpack_from("<I", image, sh + 8)[0]
        virtual_addr = struct.unpack_from("<I", image, sh + 12)[0]
        size_of_raw = struct.unpack_from("<I", image, sh + 16)[0]

        # Source data length: take the larger of VirtualSize and
        # SizeOfRawData (some compilers/packers set one and zero the other),
        # then clamp to what we actually have in memory.
        copy_size = max(virtual_size, size_of_raw)
        if copy_size == 0:
            new_raw_ptr = _align_up(len(out), file_alignment)
            if new_raw_ptr > len(out):
                out.extend(b"\x00" * (new_raw_ptr - len(out)))
            struct.pack_into("<I", out, sh + 16, 0)
            struct.pack_into("<I", out, sh + 20, new_raw_ptr)
            continue

        src_end = min(virtual_addr + copy_size, len(image))
        section_bytes = image[virtual_addr:src_end]
        # Pad to FileAlignment.
        padded_size = _align_up(len(section_bytes), file_alignment)
        if padded_size > len(section_bytes):
            section_bytes = section_bytes + b"\x00" * (padded_size - len(section_bytes))

        new_raw_ptr = _align_up(len(out), file_alignment)
        if new_raw_ptr > len(out):
            out.extend(b"\x00" * (new_raw_ptr - len(out)))
        out.extend(section_bytes)

        struct.pack_into("<I", out, sh + 16, len(section_bytes))   # SizeOfRawData
        struct.pack_into("<I", out, sh + 20, new_raw_ptr)          # PointerToRawData

    return bytes(out)