"""PE image TimeDateStamp and version strings, read with bounded positioned reads."""
import struct

_HEADER_LEN = 4096
_RT_VERSION = 16
_MAX_DIR_ENTRIES = 512
_MAX_VERSION_LEN = 64 << 10
_FIXED_SIGNATURE = 0xFEEF04BD


def _rva_to_offset(sections, rva: int) -> int:
    for vsize, va, rawsize, rawptr in sections:
        if va <= rva < va + max(vsize, rawsize):
            return rva - va + rawptr
    raise ValueError('RVA outside every section')


def _read(f, offset: int, size: int) -> bytes:
    f.seek(offset)
    data = f.read(size)
    if len(data) != size:
        raise ValueError('truncated PE image')
    return data


def _headers(head: bytes):
    """(TimeDateStamp, resource directory RVA, sections) from the first 4 KiB; raises ValueError for a non-PE."""
    if len(head) < 64 or head[:2] != b'MZ':
        raise ValueError('no MZ header')
    (e,) = struct.unpack_from('<I', head, 0x3C)
    if e + 24 > len(head) or head[e:e + 4] != b'PE\0\0':
        raise ValueError('no PE signature')
    nsec, stamp = struct.unpack_from('<HI', head, e + 6)
    (opt_size,) = struct.unpack_from('<H', head, e + 20)
    opt = e + 24
    sec = opt + opt_size
    if opt_size < 2 or sec + 40 * nsec > len(head):
        return stamp, 0, ()
    (magic,) = struct.unpack_from('<H', head, opt)
    dd = opt + (112 if magic == 0x20B else 96)
    rsrc = 0
    if dd + 24 <= sec and struct.unpack_from('<I', head, dd - 4)[0] > 2:
        (rsrc,) = struct.unpack_from('<I', head, dd + 16)
    sections = tuple(struct.unpack_from('<IIII', head, sec + 40 * i + 8) for i in range(nsec))  # vsize, va, rawsize, rawptr
    return stamp, rsrc, sections


def _version_blob(f, rsrc: int, sections) -> bytes:
    """The first RT_VERSION resource (first name, first language); raises ValueError when there is none."""
    base = _rva_to_offset(sections, rsrc)

    def entries(rel: int):
        named, ids = struct.unpack_from('<HH', _read(f, base + rel, 16), 12)
        n = min(named + ids, _MAX_DIR_ENTRIES)
        raw = _read(f, base + rel + 16, 8 * n)
        return [struct.unpack_from('<II', raw, 8 * i) for i in range(n)]

    types = [off for name, off in entries(0) if name == _RT_VERSION]
    if not types or not types[0] & 0x80000000:
        raise ValueError('no RT_VERSION directory')
    names = entries(types[0] & 0x7FFFFFFF)
    if not names or not names[0][1] & 0x80000000:
        raise ValueError('RT_VERSION has no name directory')
    langs = entries(names[0][1] & 0x7FFFFFFF)
    if not langs or langs[0][1] & 0x80000000:
        raise ValueError('RT_VERSION has no data entry')
    data_rva, size = struct.unpack_from('<II', _read(f, base + langs[0][1], 16))
    if size > _MAX_VERSION_LEN:
        raise ValueError('version resource too large')
    return _read(f, _rva_to_offset(sections, data_rva), size)


def _node(buf: bytes, off: int, end: int):
    """(value length, key, value offset, node end) of one VS_VERSIONINFO-style node."""
    length, vlen, _vtype = struct.unpack_from('<HHH', buf, off)
    stop = off + length
    if length < 6 or stop > end:
        raise ValueError('bad version node length')
    q = off + 6
    while q + 1 < stop and buf[q:q + 2] != b'\0\0':
        q += 2
    return vlen, buf[off + 6:q].decode('utf-16-le', 'replace'), (q + 5) & ~3, stop


def _children(buf: bytes, start: int, stop: int):
    off = (start + 3) & ~3
    while off + 6 <= stop:
        node = _node(buf, off, stop)
        yield node
        off = (node[3] + 3) & ~3


def _fixed_version(buf: bytes) -> str | None:
    vlen, key, value, _stop = _node(buf, 0, len(buf))
    if key != 'VS_VERSION_INFO' or vlen < 52 or value + 16 > len(buf):
        return None
    sig, _struct_version, ms, ls = struct.unpack_from('<4I', buf, value)
    return f'{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}' if sig == _FIXED_SIGNATURE else None


def _product_version(buf: bytes) -> str | None:
    vlen, key, value, stop = _node(buf, 0, len(buf))
    if key != 'VS_VERSION_INFO':
        return None
    for vlen2, key2, value2, stop2 in _children(buf, value + vlen, stop):
        if key2 != 'StringFileInfo':
            continue
        for vlen3, _table, value3, stop3 in _children(buf, value2 + vlen2, stop2):
            for vlen4, key4, value4, stop4 in _children(buf, value3 + vlen3, stop3):
                if key4 == 'ProductVersion':
                    return buf[value4:min(stop4, value4 + 2 * vlen4)].decode('utf-16-le', 'replace').split('\0')[0] or None
            return None
        return None
    return None


def version_from_resource(blob: bytes) -> str | None:
    """'{fixed file version} {ProductVersion}' of a VS_VERSIONINFO blob; one part when the other is missing, else None."""
    parts = []
    for part in (_fixed_version, _product_version):
        try:
            if (text := part(blob)) is not None:
                parts.append(text)
        except (ValueError, struct.error):
            pass
    return ' '.join(parts) or None


def read_build(path: str) -> tuple[int, str | None]:
    """(PE TimeDateStamp, version string or None) of the image at `path`.

    Raises OSError when the file cannot be read and ValueError when it is not a PE image.
    """
    with open(path, 'rb') as f:
        stamp, rsrc, sections = _headers(f.read(_HEADER_LEN))
        version = None
        if rsrc and sections:
            try:
                version = version_from_resource(_version_blob(f, rsrc, sections))
            except (OSError, ValueError, struct.error):
                version = None
    return stamp, version
