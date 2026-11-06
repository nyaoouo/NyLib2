import struct
import zlib
from . import _pixels

_IDAT_BYTES = 1 << 30
_compressobj = zlib.compressobj
_SIGNATURE = b'\x89PNG\r\n\x1a\n'


def _chunk(kind: bytes, body: bytes) -> bytes:
    return struct.pack('>I', len(body)) + kind + body + struct.pack('>I', zlib.crc32(body, zlib.crc32(kind)))


def _idat(parts: list) -> list:
    """IDAT chunk pieces over the zlib stream `parts`: `_IDAT_BYTES` per chunk, the last holding the rest."""
    limit, out, cur, n, crc = _IDAT_BYTES, [], [], 0, zlib.crc32(b'IDAT')
    for p in parts:
        v = memoryview(p)
        while v:
            take, v = v[:limit - n], v[limit - n:]
            cur.append(take)
            crc, n = zlib.crc32(take, crc), n + len(take)
            if n == limit:
                out += [struct.pack('>I', n), b'IDAT', *cur, struct.pack('>I', crc)]
                cur, n, crc = [], 0, zlib.crc32(b'IDAT')
    if n:
        out += [struct.pack('>I', n), b'IDAT', *cur, struct.pack('>I', crc)]
    return out


def encode(bv: memoryview, width: int, height: int) -> bytes:
    """PNG file of RGBA8 byte view `bv`: IHDR (colour type 6), filter 0 rows in one zlib level-9 stream, IEND."""
    stride = 4 * width
    c = _compressobj(9)
    parts, buf = [], None
    for y0, rows in _pixels.strips(width, height):
        if buf is None:
            buf = bytearray(rows * (stride + 1))
        for r in range(rows):
            o = r * (stride + 1) + 1
            with bv[(y0 + r) * stride:(y0 + r + 1) * stride] as row:
                buf[o:o + stride] = row
        with memoryview(buf) as v, v[:rows * (stride + 1)] as part:
            if p := c.compress(part):
                parts.append(p)
    buf = None
    parts.append(c.flush())
    out = [_SIGNATURE, _chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)), *_idat(parts), _chunk(b'IEND', b'')]
    parts = None
    return b''.join(out)
