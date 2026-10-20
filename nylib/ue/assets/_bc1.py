"""Pure-Python BC1 (DXT1) decode to tightly packed RGBA8. Alpha is always 255, including three-colour index 3."""
import operator
import struct

_ROW_IDX = [tuple((b >> (2 * k)) & 3 for k in range(4)) for b in range(256)]


def _colors(c0: int, c1: int) -> list:
    r0, g0, b0 = (c0 >> 11) & 31, (c0 >> 5) & 63, c0 & 31
    r1, g1, b1 = (c1 >> 11) & 31, (c1 >> 5) & 63, c1 & 31
    r0, g0, b0 = (r0 << 3) | (r0 >> 2), (g0 << 2) | (g0 >> 4), (b0 << 3) | (b0 >> 2)
    r1, g1, b1 = (r1 << 3) | (r1 >> 2), (g1 << 2) | (g1 >> 4), (b1 << 3) | (b1 >> 2)
    if c0 > c1:
        return [bytes((r0, g0, b0, 255)), bytes((r1, g1, b1, 255)),
                bytes((((2 * r0 + r1) * 683) >> 11, ((2 * g0 + g1) * 683) >> 11, ((2 * b0 + b1) * 683) >> 11, 255)),
                bytes((((r0 + 2 * r1) * 683) >> 11, ((g0 + 2 * g1) * 683) >> 11, ((b0 + 2 * b1) * 683) >> 11, 255))]
    return [bytes((r0, g0, b0, 255)), bytes((r1, g1, b1, 255)),
            bytes(((r0 + r1) >> 1, (g0 + g1) >> 1, (b0 + b1) >> 1, 255)), bytes((0, 0, 0, 255))]


_GETTERS = [operator.itemgetter(*idx) for idx in _ROW_IDX]


def decode(src: bytes, width: int, height: int) -> bytearray:
    """BC1 (DXT1) `src` to a width*height*4 RGBA8 bytearray, rows top to bottom; width and height a multiple of 4."""
    if width <= 0 or height <= 0 or width % 4 or height % 4:
        raise ValueError(f'width and height must be positive multiples of 4, got {width}x{height}')
    bw, bh = width // 4, height // 4
    need = 8 * bw * bh
    if len(src) < need:
        raise ValueError(f'BC1 source is {len(src)} bytes, need {need} for {width}x{height}')
    out = bytearray(width * height * 4)
    stride = 4 * width
    cache = {}
    get = _GETTERS
    vals = struct.unpack(f'<{2 * bw * bh}I', src[:need])
    pos = 0
    o = 0
    join = b''.join
    for _by in range(bh):
        r0, r1, r2, r3 = [], [], [], []
        for _bx in range(bw):
            ends = vals[pos]
            bits = vals[pos + 1]
            pos += 2
            cols = cache.get(ends)
            if cols is None:
                cols = cache[ends] = _colors(ends & 0xFFFF, ends >> 16)
            r0 += get[bits & 0xFF](cols)
            r1 += get[(bits >> 8) & 0xFF](cols)
            r2 += get[(bits >> 16) & 0xFF](cols)
            r3 += get[bits >> 24](cols)
        out[o:o + stride] = join(r0)
        out[o + stride:o + 2 * stride] = join(r1)
        out[o + 2 * stride:o + 3 * stride] = join(r2)
        out[o + 3 * stride:o + 4 * stride] = join(r3)
        o += 4 * stride
    return out
