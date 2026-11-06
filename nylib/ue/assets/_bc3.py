"""Pure-Python BC3 (DXT5) decode to tightly packed RGBA8, per CUE4Parse's BCDecoder exactly (colour always four-colour)."""
import struct

_ROW_IDX = [tuple((b >> (2 * k)) & 3 for k in range(4)) for b in range(256)]


def _colors(c0: int, c1: int) -> list:
    r0, g0, b0 = (c0 >> 11) & 31, (c0 >> 5) & 63, c0 & 31
    r1, g1, b1 = (c1 >> 11) & 31, (c1 >> 5) & 63, c1 & 31
    r0, g0, b0 = (r0 << 3) | (r0 >> 2), (g0 << 2) | (g0 >> 4), (b0 << 3) | (b0 >> 2)
    r1, g1, b1 = (r1 << 3) | (r1 >> 2), (g1 << 2) | (g1 >> 4), (b1 << 3) | (b1 >> 2)
    return [(r0, g0, b0), (r1, g1, b1),
            (((2 * r0 + r1) * 683) >> 11, ((2 * g0 + g1) * 683) >> 11, ((2 * b0 + b1) * 683) >> 11),
            (((r0 + 2 * r1) * 683) >> 11, ((g0 + 2 * g1) * 683) >> 11, ((b0 + 2 * b1) * 683) >> 11)]


def _alphas(a0: int, a1: int) -> tuple:
    if a0 > a1:
        v, diff, t = [a0, a1], a0 - a1, 6 * a0 + a1 + 3
        for _ in range(6):
            v.append((t * 9365) >> 16)
            t -= diff
        return tuple(v)
    v, diff, t = [a0, a1], a1 - a0, 4 * a0 + a1 + 2
    for _ in range(4):
        v.append((t * 1636) >> 13)
        t += diff
    return tuple(v + [0, 255])


def decode(src: bytes, width: int, height: int) -> bytearray:
    """BC3 (DXT5) `src` to a width*height*4 RGBA8 bytearray, rows top to bottom; width and height a multiple of 4."""
    if width <= 0 or height <= 0 or width % 4 or height % 4:
        raise ValueError(f'width and height must be positive multiples of 4, got {width}x{height}')
    bw, bh = width // 4, height // 4
    need = 16 * bw * bh
    if len(src) < need:
        raise ValueError(f'BC3 source is {len(src)} bytes, need {need} for {width}x{height}')
    out = bytearray(width * height * 4)
    stride = 4 * width
    color_cache = {}
    alpha_cache = {}
    row_idx = _ROW_IDX
    base = 0
    blocks = struct.iter_unpack('<IIHHI', src[:need])
    for _by in range(bh):
        for bx in range(bw):
            alo, ahi, c0, c1, bits = next(blocks)
            a = alo | (ahi << 32)
            akey = a & 0xFFFF
            al = alpha_cache.get(akey)
            if al is None:
                al = alpha_cache[akey] = _alphas(a & 0xFF, (a >> 8) & 0xFF)
            ckey = c0 | (c1 << 16)
            cols = color_cache.get(ckey)
            if cols is None:
                cols = color_cache[ckey] = _colors(c0, c1)
            idxfield = a >> 16
            xo = base + 16 * bx
            for byte, k0 in ((bits & 0xFF, 0), ((bits >> 8) & 0xFF, 4), ((bits >> 16) & 0xFF, 8), (bits >> 24, 12)):
                cidx = row_idx[byte]
                o = xo
                for i in range(4):
                    c = cols[cidx[i]]
                    out[o:o + 4] = (c[0], c[1], c[2], al[(idxfield >> (3 * (k0 + i))) & 7])
                    o += 4
                xo += stride
        base += 4 * stride
    return out
