_STRIP_BYTES = 1 << 22  # input bytes per strip, at least one row
_CHUNK_PIXELS = 1 << 16  # pixels per big-integer composite chunk

_ALPHA_BIT = [bytes(0xFF if (a >> k) & 1 else 0 for a in range(256)) for k in range(8)]


def strips(width: int, height: int):
    """Yield `(y0, rows)` covering rows 0..height-1 in strips of at most `_STRIP_BYTES` input bytes (at least one row)."""
    per = max(1, _STRIP_BYTES // (4 * width))
    for y0 in range(0, height, per):
        yield y0, min(per, height - y0)


def count_non_opaque(bv: memoryview, width: int, height: int) -> int:
    """The number of pixels of RGBA8 byte view `bv` whose alpha is not 255."""
    stride, k = 4 * width, 0
    for y0, rows in strips(width, height):
        with bv[y0 * stride:(y0 + rows) * stride] as s, s[3::4] as a:
            k += width * rows - a.tobytes().count(255)
    return k


def _bg_tables(bg: int) -> tuple[bytes, bytes]:
    v = [bg * (255 - a) for a in range(256)]
    return bytes(x & 0xFF for x in v), bytes(x >> 8 for x in v)


def composite(strip: memoryview, background: tuple[int, int, int], out: bytearray) -> bytearray:
    """BGR of RGBA8 `strip` over `background` into `out`: `(c * a + bg * (255 - a) + 127) // 255` per channel."""
    tables = [_bg_tables(background[ch]) for ch in (2, 1, 0)]
    total = len(strip) // 4
    for p0 in range(0, total, _CHUNK_PIXELS):
        p1 = min(total, p0 + _CHUNK_PIXELS)
        n = p1 - p0
        with strip[4 * p0:4 * p1] as s:
            with s[3::4] as a:
                alpha = a.tobytes()
            if alpha.count(255) == n:
                for dst, src in ((0, 2), (1, 1), (2, 0)):
                    with s[src::4] as cv:
                        out[3 * p0 + dst:3 * p1:3] = cv
                continue
            masks = []
            for k in range(8):
                m = bytearray(2 * n)
                m[0::2] = alpha.translate(_ALPHA_BIT[k])
                masks.append(int.from_bytes(m, 'little'))
            half = int.from_bytes(b'\x80\x00' * n, 'little')  # 128 in every 16-bit lane
            low8 = int.from_bytes(b'\xff\x00' * n, 'little')
            for (dst, src), (lo, hi) in zip(((0, 2), (1, 1), (2, 0)), tables):
                c16 = bytearray(2 * n)
                with s[src::4] as cv:
                    c16[0::2] = cv
                c = int.from_bytes(c16, 'little')
                acc = 0
                for k in range(8):
                    acc += (c & masks[k]) << k
                t = bytearray(2 * n)
                t[0::2] = alpha.translate(lo)
                t[1::2] = alpha.translate(hi)
                acc += int.from_bytes(t, 'little') + half
                acc = ((acc + ((acc >> 8) & low8)) >> 8) & low8  # (x + 128 + ((x + 128) >> 8)) >> 8 per lane
                out[3 * p0 + dst:3 * p1:3] = acc.to_bytes(2 * n, 'little')[0::2]
    return out
