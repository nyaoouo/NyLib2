"""Pure-Python BC7 (BPTC UNORM) decode to tightly packed RGBA8, per the D3D11 / KHR BPTC specification.

A reserved block (byte 0 is 0) decodes to (0, 0, 0, 0).
"""
# mode: subsets, partition bits, rotation bits, index-selection bits, colour bits, alpha bits, endpoint P-bits,
# shared P-bits, index bits, secondary index bits
_MODES = (
    (3, 4, 0, 0, 4, 0, 1, 0, 3, 0),
    (2, 6, 0, 0, 6, 0, 0, 1, 3, 0),
    (3, 6, 0, 0, 5, 0, 0, 0, 2, 0),
    (2, 6, 0, 0, 7, 0, 1, 0, 2, 0),
    (1, 0, 2, 1, 5, 6, 0, 0, 2, 3),
    (1, 0, 2, 0, 7, 8, 0, 0, 2, 2),
    (1, 0, 0, 0, 7, 7, 1, 0, 4, 0),
    (2, 6, 0, 0, 5, 5, 1, 0, 2, 0),
)
_WEIGHTS = {2: (0, 21, 43, 64), 3: (0, 9, 18, 27, 37, 46, 55, 64),
            4: (0, 4, 9, 13, 17, 21, 26, 30, 34, 38, 43, 47, 51, 55, 60, 64)}

_P2 = (
    '0011001100110011', '0001000100010001', '0111011101110111', '0001001100110111', '0000000100010011', '0011011101111111',
    '0001001101111111', '0000000100110111', '0000000000010011', '0011011111111111', '0000000101111111', '0000000000010111',
    '0001011111111111', '0000000011111111', '0000111111111111', '0000000000001111', '0000100011101111', '0111000100000000',
    '0000000010001110', '0111001100010000', '0011000100000000', '0000100011001110', '0000000010001100', '0111001100110001',
    '0011000100010000', '0000100010001100', '0110011001100110', '0011011001101100', '0001011111101000', '0000111111110000',
    '0111000110001110', '0011100110011100', '0101010101010101', '0000111100001111', '0101101001011010', '0011001111001100',
    '0011110000111100', '0101010110101010', '0110100101101001', '0101101010100101', '0111001111001110', '0001001111001000',
    '0011001001001100', '0011101111011100', '0110100110010110', '0011110011000011', '0110011010011001', '0000011001100000',
    '0100111001000000', '0010011100100000', '0000001001110010', '0000010011100100', '0110110010010011', '0011011011001001',
    '0110001110011100', '0011100111000110', '0110110011001001', '0110001100111001', '0111111010000001', '0001100011100111',
    '0000111100110011', '0011001111110000', '0010001011101110', '0100010001110111',
)
_P3 = (
    '0011001102212222', '0001001122112221', '0000200122112211', '0222002200110111', '0000000011221122', '0011001100220022',
    '0022002211111111', '0011001122112211', '0000000011112222', '0000111111112222', '0000111122222222', '0012001200120012',
    '0112011201120112', '0122012201220122', '0011011211221222', '0011200122002220', '0001001101121122', '0111001120012200',
    '0000112211221122', '0022002200221111', '0111011102220222', '0001000122212221', '0000001101220122', '0000110022102210',
    '0122012200110000', '0012001211222222', '0110122112210110', '0000011012211221', '0022110211020022', '0110011020022222',
    '0011012201220011', '0000200022112221', '0000000211221222', '0222002200120011', '0011001200220222', '0120012001200120',
    '0000111122220000', '0120120120120120', '0120201212010120', '0011220011220011', '0011112222000011', '0101010122222222',
    '0000000021212121', '0022112200221122', '0022001100220011', '0220122102201221', '0101222222220101', '0000212121212121',
    '0101010101012222', '0222011102220111', '0002111200021112', '0000211221122112', '0222011101110222', '0002111211120002',
    '0110011001102222', '0000000021122112', '0110011022222222', '0022001100110022', '0022112211220022', '0000000000002112',
    '0002000100020001', '0222122202221222', '0101222222222222', '0111201122012220',
)
_PART2 = tuple(tuple(int(c) for c in s) for s in _P2)
_PART3 = tuple(tuple(int(c) for c in s) for s in _P3)
_ANCHOR2 = (15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
            15, 2, 8, 2, 2, 8, 8, 15, 2, 8, 2, 2, 8, 8, 2, 2,
            15, 15, 6, 8, 2, 8, 15, 15, 2, 8, 2, 2, 2, 15, 15, 6,
            6, 2, 6, 8, 15, 15, 2, 2, 15, 15, 15, 15, 15, 2, 2, 15)
_ANCHOR3A = (3, 3, 15, 15, 8, 3, 15, 15, 8, 8, 6, 6, 6, 5, 3, 3,
             3, 3, 8, 15, 3, 3, 6, 10, 5, 8, 8, 6, 8, 5, 15, 15,
             8, 15, 3, 5, 6, 10, 8, 15, 15, 3, 15, 5, 15, 15, 15, 15,
             3, 15, 5, 5, 5, 8, 5, 10, 5, 10, 8, 13, 15, 12, 3, 3)
_ANCHOR3B = (15, 8, 8, 3, 15, 15, 3, 8, 15, 15, 15, 15, 15, 15, 15, 8,
             15, 8, 15, 3, 15, 8, 15, 8, 3, 15, 6, 10, 15, 15, 10, 8,
             15, 3, 15, 10, 10, 8, 9, 10, 6, 15, 8, 15, 3, 6, 6, 8,
             15, 3, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 3, 15, 15, 8)
_ZERO16 = (0,) * 16


def _widen(v: int, n: int) -> int:
    v <<= 8 - n
    return v | (v >> n)


def _decode_block(blk: bytes) -> list:
    """16 RGBA8 bytes objects of one 16-byte BC7 block, texels in row-major order."""
    v = int.from_bytes(blk, 'little')
    low = v & 0xFF
    if not low:
        return [bytes(4)] * 16
    mode = (low & -low).bit_length() - 1
    ns, pb, rb, isb, cb, ab, epb, spb, ib, ib2 = _MODES[mode]
    pos = mode + 1
    part = (v >> pos) & ((1 << pb) - 1)
    pos += pb
    rot = (v >> pos) & ((1 << rb) - 1)
    pos += rb
    isel = (v >> pos) & ((1 << isb) - 1)
    pos += isb
    ne = 2 * ns
    ep = [[0, 0, 0, 255] for _ in range(ne)]
    m = (1 << cb) - 1
    for ch in range(3):
        for e in range(ne):
            ep[e][ch] = (v >> pos) & m
            pos += cb
    if ab:
        m = (1 << ab) - 1
        for e in range(ne):
            ep[e][3] = (v >> pos) & m
            pos += ab
    nch = 4 if ab else 3
    if epb:
        for e in range(ne):
            p = (v >> pos) & 1
            pos += 1
            for ch in range(nch):
                ep[e][ch] = (ep[e][ch] << 1) | p
    elif spb:
        for s in range(ns):
            p = (v >> pos) & 1
            pos += 1
            for e in (2 * s, 2 * s + 1):
                for ch in range(3):
                    ep[e][ch] = (ep[e][ch] << 1) | p
    cbits = cb + (1 if epb or spb else 0)
    abits = ab + (1 if epb else 0)
    for e in range(ne):
        q = ep[e]
        q[0], q[1], q[2] = _widen(q[0], cbits), _widen(q[1], cbits), _widen(q[2], cbits)
        if ab:
            q[3] = _widen(q[3], abits)
    if ns == 1:
        sub, anchors = _ZERO16, (0,)
    elif ns == 2:
        sub, anchors = _PART2[part], (0, _ANCHOR2[part])
    else:
        sub, anchors = _PART3[part], (0, _ANCHOR3A[part], _ANCHOR3B[part])
    idx = []
    for i in range(16):
        n = ib - 1 if i in anchors else ib
        idx.append((v >> pos) & ((1 << n) - 1))
        pos += n
    if ib2:
        idx2 = []
        for i in range(16):
            n = ib2 - 1 if i == 0 else ib2
            idx2.append((v >> pos) & ((1 << n) - 1))
            pos += n
        if isel:
            cidx, cw, aidx, aw = idx2, _WEIGHTS[ib2], idx, _WEIGHTS[ib]
        else:
            cidx, cw, aidx, aw = idx, _WEIGHTS[ib], idx2, _WEIGHTS[ib2]
    else:
        cidx = aidx = idx
        cw = aw = _WEIGHTS[ib]
    out = []
    for i in range(16):
        s = sub[i]
        e0, e1 = ep[2 * s], ep[2 * s + 1]
        w = cw[cidx[i]]
        u = 64 - w
        r = (u * e0[0] + w * e1[0] + 32) >> 6
        g = (u * e0[1] + w * e1[1] + 32) >> 6
        b = (u * e0[2] + w * e1[2] + 32) >> 6
        w = aw[aidx[i]]
        a = ((64 - w) * e0[3] + w * e1[3] + 32) >> 6
        if rot == 1:
            r, a = a, r
        elif rot == 2:
            g, a = a, g
        elif rot == 3:
            b, a = a, b
        out.append(bytes((r, g, b, a)))
    return out


def decode(src: bytes, width: int, height: int) -> bytearray:
    """BC7 (BPTC UNORM) `src` to a width*height*4 RGBA8 bytearray, rows top to bottom; width and height a multiple of 4."""
    if width <= 0 or height <= 0 or width % 4 or height % 4:
        raise ValueError(f'width and height must be positive multiples of 4, got {width}x{height}')
    bw, bh = width // 4, height // 4
    need = 16 * bw * bh
    if len(src) < need:
        raise ValueError(f'BC7 source is {len(src)} bytes, need {need} for {width}x{height}')
    out = bytearray(width * height * 4)
    stride = 4 * width
    pos = 0
    o = 0
    for _by in range(bh):
        rows = [bytearray(stride) for _ in range(4)]
        for bx in range(bw):
            texels = _decode_block(src[pos:pos + 16])
            pos += 16
            xo = 16 * bx
            for j in range(4):
                rows[j][xo:xo + 16] = b''.join(texels[4 * j:4 * j + 4])
        for j in range(4):
            out[o:o + stride] = rows[j]
            o += stride
    return out
