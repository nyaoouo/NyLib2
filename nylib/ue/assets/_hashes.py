"""CityHash64, FPackageId and the TOC's seeded chunk-id hash."""

_MASK64 = 0xFFFFFFFFFFFFFFFF
_K0, _K1, _K2 = 0xc3a5c85c97cb3127, 0xb492b66fbe98f273, 0x9ae16a3b2f90404f
_KMUL = 0x9ddfea08eb382d69


def _f64(s, p): return int.from_bytes(s[p:p + 8], 'little')
def _f32(s, p): return int.from_bytes(s[p:p + 4], 'little')
def _rot(v, n): return v if n == 0 else ((v >> n) | (v << (64 - n))) & _MASK64
def _smix(v): return v ^ (v >> 47)
def _bswap(v): return int.from_bytes(v.to_bytes(8, 'little'), 'big')


def _h16(u, v, mul=_KMUL):
    a = ((u ^ v) * mul) & _MASK64
    a ^= a >> 47
    b = ((v ^ a) * mul) & _MASK64
    b ^= b >> 47
    return (b * mul) & _MASK64


def _len0to16(s, n):
    if n >= 8:
        mul = (_K2 + n * 2) & _MASK64
        a = (_f64(s, 0) + _K2) & _MASK64
        b = _f64(s, n - 8)
        c = (_rot(b, 37) * mul + a) & _MASK64
        d = ((_rot(a, 25) + b) * mul) & _MASK64
        return _h16(c, d, mul)
    if n >= 4:
        mul = (_K2 + n * 2) & _MASK64
        a = _f32(s, 0)
        return _h16((n + (a << 3)) & _MASK64, _f32(s, n - 4), mul)
    if n > 0:
        a, b, c = s[0], s[n >> 1], s[n - 1]
        y = (a + (b << 8)) & 0xFFFFFFFF
        z = (n + (c << 2)) & 0xFFFFFFFF
        return (_smix(((y * _K2) ^ (z * _K0)) & _MASK64) * _K2) & _MASK64
    return _K2


def _len17to32(s, n):
    mul = (_K2 + n * 2) & _MASK64
    a = (_f64(s, 0) * _K1) & _MASK64
    b = _f64(s, 8)
    c = (_f64(s, n - 8) * mul) & _MASK64
    d = (_f64(s, n - 16) * _K2) & _MASK64
    return _h16((_rot((a + b) & _MASK64, 43) + _rot(c, 30) + d) & _MASK64, (a + _rot((b + _K2) & _MASK64, 18) + c) & _MASK64, mul)


def _len33to64(s, n):
    mul = (_K2 + n * 2) & _MASK64
    a = (_f64(s, 0) * _K2) & _MASK64
    b = _f64(s, 8)
    c = _f64(s, n - 24)
    d = _f64(s, n - 32)
    e = (_f64(s, 16) * _K2) & _MASK64
    f = (_f64(s, 24) * 9) & _MASK64
    g = _f64(s, n - 8)
    h = (_f64(s, n - 16) * mul) & _MASK64
    u = (_rot((a + g) & _MASK64, 43) + (_rot(b, 30) + c) * 9) & _MASK64
    v = (((a + g) & _MASK64 ^ d) + f + 1) & _MASK64
    w = (_bswap(((u + v) * mul) & _MASK64) + h) & _MASK64
    x = (_rot((e + f) & _MASK64, 42) + c) & _MASK64
    y = ((_bswap(((v + w) * mul) & _MASK64) + g) * mul) & _MASK64
    z = (e + f + c) & _MASK64
    a = (_bswap(((x + z) * mul + y) & _MASK64) + b) & _MASK64
    b = (_smix(((z + a) * mul + d + h) & _MASK64) * mul) & _MASK64
    return (b + x) & _MASK64


def _weak(s, p, a, b):
    w, x, y, z = _f64(s, p), _f64(s, p + 8), _f64(s, p + 16), _f64(s, p + 24)
    a = (a + w) & _MASK64
    b = _rot((b + a + z) & _MASK64, 21)
    c = a
    a = (a + x + y) & _MASK64
    b = (b + _rot(a, 44)) & _MASK64
    return (a + z) & _MASK64, (b + c) & _MASK64


def cityhash64(data: bytes) -> int:
    """CityHash64 (v1.1) over `data`, as used by UE's FPackageId::FromName."""
    s, n = data, len(data)
    if n <= 32:
        return _len0to16(s, n) if n <= 16 else _len17to32(s, n)
    if n <= 64:
        return _len33to64(s, n)
    x = _f64(s, n - 40)
    y = (_f64(s, n - 16) + _f64(s, n - 56)) & _MASK64
    z = _h16((_f64(s, n - 48) + n) & _MASK64, _f64(s, n - 24))
    v = _weak(s, n - 64, n, z)
    w = _weak(s, n - 32, (y + _K1) & _MASK64, x)
    x = (x * _K1 + _f64(s, 0)) & _MASK64
    left = (n - 1) & ~63
    p = 0
    while True:
        x = (_rot((x + y + v[0] + _f64(s, p + 8)) & _MASK64, 37) * _K1) & _MASK64
        y = (_rot((y + v[1] + _f64(s, p + 48)) & _MASK64, 42) * _K1) & _MASK64
        x ^= w[1]
        y = (y + v[0] + _f64(s, p + 40)) & _MASK64
        z = (_rot((z + w[0]) & _MASK64, 33) * _K1) & _MASK64
        v = _weak(s, p, (v[1] * _K1) & _MASK64, (x + w[0]) & _MASK64)
        w = _weak(s, p + 32, (z + w[1]) & _MASK64, (y + _f64(s, p + 16)) & _MASK64)
        z, x = x, z
        p += 64
        left -= 64
        if left == 0:
            break
    return _h16((_h16(v[0], w[0]) + _smix(y) * _K1 + z) & _MASK64, (_h16(v[1], w[1]) + x) & _MASK64)


def _ascii_lower(name: str) -> str:
    """UE TChar::ToLower: A-Z become a-z; every other code point, ASCII or not, is unchanged."""
    return ''.join(chr(ord(c) + 32) if 'A' <= c <= 'Z' else c for c in name)


def package_id(name: str) -> int:
    """FPackageId::FromName: CityHash64 over the ASCII-lower-cased name, encoded UTF-16LE."""
    return cityhash64(_ascii_lower(name).encode('utf-16-le'))


_FNV_OFFSET_BASIS = 0xcbf29ce484222325
_FNV_PRIME = 0x100000001B3


def chunk_hash(raw12: bytes, seed: int) -> int:
    """FIoChunkId.HashWithSeed: seeded FNV-1 64 over a 12-byte chunk-id/index/type triple.

    `seed == 0` means the FNV-1 offset basis, matching UE's own convention for an unseeded hash.
    """
    h = (seed & _MASK64) if seed else _FNV_OFFSET_BASIS
    for b in raw12:
        h = (h * _FNV_PRIME) & _MASK64
        h ^= b
    return h
