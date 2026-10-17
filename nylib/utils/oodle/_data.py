import ctypes
import enum
import sys
from ._buf import int_arg, overlaps, pinned, view
from ._lib import OodleError, current


class Compressor(enum.IntEnum):
    None_ = 3
    Kraken = 8
    Mermaid = 9
    Selkie = 11
    Hydra = 12
    Leviathan = 13


class CompressionLevel(enum.IntEnum):
    HyperFast4 = -4
    HyperFast3 = -3
    HyperFast2 = -2
    HyperFast1 = -1
    None_ = 0
    SuperFast = 1
    VeryFast = 2
    Fast = 3
    Normal = 4
    Optimal1 = 5
    Optimal2 = 6
    Optimal3 = 7
    Optimal4 = 8
    Optimal5 = 9
    HyperFast = -1
    Optimal = 6
    Max = 9
    Min = -4


def _enum_arg(x, cls, other, name: str):
    if isinstance(x, (bool, other)) or not isinstance(x, int):
        raise TypeError(f'{name} must be a {cls.__name__} or int, not {type(x).__name__}')
    try:
        return cls(x)
    except ValueError:
        raise ValueError(f'{name} {int(x)} is not a {cls.__name__} value') from None


def _bound(lib, compressor: int, raw_size: int, needed_by: str) -> int:
    get_bound = lib.require('OodleLZ_GetCompressedBufferSizeNeeded', needed_by)
    if (v := get_bound(compressor, raw_size)) < raw_size:
        raise OodleError(f'OodleLZ_GetCompressedBufferSizeNeeded returned {v} ({raw_size} raw bytes)',
                         func='OodleLZ_GetCompressedBufferSizeNeeded', result=v, path=lib.path)
    return v


def _with_views(fn, src, out, *args):
    """Call `fn(src_view, out_view, *args)`, releasing both views on return or error."""
    src_mv = view(src, 'src')
    try:
        out_mv = None if out is None else view(out, 'out', writable=True)
        try:
            return fn(src_mv, out_mv, *args)
        finally:
            if out_mv is not None: out_mv.release()
    finally:
        src_mv.release()


def compress(src, compressor=Compressor.Kraken, level=CompressionLevel.Normal, *, out=None) -> bytes | memoryview:
    """Compress `src`; with `out`, write into it and return the written view `out[:n]`.

    `out` must hold `compress_bound(len(src), compressor)` bytes; all of that range may be used as scratch.
    """
    compressor = _enum_arg(compressor, Compressor, CompressionLevel, 'compressor')
    level = _enum_arg(level, CompressionLevel, Compressor, 'level')
    return _with_views(_compress, src, out, compressor, level)


def _compress(src: memoryview, out: memoryview | None, compressor: Compressor, level: CompressionLevel):
    if not (n_src := src.nbytes):
        return b'' if out is None else out[:0]
    lib = current('core')
    lz_compress = lib.require('OodleLZ_Compress', 'oodle.compress')
    bound = _bound(lib, compressor, n_src, 'oodle.compress')
    if out is not None and out.nbytes < bound:
        raise ValueError(f'out is {out.nbytes} bytes, compress_bound is {bound}')
    with pinned(src) as p_src, pinned(out, writable=True) as p_out:
        if out is None:
            p_out = buf = ctypes.create_string_buffer(bound)
        elif overlaps(p_src, n_src, p_out, bound):
            raise ValueError('out overlaps src')
        n = lz_compress(compressor, p_src, n_src, p_out, level, None, None, None, None, 0)
    if not 0 < n <= bound:
        raise OodleError(f'OodleLZ_Compress returned {n} ({compressor.name}/{level.name}, {n_src} raw bytes)',
                         func='OodleLZ_Compress', result=n, path=lib.path)
    return bytes(memoryview(buf)[:n]) if out is None else out[:n]


def compress_bound(raw_size: int, compressor: Compressor | None = None) -> int:
    """Output buffer size `compress` needs for `raw_size` bytes; None means enough for any compressor."""
    raw_size = int_arg(raw_size, 'raw_size', 0, sys.maxsize)
    compressor = -1 if compressor is None else _enum_arg(compressor, Compressor, CompressionLevel, 'compressor')
    return _bound(current('core'), compressor, raw_size, 'oodle.compress_bound')


def decompress(src, raw_size: int, *, out=None) -> bytes | memoryview:
    """Decompress `src` to exactly `raw_size` bytes; with `out`, write into it and return the view `out[:raw_size]`.

    Never writes `out[raw_size:]`. Undetected corruption returns garbage: Oodle streams carry no checksum.
    """
    raw_size = int_arg(raw_size, 'raw_size', 0, sys.maxsize)
    return _with_views(_decompress, src, out, raw_size)


def _decompress(src: memoryview, out: memoryview | None, raw_size: int):
    if out is not None and out.nbytes < raw_size:
        raise ValueError(f'out is {out.nbytes} bytes, raw_size is {raw_size}')
    if not raw_size:
        return b'' if out is None else out[:0]
    n_src = src.nbytes
    with pinned(src) as p_src, pinned(out, writable=True) as p_out:
        if out is not None and overlaps(p_src, n_src, p_out, raw_size):
            raise ValueError('out overlaps src')
        lib = current('core')
        lz_decompress = lib.require('OodleLZ_Decompress', 'oodle.decompress')
        if out is None:
            p_out = buf = ctypes.create_string_buffer(raw_size)
        r = lz_decompress(p_src, n_src, p_out, raw_size, 1, 0, 0, None, 0, None, None, None, 0, 3)  # FuzzSafe, no CRC, unthreaded
    if r != raw_size:
        hint = ('wrong raw_size, corrupt data, or not Oodle data' if r == 0 else
                'wrong raw_size or corrupt data' if 0 < r < raw_size else 'invalid result from the DLL')
        raise OodleError(f'OodleLZ_Decompress returned {r}, expected {raw_size} ({n_src} compressed bytes; {hint})',
                         func='OodleLZ_Decompress', result=r, expected=raw_size, path=lib.path)
    return buf.raw if out is None else out[:raw_size]
