import operator
import struct
import sys
from . import _pixels, _png, _wic
from ._buf import int_arg, view
from ._wic import ImageCodecError

ENCODER_REVISION = 1
_SUBSAMPLING = {'4:2:0': 1, '4:2:2': 2, '4:4:4': 3}  # JpegYCrCbSubsampling


def _background(bg) -> tuple[int, int, int] | None:
    if bg is None: return None
    if not isinstance(bg, tuple):
        raise TypeError(f'background must be an (r, g, b) tuple or None, not {type(bg).__name__}')
    if len(bg) != 3:
        raise ValueError(f'background must have 3 channels (r, g, b), not {len(bg)}')
    values = []
    for c in bg:
        if isinstance(c, bool):
            raise TypeError('background channels must be integers, not bool')
        try:
            values.append(operator.index(c))
        except TypeError:
            raise TypeError(f'background channels must be integers, not {type(c).__name__}') from None
    if not all(0 <= v <= 255 for v in values):
        raise ValueError(f'background channels must be in 0..255, not {tuple(values)}')
    return tuple(values)


def _pixels_view(pixels, width: int, height: int) -> memoryview:
    try:
        bv = view(pixels, 'pixels')
    except TypeError as e:
        if hasattr(pixels, 'pixels') and hasattr(pixels, 'width') and hasattr(pixels, 'height'):
            raise TypeError(f'{e}; pass region.pixels, region.width, region.height') from None
        raise
    if (n := bv.nbytes) != (need := width * height * 4):
        bv.release()
        raise ValueError(f'pixels is {n} bytes; a {width}x{height} RGBA8 image needs {need}')
    return bv


def encode_jpeg(pixels, width: int, height: int, *, quality: int = 90, subsampling: str = '4:2:0',
                background: tuple[int, int, int] | None = None) -> bytes:
    """Baseline JFIF of RGBA8 `pixels` through Windows WIC; non-opaque pixels need `background` to composite over."""
    width = int_arg(width, 'width', 1, 65500)
    height = int_arg(height, 'height', 1, 65500)
    quality = int_arg(quality, 'quality', 1, 100)
    if not isinstance(subsampling, str):
        raise TypeError(f'subsampling must be a str, not {type(subsampling).__name__}')
    if subsampling not in _SUBSAMPLING:
        raise ValueError(f"subsampling must be '4:2:0', '4:2:2' or '4:4:4', not {subsampling!r}")
    background = _background(background)
    bv = _pixels_view(pixels, width, height)
    try:
        if (k := _pixels.count_non_opaque(bv, width, height)) and background is None:
            raise ValueError(f'{k} of {width * height} pixels are not opaque and JPEG has no alpha; pass background=(r, g, b) to composite them')
        if sys.platform != 'win32' or struct.calcsize('P') != 8:
            raise ImageCodecError('nylib.utils.imagecodec needs 64-bit Python on Windows (the Windows Imaging Component)')
        writer = _wic.write_bgr_strips(bv, width, height, background) if k else _wic.write_rgba_strips(bv, width, height)
        data = _wic.encode(width, height, min(1.0, (quality + 0.25) / 100), _SUBSAMPLING[subsampling], writer)
    finally:
        bv.release()
    if not (data[:2] == b'\xff\xd8' and data[-2:] == b'\xff\xd9'):
        raise ImageCodecError('the WIC JPEG encoder wrote a malformed file')
    return data


def encode_png(pixels, width: int, height: int) -> bytes:
    """PNG (RGBA, 8 bits per channel) of RGBA8 `pixels`, written with the stdlib's zlib; lossless on every platform."""
    width = int_arg(width, 'width', 1, 65535)
    height = int_arg(height, 'height', 1, 65535)
    bv = _pixels_view(pixels, width, height)
    try:
        return _png.encode(bv, width, height)
    finally:
        bv.release()
