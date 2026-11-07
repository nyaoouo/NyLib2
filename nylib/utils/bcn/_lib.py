import ctypes
import operator
import os
import sys
import sysconfig
import threading

from ._buf import pinned, view

_DIR = os.path.dirname(os.path.abspath(__file__))
_NAME = 'bcn_win64.dll'
_PROTO = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t)
_lock = threading.Lock()
_fn = None


class BcnError(Exception):
    """A DLL load failure or a failed native BC1 call."""
    path: str | None

    def __init__(self, message, *, path=None):
        super().__init__(message)
        self.path = path


def _reason(e: OSError) -> str:
    if isinstance(code := getattr(e, 'winerror', None), int):
        return f'[WinError {code}] {ctypes.FormatError(code)}'
    if isinstance(e, FileNotFoundError):
        return f'[WinError 126] {ctypes.FormatError(126)}'
    return type(e).__name__


def _open():
    if not (sys.platform == 'win32' and sysconfig.get_platform() == 'win-amd64'):
        raise BcnError('the bundled bcn DLL is Windows x64 only')
    path = os.path.join(_DIR, _NAME)
    try:
        cdll = ctypes.CDLL(path)
    except OSError as e:
        raise BcnError(f'cannot load the bundled bcn DLL ({_NAME}): {_reason(e)}', path=path) from e
    try:
        return _PROTO(('bcn_decode_bc1', cdll))
    except AttributeError:
        raise BcnError(f'the bundled bcn DLL ({_NAME}) does not export bcn_decode_bc1', path=path) from None


def load() -> None:
    """Load the bundled decoder once; a failed load may be retried."""
    global _fn
    if _fn is None:
        with _lock:
            if _fn is None:
                _fn = _open()


def decode_bc1(src, width: int, height: int) -> bytearray:
    """Decode row-major BC1 blocks into a new RGBA8 bytearray with opaque alpha."""
    try:
        w = operator.index(width)
    except TypeError:
        raise TypeError(f'width must be an integer, not {type(width).__name__}') from None
    try:
        h = operator.index(height)
    except TypeError:
        raise TypeError(f'height must be an integer, not {type(height).__name__}') from None
    if w <= 0 or h <= 0 or w % 4 or h % 4:
        raise ValueError(f'width and height must be positive multiples of 4, got {width}x{height}')
    mv = view(src, 'src')
    try:
        need = 8 * (w // 4) * (h // 4)
        if mv.nbytes < need:
            raise ValueError(f'BC1 source is {mv.nbytes} bytes, need {need} for {width}x{height}')
        load()
        out = bytearray(w * h * 4)
        with memoryview(out) as dst:
            with pinned(mv) as src_ptr, pinned(dst, writable=True) as dst_ptr:
                rc = _fn(src_ptr, mv.nbytes, w, h, dst_ptr, dst.nbytes)
        if rc != 0:
            raise BcnError(f'bcn_decode_bc1 returned {rc}', path=os.path.join(_DIR, _NAME))
        return out
    finally:
        mv.release()
