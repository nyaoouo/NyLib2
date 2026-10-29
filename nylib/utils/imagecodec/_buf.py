import ctypes
import operator


class _Py_buffer(ctypes.Structure):
    _fields_ = [
        ('buf', ctypes.c_void_p), ('obj', ctypes.c_void_p), ('len', ctypes.c_ssize_t), ('itemsize', ctypes.c_ssize_t),
        ('readonly', ctypes.c_int), ('ndim', ctypes.c_int), ('format', ctypes.c_void_p), ('shape', ctypes.c_void_p),
        ('strides', ctypes.c_void_p), ('suboffsets', ctypes.c_void_p), ('internal', ctypes.c_void_p),
    ]


# own prototypes, independent of the shared ctypes.pythonapi attributes
_get_buffer = ctypes.PYFUNCTYPE(ctypes.c_int, ctypes.py_object, ctypes.POINTER(_Py_buffer), ctypes.c_int)(('PyObject_GetBuffer', ctypes.pythonapi))
_release_buffer = ctypes.PYFUNCTYPE(None, ctypes.POINTER(_Py_buffer))(('PyBuffer_Release', ctypes.pythonapi))
_PyBUF_SIMPLE = 0


def view(obj, name: str) -> memoryview:
    """A new 1-D unsigned-byte memoryview of `obj`; TypeError if not bytes-like, ValueError if not C-contiguous.

    The caller owns the view and releases it; on error nothing stays exported.
    """
    try:
        mv = memoryview(obj)
    except TypeError:
        raise TypeError(f'{name} must be a bytes-like object, not {type(obj).__name__}') from None
    if not mv.c_contiguous:
        mv.release()
        raise ValueError(f'{name} must be C-contiguous')
    if mv.format == 'B' and mv.ndim == 1:
        return mv
    with mv:
        return mv.cast('B') if mv.nbytes else memoryview(b'')  # cast refuses a zero in the shape


class pinned:
    """Context manager yielding the address of `mv`, holding a buffer export until exit."""
    __slots__ = ('_mv', '_b')

    def __init__(self, mv: memoryview):
        self._mv, self._b = mv, None

    def __enter__(self) -> int:
        self._b = b = _Py_buffer()
        try:
            _get_buffer(self._mv, b, _PyBUF_SIMPLE)  # raises BufferError on failure
        except BaseException:
            self._b = None
            _release_buffer(b)  # no-op unless the export was taken before an async exception
            raise
        return b.buf

    def __exit__(self, *exc):
        if (b := self._b) is not None:
            self._b = None
            _release_buffer(b)


def int_arg(x, name: str, lo: int, hi: int) -> int:
    """`operator.index(x)` within lo..hi; TypeError for bool or non-integers, ValueError when out of range."""
    if isinstance(x, bool):
        raise TypeError(f'{name} must be an integer, not bool')
    try:
        v = operator.index(x)
    except TypeError:
        raise TypeError(f'{name} must be an integer, not {type(x).__name__}') from None
    if not lo <= v <= hi:
        raise ValueError(f'{name} must be in {lo}..{hi}, not {v}')
    return v
