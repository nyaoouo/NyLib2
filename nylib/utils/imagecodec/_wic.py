import ctypes
import os
import struct
import threading
from . import _pixels
from ._buf import pinned

_p, _u32, _long = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_long
_E_FAIL = 0x80004005


class ImageCodecError(Exception):
    """A failure of the Windows Imaging Component, or a platform without it."""
    func: str | None
    hresult: int | None

    def __init__(self, message, *, func=None, hresult=None):
        super().__init__(message)
        self.func, self.hresult = func, hresult


class _GUID(ctypes.Structure):
    _fields_ = [('Data1', ctypes.c_uint32), ('Data2', ctypes.c_ushort), ('Data3', ctypes.c_ushort), ('Data4', ctypes.c_ubyte * 8)]


def _guid(s: str) -> _GUID:
    h = s.replace('-', '')
    return _GUID.from_buffer_copy(struct.pack('<IHH', int(h[:8], 16), int(h[8:12], 16), int(h[12:16], 16)) + bytes.fromhex(h[16:]))


class _PROPBAG2(ctypes.Structure):
    _fields_ = [('dwType', ctypes.c_uint32), ('vt', ctypes.c_ushort), ('cfType', ctypes.c_ushort), ('dwHint', ctypes.c_uint32),
                ('pstrName', ctypes.c_wchar_p), ('clsid', _GUID)]


class _VARIANT_U(ctypes.Union):
    _fields_ = [('fltVal', ctypes.c_float), ('bVal', ctypes.c_ubyte), ('_pad', ctypes.c_uint64 * 2)]


class _VARIANT(ctypes.Structure):
    _fields_ = [('vt', ctypes.c_ushort), ('_r1', ctypes.c_ushort), ('_r2', ctypes.c_ushort), ('_r3', ctypes.c_ushort), ('u', _VARIANT_U)]


_CLSID_WICImagingFactory = _guid('cacaf262-9370-4615-a13b-9f5539da4c0a')
_IID_IWICImagingFactory = _guid('ec5ec8a9-c395-4314-9c77-54d7a935ff70')
_GUID_ContainerFormatJpeg = _guid('19e4a5aa-5662-4fc5-a0c0-1758028e1057')
_FORMATS = {
    'GUID_WICPixelFormat24bppBGR': '6fddc324-4e03-4bfe-b185-3d77768dc90c',
    'GUID_WICPixelFormat32bppBGRA': '6fddc324-4e03-4bfe-b185-3d77768dc90f',
    'GUID_WICPixelFormat32bppRGBA': 'f5c7ad2d-6a8d-43dd-a7a8-a29935261ae9',
}
_FORMAT_NAMES = {bytes(_guid(v)): k for k, v in _FORMATS.items()}
_BGR24, _RGBA32 = _guid(_FORMATS['GUID_WICPixelFormat24bppBGR']), _guid(_FORMATS['GUID_WICPixelFormat32bppRGBA'])

_METHODS = {  # name: (argtypes after `this`, releases the GIL)
    'IWICImagingFactory::CreateEncoder': ((_p, _p, _p), False),
    'IWICImagingFactory::CreateBitmapFromMemory': ((_u32, _u32, _p, _u32, _u32, _p, _p), False),
    'IWICBitmapEncoder::Initialize': ((_p, _u32), False),
    'IWICBitmapEncoder::CreateNewFrame': ((_p, _p), False),
    'IWICBitmapEncoder::Commit': ((), False),
    'IPropertyBag2::Write': ((_u32, _p, _p), False),
    'IWICBitmapFrameEncode::Initialize': ((_p,), False),
    'IWICBitmapFrameEncode::SetSize': ((_u32, _u32), False),
    'IWICBitmapFrameEncode::SetResolution': ((ctypes.c_double, ctypes.c_double), False),
    'IWICBitmapFrameEncode::SetPixelFormat': ((_p,), False),
    'IWICBitmapFrameEncode::WritePixels': ((_u32, _u32, _u32, _p), True),
    'IWICBitmapFrameEncode::WriteSource': ((_p, _p), True),
    'IWICBitmapFrameEncode::Commit': ((), False),
    'IStream::Seek': ((ctypes.c_longlong, _u32, _p), False),
}
_LAST_ERROR_FUNCS = ('GetSystemDirectoryW', 'GlobalLock')

_lock = threading.Lock()
_ready = False
_windowscodecs = None
_protos: dict = {}
_Release = _GetLastError = _GetSystemDirectoryW = _CoIncrementMTAUsage = _CoCreateInstance = None
_CreateStreamOnHGlobal = _GetHGlobalFromStream = _GlobalLock = _GlobalUnlock = None


def _message_text(hresult: int) -> str:
    text = ctypes.FormatError(hresult - (1 << 32) if hresult & 0x80000000 else hresult).strip()
    return 'no system message' if not text or text == '<no description>' else text


def _error(name: str, hresult: int) -> ImageCodecError:
    hresult &= 0xFFFFFFFF
    return ImageCodecError(f'{name} failed: HRESULT {hresult:#010x} ({_message_text(hresult)})', func=name, hresult=hresult)


def _api(name: str, fn, *args):
    """Call a non-COM function that can fail: an HRESULT below 0, or a zero result with the thread's last error."""
    if name in _LAST_ERROR_FUNCS:
        if not (r := fn(*args)):
            e = _GetLastError()
            raise _error(name, 0x80070000 | (e & 0xFFFF) if e else _E_FAIL)
        return r
    if (r := fn(*args)) < 0:
        raise _error(name, r)
    return r


def _call(ptr, index: int, name: str, *args) -> int:
    """Call vtable slot `index` of COM object `ptr` through the prototype of `name`; ImageCodecError on a failed HRESULT."""
    this = ptr.value if isinstance(ptr, ctypes.c_void_p) else ptr
    vtable = ctypes.c_void_p.from_address(this).value
    if (hr := _protos[name](ctypes.c_void_p.from_address(vtable + 8 * index).value)(this, *args)) < 0:
        raise _error(name, hr)
    return hr


def _release(ptr) -> None:
    """IUnknown::Release."""
    this = ptr.value if isinstance(ptr, ctypes.c_void_p) else ptr
    _Release(ctypes.c_void_p.from_address(ctypes.c_void_p.from_address(this).value + 16).value)(this)


def _load_reason(e: OSError) -> str:
    if isinstance(code := getattr(e, 'winerror', None), int):
        return f'[WinError {code}] {ctypes.FormatError(code)}'
    if isinstance(e, FileNotFoundError):
        return f'[WinError 126] {ctypes.FormatError(126)}'
    return type(e).__name__


def _init() -> None:
    """Once per process: load windowscodecs.dll from the system directory, build the prototypes, join the process MTA."""
    global _ready
    if _ready: return
    with _lock:
        if _ready: return
        _setup()
        _ready = True


def _setup() -> None:
    global _windowscodecs, _Release, _GetLastError, _GetSystemDirectoryW, _CoIncrementMTAUsage, _CoCreateInstance
    global _CreateStreamOnHGlobal, _GetHGlobalFromStream, _GlobalLock, _GlobalUnlock
    py, win = ctypes.PYFUNCTYPE, ctypes.WINFUNCTYPE
    if _GetSystemDirectoryW is None:
        kernel32 = ctypes.WinDLL('kernel32')
        _GetLastError = py(_u32)(('GetLastError', kernel32))
        _GetSystemDirectoryW = py(_u32, ctypes.c_wchar_p, _u32)(('GetSystemDirectoryW', kernel32))
        _GlobalLock = py(_p, _p)(('GlobalLock', kernel32))
        _GlobalUnlock = py(ctypes.c_int, _p)(('GlobalUnlock', kernel32))
    buf = ctypes.create_unicode_buffer(1024)
    system = buf.value[:_api('GetSystemDirectoryW', _GetSystemDirectoryW, buf, len(buf))]
    if _windowscodecs is None:
        try:
            _windowscodecs = ctypes.WinDLL(os.path.join(system, 'windowscodecs.dll'))
        except OSError as e:
            raise ImageCodecError(f'cannot load windowscodecs.dll: {_load_reason(e)}') from e
    if _CoCreateInstance is None:
        ole32 = ctypes.WinDLL(os.path.join(system, 'ole32.dll'))
        _CoIncrementMTAUsage = win(_long, _p)(('CoIncrementMTAUsage', ole32))
        _CreateStreamOnHGlobal = py(_long, _p, ctypes.c_int, _p)(('CreateStreamOnHGlobal', ole32))
        _GetHGlobalFromStream = py(_long, _p, _p)(('GetHGlobalFromStream', ole32))
        _Release = py(ctypes.c_ulong, _p)
        for name, (argtypes, releases) in _METHODS.items():
            _protos[name] = (win if releases else py)(_long, _p, *argtypes)
        _CoCreateInstance = py(_long, _p, _p, _u32, _p, _p)(('CoCreateInstance', ole32))
    _api('CoIncrementMTAUsage', _CoIncrementMTAUsage, ctypes.byref(ctypes.c_void_p()))  # the cookie is never released


def _write_property(bag, name: str, vt: int, field: str, value) -> None:
    prop, var = _PROPBAG2(pstrName=name), _VARIANT(vt=vt)
    setattr(var.u, field, value)
    _call(bag, 4, 'IPropertyBag2::Write', 1, ctypes.byref(prop), ctypes.byref(var))


def encode(width: int, height: int, quality: float, subsampling: int, writer) -> bytes:
    """One JPEG session: `writer(factory, frame)` writes the pixels; every object is released on return or error."""
    _init()
    factory, stream, encoder, frame, bag = (ctypes.c_void_p() for _ in range(5))
    try:
        _api('CoCreateInstance(CLSID_WICImagingFactory)', _CoCreateInstance, ctypes.byref(_CLSID_WICImagingFactory), None, 1,
             ctypes.byref(_IID_IWICImagingFactory), ctypes.byref(factory))  # CLSCTX_INPROC_SERVER
        _api('CreateStreamOnHGlobal', _CreateStreamOnHGlobal, None, 1, ctypes.byref(stream))
        _call(factory, 8, 'IWICImagingFactory::CreateEncoder', ctypes.byref(_GUID_ContainerFormatJpeg), None, ctypes.byref(encoder))
        _call(encoder, 3, 'IWICBitmapEncoder::Initialize', stream, 2)  # WICBitmapEncoderNoCache
        _call(encoder, 10, 'IWICBitmapEncoder::CreateNewFrame', ctypes.byref(frame), ctypes.byref(bag))
        _write_property(bag, 'ImageQuality', 4, 'fltVal', quality)  # VT_R4
        _write_property(bag, 'JpegYCrCbSubsampling', 17, 'bVal', subsampling)  # VT_UI1
        _call(frame, 3, 'IWICBitmapFrameEncode::Initialize', bag)
        _call(frame, 4, 'IWICBitmapFrameEncode::SetSize', width, height)
        _call(frame, 5, 'IWICBitmapFrameEncode::SetResolution', 72.0, 72.0)
        fmt = _GUID.from_buffer_copy(_BGR24)
        _call(frame, 6, 'IWICBitmapFrameEncode::SetPixelFormat', ctypes.byref(fmt))
        if bytes(fmt) != bytes(_BGR24):
            got = _FORMAT_NAMES.get(bytes(fmt)) or '{%08x-%04x-%04x-%s-%s}' % (fmt.Data1, fmt.Data2, fmt.Data3, bytes(fmt.Data4[:2]).hex(), bytes(fmt.Data4[2:]).hex())
            raise ImageCodecError(f'IWICBitmapFrameEncode::SetPixelFormat chose {got} instead of GUID_WICPixelFormat24bppBGR',
                                  func='IWICBitmapFrameEncode::SetPixelFormat')
        writer(factory, frame)
        _call(frame, 12, 'IWICBitmapFrameEncode::Commit')
        _call(encoder, 11, 'IWICBitmapEncoder::Commit')
        size = ctypes.c_ulonglong()
        _call(stream, 5, 'IStream::Seek', 0, 2, ctypes.byref(size))  # STREAM_SEEK_END
        hglobal = ctypes.c_void_p()
        _api('GetHGlobalFromStream', _GetHGlobalFromStream, stream, ctypes.byref(hglobal))
        address = _api('GlobalLock', _GlobalLock, hglobal)
        try:
            return (ctypes.c_char * size.value).from_address(address).raw
        finally:
            _GlobalUnlock(hglobal)
    finally:
        for obj in (bag, frame, encoder, stream, factory):
            if obj.value:
                _release(obj)


def write_rgba_strips(bv: memoryview, width: int, height: int):
    """A writer passing each strip of RGBA8 `bv` to WIC as a 32bppRGBA bitmap through WriteSource."""
    def writer(factory, frame):
        stride = 4 * width
        with pinned(bv) as address:
            for y0, rows in _pixels.strips(width, height):
                bitmap = ctypes.c_void_p()
                _call(factory, 20, 'IWICImagingFactory::CreateBitmapFromMemory', width, rows, ctypes.byref(_RGBA32), stride, stride * rows,
                      address + y0 * stride, ctypes.byref(bitmap))
                try:
                    _call(frame, 11, 'IWICBitmapFrameEncode::WriteSource', bitmap, None)
                finally:
                    _release(bitmap)
    return writer


def write_bgr_strips(bv: memoryview, width: int, height: int, background: tuple[int, int, int]):
    """A writer compositing each strip of RGBA8 `bv` over `background` into 24bppBGR rows for WritePixels."""
    def writer(factory, frame):
        stride = 4 * width
        for y0, rows in _pixels.strips(width, height):
            out = bytearray(3 * width * rows)
            with bv[y0 * stride:(y0 + rows) * stride] as strip:
                _pixels.composite(strip, background, out)
            with pinned(memoryview(out)) as address:
                _call(frame, 10, 'IWICBitmapFrameEncode::WritePixels', rows, 3 * width, len(out), address)
    return writer
