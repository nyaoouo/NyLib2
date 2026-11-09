"""Last-error capturing call stubs for nylib.winapi bindings (x64, private)."""
import ctypes
import logging
import os
import struct
import sysconfig
import threading
import types

state = None
tl = threading.local()
_lock = threading.Lock()
_owner = None
_tls = None
_blocks = []
_used = 0
_api = None
_get_teb = None
_gle = None
_BODY, _TEB, _UNWIND, _RF, _STUBS, _STUB_SIZE, _NSTUBS, _DATA = 0x000, 0x080, 0x0C0, 0x0D0, 0x100, 16, 240, 0x1000
_TEB_CODE = bytes.fromhex('65488b042530000000c3')
_UNWIND_INFO = bytes.fromhex('0104020504030150')


def _body(cell_off) -> bytes:
    """Machine code of the shared body for a capture cell at gs:[cell_off]."""
    from .utils import _NO_CODE
    no = struct.pack('<I', _NO_CODE)
    return (bytes.fromhex('554889e54881ecb0000000658b0425680000008945f865c7042568000000') + no
            + bytes.fromhex('b8100000004c8b54c5284c8954c418ffc875f241ffd3658b0c256800000081f9') + no
            + bytes.fromhex('750b8b55f86589142568000000') + b'\x65\x89\x0c\x25' + struct.pack('<I', cell_off)
            + bytes.fromhex('488d65005dc3'))


def _register(base) -> bool:
    """Register the unwind data of the block at `base`."""
    return bool(_api.RtlAddFunctionTable(base + _RF, 1, base))


def _plumbing():
    from .utils import _capturing, _dll
    k = _dll('kernel32.dll', True)
    vp, u32 = ctypes.c_void_p, ctypes.c_uint32

    def f(name, restype, *argtypes):
        fn = k[name]
        fn.restype, fn.argtypes = restype, argtypes
        return _capturing(fn)
    return types.SimpleNamespace(
        TlsAlloc=f('TlsAlloc', u32), TlsFree=f('TlsFree', ctypes.c_int, u32), TlsGetValue=f('TlsGetValue', vp, u32),
        VirtualAlloc=f('VirtualAlloc', vp, vp, ctypes.c_size_t, u32, u32), VirtualFree=f('VirtualFree', ctypes.c_int, vp, ctypes.c_size_t, u32),
        VirtualProtect=f('VirtualProtect', ctypes.c_int, vp, ctypes.c_size_t, u32, ctypes.POINTER(u32)),
        FlushInstructionCache=f('FlushInstructionCache', ctypes.c_int, vp, vp, ctypes.c_size_t),
        RtlAddFunctionTable=f('RtlAddFunctionTable', ctypes.c_bool, vp, u32, ctypes.c_uint64))


def _new_block():
    """Map one block; return (base, None) or (None, reason)."""
    base = _api.VirtualAlloc(None, 0x2000, 0x3000, 0x04)  # MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE
    if not base: return None, f'VirtualAlloc failed with error {ctypes.get_last_error()}'
    page = bytearray(b'\xcc' * 0x1000)
    body = _body(0x1480 + 8 * _tls)
    page[_BODY:_BODY + len(body)] = body
    page[_TEB:_TEB + len(_TEB_CODE)] = _TEB_CODE
    page[_UNWIND:_UNWIND + len(_UNWIND_INFO)] = _UNWIND_INFO
    page[_RF:_RF + 12] = struct.pack('<III', _BODY, _BODY + len(body), _UNWIND)
    for k in range(_NSTUBS):
        at = _STUBS + _STUB_SIZE * k
        page[at:at + 12] = b'\x4c\x8b\x1d' + struct.pack('<i', _DATA + 8 * k - (at + 7)) + b'\xe9' + struct.pack('<i', _BODY - (at + 12))
    (ctypes.c_char * 0x1000).from_address(base)[:] = bytes(page)
    old = ctypes.c_uint32()
    if not _api.VirtualProtect(base, 0x1000, 0x20, ctypes.byref(old)):  # PAGE_EXECUTE_READ
        e = ctypes.get_last_error()
        _api.VirtualFree(base, 0, 0x8000)
        return None, f'VirtualProtect failed with error {e}'
    if not _api.FlushInstructionCache(-1, base, 0x1000):
        e = ctypes.get_last_error()
        _api.VirtualFree(base, 0, 0x8000)
        return None, f'FlushInstructionCache failed with error {e}'
    if not _register(base):
        e = ctypes.get_last_error()
        _api.VirtualFree(base, 0, 0x8000)
        return None, f'RtlAddFunctionTable failed with error {e}'
    return base, None


def _claim(target):
    global _used
    if _used == _NSTUBS:
        from .utils import _SET_LAST_ERROR
        thread0, slot0 = _gle(), ctypes.get_last_error()
        try:
            base, why = _new_block()
        finally:
            _SET_LAST_ERROR[1](thread0)
            ctypes.set_last_error(slot0)
        if base is None: raise OSError(why)
        _blocks.append(base)
        _used = 0
    k, _used = _used, _used + 1
    ctypes.c_uint64.from_address(_blocks[-1] + _DATA + 8 * k).value = target
    return _blocks[-1] + _STUBS + _STUB_SIZE * k


def _init():
    """Set `state`; return None or (level, reason) to log."""
    global state, _api, _tls, _get_teb, _gle
    if os.environ.get('NYLIB_WINAPI_THUNK') == '0':
        state = False
        return None
    if (platform := sysconfig.get_platform()) != 'win-amd64':
        state = False
        return 'debug', f'unsupported interpreter platform {platform}'
    from .utils import _SET_LAST_ERROR, _dll
    _gle = get = _dll('kernel32.dll', True)['GetLastError']
    get.restype = ctypes.c_uint32
    get.argtypes = ()
    thread0, slot0 = get(), ctypes.get_last_error()
    try:
        _api = _plumbing()
        if (idx := _api.TlsAlloc()) == 0xFFFFFFFF:
            state = False
            return 'info', f'TlsAlloc failed with error {ctypes.get_last_error()}'
        if idx >= 64:
            _api.TlsFree(idx)
            state = False
            return 'info', f'TLS index {idx} is not below 64'
        _tls = idx
        base, why = _new_block()
        if base is None:
            _api.TlsFree(idx)
            _tls, state = None, False
            return 'info', why
        _blocks.append(base)
        _get_teb = ctypes.PYFUNCTYPE(ctypes.c_void_p)(base + _TEB)
        raw = _dll('kernel32.dll', True)['SetLastError']
        probe = type(raw)(_claim(ctypes.cast(raw, ctypes.c_void_p).value))
        probe.argtypes, probe.restype = (ctypes.c_uint32,), None
        probe(0x1234ABCD)
        seen = [cell().value, (_api.TlsGetValue(idx) or 0) & 0xFFFFFFFF]
        if seen != [0x1234ABCD] * 2:
            raise RuntimeError(f'self-test read {seen}')
        state = True
        return None
    finally:
        _SET_LAST_ERROR[1](thread0)
        ctypes.set_last_error(slot0)


def stub(target: int) -> int | None:
    """Address of a stub that calls `target` and captures its last error, or None when stubs are off in this process."""
    global state, _owner
    if not isinstance(target, int) or not 0 < target < 1 << 64: raise ValueError(f'thunk target {target!r}')
    if state is False or _owner == threading.get_ident(): return None
    log, at = None, None
    with _lock:
        _owner = threading.get_ident()
        try:
            if state is None: log = _init()
            if state: at = _claim(target)
        except Exception as e:
            state, log = False, ('warning', e)
        except BaseException:
            state = False
            raise
        finally:
            _owner = None
    if log:
        level, why = log
        getattr(logging.getLogger('nylib.winapi'), level)('winapi thunks off: %s', why, exc_info=why if isinstance(why, BaseException) else None)
    return at


def cell() -> ctypes.c_int32:
    """This thread's c_int32 view of the capture cell."""
    try:
        return tl.cell
    except AttributeError:
        pass
    if _get_teb is None: raise RuntimeError('winapi thunks are off')
    tl.cell = c = ctypes.c_int32.from_address(_get_teb() + 0x1480 + 8 * _tls)
    return c
