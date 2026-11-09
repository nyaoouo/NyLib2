import logging as _logging
import os as _os
import threading as _threading
import typing
from .defs import *


if not globals().get('_gle_installed', False) and not getattr(ctypes.GetLastError, '_nylib_gle_warning', False):
    _gle_installed = True
    _gle_original = ctypes.GetLastError
    _gle_lock = _threading.Lock()
    _gle_warned = False

    def _warn_get_last_error():
        code = _gle_original()
        global _gle_warned
        with _gle_lock:
            warn = not _gle_warned
            _gle_warned = True
        if warn:
            _logging.getLogger('nylib.winapi').warning(
                "ctypes.GetLastError() reads the thread's last error, which a GIL switch can overwrite on Python 3.13+; "
                "read the raised exception's winerror or ctypes.get_last_error() after a use_last_error call", stacklevel=2)
            ctypes.GetLastError = _gle_original
        return code

    _warn_get_last_error._nylib_gle_warning = True
    ctypes.GetLastError = _warn_get_last_error

_NULL = type('NULL', (), {})
_NO_CODE = 0x20004E59
_dlls: dict = {}


def _dll(name: str, gil: bool):
    """Return the cached WinDLL or PyDLL for `name`."""
    key = _os.path.normcase(name)
    gil = bool(gil)
    if (dll := _dlls.get((key, gil))) is None:
        other = _dlls.get((key, not gil))
        dll = (ctypes.PyDLL if gil else ctypes.WinDLL)(name, handle=None if other is None else other._handle)
        dll = _dlls.setdefault((key, gil), dll)
    return dll


_SET_LAST_ERROR = _dll('kernel32.dll', False)['SetLastError'], _dll('kernel32.dll', True)['SetLastError']
for _func in _SET_LAST_ERROR:
    _func.restype = None


def _errcheck_view(func, check):
    """Wrap `check` so it sees the call's code on the thread and the original `func`."""
    def errcheck(result, _twin, args):
        code = ctypes.get_last_error()
        if code != _NO_CODE:
            _SET_LAST_ERROR[0](code)
        return check(result, func, args)

    return errcheck


def _capturing(func):
    """Return a ctypes function that captures its last error."""
    cls = type(func)
    if cls._flags_ & ctypes._FUNCFLAG_USE_LASTERROR:
        return func
    call = ctypes.cast(func, type(cls.__name__, (cls,), {'_flags_': cls._flags_ | ctypes._FUNCFLAG_USE_LASTERROR}))
    call.restype, call.argtypes = func.restype, func.argtypes
    if func.errcheck is not None:
        call.errcheck = _errcheck_view(func, func.errcheck)
    return call


def _win_error(code, prev, gil):
    """Build a WinError and write back the code or restore the slot."""
    e = ctypes.WinError(code) if code not in (0, _NO_CODE) else ctypes.WinError(0, 'The operation completed successfully.')
    if code != _NO_CODE:
        _SET_LAST_ERROR[1 if gil else 0](code)
    else:
        ctypes.set_last_error(prev)
    return e


def _bind(make, dll_name, func_name, error_zero, error_nonzero, error_val, error_nt):
    slots = [None, None]
    capture = bool(error_zero or error_nonzero or error_val is not _NULL)

    def resolve(gil=False):
        g = 1 if gil else 0
        if (fn := slots[g]) is None:
            fn = make(bool(g))
            if capture: fn = _capturing(fn)
            slots[g] = fn
        return fn

    if error_zero:
        def wrapper(*args, _ignore_error=False, _gil=False, **kwargs):
            if (call := slots[1 if _gil else 0]) is None: call = resolve(_gil)
            prev = ctypes.set_last_error(_NO_CODE)
            res = call(*args, **kwargs)
            code = ctypes.get_last_error()
            if not res and not _ignore_error:
                raise _win_error(code, prev, _gil)
            if code != _NO_CODE:
                _SET_LAST_ERROR[1 if _gil else 0](code)
            else:
                ctypes.set_last_error(prev)
            return res
    elif error_nonzero:
        def wrapper(*args, _ignore_error=False, _gil=False, **kwargs):
            if (call := slots[1 if _gil else 0]) is None: call = resolve(_gil)
            prev = ctypes.set_last_error(_NO_CODE)
            res = call(*args, **kwargs)
            code = ctypes.get_last_error()
            if res != 0 and not _ignore_error:
                raise _win_error(code, prev, _gil)
            if code != _NO_CODE:
                _SET_LAST_ERROR[1 if _gil else 0](code)
            else:
                ctypes.set_last_error(prev)
            return res
    elif error_val is not _NULL:
        def wrapper(*args, _ignore_error=False, _gil=False, **kwargs):
            if (call := slots[1 if _gil else 0]) is None: call = resolve(_gil)
            prev = ctypes.set_last_error(_NO_CODE)
            res = call(*args, **kwargs)
            code = ctypes.get_last_error()
            if res == error_val and not _ignore_error:
                raise _win_error(code, prev, _gil)
            if code != _NO_CODE:
                _SET_LAST_ERROR[1 if _gil else 0](code)
            else:
                ctypes.set_last_error(prev)
            return res
    elif error_nt:
        def wrapper(*args, _ignore_error=False, _gil=False, **kwargs):
            if (call := slots[1 if _gil else 0]) is None: call = resolve(_gil)
            res = call(*args, **kwargs)
            if not NT_SUCCESS(res) and not _ignore_error:
                raise OSError(f'NtStatus: {res:#x}')
            return res
    else:
        def wrapper(*args, _ignore_error=False, _gil=False, **kwargs):
            if (call := slots[1 if _gil else 0]) is None: call = resolve(_gil)
            return call(*args, **kwargs)
    if isinstance(func_name, str): wrapper.__name__ = wrapper.__qualname__ = func_name
    wrapper.dll_name, wrapper.func_name, wrapper.resolve = dll_name, func_name, resolve
    return wrapper


def def_win_api(dll_name, func_name: str, res_type: typing.Any = ctypes.c_void_p, arg_types=(), error_zero=False, error_nonzero=False, error_val: typing.Any = _NULL, error_nt=False):
    if isinstance(dll_name, ctypes._CFuncPtr):
        func = dll_name
        if isinstance(arg_types, bool):
            raise TypeError('legacy def_win_api(func, ...) takes the error flags by keyword')
        if res_type is not ctypes.c_void_p and len(arg_types) > 0:
            raise TypeError('legacy def_win_api(func, ...) got argtypes twice')
        func.argtypes = arg_types if res_type is ctypes.c_void_p else res_type
        func.restype = func_name
        if not (error_zero or error_nonzero or error_val is not _NULL or error_nt):
            return func
        call = _capturing(func) if error_zero or error_nonzero or error_val is not _NULL else func

        def make(gil):
            if gil: raise TypeError('_gil=True needs a binding defined by DLL name and export name')
            return call
        return _bind(make, None, getattr(func, '__name__', None), error_zero, error_nonzero, error_val, error_nt)
    name = _os.fspath(dll_name)
    if not isinstance(name, str) or not isinstance(func_name, str):
        raise TypeError(f'def_win_api needs a str or os.PathLike DLL name and a str export name, got {dll_name!r}, {func_name!r}')

    def make(gil):
        func = _dll(name, gil)[func_name]
        func.argtypes, func.restype = arg_types, res_type
        return func
    return _bind(make, name, func_name, error_zero, error_nonzero, error_val, error_nt)
