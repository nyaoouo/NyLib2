import typing
from .defs import *

_NULL = type('NULL', (), {})

_SetLastError = ctypes.WinDLL('kernel32.dll').SetLastError
_SetLastError.restype = None
_NO_CODE = 0x20004E59


def _errcheck_view(func, check):
    """Wrap `check` so it sees the call's code on the thread and the original `func`."""
    def errcheck(result, _twin, args):
        code = ctypes.get_last_error()
        if code != _NO_CODE:
            _SetLastError(code)
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


def _win_error(code, prev):
    """Build a WinError and write back the code or restore the slot."""
    e = ctypes.WinError(code) if code not in (0, _NO_CODE) else ctypes.WinError(0, 'The operation completed successfully.')
    if code != _NO_CODE:
        _SetLastError(code)
    else:
        ctypes.set_last_error(prev)
    return e


def def_win_api(func, res_type: typing.Any = ctypes.c_void_p, arg_types=(), error_zero=False, error_nonzero=False, error_val: typing.Any = _NULL, error_nt=False):
    func.argtypes = arg_types
    func.restype = res_type

    if error_zero:
        call = _capturing(func)

        def wrapper(*args, _ignore_error=False, **kwargs):
            prev = ctypes.set_last_error(_NO_CODE)
            res = call(*args, **kwargs)
            code = ctypes.get_last_error()
            if not res and not _ignore_error:
                raise _win_error(code, prev)
            if code != _NO_CODE:
                _SetLastError(code)
            else:
                ctypes.set_last_error(prev)
            return res

        return wrapper

    if error_nonzero:
        call = _capturing(func)

        def wrapper(*args, _ignore_error=False, **kwargs):
            prev = ctypes.set_last_error(_NO_CODE)
            res = call(*args, **kwargs)
            code = ctypes.get_last_error()
            if res != 0 and not _ignore_error:
                raise _win_error(code, prev)
            if code != _NO_CODE:
                _SetLastError(code)
            else:
                ctypes.set_last_error(prev)
            return res

        return wrapper

    if error_val is not _NULL:
        call = _capturing(func)

        def wrapper(*args, _ignore_error=False, **kwargs):
            prev = ctypes.set_last_error(_NO_CODE)
            res = call(*args, **kwargs)
            code = ctypes.get_last_error()
            if res == error_val and not _ignore_error:
                raise _win_error(code, prev)
            if code != _NO_CODE:
                _SetLastError(code)
            else:
                ctypes.set_last_error(prev)
            return res

        return wrapper

    if error_nt:
        def wrapper(*args, _ignore_error=False, **kwargs):
            res = func(*args, **kwargs)
            if not NT_SUCCESS(res) and not _ignore_error:
                raise OSError(f'NtStatus: {res:#x}')
            return res

        return wrapper
    return func
