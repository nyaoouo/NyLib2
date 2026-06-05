from .utils import *

_dll = ctypes.WinDLL('propsys.dll')


class PROPERTYKEY(ctypes.Structure):
    _fields_ = [
        ('fmtid', GUID),
        ('pid', ctypes.c_ulong),
    ]


class _CA(ctypes.Structure):
    # Counted array header shared by all PROPVARIANT vector (VT_VECTOR) members.
    _fields_ = [
        ('cElems', ctypes.c_ulong),
        ('pElems', ctypes.c_void_p),
    ]


class _PROPVARIANT_VALUE(ctypes.Union):
    _fields_ = [
        ('cVal', ctypes.c_byte),
        ('bVal', ctypes.c_ubyte),
        ('iVal', ctypes.c_short),
        ('uiVal', ctypes.c_ushort),
        ('lVal', ctypes.c_long),
        ('ulVal', ctypes.c_ulong),
        ('intVal', ctypes.c_int),
        ('uintVal', ctypes.c_uint),
        ('hVal', ctypes.c_longlong),
        ('uhVal', ctypes.c_ulonglong),
        ('fltVal', ctypes.c_float),
        ('dblVal', ctypes.c_double),
        ('boolVal', ctypes.c_short),
        ('pwszVal', ctypes.c_wchar_p),
        ('pszVal', ctypes.c_char_p),
        ('filetime', ctypes.wintypes.FILETIME),
        ('ca', _CA),
        ('puuid', ctypes.c_void_p),
    ]


class PROPVARIANT(ctypes.Structure):
    _fields_ = [
        ('vt', ctypes.c_ushort),
        ('wReserved1', ctypes.c_ushort),
        ('wReserved2', ctypes.c_ushort),
        ('wReserved3', ctypes.c_ushort),
        ('val', _PROPVARIANT_VALUE),
    ]


# All HRESULT-returning; callers inspect the result (some failures are expected for
# value-less keys), so no error wrapper is applied.
PSGetNameFromPropertyKey = def_win_api(_dll.PSGetNameFromPropertyKey, ctypes.c_long, (ctypes.c_void_p, ctypes.c_void_p))
PSGetPropertyDescription = def_win_api(_dll.PSGetPropertyDescription, ctypes.c_long, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p))
PropVariantToStringAlloc = def_win_api(_dll.PropVariantToStringAlloc, ctypes.c_long, (ctypes.c_void_p, ctypes.c_void_p))
