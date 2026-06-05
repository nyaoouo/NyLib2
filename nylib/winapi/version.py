from .utils import *

_dll = ctypes.WinDLL('version.dll')

# Returns the size of the version resource, 0 if the file has none (e.g. non-PE files).
GetFileVersionInfoSizeW = def_win_api(_dll.GetFileVersionInfoSizeW, ctypes.c_ulong, (ctypes.c_wchar_p, ctypes.c_void_p))
GetFileVersionInfoW = def_win_api(_dll.GetFileVersionInfoW, ctypes.c_bool, (ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p), error_zero=True)
# Returns FALSE when the queried sub-block is absent; that is expected, so no error wrapper.
VerQueryValueW = def_win_api(_dll.VerQueryValueW, ctypes.c_bool, (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_void_p))


class VS_FIXEDFILEINFO(ctypes.Structure):
    _fields_ = [
        ('dwSignature', ctypes.c_ulong),
        ('dwStrucVersion', ctypes.c_ulong),
        ('dwFileVersionMS', ctypes.c_ulong),
        ('dwFileVersionLS', ctypes.c_ulong),
        ('dwProductVersionMS', ctypes.c_ulong),
        ('dwProductVersionLS', ctypes.c_ulong),
        ('dwFileFlagsMask', ctypes.c_ulong),
        ('dwFileFlags', ctypes.c_ulong),
        ('dwFileOS', ctypes.c_ulong),
        ('dwFileType', ctypes.c_ulong),
        ('dwFileSubtype', ctypes.c_ulong),
        ('dwFileDateMS', ctypes.c_ulong),
        ('dwFileDateLS', ctypes.c_ulong),
    ]
