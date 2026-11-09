from .utils import *


SHGetPropertyStoreFromParsingName = def_win_api('Shell32.dll', 'SHGetPropertyStoreFromParsingName', ctypes.c_long, (ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p), error_nonzero=True)
