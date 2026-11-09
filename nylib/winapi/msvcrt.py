from .utils import *

memcpy = def_win_api('msvcrt.dll', 'memcpy', ctypes.c_void_p, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t), error_zero=True)
