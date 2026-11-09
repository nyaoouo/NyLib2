from .utils import *

OpenClipboard = def_win_api('user32.dll', 'OpenClipboard', ctypes.c_void_p, (ctypes.c_void_p,), error_zero=True)
EmptyClipboard = def_win_api('user32.dll', 'EmptyClipboard', ctypes.c_bool, (), error_zero=True)
SetClipboardData = def_win_api('user32.dll', 'SetClipboardData', ctypes.c_void_p, (ctypes.c_uint, ctypes.c_void_p), error_zero=True)
CloseClipboard = def_win_api('user32.dll', 'CloseClipboard', ctypes.c_bool, (), error_zero=True)
