from .utils import *

_dll = ctypes.WinDLL('Ole32.dll')

# HRESULT returning; S_OK(0)/S_FALSE(1) are both "ok", RPC_E_CHANGED_MODE means our
# call did not initialize COM. Caller inspects the value, so no error wrapper here.
CoInitializeEx = def_win_api(_dll.CoInitializeEx, ctypes.c_long, (ctypes.c_void_p, ctypes.c_ulong))
CoUninitialize = def_win_api(_dll.CoUninitialize, None, ())
CoTaskMemFree = def_win_api(_dll.CoTaskMemFree, None, (ctypes.c_void_p,))
PropVariantClear = def_win_api(_dll.PropVariantClear, ctypes.c_long, (ctypes.c_void_p,))
