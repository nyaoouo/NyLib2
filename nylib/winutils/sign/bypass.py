import ctypes
import datetime
from functools import cache
from ctypes import wintypes

from ...hook import Hook


def getAddr(dll, name):
    if func := getattr(dll, name, None):
        return ctypes.cast(func, ctypes.c_void_p).value
    return None


@cache
def load_hook_address():
    crypt32 = ctypes.WinDLL("crypt32.dll", use_last_error=True)
    mssign32 = ctypes.WinDLL("Mssign32.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

    return {
        "CertVerifyTimeValidity": getAddr(crypt32, "CertVerifyTimeValidity"),
        "SignerSign": getAddr(mssign32, "SignerSign"),
        "SignerTimeStamp": getAddr(mssign32, "SignerTimeStamp"),
        "SignerTimeStampEx2": getAddr(mssign32, "SignerTimeStampEx2"),
        "SignerTimeStampEx3": getAddr(mssign32, "SignerTimeStampEx3"),
        "GetLocalTime": getAddr(kernel32, "GetLocalTime"),
    }


class SYSTEMTIME(ctypes.Structure):
    _fields_ = [
        ("wYear", ctypes.c_ushort),
        ("wMonth", ctypes.c_ushort),
        ("wDayOfWeek", ctypes.c_ushort),
        ("wDay", ctypes.c_ushort),
        ("wHour", ctypes.c_ushort),
        ("wMinute", ctypes.c_ushort),
        ("wSecond", ctypes.c_ushort),
        ("wMilliseconds", ctypes.c_ushort),
    ]


class BypassTsCheck:
    def __init__(self, replacement: datetime.datetime) -> None:
        self.replacement = replacement
        self.hooks = None

    def patch_GetLocalTime(self, hook, SYSTEMTIME_ptr):
        st = SYSTEMTIME_ptr.contents
        st.wYear = self.replacement.year
        st.wMonth = self.replacement.month
        st.wDay = self.replacement.day
        st.wHour = self.replacement.hour
        st.wMinute = self.replacement.minute
        st.wSecond = self.replacement.second
        st.wMilliseconds = int(self.replacement.microsecond / 1000)
        return 0

    def do_patch(self):
        assert self.hooks is None, "Already patched"
        hooks = []
        addrs = load_hook_address()
        if addrs["CertVerifyTimeValidity"]:
            hooks.append(Hook(at=addrs["CertVerifyTimeValidity"], hook_func=lambda *args, **kwargs: 0, restype=ctypes.c_long, argtypes=[wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]))
        if addrs["GetLocalTime"]:
            hooks.append(Hook(at=addrs["GetLocalTime"], hook_func=self.patch_GetLocalTime, restype=ctypes.c_long, argtypes=[ctypes.POINTER(SYSTEMTIME)]))
        for hook in hooks:
            hook.install()
        self.hooks = hooks

    def undo_patch(self):
        assert self.hooks is not None, "Not patched yet"
        for hook in self.hooks:
            hook.uninstall()
        self.hooks = None

    def __enter__(self):
        self.do_patch()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.undo_patch()
