import ctypes

from .. import winapi


class Thread:
    """Own a thread handle; close it explicitly or use it as a context manager."""

    def __init__(self, thread_id: int, handle=None, da=0x1FFFFF):
        self.thread_id = thread_id
        self.handle = winapi.OpenThread(da, False, thread_id) if handle is None else handle

    @property
    def process_id(self) -> int:
        return winapi.GetProcessIdOfThread(self.handle)

    def description(self) -> str | None:
        """The thread's description, or None if unnamed; needs THREAD_QUERY_LIMITED_INFORMATION."""
        buf = ctypes.c_void_p()
        if (hr := winapi.GetThreadDescription(self.handle, ctypes.byref(buf))) < 0:
            raise OSError(f'GetThreadDescription failed: HRESULT {hr & 0xFFFFFFFF:#x}')
        try:
            return ctypes.wstring_at(buf.value) or None
        finally:
            winapi.LocalFree(buf)

    def creation_time(self) -> int:
        """Creation time as a FILETIME (100-ns ticks since 1601); raises OSError if the handle cannot be queried."""
        times = (ctypes.c_uint64 * 4)()
        winapi.GetThreadTimes(self.handle, *(ctypes.byref(times, i * 8) for i in range(4)))
        return times[0]

    def suspend(self):
        return winapi.SuspendThread(self.handle)

    def resume(self):
        return winapi.ResumeThread(self.handle)

    def close(self):
        if (handle := self.handle) is None: return
        self.handle = None
        winapi.CloseHandle(handle)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
