from .. import winapi


class Thread:
    """Own a thread handle; close it explicitly or use it as a context manager."""

    def __init__(self, thread_id: int, handle=None, da=0x1FFFFF):
        self.thread_id = thread_id
        self.handle = winapi.OpenThread(da, False, thread_id) if handle is None else handle

    @property
    def process_id(self) -> int:
        return winapi.GetProcessIdOfThread(self.handle)

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
