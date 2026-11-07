"""Delete-sharing file handles with positional reads and stable file identities."""
import ctypes
import threading
import weakref
from ctypes import wintypes
from typing import NamedTuple

from nylib.winapi import BY_HANDLE_FILE_INFORMATION, OVERLAPPED, CloseHandle, CreateFile, GetFileInformationByHandle, ReadFile

__all__ = ['FileIdentity', 'file_identity', 'SharedFile']


class FileIdentity(NamedTuple):
    volume: int
    index: int
    size: int
    mtime: int


def _open(path, access):
    if not isinstance(path, str):
        raise TypeError('path must be a str')
    if not path or '\0' in path:
        raise ValueError('path must be nonempty and contain no NUL')
    return CreateFile(path, access, 1 | 2 | 4, None, 3, 0x80, None)


def _identity(handle):
    info = BY_HANDLE_FILE_INFORMATION()
    GetFileInformationByHandle(handle, ctypes.byref(info))
    return FileIdentity(info.dwVolumeSerialNumber, (info.nFileIndexHigh << 32) | info.nFileIndexLow,
                        (info.nFileSizeHigh << 32) | info.nFileSizeLow, (info.ftLastWriteTime.dwHighDateTime << 32) | info.ftLastWriteTime.dwLowDateTime)


def _close_handle(handle):
    CloseHandle(handle)


def file_identity(path: str) -> FileIdentity:
    """Return the current identity of a path without retaining a handle."""
    handle = _open(path, 0x80)  # FILE_READ_ATTRIBUTES
    try:
        return _identity(handle)
    finally:
        _close_handle(handle)


class _Handle:
    def __init__(self, handle):
        self.handle = handle
        self.lock = threading.Lock()
        self.users = 0
        self.closed = False

    def acquire(self):
        with self.lock:
            if self.closed:
                raise ValueError('the file is closed')
            self.users += 1
            return self.handle

    def release(self):
        with self.lock:
            self.users -= 1
            if self.closed and not self.users:
                handle, self.handle = self.handle, None
                _close_handle(handle)


def _close(state):
    with state.lock:
        state.closed = True
        if not state.users and state.handle is not None:
            handle, state.handle = state.handle, None
            _close_handle(handle)


class SharedFile:
    """Read a delete-sharing file by offset until explicitly closed or collected."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._state = _Handle(_open(path, 0x80000000))  # GENERIC_READ
        self._finalizer = weakref.finalize(self, _close, self._state)

    def identity(self) -> FileIdentity:
        handle = self._state.acquire()
        try:
            return _identity(handle)
        finally:
            self._state.release()

    def pread(self, offset: int, size: int) -> bytes:
        if not isinstance(offset, int) or isinstance(offset, bool) or not isinstance(size, int) or isinstance(size, bool):
            raise TypeError('offset and size must be ints')
        if offset < 0 or offset >= 2**63 or size < 0:
            raise ValueError('offset or size out of range')
        handle = self._state.acquire()
        try:
            if not size:
                return b''
            buf = ctypes.create_string_buffer(size)
            done = 0
            while done < size:
                position = offset + done
                amount = min(size - done, 1 << 30, 2**63 - 1 - position)
                if not amount:
                    break
                overlapped = OVERLAPPED(Offset=position & 0xFFFFFFFF, OffsetHigh=position >> 32)
                count = wintypes.DWORD()
                try:
                    ReadFile(handle, ctypes.byref(buf, done), amount, ctypes.byref(count), ctypes.byref(overlapped))
                except OSError as e:
                    if e.winerror == 38:  # ERROR_HANDLE_EOF
                        break
                    try:
                        at_eof = position >= _identity(handle).size
                    except OSError:
                        pass
                    else:
                        if at_eof:
                            break
                    raise
                if not count.value:
                    break
                done += count.value
            return buf.raw[:done]
        finally:
            self._state.release()

    def close(self) -> None:
        _close(self._state)
        self._finalizer.detach()

    def __enter__(self) -> 'SharedFile':
        return self

    def __exit__(self, *exc) -> None:
        self.close()
