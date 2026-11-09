import codecs
import ctypes
import struct
import typing

from .. import winapi

_size: int = 0x100000


class ThreadRecord(typing.NamedTuple):
    thread_id: int
    creation_time: int


class ProcessRecord(typing.NamedTuple):
    process_id: int
    parent_process_id: int
    name: str
    session_id: int
    creation_time: int
    thread_count: int
    base_priority: int


class Snapshot:
    def __init__(self, size: int | None = None):
        global _size
        n = min(max(0x1000, _size if size is None else size), 0xFFFFFFFF)
        for _ in range(8):
            buffer = ctypes.create_string_buffer(n)
            length = ctypes.c_ulong()
            status = winapi.NtQuerySystemInformation(5, buffer, n, ctypes.byref(length), _ignore_error=True)
            if status == 0: break
            if status != 0xC0000004: raise OSError(f'NtStatus: {status:#x}')
            n = min(length.value + 0x10000, 0xFFFFFFFF)
        else:
            raise OSError(f'NtStatus: {status:#x}')
        self.size = n
        _size = max(_size, n)
        self._processes = []
        self._threads = []
        base, limit = ctypes.addressof(buffer), min(n, length.value)
        o = 0
        if not limit: return
        while True:
            if o + 0x100 > limit: raise OSError('truncated process snapshot')
            following, count = struct.unpack_from('<II', buffer, o)
            end = o + following if following else limit
            if end < o + 0x100 or end > limit: raise OSError('truncated process snapshot')
            if count * 0x50 > end - o - 0x100: raise OSError('truncated thread snapshot')
            name_length = struct.unpack_from('<H', buffer, o + 0x38)[0]
            if name_length:
                r = struct.unpack_from('<Q', buffer, o + 0x40)[0] - base
                m = name_length & ~1
                if r < 0 or r + m > limit: raise OSError('truncated process snapshot')
                name = codecs.utf_16_le_decode(buffer[r:r + m], 'surrogatepass', True)[0]
            else:
                name = '[System Process]'
            pid, parent = struct.unpack_from('<QQ', buffer, o + 0x50)
            creation_time = struct.unpack_from('<Q', buffer, o + 0x20)[0]
            session = struct.unpack_from('<I', buffer, o + 0x64)[0]
            priority = struct.unpack_from('<i', buffer, o + 0x48)[0]
            self._processes.append(ProcessRecord(pid, parent, name, session, creation_time, count, priority))
            self._threads.append([ThreadRecord(struct.unpack_from('<Q', buffer, o + 0x130 + i * 0x50)[0],
                                               struct.unpack_from('<Q', buffer, o + 0x110 + i * 0x50)[0]) for i in range(count)])
            if not following: break
            o = end

    def processes(self) -> list[ProcessRecord]:
        return list(self._processes)

    def threads(self, process_id: int) -> list[ThreadRecord]:
        for record, threads in zip(self._processes, self._threads):
            if record.process_id == process_id: return list(threads)
        return []
