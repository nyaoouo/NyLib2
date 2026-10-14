"""Local and cross-process hosts for the PE image loader."""

import ctypes
import typing

from ... import winapi
from ...process import Process
from .contracts import ICrtGlue, IImageMemory, MapHost
from .core import ImagePlan, TlsPlan, UnsupportedImageError
from .loader import InstallTier, LoadedImage, MappedBlock, SectSkip, load as load_with_host


class _ProcessHostBase:
    def __init__(self, process: Process):
        self.process = process

    @classmethod
    def from_process(cls, process: Process):
        return cls(process)

    def as_host(self) -> MapHost:
        return MapHost(self, self, self, 0x8664, self)

    def alloc(self, size: int, preferred: int = 0) -> int:
        if preferred:
            try:
                return self.process.alloc(size, protect=0x04, address=preferred)
            except OSError:
                pass
        return self.process.alloc(size, protect=0x04)

    def free(self, address: int) -> None:
        self.process.free(address)

    def discard(self, address: int, size: int) -> None:
        self.process.free(address, size)

    def read(self, address: int, size: int) -> bytes:
        return self.process.read(address, size)

    def write(self, address: int, value: bytes) -> None:
        self.process.write(address, value)

    def protect(self, address: int, size: int, protection: int) -> None:
        self.process.virtual_protect(address, size, protection)

    def flush(self, address: int, size: int) -> None:
        winapi.FlushInstructionCache(self.process.handle, address, size)

    def acquire(self, name: str) -> object:
        self.process.get_ldr_data(name)
        return name

    def resolve(self, module: object, name: str | int) -> int:
        return self.process.get_proc_address(module, name)

    def base(self, module: object) -> int:
        return self.process.get_ldr_data(module).DllBase

    def release(self, module: object) -> None:
        pass

    def call(self, address: int, *args: int) -> int:
        return self.process.call(address, *args)


class LocalProcessHost(_ProcessHostBase):
    """Adapt ``Process.current`` to the memory, module, and runtime contracts."""

    supports_tls_process_callbacks = True
    supports_static_tls = False
    supports_tls_thread_lifecycle = False

    def __init__(self, process: Process):
        if process is not Process.current:
            raise ValueError('LocalProcessHost requires Process.current')
        super().__init__(process)

    def prepare_tls(self, base: int, plan: TlsPlan, memory: IImageMemory) -> object:
        if plan.template_size or plan.zero_fill:
            raise UnsupportedImageError('LocalProcessHost cannot install static TLS')
        index = winapi.TlsAlloc()
        try:
            memory.write(base + plan.index_rva, index.to_bytes(4, 'little'))
        except Exception:
            winapi.TlsFree(index)
            raise
        return index

    def release_tls(self, token: object) -> None:
        winapi.TlsFree(token)

    def register_unwind(self, base: int, table_rva: int, count: int) -> object:
        table = ctypes.cast(base + table_rva, ctypes.POINTER(winapi.RUNTIME_FUNCTION))
        winapi.RtlAddFunctionTable(table, count, base)
        return table

    def unregister_unwind(self, token: object) -> None:
        winapi.RtlDeleteFunctionTable(token)


class RemoteProcessHost(_ProcessHostBase):
    """Adapt an AMD64 target Process using its remote memory and call methods."""

    supports_tls_process_callbacks = False
    supports_static_tls = False
    supports_tls_thread_lifecycle = False

    def __init__(self, process: Process):
        if process.process_id == Process.current.process_id:
            raise ValueError('use Process.current for local mapping')
        wow64 = ctypes.c_long()
        winapi.IsWow64Process(process.handle, ctypes.byref(wow64))
        if wow64.value:
            raise UnsupportedImageError('remote process must be AMD64')
        super().__init__(process)

    def prepare_tls(self, base: int, plan: TlsPlan, memory: IImageMemory) -> object:
        raise UnsupportedImageError('RemoteProcessHost does not support TLS')

    def release_tls(self, token: object) -> None:
        raise UnsupportedImageError('RemoteProcessHost does not support TLS')

    def register_unwind(self, base: int, table_rva: int, count: int) -> object:
        table = base + table_rva
        address = self.process.get_proc_address('ntdll.dll', 'RtlAddFunctionTable')
        if not self.call(address, table, count, base):
            raise OSError('RtlAddFunctionTable failed in target process')
        return table

    def unregister_unwind(self, token: object) -> None:
        address = self.process.get_proc_address('ntdll.dll', 'RtlDeleteFunctionTable')
        if not self.call(address, token):
            raise OSError('RtlDeleteFunctionTable failed in target process')


def load(image_bytes: bytes | bytearray | memoryview, *, tier: InstallTier = InstallTier.MINIMAL,
         process: Process | None = None, host: LocalProcessHost | RemoteProcessHost | None = None,
         crt_glue: ICrtGlue | None = None, on_block: typing.Callable[[ImagePlan, MappedBlock], None] | None = None) -> LoadedImage:
    """Map a DLL using Process.current or a caller-owned remote Process."""
    if process is not None and host is not None:
        raise ValueError('pass either process or host, not both')
    if host is None:
        process = Process.current if process is None else process
        host = LocalProcessHost(process) if process is Process.current else RemoteProcessHost(process)
    return load_with_host(image_bytes, tier=tier, host=host.as_host(), crt_glue=crt_glue, on_block=on_block)
