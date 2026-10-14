"""Current-process host for the PE image loader."""

import ctypes

from ... import winapi
from ...process import Process
from .contracts import ICrtGlue, IImageMemory, MapHost
from .core import TlsPlan, UnsupportedImageError
from .loader import InstallTier, LoadedImage, load as load_with_host


class LocalProcessHost:
    """Adapt ``Process.current`` to the memory, module, and runtime contracts."""

    supports_static_tls = False
    supports_tls_thread_lifecycle = False

    def __init__(self, process: Process):
        if process is not Process.current:
            raise ValueError('LocalProcessHost requires Process.current')
        self.process = process

    @classmethod
    def from_process(cls, process: Process) -> 'LocalProcessHost':
        return cls(process)

    def as_host(self) -> MapHost:
        return MapHost(self, self, self, 0x8664)

    def alloc(self, size: int, preferred: int = 0) -> int:
        if preferred:
            try:
                return self.process.alloc(size, protect=0x04, address=preferred)
            except OSError:
                pass
        return self.process.alloc(size, protect=0x04)

    def free(self, address: int) -> None:
        self.process.free(address)

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


def load(image_bytes: bytes | bytearray | memoryview, *, tier: InstallTier = InstallTier.MINIMAL,
         host: LocalProcessHost | None = None, crt_glue: ICrtGlue | None = None) -> LoadedImage:
    """Map a DLL into the current process using the local Process adapter."""
    host = host or LocalProcessHost.from_process(Process.current)
    return load_with_host(image_bytes, tier=tier, host=host.as_host(), crt_glue=crt_glue)
