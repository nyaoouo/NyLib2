"""Host contracts for mapping an image into an address space."""

import dataclasses
import typing

from .core import ImagePlan, TlsPlan


class IImageMemory(typing.Protocol):
    """Allocate a zero-filled writable region and own its memory operations."""

    def alloc(self, size: int, preferred: int = 0) -> int: ...
    def free(self, address: int) -> None: ...
    def read(self, address: int, size: int) -> bytes: ...
    def write(self, address: int, value: bytes) -> None: ...
    def protect(self, address: int, size: int, protection: int) -> None: ...
    def flush(self, address: int, size: int) -> None: ...


class IImageDiscard(typing.Protocol):
    """Decommit whole pages inside a mapped image."""

    def discard(self, address: int, size: int) -> None: ...


class IModuleResolver(typing.Protocol):
    """Acquire and release dependencies in the target address space."""

    def acquire(self, name: str) -> object: ...
    def resolve(self, module: object, name: str | int) -> int: ...
    def base(self, module: object) -> int: ...
    def release(self, module: object) -> None: ...


class IImageRuntime(typing.Protocol):
    """Invoke code and manage TLS/unwind state in the mapped image's context."""

    supports_tls_process_callbacks: bool
    supports_static_tls: bool
    supports_tls_thread_lifecycle: bool
    def call(self, address: int, *args: int) -> int: ...
    def prepare_tls(self, base: int, plan: TlsPlan, memory: IImageMemory) -> object: ...
    def release_tls(self, token: object) -> None: ...
    def register_unwind(self, base: int, table_rva: int, count: int) -> object: ...
    def unregister_unwind(self, token: object) -> None: ...


class ICrtGlue(typing.Protocol):
    """Initialize optional compiler-specific state around DLL attach/detach."""

    def prepare(self, plan: ImagePlan) -> object: ...
    def cleanup(self, plan: ImagePlan, token: object) -> None: ...


class NoopCrtGlue:
    def prepare(self, plan: ImagePlan) -> object:
        return None

    def cleanup(self, plan: ImagePlan, token: object) -> None:
        pass


@dataclasses.dataclass(frozen=True)
class MapHost:
    """Compose host roles that all operate on one target address space."""

    memory: IImageMemory
    modules: IModuleResolver
    runtime: IImageRuntime
    machine: int
    discarder: IImageDiscard | None = None
