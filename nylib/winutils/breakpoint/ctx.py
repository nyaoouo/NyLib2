"""Live view over a kernel CONTEXT pointer."""

from __future__ import annotations

import ctypes
import typing

# AMD64 CONTEXT structure - stable Win32 ABI. Offsets from winnt.h.
CONTEXT_REG_OFFSETS: dict[str, int] = {
    "rax": 0x78,
    "rcx": 0x80,
    "rdx": 0x88,
    "rbx": 0x90,
    "rsp": 0x98,
    "rbp": 0xA0,
    "rsi": 0xA8,
    "rdi": 0xB0,
    "r8":  0xB8,
    "r9":  0xC0,
    "r10": 0xC8,
    "r11": 0xD0,
    "r12": 0xD8,
    "r13": 0xE0,
    "r14": 0xE8,
    "r15": 0xF0,
    "rip": 0xF8,
}
# EFlags is a uint32 at offset 0x44 in the AMD64 CONTEXT.
EFLAGS_OFFSET = 0x44


def _make_reg64(name: str, offset: int):
    def fget(self: "BpCtx") -> int:
        self._check_valid()
        return ctypes.c_uint64.from_address(self._addr + offset).value

    def fset(self: "BpCtx", value: int) -> None:
        self._check_valid()
        ctypes.c_uint64.from_address(self._addr + offset).value = int(value) & ((1 << 64) - 1)

    fget.__name__ = name
    fset.__name__ = name
    return property(fget, fset)


def _make_reg32_alias(name: str, full_name: str):
    offset = CONTEXT_REG_OFFSETS[full_name]

    def fget(self: "BpCtx") -> int:
        self._check_valid()
        return ctypes.c_uint64.from_address(self._addr + offset).value & 0xFFFFFFFF

    def fset(self: "BpCtx", value: int) -> None:
        self._check_valid()
        addr = self._addr + offset
        old = ctypes.c_uint64.from_address(addr).value
        ctypes.c_uint64.from_address(addr).value = (old & 0xFFFFFFFF_00000000) | (int(value) & 0xFFFFFFFF)

    fget.__name__ = name
    fset.__name__ = name
    return property(fget, fset)


class BpCtx:
    """Live view over the trapping thread's CONTEXT record.

    Valid only inside the user callback. The dispatcher invalidates the view
    immediately after the callback returns; subsequent attribute access raises
    RuntimeError instead of corrupting memory.
    """

    __slots__ = ("_addr", "_valid", "bp", "address", "tid", "frm", "_disable_once_pending")

    def __init__(
        self,
        *,
        context_addr: int,
        bp: typing.Any,
        address: int,
        tid: int,
        frm: int,
    ):
        self._addr = int(context_addr)
        self._valid = True
        self.bp = bp
        self.address = int(address)
        self.tid = int(tid)
        self.frm = int(frm)
        self._disable_once_pending = False

    def _check_valid(self) -> None:
        if not self._valid:
            raise RuntimeError("BpCtx is no longer valid")

    def _invalidate(self) -> None:
        self._valid = False
        self._addr = 0

    # ----- eflags + regs snapshot -----

    @property
    def eflags(self) -> int:
        self._check_valid()
        return ctypes.c_uint32.from_address(self._addr + EFLAGS_OFFSET).value

    @eflags.setter
    def eflags(self, value: int) -> None:
        self._check_valid()
        ctypes.c_uint32.from_address(self._addr + EFLAGS_OFFSET).value = int(value) & 0xFFFFFFFF

    @property
    def regs(self) -> dict[str, int]:
        self._check_valid()
        snap = {
            name: ctypes.c_uint64.from_address(self._addr + off).value
            for name, off in CONTEXT_REG_OFFSETS.items()
        }
        snap["eflags"] = ctypes.c_uint32.from_address(self._addr + EFLAGS_OFFSET).value
        return snap

    # ----- stack / memory -----

    @staticmethod
    def _is_readable(addr: int, size: int) -> bool:
        if addr == 0 or size == 0:
            return False
        from ...winapi.defs import MEMORY_BASIC_INFORMATION
        mbi = MEMORY_BASIC_INFORMATION()
        kernel32 = ctypes.windll.kernel32
        n = kernel32.VirtualQuery(
            ctypes.c_void_p(addr),
            ctypes.byref(mbi),
            ctypes.c_size_t(ctypes.sizeof(mbi)),
        )
        if n == 0:
            return False
        if mbi.State != 0x1000:                     # MEM_COMMIT
            return False
        # PAGE_NOACCESS=0x01, PAGE_GUARD=0x100
        if mbi.Protect & 0x101:
            return False
        return True

    def _stack_at(self, *, rsp: int, n: int, offset: int) -> list[int]:
        n = max(0, int(n))
        out: list[int] = []
        for i in range(n):
            addr = rsp + offset + i * 8
            if self._is_readable(addr, 8):
                out.append(ctypes.c_uint64.from_address(addr).value)
            else:
                out.append(0)
        return out

    def stack(self, n: int = 16, offset: int = 0) -> list[int]:
        self._check_valid()
        return self._stack_at(rsp=self.rsp, n=n, offset=offset)

    def read(self, addr: int, size: int) -> bytes:
        from ...process import Process
        return Process.current.read(addr, size)

    def write(self, addr: int, data: bytes) -> int:
        from ...process import Process
        Process.current.write(addr, data)
        return len(data)

    # ----- control helpers -----

    def skip(self, n_bytes: int) -> None:
        self.rip = self.rip + int(n_bytes)

    def disable_once(self) -> None:
        # Marker consumed by the backend after the callback returns; v1 noop
        # (documented as such in the module docstring).
        self._disable_once_pending = True


# attach register descriptors
for _name, _off in CONTEXT_REG_OFFSETS.items():
    setattr(BpCtx, _name, _make_reg64(_name, _off))

for _short, _full in (
    ("eax", "rax"), ("ebx", "rbx"), ("ecx", "rcx"), ("edx", "rdx"),
    ("esi", "rsi"), ("edi", "rdi"), ("ebp", "rbp"), ("esp", "rsp"),
):
    setattr(BpCtx, _short, _make_reg32_alias(_short, _full))
