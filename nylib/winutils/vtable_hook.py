import ctypes
import struct

from .. import winapi
from .inline_hook import asm


_CAS_CODE = b'\x4C\x89\xC0\xF0\x48\x0F\xB1\x11\xC3'  # lock cmpxchg [rcx], rdx; return the previous pointer


class VTableHook:
    """Replace one x64 virtual function pointer with code that jumps to the original."""

    def __init__(self, process, code, addr: int, data_size=0):
        if not winapi.IS_64BIT: raise OSError('VTableHook requires a 64-bit host')
        wow64 = ctypes.c_long()
        winapi.IsWow64Process(process.handle, ctypes.byref(wow64))
        if wow64.value: raise OSError('VTableHook requires a 64-bit target')
        if addr & 7: raise ValueError('vtable slot address must be 8-byte aligned')
        mbi = process.virtual_query(addr)
        if mbi.State != 0x1000 or mbi.Protect & 0x100 or (mbi.Protect & 0xFF) not in (0x02, 0x04, 0x08, 0x20, 0x40, 0x80):
            raise ValueError(f'vtable slot {addr:#x} is not readable')
        original_at = process.read_ptr(addr)
        mbi = process.virtual_query(original_at)
        if mbi.State != 0x1000 or not mbi.Protect & 0xF0 or mbi.Protect & 0x100:
            raise ValueError(f'original virtual function {original_at:#x} is not executable')
        if not 0 <= data_size < 0x1000: raise ValueError('data_size must fit in one page')
        self.process = process
        self._source = code
        self.code = code if isinstance(code, bytes) else b''
        self.labels = {}
        self.addr = addr
        self.data_size = data_size
        self.original_at = original_at
        self.alloc_at = self._cas_at = 0
        self._enabled = False

    @property
    def data_at(self):
        self.alloc()
        return self.alloc_at + len(_CAS_CODE)

    @property
    def code_at(self):
        self.alloc()
        return self.alloc_at + len(_CAS_CODE) + self.data_size

    def alloc(self):
        if self.alloc_at: return
        jump = b'\xFF\x25\x00\x00\x00\x00' + struct.pack('<Q', self.original_at)
        alloc_at = self.process.alloc(0x1000, protect=0x04)
        try:
            body, labels = (self._source, {}) if isinstance(self._source, bytes) else asm(
                self._source, alloc_at + len(_CAS_CODE) + self.data_size, self.data_size)
            body = bytes(body)
            if len(_CAS_CODE) + self.data_size + len(body) + len(jump) > 0x1000:
                raise ValueError('hook code exceeds one page')
            generated = _CAS_CODE + b'\0' * self.data_size + body + jump
            self.process.write(alloc_at, generated)
            self.process.virtual_protect(alloc_at, 0x1000, 0x20)
            winapi.FlushInstructionCache(self.process.handle, alloc_at, len(generated))
        except BaseException:
            self.process.free(alloc_at)
            raise
        self.alloc_at = alloc_at
        self.code, self.labels = body, labels
        self._cas_at = alloc_at

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        if (value := bool(value)) == self._enabled: return
        self.alloc()
        expected = self.original_at if value else self.code_at
        replacement = self.code_at if value else self.original_at
        old = self.process.virtual_protect(self.addr, 8, 0x04)
        try:
            try:
                previous = self.process.call(self._cas_at, self.addr, replacement, expected)
            except BaseException:
                try:
                    current = self.process.read_ptr(self.addr)
                except BaseException:
                    self._enabled = True  # retain code when the slot state cannot be determined
                    raise
                self._enabled = current == self.code_at
                raise
            if previous != expected:
                if previous == self.code_at: self._enabled = True
                raise RuntimeError(f'vtable slot changed from expected {expected:#x} to {previous:#x}')
            self._enabled = value
        finally:
            self.process.virtual_protect(self.addr, 8, old)

    def free(self):
        if not self.alloc_at: return
        if self._enabled: self.enabled = False
        self.process.free(self.alloc_at)
        self.alloc_at = self._cas_at = 0

    def __del__(self):
        if getattr(self, 'alloc_at', 0): self.free()
