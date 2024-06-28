import ctypes
import functools
import pathlib
import struct
import typing
from .namespace import Namespace
from ..pattern import CachedRawMemoryPatternScanner, StaticPatternSearcher

from .. import winapi, winutils

_T = typing.TypeVar('_T')


class Process:
    current: 'Process'

    def __init__(self, process_id: int, da=0x1F0FFF):
        self.process_id = process_id
        self.handle = winapi.OpenProcess(da, False, process_id)
        self._cached_scanners = {}
        self._ldr_cache = {}

    @classmethod
    def from_name(cls, name: str | bytes):
        if (pid := next(winutils.pid_by_executable(name), None)) is None:
            raise ValueError(f'Process {name!r} not found')
        return cls(pid)

    def alloc(self, size: int, protect=0x40, address=0):
        return winapi.VirtualAllocEx(self.handle, address, size, 0x1000 | 0x2000, protect)  # MEM_COMMIT|MEM_RESERVE

    def free(self, address: int, size: int):
        return winapi.VirtualFreeEx(self.handle, address, size, 0x4000)  # MEM_DECOMMIT

    def virtual_query(self, address: int):
        winapi.VirtualQueryEx(self.handle, address, ctypes.byref(mbi := winapi.MEMORY_BASIC_INFORMATION()), ctypes.sizeof(mbi))
        return mbi

    def virtual_protect(self, address: int, size: int, protect: int):
        return winapi.VirtualProtectEx(self.handle, address, size, protect, ctypes.byref(ctypes.c_ulong()))

    def iter_memory_region(self, start=0, end=None):
        pos = start
        while mbi := self.virtual_query(pos):
            yield mbi
            next_addr = mbi.BaseAddress + mbi.RegionSize
            if pos >= next_addr or end is not None and end < next_addr: break
            pos = next_addr

    def alloc_near(self, size: int, address, protect=0x40):
        for mbi in self.iter_memory_region(max(address - 0x7fff0000, 0), address + 0x7fff0000):
            if mbi.State & 0x10000:  # MEM_FREE
                pos = (mbi.BaseAddress + 0xffff) & ~0xffff
                if mbi.RegionSize - (pos - mbi.BaseAddress) >= size:
                    return self.alloc(size, protect, pos)
        raise ValueError("No suitable memory region")

    def read(self, address, type_: typing.Type[_T] | int) -> _T:
        if isinstance(type_, int):
            value = (ctypes.c_ubyte * type_)()
            try:
                winapi.ReadProcessMemory(self.handle, address, ctypes.byref(value), type_, None)
            except WindowsError as e:
                if e.winerror != 299: raise
            return bytes(value)
        value = type_()
        winapi.ReadProcessMemory(self.handle, address, ctypes.byref(value), ctypes.sizeof(value), None)
        return value

    def write(self, address, value):
        if isinstance(value, (bytes, bytearray)):
            if isinstance(value, bytes): value = bytearray(value)
            size = len(value)
            value = (ctypes.c_ubyte * size).from_buffer(value)
        size = ctypes.sizeof(value)
        winapi.WriteProcessMemory(self.handle, address, ctypes.byref(value), size, None)
        return size

    def read_i8(self, address: int) -> int:
        return self.read(address, ctypes.c_byte).value

    def read_i16(self, address: int) -> int:
        return self.read(address, ctypes.c_short).value

    def read_i32(self, address: int) -> int:
        return self.read(address, ctypes.c_int).value

    def read_i64(self, address: int) -> int:
        return self.read(address, ctypes.c_longlong).value

    def read_i128(self, address: int) -> int:
        return int.from_bytes(self.read(address, 16), 'little')

    def read_u8(self, address: int) -> int:
        return self.read(address, ctypes.c_ubyte).value

    def read_u16(self, address: int) -> int:
        return self.read(address, ctypes.c_ushort).value

    def read_u32(self, address: int) -> int:
        return self.read(address, ctypes.c_uint).value

    def read_u64(self, address: int) -> int:
        return self.read(address, ctypes.c_ulonglong).value

    def read_u128(self, address: int) -> int:
        return int.from_bytes(self.read(address, 16), 'little')

    def read_float(self, address: int) -> float:
        return self.read(address, ctypes.c_float).value

    def read_double(self, address: int) -> float:
        return self.read(address, ctypes.c_double).value

    def write_i8(self, address: int, value: int):
        return self.write(address, ctypes.c_byte(value))

    def write_i16(self, address: int, value: int):
        return self.write(address, ctypes.c_short(value))

    def write_i32(self, address: int, value: int):
        return self.write(address, ctypes.c_int(value))

    def write_i64(self, address: int, value: int):
        return self.write(address, ctypes.c_longlong(value))

    def write_i128(self, address: int, value: int):
        return self.write(address, value.to_bytes(16, 'little'))

    def write_u8(self, address: int, value: int):
        return self.write(address, ctypes.c_ubyte(value))

    def write_u16(self, address: int, value: int):
        return self.write(address, ctypes.c_ushort(value))

    def write_u32(self, address: int, value: int):
        return self.write(address, ctypes.c_uint(value))

    def write_u64(self, address: int, value: int):
        return self.write(address, ctypes.c_ulonglong(value))

    def write_u128(self, address: int, value: int):
        return self.write(address, value.to_bytes(16, 'little'))

    def write_float(self, address: int, value: float):
        return self.write(address, ctypes.c_float(value))

    def write_double(self, address: int, value: float):
        return self.write(address, ctypes.c_double(value))

    def read_ptr(self, address: int):
        return self.read(address, ctypes.c_size_t).value

    def write_ptr(self, address: int, value: int):
        return self.write(address, ctypes.c_size_t(value))

    def still_alive(self):
        exit_code = ctypes.c_ulong()
        winapi.GetExitCodeProcess(self.handle, ctypes.byref(exit_code))
        return exit_code.value == 259

    def read_bytes_zero_trim_unk_size(self, address: int, chunk_size=0x100):
        mbi = self.virtual_query(address)
        max_addr = mbi.BaseAddress + mbi.RegionSize
        buf = bytearray()
        while address < max_addr:
            read_size = min(chunk_size, max_addr - address)
            _buf = self.read(address, read_size)
            if (sep := _buf.find(b'\0')) >= 0:
                buf.extend(_buf[:sep])
                break
            buf.extend(_buf)
            address += read_size
        return bytes(buf)

    def read_bytes_zero_trim(self, address: int, max_size: int = 0):
        if max_size == 0:
            return self.read_bytes_zero_trim_unk_size(address)
        res = self.read(address, max_size)
        if (sep := res.find(b'\0')) >= 0:
            return res[:sep]
        return res

    def read_string(self, address: int, max_size: int = 0, encoding='utf-8', errors='ignore'):
        return self.read_bytes_zero_trim(address, max_size).decode(encoding, errors)

    def write_string(self, address: int, value: str | bytes, encoding='utf-8'):
        if isinstance(value, str): value = value.encode(encoding)
        return self.write(address, value)

    def enum_ldr_data(self):
        pbi = winapi.PROCESS_BASIC_INFORMATION()
        winapi.NtQueryInformationProcess(self.handle, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None)
        peb = self.read(pbi.PebBaseAddress, winapi.PEB)
        ldr = self.read(peb.Ldr, winapi.PEB_LDR_DATA)
        p_data = p_end = ldr.InMemoryOrderModuleList.Flink
        offset = winapi.LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks.offset
        while True:
            data = self.read(p_data - offset, winapi.LDR_DATA_TABLE_ENTRY)
            if data.DllBase:
                yield data
            p_data = data.InMemoryOrderLinks.Flink
            if p_data == p_end: break

    @functools.cached_property
    def base_ldr_data(self):
        return next(self.enum_ldr_data())

    def get_ldr_data(self, dll_name: str, rescan=False):
        dll_name = dll_name.lower()
        if dll_name in self._ldr_cache and not rescan:
            return self._ldr_cache[dll_name]
        self._ldr_cache.pop(dll_name, None)
        for data in self.enum_ldr_data():
            if data.BaseDllName.remote_value(self).lower() == dll_name:
                self._ldr_cache[dll_name] = data
                return data
        raise KeyError(f'dll {dll_name!r} not found')

    def scanner(self, dll_name: str, force_new=False) -> 'CachedRawMemoryPatternScanner':
        if dll_name not in self._cached_scanners or force_new:
            for data in self.enum_ldr_data():
                if data.BaseDllName.remote_value(self) == dll_name:
                    self._cached_scanners[dll_name] = CachedRawMemoryPatternScanner(self, data.DllBase, data.SizeOfImage)
                    break
            else:
                raise KeyError(f'dll {dll_name!r} not found')
        return self._cached_scanners[dll_name]

    def static_scanner(self, dll_name) -> 'StaticPatternSearcher':
        for data in self.enum_ldr_data():
            if data.BaseDllName.remote_value(self) == dll_name:
                return StaticPatternSearcher(data.FullDllName.remote_value(self), data.DllBase)
        raise KeyError(f'dll {dll_name!r} not found')

    def base_scanner(self, force_new=False):
        return self.scanner(self.base_ldr_data.BaseDllName.remote_value(self), force_new)

    def base_static_scanner(self):
        return self.static_scanner(self.base_ldr_data.BaseDllName.remote_value(self))

    def get_proc_address(self, dll: str | int, func_name: str):
        if isinstance(func_name, str): func_name = func_name.encode('utf-8')
        if isinstance(dll, str): dll = self.get_ldr_data(dll).DllBase
        return winapi.GetProcAddress(dll, func_name)

    def name_space(self):
        return Namespace(self)

    def load_library(self, filepath):
        if isinstance(filepath, pathlib.Path): filepath = str(filepath)
        if isinstance(filepath, str): filepath = filepath.encode(winapi.DEFAULT_ENCODING)
        with self.name_space() as name_space:
            result_at = name_space.take(0x10)
            shell = (
                    b"\x55"  # push rbp
                    b"\x48\x89\xe5"  # mov rbp, rsp
                    b"\x48\x83\xec\x28"  # sub rsp, 0x28
                    b"\x53"  # push rbx
                    b"\x48\xbb" + struct.pack('<Q', result_at) +  # movabs rbx, result_at
                    b"\x48\xb8" + struct.pack('<Q', self.get_proc_address('kernel32.dll', "LoadLibraryA")) +  # movabs rax, LoadLibraryA
                    b"\x48\xb9" + struct.pack('<Q', name_space.store(filepath + b'\0')) +  # movabs rcx, filepath
                    b"\xff\xd0"  # call rax
                    b"\x48\x85\xc0"  # test rax, rax
                    b"\x74\x0c"  # je fail
                    b"\x48\x89\x43\x08"  # mov qword ptr [rbx + 8], rax
                    b"\x48\x31\xc0"  # xor rax, rax
                    b"\x48\x89\x03"  # mov qword ptr [rbx], rax
                    b"\xeb\x16"  # jmp end
                    # fail:
                    b"\x48\xb8" + struct.pack('<Q', self.get_proc_address('kernel32.dll',
                                                                          "GetLastError")) +  # movabs rax, GetLastError
                    b"\xff\xd0"  # call rax
                    b"\x48\x89\x03"  # mov qword ptr [rbx], rax
                    b"\x48\x31\xc0"  # xor rax, rax
                    b"\x48\x89\x43\x08"  # mov qword ptr [rbx + 8], rax
                    # end:
                    b"\x5b"  # pop rbx
                    b"\x48\x83\xc4\x28"  # add rsp, 0x28
                    b"\x5d"  # pop rbp
                    b"\xc3"  # ret
            )
            self._call(name_space.store(shell), block=True)
            if err := self.read_u32(result_at): raise ctypes.WinError(err)
            return self.read_u64(result_at + 8)

    def _call(self, call_address, params=None, block=True):
        params = params or 0
        thread_h = winapi.CreateRemoteThread(self.handle, None, 0, call_address, params, 0, None)
        if block: winapi.WaitForSingleObject(thread_h, -1)
        return thread_h

    def call(self, func_ptr, *args: int | float | bytes | bool, push_stack_depth=0x28, block=True):
        _MOV_RBX = b'\x48\xBB'  # MOV rbx, n
        _INT_ARG = (
            b'\x48\xB9',  # MOV rcx, n
            b'\x48\xBA',  # MOV rdx, n
            b'\x49\xB8',  # MOV r8, n
            b'\x49\xB9',  # MOV r9, n
        )
        _FLOAT_ARG = (
            b'\xF3\x0F\x10\x03',  # MOVSS xmm0, [rbx]
            b'\xF3\x0F\x10\x0B',  # MOVSS xmm1, [rbx]
            b'\xF3\x0F\x10\x13',  # MOVSS xmm2, [rbx]
            b'\xF3\x0F\x10\x1B',  # MOVSS xmm3, [rbx]
        )

        if len(args) > 4:
            raise ValueError('not yet handle args more then 4')
        with self.name_space() as name_space:
            return_address = name_space.take(8)
            shell = (
                    b"\x55"  # PUSH rbp
                    b"\x48\x89\xE5"  # MOV rbp, rsp
                    b"\x48\x83\xec" + struct.pack('B', push_stack_depth) +  # SUB rsp, push_stack_depth
                    b"\x53"  # PUSH rbx
                    b"\x48\x31\xDB"  # XOR rbx, rbx
            )
            for i, a in enumerate(args):
                if isinstance(a, bytes):
                    a = name_space.store(a)
                elif isinstance(a, bool):
                    a = int(a)
                if isinstance(a, int):
                    shell += _INT_ARG[i] + struct.pack('q', a)
                elif isinstance(a, float):
                    shell += _MOV_RBX + struct.pack('f', a) + bytes(4) + _FLOAT_ARG[i]
                else:
                    raise TypeError(f'not support arg type {type(a)} at pos {i}')
            shell += (
                    b"\x48\xBB" + struct.pack('q', func_ptr) +  # MOV rbx, func_ptr
                    b"\xFF\xD3"  # CALL rbx
                    b"\x48\xBB" + struct.pack('q', return_address) +  # MOV rbx, return_address
                    b"\x48\x89\x03"  # MOV [rbx], rax
                    b"\x5B"  # POP rbx
                    b"\x48\x83\xc4" + struct.pack('B', push_stack_depth) +  # ADD rsp, 0x28
                    b"\x48\x89\xEC"  # MOV rsp, rbp
                    b"\x5D"  # POP rbp
                    b"\xC3"  # RET
            )
            code_address = name_space.store(shell)
            self._call(code_address, block=block)
            return self.read_u64(return_address)

    @functools.cache
    def _get_pyfunc_offset(self, func_name):
        c = Process.current
        ldr = c.get_ldr_data(PYTHON_DLL)
        base = ldr.DllBase
        return c.get_proc_address(base, func_name) - base

    def get_python_base(self, auto_inject=False):
        try:
            return self.get_ldr_data(PYTHON_DLL).DllBase
        except KeyError:
            if auto_inject:
                base = self.load_library(Process.current.get_ldr_data(PYTHON_DLL).FullDllName.value)
                self.call(base + self._get_pyfunc_offset("Py_Initialize"), 1, push_stack_depth=0x58)
                return base
            raise

    def exec_shell_code(self, code: str, p_dict=None, auto_inject=False):
        py_base = self.get_python_base(auto_inject)
        need_decref = False
        if p_dict is None:
            p_dict = self.call(py_base + self._get_pyfunc_offset("PyDict_New"))
            need_decref = True

        with tempfile.NamedTemporaryFile('w', encoding='utf-8', delete=False) as f:
            f.write(code)
            f.close()
            res = self.call(py_base + self._get_pyfunc_offset("PyRun_String"),
                            f'with open({f.name!r},encoding="utf-8") as f:exec(f.read())'.encode('utf-8'), 0x101,
                            p_dict, p_dict)

        if not res:
            if error_occurred := self.call(py_base + self._get_pyfunc_offset("PyErr_Occurred")):
                type_name = self.read_string(self.read_ptr(error_occurred + 0x18))
                with self.name_space() as ns:
                    p_data = ns.take(0x18)
                    self.call(py_base + self._get_pyfunc_offset("PyErr_Fetch"), p_data, p_data + 0x8, p_data + 0x10)
                    exc_val = self.read_ptr(p_data + 0x8)
                    desc = None
                    if exc_val:
                        py_str = self.call(py_base + self._get_pyfunc_offset("PyObject_Str"), exc_val)
                        str_size = ns.take(8)
                        if p_str := self.call(py_base + self._get_pyfunc_offset("PyUnicode_AsUTF8AndSize"), py_str,
                                              str_size):
                            desc = self.read_string(p_str, self.read_u64(str_size))
                            # decref(py_str)
                        # decref(exc_val)
                    # decref(error_occurred)
                    if desc:
                        raise RuntimeError(f"Exception in shell: {type_name}: {desc}")
                    else:
                        raise RuntimeError(f"Exception in shell: {type_name}")
            else:
                raise RuntimeError(f"Exception in shell but no error occurred")
        else:
            pass  # decref(res)
        if need_decref:
            pass  # decref(p_dict)

    @functools.cached_property
    def injector(self):
        return self.Injector(self)


Process.current = Process(winapi.GetCurrentProcessId())
