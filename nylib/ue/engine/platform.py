"""Platform layer: PlatformWindows + Architecture_x86_64 + Utils.h of Dumper-7 @ ea0dab3, over MemorySource/PeImage/Scanner."""
import bisect
import re

from ..errors import PeFormatError
from ..memory import MemorySource
from ..pe import IMAGE_SCN_MEM_READ, PeImage, Section
from ..scan import Scanner

_NEVER = b'[^\x00-\xff]'  # a byte class no actual byte can satisfy


def align(size: int, alignment: int) -> int:
    """TmpUtils.h Align @ ea0dab3."""
    required = alignment - (size % alignment)
    return size + (required if required != alignment else 0)


def str_to_lower(text: str) -> str:
    """TmpUtils.h Utils::StrToLower @ ea0dab3 (ASCII)."""
    return ''.join(chr(ord(c) + 32) if 'A' <= c <= 'Z' else c for c in text)


def _aligned_size_with_offset_from_end(size_to_align: int, alignment: int, offset_from_end: int) -> int:
    """PlatformWindows.cpp GetAlignedSizeWithOffsetFromEnd @ ea0dab3 (uint32 arithmetic); -1 on underflow."""
    value_to_align = (size_to_align - (alignment - 1) - offset_from_end) & 0xFFFFFFFF
    if value_to_align > size_to_align:
        return -1
    return align(value_to_align, alignment)


def _search_start_and_range(image: PeImage, section: Section, start_address: int, range_: int) -> tuple[int, int]:
    """PlatformWindows.cpp GetSearchStartAndRangeBasedOnOverrides @ ea0dab3."""
    if image.rva(section.address) == 0 or section.size == 0:
        return 0, 0
    section_start, section_end = section.address, section.address + section.size
    search_range = range_ if 0 < range_ < section.size else section.size
    search_start = section_start
    if start_address != 0 and start_address > section_start:
        if start_address >= section_end:
            return 0, 0
        search_start = start_address
        search_range = section_end - start_address
    return search_start, search_range


def _pattern_values(signature) -> list[int]:
    """PlatformWindows.cpp FindPatternInRange's PatternToByte @ ea0dab3."""
    if isinstance(signature, str):
        return [-1 if tok[0] == '?' else int(tok, 16) for tok in signature.split()]
    return list(signature)


def _compile_pattern(signature) -> tuple[re.Pattern, int]:
    """PatternToByte compiled to a bytes regex (A2)."""
    values = _pattern_values(signature)
    parts = [b'.' if v == -1 else re.escape(bytes([v])) if 0 <= v <= 255 else _NEVER for v in values]
    return re.compile(b''.join(parts), re.DOTALL), len(values)


class Platform:
    """PlatformWindows + Architecture_x86_64 + Utils.h of Dumper-7 @ ea0dab3 over a MemorySource."""

    def __init__(self, source: MemorySource):
        self.source = source
        self.image = PeImage(source, source.main_module.base)
        self.scanner = Scanner(source, self.image)

    # -- general interface --------------------------------------------------

    def get_module_base(self) -> int:
        """PlatformWindows::GetModuleBase(nullptr) @ ea0dab3."""
        return self.image.base

    def get_image_base_and_size(self) -> tuple[int, int]:
        """GetImageBaseAndSize @ ea0dab3."""
        return self.image.base, self.image.size

    def get_offset(self, address: int) -> int:
        """PlatformWindows::GetOffset @ ea0dab3."""
        return address - self.image.base

    def get_section_info(self, name: str) -> Section | None:
        """PlatformWindows::GetSectionInfo @ ea0dab3."""
        for s in self.image.sections:
            if s.name == name and s.characteristics & IMAGE_SCN_MEM_READ:
                return s
        return None

    def iterate_section_with_callback(self, section: Section | None, callback, granularity: int = 4,
                                       offset_from_end: int = 0, *, candidates=None) -> int:
        """PlatformWindows::IterateSectionWithCallback @ ea0dab3 (A1)."""
        if section is None:
            return 0
        size = _aligned_size_with_offset_from_end(section.size, granularity, offset_from_end)
        if size == -1:
            return 0
        base, end = section.address, section.address + size
        if candidates is None:
            addr = base
            while addr < end:
                if callback(addr):
                    return addr
                addr += granularity
            return 0
        seen = set()
        for chunk_addr, data in self.scanner.chunks(section):
            for addr in candidates(chunk_addr, data):
                if not (chunk_addr <= addr < chunk_addr + len(data)):
                    continue
                if addr < base or addr >= end or (addr - base) % granularity != 0:
                    continue
                seen.add(addr)
        for addr in sorted(seen):
            if callback(addr):
                return addr
        return 0

    def iterate_all_sections_with_callback(self, callback, granularity: int = 4, offset_from_end: int = 0, *,
                                            candidates=None) -> int:
        """PlatformWindows::IterateAllSectionsWithCallback @ ea0dab3."""
        for section in self.image.sections:
            if not (section.characteristics & IMAGE_SCN_MEM_READ):
                continue
            result = self.iterate_section_with_callback(section, callback, granularity, offset_from_end, candidates=candidates)
            if result:
                return result
        return 0

    def is_address_in_any_module(self, address: int) -> bool:
        """PlatformWindows::IsAddressInAnyModule @ ea0dab3 (K7)."""
        for m in self.source.modules()[:88]:  # Ldr->Length == 0x58 list entries
            if m.base < address < m.base + m.size:
                return True
        return False

    def is_address_in_process_range(self, address: int) -> bool:
        """PlatformWindows::IsAddressInProcessRange @ ea0dab3."""
        if self.image.base <= address < self.image.base + self.image.size:
            return True
        return self.is_address_in_any_module(address)

    def is_bad_read_ptr(self, address: int) -> bool:
        """PlatformWindows::IsBadReadPtr @ ea0dab3 (K8, K13)."""
        if not self.is_valid_64_bit_virtual_address(address):
            return True
        return not self.source.readable(address, 1)

    def get_address_of_imported_function_from_any_module(self, dll: str, name: str) -> int:
        """PlatformWindows::GetAddressOfImportedFunctionFromAnyModule + GetImportAddress @ ea0dab3 (DV11)."""
        wanted_dll = dll.lower()
        for m in self.source.modules()[:88]:
            try:
                image = PeImage(self.source, m.base)
            except PeFormatError:
                continue
            for slot in image.imports():
                if slot.dll == wanted_dll and slot.name == name:
                    return slot.value
        return 0

    def iterate_vtable_functions(self, vtable: int, callback, *, resolve_jumps: bool = True) -> tuple[int, int]:
        """PlatformWindows::IterateVTableFunctions<true> @ ea0dab3."""
        for i in range(0x150):
            func_address = self.source.ptr(vtable + 8 * i)
            if func_address == 0 or not self.is_address_in_process_range(func_address):
                break
            resolved = func_address
            if resolve_jumps and self.source.u8(func_address) == 0xE9:
                target = func_address + 5 + self.source.i32(func_address + 1)
                if self.is_address_in_process_range(target):
                    resolved = target
            if callback(resolved, i):
                return resolved, i
        return 0, -1

    # -- pattern and string scanning -----------------------------------------

    def find_pattern(self, signature, offset: int = 0, search_all_sections: bool = False, start_address: int = 0) -> int:
        """PlatformWindows::FindPattern @ ea0dab3."""
        if search_all_sections:
            for section in self.image.sections:
                if not (section.characteristics & IMAGE_SCN_MEM_READ):
                    continue
                search_start, search_range = _search_start_and_range(self.image, section, start_address, 0)
                if search_start == 0 or search_range == 0:
                    continue
                result = self.find_pattern_in_range(signature, search_start, search_range, offset != 0, offset)
                if result:
                    return result
            return 0
        section = self.get_section_info('.text')
        if section is None:
            return 0
        return self.find_pattern_in_range(signature, section.address, section.size, offset != 0, offset)

    def find_pattern_in_range(self, signature, start: int, range_: int, relative: bool = False, offset: int = 0) -> int:
        """PlatformWindows::FindPatternInRange (both overloads) @ ea0dab3 (A2)."""
        pattern, length = _compile_pattern(signature)
        endpos = range_ - 1
        if endpos <= 0:
            return 0
        data = self.source.read(start, range_)
        m = pattern.search(data, 0, endpos)
        if m is None:
            return 0
        address = start + m.start()
        if relative:
            eff_offset = length if offset == -1 else offset
            address = address + eff_offset + 4 + self.source.i32(address + eff_offset)
        return address

    def find_by_string_in_all_sections(self, text: str, *, wide: bool, start_address: int = 0, range_: int = 0,
                                        only_executable: bool = True) -> int:
        """PlatformWindows::FindByStringInAllSections + FindStringInRange @ ea0dab3 (A3)."""
        sites = self.scanner.string_refs(text, wide=wide)
        remaining = range_
        for section in self.image.sections:
            if not (section.characteristics & IMAGE_SCN_MEM_READ):
                continue
            if only_executable and not section.executable:
                continue
            search_start, search_range = _search_start_and_range(self.image, section, start_address, remaining)
            if search_start == 0 or search_range == 0:
                continue
            if remaining > 0:
                remaining -= search_range
            hi = search_start + search_range - 7
            i = bisect.bisect_left(sites, search_start)
            if i < len(sites) and sites[i] < hi:
                return sites[i]
        return 0

    def find_aligned_value_in_all_sections(self, value: int, size: int, alignment: int, start_address: int = 0,
                                            range_: int = 0) -> int:
        """WindowsPrivateImplHelper::FindAlignedValueInAllSectionsImpl + FinAlignedValueInRangeImpl @ ea0dab3."""
        remaining = range_
        for section in self.image.sections:
            if not (section.characteristics & IMAGE_SCN_MEM_READ):
                continue
            search_start, search_range = _search_start_and_range(self.image, section, start_address, remaining)
            if search_start == 0 or search_range == 0:
                continue
            if remaining > 0:
                remaining -= search_range
            result = self._find_aligned_value_in_range(value, size, alignment, search_start, search_range)
            if result:
                return result
        return 0

    def _find_aligned_value_in_range(self, value: int, size: int, alignment: int, start: int, range_: int) -> int:
        """WindowsPrivateImplHelper::FinAlignedValueInRangeImpl @ ea0dab3."""
        size_from_end = _aligned_size_with_offset_from_end(range_, alignment, size)
        if size_from_end == -1:
            return 0
        needle = value.to_bytes(size, 'little')
        i = 0
        while i <= size_from_end:
            addr = start + i
            if self.source.read(addr, size) == needle:
                return addr
            i += alignment
        return 0

    def find_all_aligned_values_in_process(self, value: int, size: int = 8, alignment: int = 8, start_address: int = 0,
                                            range_: int = 0) -> list[int]:
        """PlatformWindows.h FindAllAlignedValuesInProcess @ ea0dab3 (A8)."""
        results = []
        last = start_address
        while found := self._find_aligned_value_fast(value, size, alignment, last, range_):
            results.append(found)
            last = align(found + size, alignment)
        return results

    def _find_aligned_value_fast(self, value: int, size: int, alignment: int, start_address: int, range_: int) -> int:
        """FindAlignedValueInAllSectionsImpl, bytes.find over cached section chunks (A8)."""
        needle = value.to_bytes(size, 'little')
        remaining = range_
        for section in self.image.sections:
            if not (section.characteristics & IMAGE_SCN_MEM_READ):
                continue
            search_start, search_range = _search_start_and_range(self.image, section, start_address, remaining)
            if search_start == 0 or search_range == 0:
                continue
            if remaining > 0:
                remaining -= search_range
            size_from_end = _aligned_size_with_offset_from_end(search_range, alignment, size)
            if size_from_end == -1:
                continue
            last_start = search_start + size_from_end
            for chunk_addr, data in self.scanner.chunks(section):
                pos = -1
                while (pos := data.find(needle, pos + 1)) != -1:
                    addr = chunk_addr + pos
                    if addr < search_start or addr > last_start:
                        continue
                    if (addr - search_start) % alignment == 0:
                        return addr
        return 0

    def find_unreal_exec_function_by_string(self, text: str, *, wide: bool = False, start_address: int = 0) -> int:
        """Utils.h FindUnrealExecFunctionByString @ ea0dab3 (A9)."""
        image_base, image_size = self.get_image_base_and_size()
        search_start = start_address or image_base
        limit = search_start + image_size - 8
        needle = text.encode('utf-16-le') if wide else text.encode('ascii')
        occurrences = self.scanner.find_bytes(needle, align=1, executable=None)
        if not occurrences or limit < search_start:
            return 0
        candidates = set()
        for occ in occurrences:
            for slot in self.scanner.aligned_values(occ, size=8, align=8, executable=None):
                if search_start <= slot <= limit and (slot - search_start) % 8 == 0:
                    candidates.add(slot)
        for slot in sorted(candidates):
            possible_string_address = self.source.u64(slot)
            possible_exec_func_address = self.source.u64(slot + 8)
            if possible_string_address == possible_exec_func_address:
                continue
            if not self.is_address_in_process_range(possible_string_address):
                continue
            if not self.is_address_in_process_range(possible_exec_func_address):
                continue
            if self._is_valid_exec_function_not_setup(possible_exec_func_address):
                return possible_exec_func_address
        return 0

    def _is_valid_exec_function_not_setup(self, address: int) -> bool:
        """Utils.h FindUnrealExecFunctionByString's IsValidExecFunctionNotSetupFunc lambda @ ea0dab3."""
        value = self.source.u32(address)
        if value == 0x284883EC or value == 0x4883EC28:
            return False
        sig = self.find_pattern_in_range('48 8B 05 ? ? ? ? 48 85 C0 75 ? 48 8D 15', address, 0x28)
        return sig == 0

    # -- Architecture_x86_64 (Arch_x86.cpp) ----------------------------------

    def is_valid_64_bit_virtual_address(self, address: int) -> bool:
        """Architecture_x86_64::IsValid64BitVirtualAddress @ ea0dab3."""
        mask = 0xFF << 56
        return (address & mask) == mask or (address & mask) == 0

    def is_32_bit_riprelative_jump(self, address: int) -> bool:
        """Architecture_x86_64::Is32BitRIPRelativeJump @ ea0dab3."""
        if not address:
            return False
        return self.source.u8(address) == 0xE9

    def resolve_32_bit_riprelative_jump_target(self, address: int) -> int:
        """Architecture_x86_64::Resolve32BitRIPRelativeJumpTarget @ ea0dab3."""
        return address + 5 + self.source.i32(address + 1)

    def resolve_32_bit_register_relative_jump(self, address: int) -> int:
        """Architecture_x86_64::Resolve32BitRegisterRelativeJump @ ea0dab3."""
        return address + 7 + self.source.i32(address + 3)

    def resolve_32_bit_section_relative_call(self, address: int) -> int:
        """Architecture_x86_64::Resolve32BitSectionRelativeCall @ ea0dab3."""
        return address + 6 + self.source.i32(address + 2)

    def resolve_32_bit_relative_call(self, address: int) -> int:
        """Architecture_x86_64::Resolve32BitRelativeCall @ ea0dab3."""
        return address + 5 + self.source.i32(address + 1)

    def resolve_32_bit_relative_move(self, address: int) -> int:
        """Architecture_x86_64::Resolve32BitRelativeMove @ ea0dab3."""
        return address + 7 + self.source.i32(address + 3)

    def resolve_32_bit_relative_lea(self, address: int) -> int:
        """Architecture_x86_64::Resolve32BitRelativeLea @ ea0dab3."""
        return address + 7 + self.source.i32(address + 3)

    def is_function_ret(self, address: int) -> bool:
        """Architecture_x86_64::IsFunctionRet @ ea0dab3."""
        if not address:
            return False
        first = self.source.u8(address)
        if first != 0xC3 and first != 0xCB:
            return False
        one_before = self.source.u8(address - 1)
        self.source.u8(address - 2)  # ByteTwoBeforeRet: read but unused in ea0dab3
        return one_before in (0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F)

    def resolve_jump_if_instruction_is_jump(self, address: int, default: int = 0) -> int:
        """Architecture_x86_64::ResolveJumpIfInstructionIsJump @ ea0dab3."""
        if not self.is_32_bit_riprelative_jump(address):
            return default
        target = self.resolve_32_bit_riprelative_jump_target(address)
        if not self.is_address_in_process_range(target):
            return default
        return target

    def find_function_end(self, address: int, range_: int = 0xFFFF) -> int:
        """Architecture_x86_64::FindFunctionEnd @ ea0dab3."""
        if not address:
            return 0
        if range_ > 0xFFFF:
            range_ = 0xFFFF
        for i in range(range_):
            if self.is_function_ret(address + i):
                return address + i
        return 0

    def find_next_function_start(self, address: int) -> int:
        """Architecture_x86_64::FindNextFunctionStart @ ea0dab3."""
        if not address:
            return 0
        func_end = self.find_function_end(address)
        return func_end + (0x10 - func_end % 0x10) if func_end % 0x10 != 0 else func_end

    def get_rip_relative_called_function(self, address: int, one_based_func_index: int, is_wanted_target=None) -> int:
        """Architecture_x86_64::GetRipRelativeCalledFunction @ ea0dab3."""
        if not address or one_based_func_index == 0:
            return 0
        multiply = 1 if one_based_func_index > 0 else -1
        num_calls = 0
        for i in range(0xFFF):
            index = i * multiply
            if self.source.u8(address + index) != 0xE8:
                continue
            relative_offset = self.source.i32(address + index + 1)
            target = address + index + relative_offset + 5
            if not self.is_address_in_process_range(target):
                continue
            num_calls += 1
            if num_calls == abs(one_based_func_index):
                if is_wanted_target is not None and not is_wanted_target(target):
                    num_calls -= 1
                    continue
                return target
        return 0
