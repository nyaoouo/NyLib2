"""NameArray, FNameEntry and FName of Dumper-7 @ ea0dab3 (NameArray.cpp, UnrealTypes.cpp), reading names from the pool."""
import struct
import typing

from ..errors import DetectionError, MemoryReadError
from ..names import make_name_valid
from .utfn import string_to_wstring, wstring_to_string

if typing.TYPE_CHECKING:
    from .core import Engine

_NAME_WIDE_MASK = 0x1
_NUMBERED_NAME_LINKS = 16  # DV18
_INLINE_FNAME = struct.Struct('<iI')  # CompIdx at 0, Number at 4


def _i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _read_until_nul(mem, address: int, unit: int) -> bytes:
    data = bytearray()
    pos = 0
    nul = bytes(unit)
    while True:
        n = 0x1000 - (address & 0xFFF)
        data += mem.read(address, n)
        address += n
        while (i := data.find(nul, pos)) >= 0:
            if i % unit == 0:
                return bytes(data[:i])
            pos = i + 1
        pos = len(data) // unit * unit


def _ansi_to_wstring(name_entry: int, data: bytes) -> str:
    try:
        return string_to_wstring(data)
    except ValueError as err:  # DV19: DV12's invalid lead byte
        raise MemoryReadError(name_entry, len(data), f'name entry bytes are not valid UTF-8: {err}') from err


class _UnresolvedBase(Exception):
    """A numbered entry's base that the fresh cursor does not cover either."""


class FNameEntry:
    __slots__ = ('e', 'address')

    def __init__(self, e: 'Engine', address: int):
        self.e = e
        self.address = address

    def get_address(self) -> int:
        return self.address

    def get_wstring(self) -> str:
        """FNameEntry::GetWString @ ea0dab3."""
        if not self.address:
            return ''
        return self.e.names._get_str_memo(self.address)

    def get_string(self) -> str:
        """FNameEntry::GetString @ ea0dab3."""
        if not self.address:
            return ''
        return wstring_to_string(self.get_wstring())


class NameArray:
    """NameArray + FNameEntry statics of one engine."""

    def __init__(self, e: 'Engine'):
        self.e = e
        self.GNames = 0
        self.FNameBlockOffsetBits = 0x10
        self.NameEntryStride = 0
        self.FNameEntryLengthShiftCount = 0
        self._ByIndex = None
        self._GetStr = None
        self._memo: dict[int, str] = {}
        self._comp_memo: dict[int, str] = {}
        self._memo_state = None
        self._name_pool_sig_occurrence = 0

    def _rec(self, key: str, label: str) -> None:
        self.e.provenance[key] = label

    # FNameEntry

    def _memo_key(self) -> tuple:
        o = self.e.off
        return (self._GetStr, self._ByIndex, self.FNameEntryLengthShiftCount, self.GNames, self.FNameBlockOffsetBits, self.NameEntryStride,
                o.FNameEntry.NamePool.HeaderOffset, o.FNameEntry.NamePool.StringOffset, o.FNameEntry.NameArray.StringOffset,
                o.FNameEntry.NameArray.IndexOffset, o.NameArray.ChunksStart, o.NameArray.MaxChunkIndex, o.NameArray.NumElements,
                o.NameArray.ByteCursor, self.e.settings.Internal.bUseNamePool)

    def _check_memo_state(self) -> None:
        if (state := self._memo_key()) != self._memo_state:
            self._memo.clear()
            self._comp_memo.clear()
            self._memo_state = state

    def _get_str_memo(self, address: int) -> str:
        self._check_memo_state()
        if (s := self._memo.get(address)) is None:
            s = self._memo[address] = self._GetStr(address)
        return s

    def _comp_idx_wstring(self, comp_idx: int) -> str:
        """A11: the entry string of comp_idx; a name-pool miss gets one fresh recheck of the cursor, kept only once resolved.

        A hooked `_ByIndex` or `_GetStr` turns the fresh recheck off.
        """
        self._check_memo_state()
        if (s := self._comp_memo.get(comp_idx)) is None:
            if self._ByIndex == self._by_index_name_pool and self._GetStr == self._get_str_name_pool:
                if address := self._written_name_pool_entry(comp_idx):
                    s = FNameEntry(self.e, address).get_wstring()
                else:
                    address, s = self._fresh_name_pool_lookup(comp_idx)
            else:
                address = self._ByIndex(self.GNames, comp_idx, self.FNameBlockOffsetBits)
                s = FNameEntry(self.e, address).get_wstring()
            if address:
                self._comp_memo[comp_idx] = s
        return s

    def _written_name_pool_entry(self, comp_idx: int) -> int:
        """`_by_index_name_pool` with the same reads, but an entry at the cursor is not yet written and gives 0."""
        chunk_idx = comp_idx >> self.FNameBlockOffsetBits
        in_chunk_offset = (comp_idx & ((1 << self.FNameBlockOffsetBits) - 1)) * self.NameEntryStride
        is_unwritten = chunk_idx == self.get_num_chunks() and in_chunk_offset >= self.get_byte_cursor()
        if chunk_idx < 0 or chunk_idx > self.get_num_chunks() or is_unwritten:
            return 0
        return self.e.mem.ptr(self.GNames + self.e.off.NameArray.ChunksStart + chunk_idx * 8) + in_chunk_offset

    def _fresh_name_pool_lookup(self, comp_idx: int) -> tuple[int, str]:
        """Decodes comp_idx through `e.mem.fresh` once written; (0, '') when it, or a numbered entry's base, is not."""
        if not (address := self._fresh_name_pool_address(comp_idx)):
            return 0, ''
        try:
            return address, self._get_str_name_pool(address, fresh=self.e.mem.fresh)
        except _UnresolvedBase:
            return 0, ''

    def _fresh_name_pool_address(self, comp_idx: int) -> int:
        """The entry address of comp_idx under CurrentBlock and CurrentByteCursor re-read through `e.mem.fresh`; 0 while not written."""
        mem, off = self.e.mem.fresh, self.e.off.NameArray
        chunk_idx = comp_idx >> self.FNameBlockOffsetBits
        in_chunk_offset = (comp_idx & ((1 << self.FNameBlockOffsetBits) - 1)) * self.NameEntryStride
        num_chunks = mem.i32(self.GNames + off.MaxChunkIndex)
        byte_cursor = mem.i32(self.GNames + off.ByteCursor)
        if chunk_idx < 0 or chunk_idx > num_chunks or (chunk_idx == num_chunks and in_chunk_offset >= byte_cursor):
            return 0
        return mem.ptr(self.GNames + off.ChunksStart + chunk_idx * 8) + in_chunk_offset

    def _fname_entry_init(self, first_chunk_ptr: int = 0, name_entry_string_offset: int = 0) -> None:
        """FNameEntry::Init @ ea0dab3."""
        e, mem, o = self.e, self.e.mem, self.e.off
        label = 'auto: FNameEntry::Init'
        if e.settings.Internal.bUseNamePool:
            none_str_len = 0x4
            byte_property_str_len = 0xC
            byte_property_start_as_uint32 = 0x65747942  # 'etyB'

            o.FNameEntry.NamePool.StringOffset = _i32(name_entry_string_offset)
            self._rec('Off.FNameEntry.NamePool.StringOffset', label)
            o.FNameEntry.NamePool.HeaderOffset = 4 if name_entry_string_offset == 6 else 0
            self._rec('Off.FNameEntry.NamePool.HeaderOffset', label)

            assumed_byte_property_entry = mem.ptr(first_chunk_ptr) + name_entry_string_offset + none_str_len
            for _ in range(0x4):
                if mem.u32(assumed_byte_property_entry + name_entry_string_offset) == byte_property_start_as_uint32:
                    break
                assumed_byte_property_entry += 0x1

            byte_property_header = mem.u16(assumed_byte_property_entry + o.FNameEntry.NamePool.HeaderOffset)
            max_allowed_shift_count = 2 * 0x8
            while byte_property_header != byte_property_str_len and self.FNameEntryLengthShiftCount < max_allowed_shift_count:
                self.FNameEntryLengthShiftCount += 1
                self._rec('FNameEntry.FNameEntryLengthShiftCount', label)
                byte_property_header >>= 1

            if self.FNameEntryLengthShiftCount == max_allowed_shift_count:
                e.cerr("\nDumper-7: Error, couldn't get FNameEntryLengthShiftCount!\n\n")
                self._GetStr = self._get_str_invalid_shift_count
                return
            self._GetStr = self._get_str_name_pool
        else:
            fname_entry_none = self.get_name_entry(0x0).get_address()
            fname_entry_idx_three = self.get_name_entry(0x3).get_address()
            fname_entry_idx_eight = self.get_name_entry(0x8).get_address()

            for i in range(0x20):
                if mem.u32(fname_entry_none + i) == 0x656E6F4E:  # 'enoN'
                    o.FNameEntry.NameArray.StringOffset = i
                    self._rec('Off.FNameEntry.NameArray.StringOffset', label)
                    break

            for i in range(0x20):
                if (mem.u32(fname_entry_idx_three + i) >> 1) == 0x3 and (mem.u32(fname_entry_idx_eight + i) >> 1) == 0x8:
                    o.FNameEntry.NameArray.IndexOffset = i
                    self._rec('Off.FNameEntry.NameArray.IndexOffset', label)
                    break

            self._GetStr = self._get_str_name_array

    @staticmethod
    def _get_str_invalid_shift_count(name_entry: int) -> str:
        return 'Invalid FNameEntryLengthShiftCount!'

    def _get_str_name_pool(self, name_entry: int, start: int = 0, hops: int = 0, fresh=None) -> str:
        mem, pool = fresh or self.e.mem, self.e.off.FNameEntry.NamePool
        header_without_number = mem.u16(name_entry + pool.HeaderOffset)
        name_len = header_without_number >> self.FNameEntryLengthShiftCount

        if name_len == 0:
            start = start or name_entry
            if hops == _NUMBERED_NAME_LINKS:
                raise MemoryReadError(start, 0, f'numbered name chain of {start:#x} exceeds {_NUMBERED_NAME_LINKS} links')
            entry_id_offset = pool.StringOffset + ((pool.StringOffset == 6) * 2)
            next_entry_index = mem.i32(name_entry + entry_id_offset)
            number = mem.i32(name_entry + entry_id_offset + 4)
            next_entry = self.get_name_entry(next_entry_index).get_address()
            if not next_entry and fresh is not None and not (next_entry := self._fresh_name_pool_address(next_entry_index)):
                raise _UnresolvedBase(next_entry_index)
            next_wstring = self._get_str_name_pool(next_entry, start, hops + 1, fresh) if next_entry else ''
            if number > 0:
                return next_wstring + '_' + str(number - 1)
            return next_wstring

        if header_without_number & _NAME_WIDE_MASK:
            return mem.read(name_entry + pool.StringOffset, name_len * 2).decode('utf-16-le', 'surrogatepass')
        return _ansi_to_wstring(name_entry, mem.read(name_entry + pool.StringOffset, name_len))

    def _get_str_name_array(self, name_entry: int) -> str:
        mem, arr = self.e.mem, self.e.off.FNameEntry.NameArray
        name_idx = mem.i32(name_entry + arr.IndexOffset)
        name_string = name_entry + arr.StringOffset
        if name_idx & _NAME_WIDE_MASK:
            return _read_until_nul(mem, name_string, 2).decode('utf-16-le', 'surrogatepass')
        return _ansi_to_wstring(name_entry, _read_until_nul(mem, name_string, 1))

    # ByIndex variants

    def _by_index_name_array(self, names_array: int, comparison_index: int, name_pool_block_offset_bits: int) -> int:
        mem = self.e.mem
        chunk_idx = abs(comparison_index) // 0x4000 * (-1 if comparison_index < 0 else 1)
        in_chunk = comparison_index - chunk_idx * 0x4000
        if comparison_index > self.get_num_elements():
            return 0
        return mem.ptr(mem.ptr(names_array + chunk_idx * 8) + in_chunk * 8)

    def _by_index_name_pool(self, names_array: int, comparison_index: int, name_pool_block_offset_bits: int) -> int:
        chunk_idx = comparison_index >> name_pool_block_offset_bits
        in_chunk_offset = (comparison_index & ((1 << name_pool_block_offset_bits) - 1)) * self.NameEntryStride
        is_beyond_last_chunk = chunk_idx == self.get_num_chunks() and in_chunk_offset > self.get_byte_cursor()
        if chunk_idx < 0 or chunk_idx > self.get_num_chunks() or is_beyond_last_chunk:
            return 0
        return self.e.mem.ptr(names_array + self.e.off.NameArray.ChunksStart + chunk_idx * 8) + in_chunk_offset  # DV2

    # NameArray

    def _initialize_name_array(self, name_array: int) -> bool:
        """NameArray::InitializeNameArray @ ea0dab3."""
        e, mem = self.e, self.e.mem
        valid_ptr_count = 0
        zero_qword_count = 0
        if not name_array or e.platform.is_bad_read_ptr(name_array):
            return False

        for i in range(0, 0x800, 8):
            some_ptr = mem.ptr(name_array + i)
            if some_ptr == 0:
                zero_qword_count += 1
            elif zero_qword_count == 0 and some_ptr != 0:
                valid_ptr_count += 1
            elif zero_qword_count > 0 and some_ptr != 0:
                num_chunks = mem.i32(name_array + i + 4)
                if num_chunks == valid_ptr_count:
                    e.off.NameArray.NumElements = i
                    self._rec('Off.NameArray.NumElements', 'auto: NameArray::InitializeNameArray')
                    e.off.NameArray.MaxChunkIndex = i + 4
                    self._rec('Off.NameArray.MaxChunkIndex', 'auto: NameArray::InitializeNameArray')
                    self._ByIndex = self._by_index_name_array
                    return True
        return False

    def _initialize_name_pool(self, name_pool: int) -> bool:
        """NameArray::InitializeNamePool @ ea0dab3."""
        e, mem, o = self.e, self.e.mem, self.e.off
        label = 'auto: NameArray::InitializeNamePool'
        o.NameArray.MaxChunkIndex = 0x0
        self._rec('Off.NameArray.MaxChunkIndex', label)
        o.NameArray.ByteCursor = 0x4
        self._rec('Off.NameArray.ByteCursor', label)
        o.NameArray.ChunksStart = 0x10
        self._rec('Off.NameArray.ChunksStart', label)

        was_max_chunk_index_found = False
        for i in range(0x0, 0x20, 4):
            possible_max_chunk_idx = mem.i32(name_pool + i)
            if possible_max_chunk_idx <= 0 or possible_max_chunk_idx > 0x10000:
                continue

            not_nullptr_count = 0
            found_first_ptr = False
            max_allowed_num_invalid_ptrs = 0x500
            num_ptrs_since_last_valid = 0
            for j in range(0x0, 0x10000, 8):
                chunk_offset = i + 8 + j + (i % 8)
                if mem.ptr(name_pool + chunk_offset) != 0:
                    not_nullptr_count += 1
                    num_ptrs_since_last_valid = 0
                    if not found_first_ptr:
                        found_first_ptr = True
                        o.NameArray.ChunksStart = i + 8 + j + (i % 8)
                        self._rec('Off.NameArray.ChunksStart', label)
                else:
                    num_ptrs_since_last_valid += 1
                    if num_ptrs_since_last_valid == max_allowed_num_invalid_ptrs:
                        break

            if possible_max_chunk_idx == not_nullptr_count - 1:
                o.NameArray.MaxChunkIndex = i
                self._rec('Off.NameArray.MaxChunkIndex', label)
                o.NameArray.ByteCursor = i + 4
                self._rec('Off.NameArray.ByteCursor', label)
                was_max_chunk_index_found = True
                break

        if not was_max_chunk_index_found:
            return False

        core_uobj_as_uint64 = 0x6A624F5565726F43  # "CoreUObj"
        none_as_uint32 = 0x656E6F4E  # "None"
        chunk_ptr = name_pool + o.NameArray.ChunksStart

        found_core_uobject_string = False
        fname_entry_header_size = 0x0
        for i in range(0x1000):
            if mem.u32(mem.ptr(chunk_ptr) + i) == none_as_uint32 and fname_entry_header_size == 0:
                fname_entry_header_size = i
            elif mem.u64(mem.ptr(chunk_ptr) + i) == core_uobj_as_uint64:
                found_core_uobject_string = True
                break

        if not found_core_uobject_string:
            return False

        self.NameEntryStride = 2 if fname_entry_header_size == 2 else 4
        o.InSDK.NameArray.FNameEntryStride = self.NameEntryStride
        self._rec('Off.InSDK.NameArray.FNameEntryStride', label)

        self._ByIndex = self._by_index_name_pool

        e.settings.Internal.bUseNamePool = True
        self._rec('Settings.Internal.bUseNamePool', label)
        self._fname_entry_init(chunk_ptr, fname_entry_header_size)
        return True

    def _find_fname_get_names_or_gnames_windows(self, enter_critical_section_address: int, start_address: int) -> tuple[int, bool]:
        """FindFNameGetNamesOrGNames_Windows @ ea0dab3."""
        e, p = self.e, self.e.platform
        asm_relative_call_size_bytes = 0x6
        get_names_call_search_range = 0x150

        byte_property_string_address = p.find_by_string_in_all_sections(
            'ByteProperty', wide=True, start_address=start_address, range_=0x0,
            only_executable=e.settings.General.bSearchOnlyExecutableSectionsForStrings)
        if not byte_property_string_address:
            return 0x0, False

        for i in range(get_names_call_search_range):
            if e.mem.u8(byte_property_string_address - i) != 0xFF:
                continue
            call_target = p.resolve_32_bit_section_relative_call(byte_property_string_address - i)
            if call_target != enter_critical_section_address:
                continue
            instruction_after_call = byte_property_string_address - (i - asm_relative_call_size_bytes)
            if e.mem.u8(instruction_after_call) == 0xE8:
                return p.resolve_32_bit_relative_call(instruction_after_call), False
            return p.resolve_32_bit_relative_move(instruction_after_call), True

        return self._find_fname_get_names_or_gnames_windows(enter_critical_section_address, byte_property_string_address + asm_relative_call_size_bytes)

    def try_find_name_array_windows(self) -> bool:
        """NameArray::TryFindNameArray_Windows @ ea0dab3 (DV3)."""
        e, p = self.e, self.e.platform
        enter_critical_section_address = p.get_address_of_imported_function_from_any_module('kernel32.dll', 'EnterCriticalSection')
        address, is_gnames_directly = self._find_fname_get_names_or_gnames_windows(enter_critical_section_address, p.get_module_base())
        if address == 0x0:
            return False

        if is_gnames_directly:
            if not p.is_address_in_process_range(address) or p.is_bad_read_ptr(e.mem.ptr(address)):
                return False
            e.off.InSDK.NameArray.GNames = _i32(p.get_offset(address))
            self._rec('Off.InSDK.NameArray.GNames', 'auto: NameArray::TryFindNameArray_Windows')
            return True

        return False  # DV3: ea0dab3 calls FName::GetNames() here

    def try_find_name_pool_windows(self, start_after: int = 0x0) -> bool:
        """NameArray::TryFindNamePool_Windows @ ea0dab3; start_after resumes the scan after a rejected candidate (K14)."""
        e, mem, p = self.e, self.e.mem, self.e.platform
        init_srw_lock_search_range = 0x50
        byte_property_search_range = 0x2A0
        only_executable = e.settings.General.bSearchOnlyExecutableSectionsForStrings

        init_srw_lock_address = p.get_address_of_imported_function_from_any_module('kernel32.dll', 'InitializeSRWLock')
        rtl_init_srw_lock_address = p.get_address_of_imported_function_from_any_module('ntdll.dll', 'RtlInitializeSRWLock')

        name_pool_intance = 0
        sig_occurrence = start_after
        while not name_pool_intance:
            if sig_occurrence > 0x0:
                sig_occurrence += 0x1

            sig_occurrence = p.find_pattern('48 8D 0D ? ? ? ? E8', 0x0, True, sig_occurrence)
            if sig_occurrence == 0x0:
                break

            size_of_mov_instruction_bytes = 0x7
            possible_constructor_address = p.resolve_32_bit_relative_call(sig_occurrence + size_of_mov_instruction_bytes)
            if not p.is_address_in_process_range(possible_constructor_address):
                continue

            window = mem.read(possible_constructor_address, init_srw_lock_search_range + 1)  # A4
            for i in range(init_srw_lock_search_range):
                if window[i] != 0xFF or window[i + 1] != 0x15:
                    continue
                relative_call_target = p.resolve_32_bit_section_relative_call(possible_constructor_address + i)
                if not p.is_address_in_process_range(relative_call_target):
                    continue
                value_of_call_target = mem.u64(relative_call_target)
                if value_of_call_target != init_srw_lock_address and value_of_call_target != rtl_init_srw_lock_address:
                    continue

                string_ref = p.find_by_string_in_all_sections('ByteProperty', wide=True, start_address=possible_constructor_address,
                                                              range_=byte_property_search_range, only_executable=only_executable)
                if not string_ref:
                    string_ref = p.find_by_string_in_all_sections('ByteProperty', wide=False, start_address=possible_constructor_address,
                                                                  range_=byte_property_search_range, only_executable=only_executable)
                if string_ref:
                    name_pool_intance = p.resolve_32_bit_relative_move(sig_occurrence)
                    break

        if name_pool_intance:
            self._name_pool_sig_occurrence = sig_occurrence
            e.off.InSDK.NameArray.GNames = _i32(p.get_offset(name_pool_intance))
            self._rec('Off.InSDK.NameArray.GNames', 'auto: NameArray::TryFindNamePool_Windows')
            return True
        return False

    def _commit(self, gnames_address: int, found_name_array: bool, found_name_pool: bool, label: str) -> bool:
        e = self.e
        if found_name_array and self._initialize_name_array(gnames_address):
            self.GNames = gnames_address
            e.settings.Internal.bUseNamePool = False
            self._rec('Settings.Internal.bUseNamePool', label)
            self._fname_entry_init()
            return True
        elif found_name_pool and self._initialize_name_pool(gnames_address):
            self.GNames = gnames_address
            e.settings.Internal.bUseNamePool = True
            self._rec('Settings.Internal.bUseNamePool', label)
            return True
        return False

    def try_init(self, is_test_only: bool = False) -> bool:
        """NameArray::TryInit(bool) @ ea0dab3."""
        e = self.e
        label = 'auto: NameArray::TryInit'
        image_base = e.platform.get_module_base()
        gnames_address = 0
        found_name_array = False
        found_name_pool = False

        if self.try_find_name_array_windows():
            e.cerr(f"Found 'TNameEntryArray GNames' at offset 0x{e.off.InSDK.NameArray.GNames:X}\n\n")
            gnames_address = e.mem.ptr(image_base + e.off.InSDK.NameArray.GNames)
            e.settings.Internal.bUseNamePool = False
            self._rec('Settings.Internal.bUseNamePool', label)
            found_name_array = True
        elif self.try_find_name_pool_windows():
            e.cerr(f"Found 'FNamePool GNames' at offset 0x{e.off.InSDK.NameArray.GNames:X}\n\n")
            gnames_address = image_base + e.off.InSDK.NameArray.GNames
            e.settings.Internal.bUseNamePool = True
            self._rec('Settings.Internal.bUseNamePool', label)
            found_name_pool = True

        if not found_name_array and not found_name_pool:
            e.cerr('\n\nCould not find GNames!\n\n\n')
            return False

        if is_test_only:
            return False

        if self._commit(gnames_address, found_name_array, found_name_pool, label):
            return True

        if found_name_pool:  # K14: retry the next candidate; keep the first one recorded if none is usable
            first_gnames = e.off.InSDK.NameArray.GNames
            while self.try_find_name_pool_windows(self._name_pool_sig_occurrence):
                e.cerr(f"Found 'FNamePool GNames' at offset 0x{e.off.InSDK.NameArray.GNames:X}\n\n")
                if self._commit(image_base + e.off.InSDK.NameArray.GNames, False, True, label):
                    return True
            e.off.InSDK.NameArray.GNames = first_gnames
            self._rec('Off.InSDK.NameArray.GNames', 'auto: NameArray::TryFindNamePool_Windows')

        e.cerr("The address that was found couldn't be used by the generator, this might be due to GNames-encryption.\n\n")
        return False

    def try_init_override(self, offset_override: int, is_name_pool: bool) -> bool:
        """NameArray::TryInit(int32, bool, const char*) @ ea0dab3."""
        e = self.e
        label = 'auto: NameArray::TryInit'
        image_base = e.platform.get_module_base()
        gnames_address = 0
        is_name_array_override = not is_name_pool
        is_name_pool_override = is_name_pool
        found_name_array = False
        found_name_pool = False

        e.off.InSDK.NameArray.GNames = _i32(offset_override)
        self._rec('Off.InSDK.NameArray.GNames', label)

        if is_name_array_override:
            e.cerr(f"Overwrote offset: 'TNameEntryArray GNames' set as offset 0x{e.off.InSDK.NameArray.GNames:X}\n\n")
            gnames_address = e.mem.ptr(image_base + e.off.InSDK.NameArray.GNames)
            e.settings.Internal.bUseNamePool = False
            self._rec('Settings.Internal.bUseNamePool', label)
            found_name_array = True
        elif is_name_pool_override:
            e.cerr(f"Overwrote offset: 'FNamePool GNames' set as offset 0x{e.off.InSDK.NameArray.GNames:X}\n\n")
            gnames_address = image_base + e.off.InSDK.NameArray.GNames
            e.settings.Internal.bUseNamePool = True
            self._rec('Settings.Internal.bUseNamePool', label)
            found_name_pool = True

        if not found_name_array and not found_name_pool:
            e.cerr('\n\nCould not find GNames!\n\n\n')
            return False

        if self._commit(gnames_address, found_name_array, found_name_pool, label):
            return True

        e.cerr("The address was overwritten, but couldn't be used. This might be due to GNames-encryption.\n\n")
        return False

    def set_gnames_without_committing(self) -> bool:
        """NameArray::SetGNamesWithoutCommitting @ ea0dab3."""
        e = self.e
        label = 'auto: NameArray::SetGNamesWithoutCommitting'
        if e.off.InSDK.NameArray.GNames != 0x0:
            return False

        if self.try_find_name_array_windows():
            e.cerr(f"Found 'TNameEntryArray GNames' at offset 0x{e.off.InSDK.NameArray.GNames:X}\n\n")
            e.settings.Internal.bUseNamePool = False
            self._rec('Settings.Internal.bUseNamePool', label)
            return True
        elif self.try_find_name_pool_windows():
            e.cerr(f"Found 'FNamePool GNames' at offset 0x{e.off.InSDK.NameArray.GNames:X}\n\n")
            e.settings.Internal.bUseNamePool = True
            self._rec('Settings.Internal.bUseNamePool', label)
            return True

        e.cerr('\n\nCould not find GNames!\n\n\n')
        return False

    def post_init(self) -> None:
        """NameArray::PostInit @ ea0dab3."""
        e = self.e
        if self.GNames and e.settings.Internal.bUseNamePool:
            self.FNameBlockOffsetBits = 0xE

            i = e.objects.num()
            while i >= 0:
                current_block = self.get_num_chunks()
                obj = e.objects.get_by_index(i)
                if not obj:
                    i -= 1
                    continue

                obj_name_chunk_idx = obj.get_fname().get_comp_idx() >> self.FNameBlockOffsetBits
                if obj_name_chunk_idx == current_block:
                    break
                if obj_name_chunk_idx > current_block:
                    self.FNameBlockOffsetBits += 1
                    i = e.objects.num()
                i -= 1

            e.off.InSDK.NameArray.FNamePoolBlockOffsetBits = self.FNameBlockOffsetBits
            self._rec('Off.InSDK.NameArray.FNamePoolBlockOffsetBits', 'auto: NameArray::PostInit')
            e.cerr(f'NameArray::FNameBlockOffsetBits: 0x{self.FNameBlockOffsetBits:x}\n\n')

    def get_num_chunks(self) -> int:
        return self.e.mem.i32(self.GNames + self.e.off.NameArray.MaxChunkIndex)

    def get_num_elements(self) -> int:
        e = self.e
        return e.mem.i32(self.GNames + e.off.NameArray.NumElements) if not e.settings.Internal.bUseNamePool else 0

    def get_byte_cursor(self) -> int:
        e = self.e
        return e.mem.i32(self.GNames + e.off.NameArray.ByteCursor) if e.settings.Internal.bUseNamePool else 0

    def _get_name_entry_of(self, name: 'FName') -> FNameEntry:
        return FNameEntry(self.e, self._ByIndex(self.GNames, name.get_comp_idx(), self.FNameBlockOffsetBits))

    def get_name_entry_by_name(self, name_address: int) -> FNameEntry:
        """NameArray::GetNameEntry(const void*) @ ea0dab3."""
        return self._get_name_entry_of(FName(self.e, name_address))

    def get_name_entry(self, index: int) -> FNameEntry:
        """NameArray::GetNameEntry(int32) @ ea0dab3."""
        return FNameEntry(self.e, self._ByIndex(self.GNames, index, self.FNameBlockOffsetBits))


class FName:
    __slots__ = ('e', 'address')

    def __init__(self, e: 'Engine', address: int):
        self.e = e
        self.address = address

    @property
    def _src(self):
        return self.e.mem

    def get_address(self) -> int:
        return self.address

    def to_raw_wstring(self) -> str:
        """FName::ToRawWString @ ea0dab3."""
        if not self.address:
            return 'None'
        return self.e.fname._ToStr(self)

    def to_wstring(self) -> str:
        """FName::ToWString @ ea0dab3."""
        output_string = self.to_raw_wstring()
        if (pos := output_string.rfind('/')) < 0:
            return output_string
        return output_string[pos + 1:]

    def to_raw_string(self) -> str:
        """FName::ToRawString @ ea0dab3."""
        if not self.address:
            return 'None'
        return wstring_to_string(self.to_raw_wstring())

    def to_string(self) -> str:
        """FName::ToString @ ea0dab3."""
        if not self.address:
            return 'None'
        return wstring_to_string(self.to_wstring())

    def to_valid_string(self) -> str:
        """FName::ToValidString @ ea0dab3."""
        return make_name_valid(self.to_wstring())

    def get_comp_idx(self) -> int:
        """FName::GetCompIdx @ ea0dab3."""
        return self._src.i32(self.address + self.e.off.FName.CompIdx)

    def get_number(self) -> int:
        """FName::GetNumber @ ea0dab3."""
        internal = self.e.settings.Internal
        if internal.bUseOutlineNumberName:
            return 0x0
        if internal.bUseNamePool:
            return self._src.u32(self.address + self.e.off.FName.Number)
        return self._src.i32(self.address + self.e.off.FName.Number) & 0xFFFFFFFF

    def __eq__(self, other) -> bool:
        return self.get_comp_idx() == other.get_comp_idx()

    def __hash__(self) -> int:
        return hash(self.get_comp_idx())


class _LocalBuffer:
    """Reads of a local C++ object (FName::CompIdxToString's FakeFName) placed at `base`."""

    def __init__(self, base: int, data: bytes):
        self.base = base
        self.data = data

    def read(self, address: int, size: int) -> bytes:
        offset = address - self.base
        if offset < 0 or offset + size > len(self.data):
            raise MemoryReadError(address, size, 'outside the local FakeFName')
        return self.data[offset:offset + size]

    def _get(self, address: int, size: int, signed: bool) -> int:
        return int.from_bytes(self.read(address, size), 'little', signed=signed)

    def i32(self, address: int) -> int:
        return self._get(address, 4, True)

    def u32(self, address: int) -> int:
        return self._get(address, 4, False)


class _FakeFName(FName):
    __slots__ = ('_src',)
    _ADDRESS = 0x1  # non-null, as the C++ stack address

    def __init__(self, e: 'Engine', cmp_idx: int, size: int):
        super().__init__(e, self._ADDRESS)
        self._src = _LocalBuffer(self._ADDRESS, (cmp_idx & 0xFFFFFFFF).to_bytes(4, 'little') + bytes(size - 4))


class FNameStatics:
    """FName statics of one engine; AppendString and GetNameEntryFromName are reported, never called (DV5)."""

    def __init__(self, e: 'Engine'):
        self.e = e
        self.AppendString = 0
        self.GetNameEntryFromName = 0
        self._ToStr = None

    def _rec(self, key: str, label: str) -> None:
        self.e.provenance[key] = label

    def _to_str_gnames(self, name: FName) -> str:
        """A11: CompIdx and an inline Number at 0 and 4 come from one read; entry strings are memoized by CompIdx."""
        e = self.e
        names = e.names
        if not e.settings.Internal.bUseOutlineNumberName:
            if e.off.FName.CompIdx == 0 and e.off.FName.Number == 4:
                comp_idx, number = _INLINE_FNAME.unpack(name._src.read(name.address, 8))
            else:
                number = name.get_number()
                comp_idx = name.get_comp_idx()
            if number > 0:
                return names._comp_idx_wstring(comp_idx) + '_' + str(number - 1)
            return names._comp_idx_wstring(comp_idx)
        return names._comp_idx_wstring(name.get_comp_idx())

    def _cerr_found(self) -> None:
        name = self.e.off.InSDK.Name
        self.e.cerr(f'Found FName::{"AppendString" if name.bIsUsingAppendStringOverToString else "ToString"} at Offset 0x{name.AppendNameToString:X}\n\n')

    def init_windows(self) -> None:
        """FName::Init_Windows(bForceGNames = false) @ ea0dab3 (DV5)."""
        e, p = self.e, self.e.platform
        label = 'auto: FName::Init_Windows'
        only_executable = e.settings.General.bSearchOnlyExecutableSectionsForStrings
        force_gnames = False
        possible_sigs = (
            '48 8D ? ? 48 8D ? ? E8',
            '48 8D ? ? ? 48 8D ? ? E8',
            '48 8D ? ? 49 8B ? E8',
            '48 8D ? ? ? 49 8B ? E8',
            '48 8D ? ? 48 8B ? E8',
            '48 8D ? ? ? 48 8B ? E8',
        )

        string_ref = p.find_by_string_in_all_sections('ForwardShadingQuality_', wide=False, start_address=0x0, range_=0x0, only_executable=only_executable)
        found_potentially_overlapping_sig = False
        if string_ref:
            matching_sig = None
            i = 0
            while not self.AppendString and i < len(possible_sigs):
                self.AppendString = p.find_pattern_in_range(possible_sigs[i], string_ref, 0x50, True, -1)
                if self.AppendString:
                    matching_sig = possible_sigs[i]
                i += 1
            found_potentially_overlapping_sig = matching_sig is not None and matching_sig == '48 8D ? ? ? 48 8B ? E8'

        if (not self.AppendString or found_potentially_overlapping_sig) and not force_gnames and string_ref:
            if sig_scan_result := p.find_pattern_in_range('8B ? ? E8 ? ? ? ? 48 8D ? ? ? 48 8B C8 E8 ? ? ? ?', string_ref, 0x180):
                self.GetNameEntryFromName = p.resolve_32_bit_relative_call(sig_scan_result + 0x3)
                self.AppendString = p.resolve_32_bit_relative_call(sig_scan_result + 0x10)
                e.off.InSDK.Name.GetNameEntryFromName = _i32(p.get_offset(self.GetNameEntryFromName))
                self._rec('Off.InSDK.Name.GetNameEntryFromName', label)
                e.off.InSDK.Name.bIsAppendStringInlinedAndUsed = True
                self._rec('Off.InSDK.Name.bIsAppendStringInlinedAndUsed', label)

        if not self.AppendString:
            self.AppendString = self.try_find_apend_string_backup_string_ref_windows()

        e.off.InSDK.Name.AppendNameToString = _i32(p.get_offset(self.AppendString)) if self.AppendString and not force_gnames else 0x0
        self._rec('Off.InSDK.Name.AppendNameToString', label)
        append_string_found = bool(self.AppendString)
        if append_string_found:
            self._cerr_found()

        # DV5: names always come from GNames (ea0dab3's bForceGNames branch); AppendString is never called
        if e.names.try_init():
            self._ToStr = self._to_str_gnames
            return
        e.names.set_gnames_without_committing()
        self.init_fallback()
        if not append_string_found:
            self._cerr_found()
        raise DetectionError('FName::Init', 'GNames could not be initialised; AppendString cannot be called read-only', explanations=tuple(e.messages))

    def init_override(self, override_offset: int, override_type: str, is_name_pool: bool = False) -> None:
        """FName::Init(int32, EOffsetOverrideType, bool, const char*) @ ea0dab3 (DV5)."""
        e = self.e
        label = 'auto: FName::Init'
        if override_type == 'GNames':
            if e.names.try_init_override(override_offset, is_name_pool):
                self._ToStr = self._to_str_gnames
                return
            raise DetectionError('FName::Init', f'the GNames override 0x{override_offset:X} could not be initialised',  # DV16
                                 explanations=tuple(e.messages))

        self.AppendString = e.platform.get_module_base() + override_offset
        e.off.InSDK.Name.AppendNameToString = _i32(override_offset)
        self._rec('Off.InSDK.Name.AppendNameToString', label)
        e.off.InSDK.Name.bIsUsingAppendStringOverToString = override_type == 'AppendString'
        self._rec('Off.InSDK.Name.bIsUsingAppendStringOverToString', label)

        kind = 'AppendString' if e.off.InSDK.Name.bIsUsingAppendStringOverToString else 'ToString'
        e.cerr(f'Manual-Override: FName::{kind} --> Offset 0x{e.off.InSDK.Name.AppendNameToString:X}\n\n')
        raise DetectionError('FName::Init', f'FName::{kind} cannot be called read-only', explanations=tuple(e.messages))

    def try_find_apend_string_backup_string_ref_windows(self) -> int:
        """FName::TryFindApendStringBackupStringRef_Windows @ ea0dab3."""
        e, p = self.e, self.e.platform
        possible_sigs = (
            '48 8B ? 48 8B ? ? E8',
            '48 8B ? ? 48 89 ? ? E8',
            '48 8B ? 48 89 ? ? ? E8',
        )
        string_ref = p.find_by_string_in_all_sections(' Bone: ', wide=True, start_address=0x0, range_=0x0,
                                                      only_executable=e.settings.General.bSearchOnlyExecutableSectionsForStrings)
        if string_ref:
            sig_search_start_address = string_ref - 0xB0
            i = 0
            while not self.AppendString and i < len(possible_sigs):
                self.AppendString = p.find_pattern_in_range(possible_sigs[i], sig_search_start_address, 0x100, True, -1)
                if self.AppendString:
                    return self.AppendString
                i += 1
        return 0

    def init_fallback(self) -> None:
        """FName::InitFallback @ ea0dab3 (DV8: bRelative = -1 -> True, Offset 0)."""
        e, p = self.e, self.e.platform
        label = 'auto: FName::InitFallback'
        e.off.InSDK.Name.bIsUsingAppendStringOverToString = False
        self._rec('Off.InSDK.Name.bIsUsingAppendStringOverToString', label)

        conv_name_to_string_address = p.find_unreal_exec_function_by_string('Conv_NameToString')
        possible_sigs = (
            '89 44 ? ? 48 01 ? ? E8',
            '48 89 ? ? 48 8D ? ? ? E8',
            '48 89 ? ? ? 48 89 ? ? E8',
        )
        i = 0
        while not self.AppendString and i < len(possible_sigs):
            self.AppendString = p.find_pattern_in_range(possible_sigs[i], conv_name_to_string_address, 0x90, True, 0)
            i += 1

        e.off.InSDK.Name.AppendNameToString = _i32(p.get_offset(self.AppendString)) if self.AppendString else 0x0
        self._rec('Off.InSDK.Name.AppendNameToString', label)

    def comp_idx_to_string(self, cmp_idx: int) -> str:
        """FName::CompIdxToString @ ea0dab3, over a local FakeFName as the C++ builds on its stack."""
        if not self.e.settings.Internal.bUseCasePreservingName:
            return _FakeFName(self.e, cmp_idx, 0x8).to_string()
        return _FakeFName(self.e, cmp_idx, 0x10).to_string()
