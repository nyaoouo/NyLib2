"""Fixed-layout UC containers of Dumper-7 @ ea0dab3 as nylib.ctype views (built only through accessor.view)."""
from ...ctype import SField, Struct, c_int32, c_uint8, c_uint64, check_finalize
from ..errors import MemoryReadError
from .utfn import utf_16_string_to_utf_8_string


class ViewStruct(Struct):
    """Base of every nylib.ctype struct in nylib.ue: a view at an address, never self-allocated."""
    _can_self_handle_ = False


class TArray(ViewStruct):
    """UC::TArray @ ea0dab3."""
    _size_ = 0x10
    Data = SField(c_uint64, 0x0)
    NumElements = SField(c_int32, 0x8)
    MaxElements = SField(c_int32, 0xC)

    def num(self) -> int:
        return self.NumElements

    def max(self) -> int:
        return self.MaxElements

    def get_data_ptr(self) -> int:
        return self.Data

    def is_valid_index(self, index: int) -> bool:
        return self.Data != 0 and index >= 0 and index < self.NumElements

    def is_valid(self) -> bool:
        return self.Data != 0 and (num := self.NumElements) > 0 and self.MaxElements >= num

    def element_address(self, index: int, element_size: int) -> int:
        if not self.is_valid_index(index):
            raise IndexError('Index was out of range!')
        return self.Data + index * element_size

    def checked(self, cap: int) -> tuple[int, int]:
        """Data/NumElements/MaxElements read once; (data, num) with a consistent header and num <= cap.

        Raises MemoryReadError, never IndexError, for a corrupt or oversized header; index from the
        returned (data, num) afterwards without touching NumElements/MaxElements again.
        """
        data, num, mx = self.Data, self.NumElements, self.MaxElements
        if not (0 <= num <= mx and (num == 0 or data != 0)):
            raise MemoryReadError(self._address_, self._size_, f'corrupt TArray header (Data {data:#x}, Num {num}, Max {mx})')
        if num > cap:
            raise MemoryReadError(self._address_, self._size_, f'TArray num {num} exceeds cap {cap}')
        return data, num


class FString(TArray):
    """UC::FString @ ea0dab3 (TArray<wchar_t>)."""
    _size_ = 0x10

    def to_wstring(self) -> str:
        """UC::FString::ToWString @ ea0dab3."""
        if not self.is_valid():
            return ''
        start = address = self.Data
        buf, scan, bytewise_end = bytearray(), 0, 0
        while True:  # std::wstring(Data): up to the first NUL unit, in pieces that never cross a 0x1000 boundary
            if address < bytewise_end:
                buf += self._accessor_.read(address, 1)
            else:
                size = min(0x100, 0x1000 - (address & 0xFFF))
                try:
                    buf += self._accessor_.read(address, size)
                except MemoryReadError:  # bytes after the NUL may be unreadable: finish this piece byte by byte
                    bytewise_end = address + size
                    continue
            address = start + len(buf)
            while (i := buf.find(b'\0\0', scan)) >= 0:
                if i & 1 == 0:
                    return buf[:i].decode('utf-16-le', 'surrogatepass')
                scan = i + 1
            scan = max(scan, len(buf) - 1 & ~1)

    def to_string(self) -> str:
        """UC::FString::ToString @ ea0dab3."""
        if not self.is_valid():
            return ''
        units = self._accessor_.read(self.Data, (self.NumElements - 1) * 2)
        return utf_16_string_to_utf_8_string(units.decode('utf-16-le', 'surrogatepass'))


class FImplementedInterface(ViewStruct):
    """TImplementedInterface<UEClass> @ ea0dab3."""
    _size_ = 0x10
    InterfaceClass = SField(c_uint64, 0x0)
    PointerOffset = SField(c_int32, 0x8)
    bImplementedByK2 = SField(c_uint8, 0xC)


for _cls in (TArray, FImplementedInterface):  # finalised now, so FString always inherits TArray's _fields_
    check_finalize(_cls)
