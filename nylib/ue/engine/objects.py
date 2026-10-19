"""ObjectArray (GObjects) of Dumper-7 @ ea0dab3 over an Engine: finder, layouts, FUObjectItem, iteration, lookups."""
import dataclasses
import re
import struct
import typing
from typing import Callable, Iterator

from ..errors import DetectionError, MemoryReadError
from ..flags import EClassCastFlags
from .state import FChunkedFixedUObjectArrayLayout, FChunkedFixedUObjectArrayLayouts, FFixedUObjectArrayLayout, FFixedUObjectArrayLayouts
from .unreal import UEClass, UEObject, UEProperty, UEStruct

if typing.TYPE_CHECKING:
    from .core import Engine

_M32 = 0xFFFFFFFF
_I32 = struct.Struct('<i')
# A1 anchors: NumObjects in [0x1000, 0x400000] (fixed rows), NumChunks in [1, 0x14] (chunked rows)
_RE_FIXED_NUM = re.compile(rb'(?=(?:[\x00-\xff][\x10-\xff]\x00|[\x00-\xff][\x00-\xff][\x01-\x3f]|\x00\x00\x40)\x00)')
_RE_CHUNKED_NUM_CHUNKS = re.compile(rb'(?=[\x01-\x14]\x00\x00\x00)')


def _i32(value: int) -> int:
    return ((value + 0x80000000) & _M32) - 0x80000000


def _trunc_div(a: int, b: int) -> int:
    q = abs(a) // abs(b)
    return q if (a < 0) == (b < 0) else -q


def _identity(ptr: int) -> int:
    return ptr


def _null_by_index(objects_array, index, item_size, item_offset, per_chunk):
    raise MemoryReadError(0, 1, 'ObjectArray::ByIndex is nullptr (ObjectArray::Init has not run)')


def _fixed_counts_valid(max_elements: int, num_elements: int) -> bool:
    if num_elements > max_elements:
        return False
    if max_elements > 0x400000:
        return False
    if num_elements < 0x1000:
        return False
    return True


def _chunked_counts_valid(max_elements: int, num_elements: int, max_chunks: int, num_chunks: int) -> bool:
    if num_chunks > 0x14 or num_chunks < 0x1:
        return False
    if max_chunks > 0x5FF or max_chunks < 0x6:
        return False
    if num_elements <= 0x800 or max_elements <= 0x10000:
        return False
    if num_elements > max_elements or num_chunks > max_chunks:
        return False
    if (max_elements % 0x10) != 0:  # every operand below is positive here, so // and % match C++
        return False
    elements_per_chunk = max_elements // max_chunks
    if (elements_per_chunk % 0x10) != 0:
        return False
    if elements_per_chunk < 0x8000 or elements_per_chunk > 0x80000:
        return False
    if ((num_elements // elements_per_chunk) + 1) != num_chunks:
        return False
    if (max_elements // elements_per_chunk) != max_chunks:
        return False
    return True


def _is_address_valid_gobjects_fixed(e: 'Engine', address: int, layout: FFixedUObjectArrayLayout) -> bool:
    """IsAddressValidGObjects(uintptr_t, const FFixedUObjectArrayLayout&) @ ea0dab3."""
    mem, is_bad_read_ptr = e.mem, e.platform.is_bad_read_ptr
    objects = mem.ptr(address + layout.ObjectsOffset)
    max_elements = mem.i32(address + layout.MaxObjectsOffset)
    num_elements = mem.i32(address + layout.NumObjectsOffset)
    objects_but_decrypted = e.objects.DecryptPtr(objects)
    if not _fixed_counts_valid(max_elements, num_elements):
        return False
    if is_bad_read_ptr(objects_but_decrypted):
        return False
    if is_bad_read_ptr(mem.ptr(objects_but_decrypted + 5 * 0x18)):  # FUObjectItem { void* Object; uint8 Pad[0x10]; }
        return False
    fifth_object = mem.ptr(objects_but_decrypted + 5 * 0x18)
    if mem.i32(fifth_object + 8 + 4) != 0x5:  # FifthObject -> InternalIndex
        return False
    return True


def _is_address_valid_gobjects_chunked(e: 'Engine', address: int, layout: FChunkedFixedUObjectArrayLayout) -> bool:
    """IsAddressValidGObjects(uintptr_t, const FChunkedFixedUObjectArrayLayout&) @ ea0dab3."""
    mem, is_bad_read_ptr = e.mem, e.platform.is_bad_read_ptr
    objects = mem.ptr(address + layout.ObjectsOffset)
    max_elements = mem.i32(address + layout.MaxElementsOffset)
    num_elements = mem.i32(address + layout.NumElementsOffset)
    max_chunks = mem.i32(address + layout.MaxChunksOffset)
    num_chunks = mem.i32(address + layout.NumChunksOffset)
    objects_ptr_but_decrypted = e.objects.DecryptPtr(objects)
    if not _chunked_counts_valid(max_elements, num_elements, max_chunks, num_chunks):
        return False
    if not objects_ptr_but_decrypted or is_bad_read_ptr(objects_ptr_but_decrypted):
        return False
    for i in range(num_chunks):
        chunk = mem.ptr(objects_ptr_but_decrypted + i * 8)
        if not chunk or is_bad_read_ptr(chunk):
            return False
    return True


def _layout_window(layout) -> int:
    return max(layout.ObjectsOffset + 8, *(o + 4 for o in dataclasses.astuple(layout)))


def _gobjects_candidates(address: int, data) -> list[int]:
    """A1 provider: every address of the chunk where an IsAddressValidGObjects overload can pass its integer checks."""
    n = len(data)
    out = set()
    fixed_anchors = [m.start() for m in _RE_FIXED_NUM.finditer(data)]
    for layout in FFixedUObjectArrayLayouts:
        window = _layout_window(layout)
        for anchor in fixed_anchors:
            p = anchor - layout.NumObjectsOffset
            if p < 0 or p + window > n:
                continue
            if _fixed_counts_valid(_I32.unpack_from(data, p + layout.MaxObjectsOffset)[0], _I32.unpack_from(data, anchor)[0]):
                out.add(address + p)
    chunked_anchors = [m.start() for m in _RE_CHUNKED_NUM_CHUNKS.finditer(data)]
    for layout in FChunkedFixedUObjectArrayLayouts:
        window = _layout_window(layout)
        for anchor in chunked_anchors:
            p = anchor - layout.NumChunksOffset
            if p < 0 or p + window > n:
                continue
            max_chunks = _I32.unpack_from(data, p + layout.MaxChunksOffset)[0]
            if max_chunks > 0x5FF or max_chunks < 0x6:
                continue
            if _chunked_counts_valid(_I32.unpack_from(data, p + layout.MaxElementsOffset)[0], _I32.unpack_from(data, p + layout.NumElementsOffset)[0],
                                     max_chunks, _I32.unpack_from(data, anchor)[0]):
                out.add(address + p)
    tail = max(_layout_window(layout) for layout in (*FFixedUObjectArrayLayouts, *FChunkedFixedUObjectArrayLayouts))
    out.update(range(address + max(0, n - tail + 1), address + n))  # windows past the end of data cannot be ruled out
    return sorted(out)


class ObjectArray:
    """ObjectArray @ ea0dab3: its statics made per-engine."""
    __slots__ = ('e', 'GObjects', 'NumElementsPerChunk', 'SizeOfFUObjectItem', 'FUObjectItemInitialOffset', 'DecryptionLambdaStr', 'DecryptPtr',
                 '_ByIndex', '_index_key', '_indices')

    def __init__(self, e: 'Engine'):
        self.e = e
        self.GObjects = 0
        self.NumElementsPerChunk = 0x10000
        self.SizeOfFUObjectItem = 0x10
        self.FUObjectItemInitialOffset = 0x0
        self.DecryptionLambdaStr = ''
        self.DecryptPtr: Callable[[int], int] = _identity
        self._ByIndex = _null_by_index
        self._index_key = None
        self._indices = {}

    def _initialize_fuobject_item(self, first_item_ptr: int) -> None:
        """ObjectArray::InitializeFUObjectItem @ ea0dab3."""
        e = self.e
        mem, is_bad_read_ptr = e.mem, e.platform.is_bad_read_ptr
        for i in range(0x0, 0x20, 4):
            if not is_bad_read_ptr(mem.ptr(first_item_ptr + i)):
                self.FUObjectItemInitialOffset = i
                break
        for i in range(self.FUObjectItemInitialOffset + 8, 0x38 + 1, 4):
            second_object = mem.ptr(first_item_ptr + i)
            third_object = mem.ptr(first_item_ptr + (((i * 2) - self.FUObjectItemInitialOffset) & _M32))
            if (not is_bad_read_ptr(second_object) and not is_bad_read_ptr(mem.ptr(second_object))
                    and not is_bad_read_ptr(third_object) and not is_bad_read_ptr(mem.ptr(third_object))):
                self.SizeOfFUObjectItem = (i - self.FUObjectItemInitialOffset) & _M32
                break
        e.off.InSDK.ObjArray.FUObjectItemInitialOffset = _i32(self.FUObjectItemInitialOffset)
        e.provenance['Off.InSDK.ObjArray.FUObjectItemInitialOffset'] = 'auto: ObjectArray::InitializeFUObjectItem'
        e.off.InSDK.ObjArray.FUObjectItemSize = _i32(self.SizeOfFUObjectItem)
        e.provenance['Off.InSDK.ObjArray.FUObjectItemSize'] = 'auto: ObjectArray::InitializeFUObjectItem'
        # std::hex is always set on std::cerr before this runs (every caller streams it first)
        e.cerr(f'Off::InSDK::ObjArray::FUObjectItemSize: {e.off.InSDK.ObjArray.FUObjectItemSize & _M32:x}\n\n')

    def init_decryption(self, decrypt_ptr: Callable[[int], int], text: str = '') -> None:
        """ObjectArray::InitDecryption @ ea0dab3."""
        self.DecryptPtr = decrypt_ptr
        self.DecryptionLambdaStr = text

    def init(self, scan_all_memory: bool = False) -> None:
        """ObjectArray::Init(bool, const char*) @ ea0dab3."""
        e = self.e
        if not scan_all_memory:
            e.cerr('\nDumper-7 by me, you & him\n\n\n')
            e.cerr('Searching for GObjects...\n\n')

        def matches_any_layout(layouts, address: int) -> bool:
            for layout in layouts:
                if isinstance(layout, FFixedUObjectArrayLayout):
                    if not _is_address_valid_gobjects_fixed(e, address, layout):
                        continue
                    e.off.FUObjectArray.bIsChunked = False
                    e.provenance['Off.FUObjectArray.bIsChunked'] = 'auto: ObjectArray::Init'
                    e.off.FUObjectArray.FixedLayout = layout
                    e.provenance['Off.FUObjectArray.FixedLayout'] = 'auto: ObjectArray::Init'
                else:
                    if not _is_address_valid_gobjects_chunked(e, address, layout):
                        continue
                    e.off.FUObjectArray.bIsChunked = True
                    e.provenance['Off.FUObjectArray.bIsChunked'] = 'auto: ObjectArray::Init'
                    e.off.FUObjectArray.ChunkedFixedLayout = layout
                    e.provenance['Off.FUObjectArray.ChunkedFixedLayout'] = 'auto: ObjectArray::Init'
                return True
            return False

        is_gobjects_chunked = False

        def is_address_valid_gobjects(current_address: int) -> bool:
            nonlocal is_gobjects_chunked
            if matches_any_layout(FFixedUObjectArrayLayouts, current_address):
                is_gobjects_chunked = False
                return True
            elif matches_any_layout(FChunkedFixedUObjectArrayLayouts, current_address):
                is_gobjects_chunked = True
                return True
            return False

        if scan_all_memory:
            gobjects_address = e.platform.iterate_all_sections_with_callback(is_address_valid_gobjects, 0x4, 0x50, candidates=_gobjects_candidates)
        else:
            gobjects_address = e.platform.iterate_section_with_callback(e.platform.get_section_info('.data'), is_address_valid_gobjects, 0x4, 0x50,
                                                                        candidates=_gobjects_candidates)

        if gobjects_address:
            if not is_gobjects_chunked:
                self.GObjects = gobjects_address
                self.NumElementsPerChunk = -1 & _M32
                e.off.InSDK.ObjArray.GObjects = _i32(e.platform.get_offset(gobjects_address))
                e.provenance['Off.InSDK.ObjArray.GObjects'] = 'auto: ObjectArray::Init'
                e.cerr(f'Found FFixedUObjectArray GObjects at offset 0x{e.off.InSDK.ObjArray.GObjects & _M32:x}\n\n')
                self._ByIndex = self._by_index_fixed
                first_item = self.DecryptPtr(e.mem.ptr(self.GObjects + e.off.FUObjectArray.get_objects_offset()))
                self._initialize_fuobject_item(first_item)
            else:
                self.GObjects = gobjects_address
                max_elements, max_chunks = self.max(), self.max_chunks()
                self.NumElementsPerChunk = _i32(_trunc_div(max_elements, max_chunks)) & _M32
                e.off.InSDK.ObjArray.ChunkSize = _i32(self.NumElementsPerChunk)
                e.provenance['Off.InSDK.ObjArray.ChunkSize'] = 'auto: ObjectArray::Init'
                self.SizeOfFUObjectItem = 8 + 4 + 4
                self.FUObjectItemInitialOffset = 0x0
                e.off.InSDK.ObjArray.GObjects = _i32(e.platform.get_offset(gobjects_address))
                e.provenance['Off.InSDK.ObjArray.GObjects'] = 'auto: ObjectArray::Init'
                e.cerr(f'Found FChunkedFixedUObjectArray GObjects at offset 0x{e.off.InSDK.ObjArray.GObjects & _M32:x}\n\n')
                self._ByIndex = self._by_index_chunked
                chunks_ptr = self.DecryptPtr(e.mem.ptr(self.GObjects + e.off.FUObjectArray.get_objects_offset()))
                self._initialize_fuobject_item(e.mem.ptr(chunks_ptr))
            return

        if not scan_all_memory:
            self.init(True)
            return

        if self.GObjects == 0:
            text = "\nGObjects couldn't be found, please overwrite the offset in Generator.cpp.\n\n\n"
            e.cerr(text)
            raise DetectionError('ObjectArray::Init', text.rstrip('\n'), explanations=tuple(e.messages))

    def init_fixed(self, gobjects_offset: int, layout: FFixedUObjectArrayLayout = FFixedUObjectArrayLayout()) -> None:
        """ObjectArray::Init(int32, const FFixedUObjectArrayLayout&, const char*) @ ea0dab3."""
        e = self.e
        self.GObjects = e.platform.get_module_base() + gobjects_offset
        e.off.InSDK.ObjArray.GObjects = gobjects_offset
        e.provenance['Off.InSDK.ObjArray.GObjects'] = 'auto: ObjectArray::Init'
        e.cerr(f'GObjects: 0x{self.GObjects:016X}\n\n')
        e.off.FUObjectArray.bIsChunked = False
        e.provenance['Off.FUObjectArray.bIsChunked'] = 'auto: ObjectArray::Init'
        e.off.FUObjectArray.FixedLayout = layout if layout.is_valid() else FFixedUObjectArrayLayouts[0]
        e.provenance['Off.FUObjectArray.FixedLayout'] = 'auto: ObjectArray::Init'
        self._ByIndex = self._by_index_fixed_override
        chunks_ptr = self.DecryptPtr(e.mem.ptr(self.GObjects + e.off.FUObjectArray.get_objects_offset()))
        e.cerr(f'Overwrote FFixedUObjectArray GObjects to offset 0x{e.off.InSDK.ObjArray.GObjects & _M32:x}\n\n')
        self._initialize_fuobject_item(e.mem.ptr(chunks_ptr))

    def init_chunked(self, gobjects_offset: int, elements_per_chunk: int,
                     layout: FChunkedFixedUObjectArrayLayout = FChunkedFixedUObjectArrayLayout()) -> None:
        """ObjectArray::Init(int32, int32, const FChunkedFixedUObjectArrayLayout&, const char*) @ ea0dab3."""
        e = self.e
        self.GObjects = e.platform.get_module_base() + gobjects_offset
        e.off.InSDK.ObjArray.GObjects = gobjects_offset
        e.provenance['Off.InSDK.ObjArray.GObjects'] = 'auto: ObjectArray::Init'
        e.off.FUObjectArray.bIsChunked = True
        e.provenance['Off.FUObjectArray.bIsChunked'] = 'auto: ObjectArray::Init'
        e.off.FUObjectArray.ChunkedFixedLayout = layout if layout.is_valid() else FChunkedFixedUObjectArrayLayouts[0]
        e.provenance['Off.FUObjectArray.ChunkedFixedLayout'] = 'auto: ObjectArray::Init'
        self.NumElementsPerChunk = elements_per_chunk & _M32
        e.off.InSDK.ObjArray.ChunkSize = elements_per_chunk
        e.provenance['Off.InSDK.ObjArray.ChunkSize'] = 'auto: ObjectArray::Init'
        self._ByIndex = self._by_index_chunked_override
        chunks_ptr = self.DecryptPtr(e.mem.ptr(self.GObjects + e.off.FUObjectArray.get_objects_offset()))
        e.cerr(f'Overwrote FChunkedFixedUObjectArray GObjects to offset 0x{e.off.InSDK.ObjArray.GObjects & _M32:x}\n\n')
        self._initialize_fuobject_item(e.mem.ptr(chunks_ptr))

    def _by_index_fixed(self, objects_array: int, index: int, item_size: int, item_offset: int, per_chunk: int) -> int:
        """ByIndex of ObjectArray::Init(bool), FFixedUObjectArray @ ea0dab3."""
        if index < 0 or index > self.num():
            return 0
        chunk_ptr = self.DecryptPtr(self.e.mem.ptr(objects_array))
        return self.e.mem.ptr(chunk_ptr + item_offset + ((index * item_size) & _M32))

    def _by_index_chunked(self, objects_array: int, index: int, item_size: int, item_offset: int, per_chunk: int) -> int:
        """ByIndex of ObjectArray::Init(bool), FChunkedFixedUObjectArray @ ea0dab3."""
        if index < 0 or index > self.num():
            return 0
        chunk_index = _i32((index & _M32) // per_chunk)
        in_chunk_idx = _i32((index & _M32) % per_chunk)
        chunk_ptr = self.DecryptPtr(self.e.mem.ptr(objects_array))
        chunk = self.e.mem.ptr(chunk_ptr + chunk_index * 8)
        item_ptr = chunk + ((in_chunk_idx * item_size) & _M32)
        return self.e.mem.ptr(item_ptr + item_offset)

    def _by_index_fixed_override(self, objects_array: int, index: int, item_size: int, item_offset: int, per_chunk: int) -> int:
        """ByIndex of ObjectArray::Init(int32, const FFixedUObjectArrayLayout&) @ ea0dab3 (no DecryptPtr)."""
        if index < 0 or index > self.num():
            return 0
        item_ptr = self.e.mem.ptr(objects_array) + ((index * item_size) & _M32)
        return self.e.mem.ptr(item_ptr + item_offset)

    def _by_index_chunked_override(self, objects_array: int, index: int, item_size: int, item_offset: int, per_chunk: int) -> int:
        """ByIndex of ObjectArray::Init(int32, int32, const FChunkedFixedUObjectArrayLayout&) @ ea0dab3 (no DecryptPtr)."""
        if index < 0 or index > self.num():
            return 0
        chunk_index = _i32((index & _M32) // per_chunk)
        in_chunk_idx = _i32((index & _M32) % per_chunk)
        chunk = self.e.mem.ptr(self.e.mem.ptr(objects_array) + chunk_index * 8)
        item_ptr = chunk + ((in_chunk_idx * item_size) & _M32)
        return self.e.mem.ptr(item_ptr + item_offset)

    def num(self) -> int:
        """ObjectArray::Num @ ea0dab3."""
        return self.e.mem.i32(self.GObjects + self.e.off.FUObjectArray.get_num_elements_offset())

    def max(self) -> int:
        """ObjectArray::Max @ ea0dab3."""
        return self.e.mem.i32(self.GObjects + self.e.off.FUObjectArray.get_max_elements_offset())

    def num_chunks(self) -> int:
        """ObjectArray::NumChunks @ ea0dab3."""
        return self.e.mem.i32(self.GObjects + self.e.off.FUObjectArray.get_num_chunks_offset())

    def max_chunks(self) -> int:
        """ObjectArray::MaxChunks @ ea0dab3."""
        return self.e.mem.i32(self.GObjects + self.e.off.FUObjectArray.get_max_chunks_offset())

    def get_by_index(self, index: int) -> UEObject:
        """ObjectArray::GetByIndex<UEObject> @ ea0dab3."""
        address = self._ByIndex(self.GObjects + self.e.off.FUObjectArray.get_objects_offset(), index, self.SizeOfFUObjectItem,
                                self.FUObjectItemInitialOffset, self.NumElementsPerChunk)
        return UEObject(self.e, address)

    def __iter__(self) -> Iterator[UEObject]:
        """Range-for over ObjectArray::begin() / end() @ ea0dab3."""
        end = _ObjectsIterator(self, self.num())
        it = _ObjectsIterator(self, 0, end.CurrentIndex)
        while it.CurrentIndex < end.CurrentIndex:  # DV27
            yield it.CurrentObject
            it.increment()

    def _lookup(self, kind: str, key) -> list[UEObject]:
        """A6: objects whose name of `kind` equals `key`, in iteration order."""
        e = self.e
        state = (e.off.UObject.Name, e.off.UObject.Outer, e.off.UObject.Class, e.off.FName.CompIdx, e.off.FName.Number,
                 e.settings.Internal.bUseOutlineNumberName, e.settings.Internal.bUseCasePreservingName, e.names.FNameBlockOffsetBits,
                 self.GObjects, self.DecryptPtr, self._ByIndex, self.SizeOfFUObjectItem, self.FUObjectItemInitialOffset, self.NumElementsPerChunk,
                 e.off.FUObjectArray.bIsChunked, e.off.FUObjectArray.FixedLayout, e.off.FUObjectArray.ChunkedFixedLayout)
        if state != self._index_key:
            self._index_key, self._indices = state, {}
        if (index := self._indices.get(kind)) is None:
            index = {}
            unreadable = 0
            for obj in self:
                try:
                    if kind == 'name':
                        name = obj.get_name()
                    elif kind == 'outer':
                        name = (obj.get_name(), obj.get_outer().get_name())
                    else:
                        name = obj.get_full_name()
                except MemoryReadError:
                    unreadable += 1
                    continue
                index.setdefault(name, []).append(obj)
            if unreadable:
                e.cerr(f'A6: {unreadable} unreadable objects left out of the {kind} index\n')
            self._indices[kind] = index
        return index.get(key, [])

    def find_object(self, full_name: str, required_type: int = 0) -> UEObject:
        """ObjectArray::FindObject<UEObject> @ ea0dab3 (A6)."""
        for obj in self._lookup('full', full_name):
            if obj.is_a(required_type):
                return obj
        return UEObject(self.e, 0)

    def find_object_fast(self, name: str, required_type: int = 0) -> UEObject:
        """ObjectArray::FindObjectFast<UEObject> @ ea0dab3 (A6)."""
        for obj in self._lookup('name', name):
            if obj.is_a(required_type):
                return obj
        return UEObject(self.e, 0)

    def find_object_fast_in_outer(self, name: str, outer: str) -> UEObject:
        """ObjectArray::FindObjectFastInOuter<UEObject> @ ea0dab3 (A6)."""
        matches = self._lookup('outer', (name, outer))
        return matches[0] if matches else UEObject(self.e, 0)

    def find_struct(self, name: str) -> UEStruct:
        """ObjectArray::FindStruct @ ea0dab3."""
        return self.find_object_fast(name, EClassCastFlags.Struct).cast(UEStruct)

    def find_struct_fast(self, name: str) -> UEStruct:
        """ObjectArray::FindStructFast @ ea0dab3."""
        return self.find_object_fast(name, EClassCastFlags.Struct).cast(UEStruct)

    def find_class(self, full_name: str) -> UEClass:
        """ObjectArray::FindClass @ ea0dab3."""
        return self.find_object(full_name, EClassCastFlags.Class).cast(UEClass)

    def find_class_fast(self, name: str) -> UEClass:
        """ObjectArray::FindClassFast @ ea0dab3."""
        return self.find_object_fast(name, EClassCastFlags.Class).cast(UEClass)


class _ObjectsIterator:
    """ObjectArray::ObjectsIterator @ ea0dab3; DV27: with end_index, its steps never pass end_index."""
    __slots__ = ('objects', 'CurrentObject', 'CurrentIndex', 'EndIndex')

    def __init__(self, objects: ObjectArray, start_index: int = 0, end_index: int | None = None):
        self.objects = objects
        self.CurrentObject = objects.get_by_index(start_index)
        self.CurrentIndex = start_index
        self.EndIndex = end_index

    def _num(self) -> int:
        num = self.objects.num()
        return num if self.EndIndex is None else min(num, self.EndIndex)

    def increment(self) -> None:
        """ObjectsIterator::operator++ @ ea0dab3."""
        objects = self.objects
        self.CurrentIndex += 1
        self.CurrentObject = objects.get_by_index(self.CurrentIndex)
        while not self.CurrentObject and self.CurrentIndex < (self._num() - 1):
            self.CurrentIndex += 1
            self.CurrentObject = objects.get_by_index(self.CurrentIndex)
        if not self.CurrentObject and self.CurrentIndex == (self._num() - 1):
            self.CurrentIndex += 1

    def __eq__(self, other) -> bool:
        return self.CurrentIndex == other.CurrentIndex

    def __ne__(self, other) -> bool:
        return self.CurrentIndex != other.CurrentIndex


class _AllFieldCursor:
    """The AllFieldIterator object of ObjectArray.h @ ea0dab3 (default and StartPos constructors)."""
    __slots__ = ('ObjectEndIterator', 'CurrentObject', 'Fields', 'PropertyIndex')

    def __init__(self, e: 'Engine', start_pos: _ObjectsIterator | None = None):
        objects = e.objects
        self.ObjectEndIterator = _ObjectsIterator(objects, objects.num())  # members initialise in declaration order
        self.CurrentObject = _ObjectsIterator(objects, 0, self.ObjectEndIterator.CurrentIndex) if start_pos is None else start_pos
        self.Fields: list[UEProperty] = []
        self.PropertyIndex = 0
        if start_pos is None and not self._is_current_object_struct():
            self._iterate_to_next_struct_with_members()

    def __ne__(self, other) -> bool:
        return self.CurrentObject != other.CurrentObject or self.PropertyIndex != other.PropertyIndex

    def increment(self) -> None:
        """AllFieldIterator::operator++ @ ea0dab3."""
        if self._curren_struct_has_more_members():
            self.PropertyIndex += 1
            return
        self._iterate_to_next_struct_with_members()

    def deref(self) -> UEProperty:
        """AllFieldIterator::operator* @ ea0dab3."""
        return self.Fields[self.PropertyIndex]

    def _iterate_to_next_struct(self) -> None:
        if self._is_end_iterator():
            return
        self.CurrentObject.increment()
        while self.CurrentObject != self.ObjectEndIterator and not self._is_current_object_struct():
            self.CurrentObject.increment()

    def _iterate_to_next_struct_with_members(self) -> None:
        while not self._curren_struct_has_more_members():
            self._iterate_to_next_struct()
            self.PropertyIndex = 0
            if self._is_end_iterator():
                return
            self.Fields = self._get_current_struct().get_properties()

    def _curren_struct_has_more_members(self) -> bool:
        return (self.PropertyIndex + 1) < len(self.Fields)

    def _get_current_struct(self) -> UEStruct:
        return self.CurrentObject.CurrentObject.cast(UEStruct)

    def _is_current_object_struct(self) -> bool:
        return self.CurrentObject.CurrentObject.is_a(EClassCastFlags.Struct)

    def _is_end_iterator(self) -> bool:
        return self.CurrentObject == self.ObjectEndIterator


class AllFieldIterator:
    """AllFieldIterator @ ea0dab3: yields every UEProperty of every struct with members, in object order."""

    def __init__(self, e: 'Engine'):
        self.e = e

    def __iter__(self) -> Iterator[UEProperty]:
        """Range-for over AllFieldIterator::begin() / end() @ ea0dab3."""
        it = _AllFieldCursor(self.e)
        end = _AllFieldCursor(self.e, _ObjectsIterator(self.e.objects, it.ObjectEndIterator.CurrentIndex))  # DV27
        while it != end:
            yield it.deref()
            it.increment()
