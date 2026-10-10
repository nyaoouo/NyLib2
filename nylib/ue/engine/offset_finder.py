"""OffsetFinder of Dumper-7 @ ea0dab3 (plus dd8fe34's FindFieldClassCastFlagsOffset) over an Engine."""
import struct
import typing
from typing import Callable, Iterable, Sequence

from ..flags import EClassCastFlags, EFunctionFlags, EObjectFlags, EPropertyFlags
from .accessor import view
from .containers import FImplementedInterface, TArray
from .objects import AllFieldIterator
from .platform import align
from .unreal import UEFunction, UEObject, UEStruct

if typing.TYPE_CHECKING:
    from .core import Engine

OffsetNotFound = -1
OffsetFinderMinValue = 0x28

_M32 = 0xFFFFFFFF
_U64 = 0xFFFFFFFFFFFFFFFF
_READERS = frozenset({'u8', 'i8', 'u16', 'i16', 'u32', 'i32', 'u64', 'i64', 'ptr'})
_F32 = struct.Struct('<f')


def _i32(value: int) -> int:
    return ((value + 0x80000000) & _M32) - 0x80000000


def _f32(value: float) -> float:
    return _F32.unpack(_F32.pack(value))[0]


def find_offset(e: 'Engine', pairs: Sequence[tuple[int, int]], min_offset: int = OffsetFinderMinValue, max_offset: int = 0x1A0, *,
                alignment: int = 4, reader: str = 'i32') -> int:
    """OffsetFinder::FindOffset<Alignement, T> @ ea0dab3; `reader` names the MemorySource reader of T."""
    if reader not in _READERS:
        raise ValueError(f'unknown reader {reader!r}')
    if alignment < 1:
        raise ValueError(f'alignment must be >= 1, got {alignment}')
    read = getattr(e.mem, reader)
    highest_found_offset = min_offset
    found_offset = False
    i = 0
    while i < len(pairs):
        address, value = pairs[i]
        if not address:
            e.cerr(f'Dumper-7 ERROR: FindOffset is skipping ObjectValuePair[{i:x}] because .first is nullptr.\n')
            i += 1
            continue
        j = highest_found_offset
        while j < max_offset:
            if read(address + j) == value and j >= highest_found_offset:
                found_offset = True
                if j > highest_found_offset:
                    highest_found_offset = j
                    i = 0  # the for-increment follows: the restart is at pair 1
                j = max_offset
            j += alignment
        i += 1
    return highest_found_offset if found_offset else OffsetNotFound


def get_valid_pointer_offset(e: 'Engine', obj_a: int, obj_b: int, starting_offset: int, max_offset: int,
                             needs_to_be_in_process_memory: bool = False, *, check_for_vft: bool = True) -> int:
    """OffsetFinder::GetValidPointerOffset<bCheckForVft> @ ea0dab3."""
    mem, platform = e.mem, e.platform
    is_bad_read_ptr = platform.is_bad_read_ptr
    if is_bad_read_ptr(obj_a) or is_bad_read_ptr(obj_b):
        return OffsetNotFound
    j = starting_offset
    while j <= max_offset:
        ptr_a = mem.ptr(obj_a + j)
        is_a_valid = not is_bad_read_ptr(ptr_a) and (not is_bad_read_ptr(mem.ptr(ptr_a)) if check_for_vft else True)
        ptr_b = mem.ptr(obj_b + j)
        is_b_valid = not is_bad_read_ptr(ptr_b) and (not is_bad_read_ptr(mem.ptr(ptr_b)) if check_for_vft else True)
        if needs_to_be_in_process_memory:
            if not platform.is_address_in_process_range(ptr_a) or not platform.is_address_in_process_range(ptr_b):
                j += 8
                continue
        if is_a_valid and is_b_valid:
            return j
        j += 8
    return OffsetNotFound


def msvc_rand(e: 'Engine') -> int:
    """MSVC CRT rand() on e.statics['rand'] (absent = the initial state 1)."""
    state = (e.statics.get('rand', 1) * 214013 + 2531011) & _M32
    e.statics['rand'] = state
    return (state >> 16) & 0x7FFF


# UObject

def find_uobject_flags_offset(e: 'Engine') -> int:
    """OffsetFinder::FindUObjectFlagsOffset @ ea0dab3 (DV1)."""
    enum_flag_value_to_search = 0x43
    min_num_flag_values_required_at_offset = 0xA0
    for i in range(0x20):
        offset = 0x0
        while offset != OffsetNotFound:
            offset = find_offset(e, [(e.objects.get_by_index(i).get_address(), enum_flag_value_to_search)], offset, 0x40)
            if offset == OffsetNotFound:
                break
            num_objects_with_flag_at_offset = 0x0
            counter = 0
            for obj in e.objects:
                if counter == 0x100:
                    break
                counter += 1
                if e.mem.i32(obj.get_address() + offset) == enum_flag_value_to_search:
                    num_objects_with_flag_at_offset += 1
            if num_objects_with_flag_at_offset > min_num_flag_values_required_at_offset:
                return offset
            offset += 4  # DV1: the next position on FindOffset's 4-byte grid
    return OffsetNotFound


def find_uobject_index_offset(e: 'Engine') -> int:
    """OffsetFinder::FindUObjectIndexOffset @ ea0dab3."""
    infos = [(e.objects.get_by_index(0x055).get_address(), 0x055), (e.objects.get_by_index(0x123).get_address(), 0x123)]
    return find_offset(e, infos, 8)


def find_uobject_class_offset(e: 'Engine') -> int:
    """OffsetFinder::FindUObjectClassOffset @ ea0dab3."""
    mem, is_bad_read_ptr = e.mem, e.platform.is_bad_read_ptr

    def is_valid_cyclic_uclass_ptr_offset(obj_a: int, obj_b: int, class_ptr_offset: int) -> bool:
        next_class_a, next_class_b = obj_a, obj_b
        for _ in range(0x10):
            current_class_a, current_class_b = next_class_a, next_class_b
            next_class_a = mem.ptr(next_class_a + class_ptr_offset)
            next_class_b = mem.ptr(next_class_b + class_ptr_offset)
            if not next_class_a or not next_class_b or is_bad_read_ptr(next_class_a) or is_bad_read_ptr(next_class_b):
                return False
            if current_class_a == next_class_a and current_class_b == next_class_b:
                return True
        return False

    obj_a = e.objects.get_by_index(0x055).get_address()
    obj_b = e.objects.get_by_index(0x123).get_address()
    offset = 0
    while offset != OffsetNotFound:
        offset = get_valid_pointer_offset(e, obj_a, obj_b, offset + 8, 0x50)
        if is_valid_cyclic_uclass_ptr_offset(obj_a, obj_b, offset):
            return offset
    return OffsetNotFound


def find_name_offset_for_some_class(e: 'Engine', is_potential_valid_offset: Callable[[int], bool], items: Iterable) -> int:
    """FindNameOffsetForSomeClass @ ea0dab3 (A7; DV13: no object considered gives OffsetNotFound)."""
    max_allowed_comparison_index_value = 0x4000000
    max_allowed_average_comparison_index_value = max_allowed_comparison_index_value // 2
    min_allowed_average_comparison_index_value = 0x280
    low_comparison_index_upper_cap = 0x10
    max_allowed_names_with_low_cmp_idx = 0x40

    # [Offset, NumNamesWithLowCmpIdx, TotalValue, bIsValidCmpIdxRange]
    possible_offsets = [[i, 0x0, 0x0, True] for i in range(8, 0x40 + 1, 4) if is_potential_valid_offset(i)]
    num_objects_considered = 0
    for item in items:
        current_object_or_field = item.address
        if (current_object_or_field & (0x1000 - 1)) > (0x1000 - 0x44):
            continue
        num_objects_considered += 1
        if not possible_offsets:
            continue
        data = e.mem.read(current_object_or_field, 0x44)
        for info in possible_offsets:
            value_at_offset = int.from_bytes(data[info[0]:info[0] + 4], 'little')
            info[2] = (info[2] + value_at_offset) & _U64
            info[3] = info[3] and value_at_offset < max_allowed_comparison_index_value
            info[1] += value_at_offset <= low_comparison_index_upper_cap
    if num_objects_considered == 0:
        return OffsetNotFound
    first_valid_offset = -1
    for offset, num_names_with_low_cmp_idx, total_value, is_valid_cmp_idx_range in possible_offsets:
        average_value = total_value // num_objects_considered
        if (is_valid_cmp_idx_range and num_names_with_low_cmp_idx <= max_allowed_names_with_low_cmp_idx
                and min_allowed_average_comparison_index_value <= average_value <= max_allowed_average_comparison_index_value):
            if first_valid_offset == -1:
                first_valid_offset = offset
                continue
            e.cerr(f'Dumper-7: Another [UObject/FField]::Name offset (0x{offset:04X}) is also considered valid.\n')
    return first_valid_offset


def find_uobject_name_offset(e: 'Engine') -> int:
    """OffsetFinder::FindUObjectNameOffset @ ea0dab3."""
    uobject = e.off.UObject

    def is_potentially_valid_offset(offset: int) -> bool:
        return (offset != uobject.Class and offset != (uobject.Class + 4)
                and offset != uobject.Outer and offset != (uobject.Outer + 4)
                and offset != uobject.Flags
                and offset != uobject.Index
                and offset != uobject.Vft and offset != (uobject.Vft + 4))

    return find_name_offset_for_some_class(e, is_potentially_valid_offset, e.objects)


def find_uobject_outer_offset(e: 'Engine') -> int:
    """OffsetFinder::FindUObjectOuterOffset @ ea0dab3 (K12)."""
    lowest_found_offset = 0xFFFF
    for _ in range(0x10):
        offset = 0
        obj_a = e.objects.get_by_index(msvc_rand(e) % 0x400).get_address()
        obj_b = e.objects.get_by_index(msvc_rand(e) % 0x400).get_address()
        while offset != OffsetNotFound:
            offset = get_valid_pointer_offset(e, obj_a, obj_b, offset + 8, 0x50)
            if offset != e.off.UObject.Class and offset != e.off.UObject.Index:
                break
        if offset != OffsetNotFound and offset < lowest_found_offset:
            lowest_found_offset = offset
    return OffsetNotFound if lowest_found_offset == 0xFFFF else lowest_found_offset


def fixup_hardcoded_offsets(e: 'Engine') -> None:
    """OffsetFinder::FixupHardcodedOffsets @ ea0dab3."""
    label = 'auto: OffsetFinder::FixupHardcodedOffsets'
    off, internal, prov = e.off, e.settings.Internal, e.provenance
    if internal.bUseCasePreservingName:
        off.FField.Flags = _i32(off.FField.Flags + 0x8)
        prov['Off.FField.Flags'] = label
        off.FFieldClass.Id = _i32(off.FFieldClass.Id + 0x08)
        prov['Off.FFieldClass.Id'] = label
        off.FFieldClass.CastFlags = _i32(off.FFieldClass.CastFlags + 0x08)
        prov['Off.FFieldClass.CastFlags'] = label
        off.FFieldClass.ClassFlags = _i32(off.FFieldClass.ClassFlags + 0x08)
        prov['Off.FFieldClass.ClassFlags'] = label
        off.FFieldClass.SuperClass = _i32(off.FFieldClass.SuperClass + 0x08)
        prov['Off.FFieldClass.SuperClass'] = label
    if internal.bUseFProperty:
        offset_to_check = off.FField.Owner + 0x8
        objects, mem = e.objects, e.mem
        possible_next_ptr_or_bool_0 = mem.ptr(objects.find_class_fast('Actor').get_child_properties().get_address() + offset_to_check)
        possible_next_ptr_or_bool_1 = mem.ptr(objects.find_class_fast('ActorComponent').get_child_properties().get_address() + offset_to_check)
        possible_next_ptr_or_bool_2 = mem.ptr(objects.find_class_fast('Pawn').get_child_properties().get_address() + offset_to_check)

        def is_valid_ptr(a: int) -> bool:
            return not e.platform.is_bad_read_ptr(a) and (a & 0x1) == 0

        if is_valid_ptr(possible_next_ptr_or_bool_0) and is_valid_ptr(possible_next_ptr_or_bool_1) and is_valid_ptr(possible_next_ptr_or_bool_2):
            e.cerr('Applaying fix to hardcoded offsets \n\n')
            internal.bUseMaskForFieldOwner = True
            prov['Settings.Internal.bUseMaskForFieldOwner'] = label
            off.FField.Next = _i32(off.FField.Next - 0x08)
            prov['Off.FField.Next'] = label
            off.FField.Name = _i32(off.FField.Name - 0x08)
            prov['Off.FField.Name'] = label
            off.FField.Flags = _i32(off.FField.Flags - 0x08)
            prov['Off.FField.Flags'] = label


def init_fname_settings(e: 'Engine') -> None:
    """OffsetFinder::InitFNameSettings @ ea0dab3 (C0.4: float threshold)."""
    label = 'auto: OffsetFinder::InitFNameSettings'
    off, internal, prov = e.off, e.settings.Internal, e.provenance
    first_object = e.objects.get_by_index(0)
    name_address = first_object.get_fname().get_address()
    fname_first_int = e.mem.i32(name_address)
    fname_second_int = e.mem.i32(name_address + 0x4)
    if not internal.bIsObjectNameBeforeClass:
        fname_size = _i32(off.UObject.Outer - off.UObject.Name)
    else:
        fname_size = _i32(off.UObject.Class - off.UObject.Name)
    off.FName.CompIdx = 0x0
    prov['Off.FName.CompIdx'] = label
    off.FName.Number = 0x4
    prov['Off.FName.Number'] = label

    def get_num_names_with_number_one_to_four() -> int:
        names_with_number_one_to_four = 0x0
        for obj in e.objects:
            number = obj.get_fname().get_number()
            if 0x0 < number < 0x5:
                names_with_number_one_to_four += 1
        return names_with_number_one_to_four

    fname_number_threashold = _i32(int(_f32(_f32(float(e.objects.num())) * _f32(0.03))))
    off.FName.CompIdx = 0x0
    prov['Off.FName.CompIdx'] = label
    if fname_size == 0x8 and fname_first_int == fname_second_int:
        internal.bUseCasePreservingName = True
        prov['Settings.Internal.bUseCasePreservingName'] = label
        internal.bUseOutlineNumberName = True
        prov['Settings.Internal.bUseOutlineNumberName'] = label
        off.FName.Number = -0x1
        prov['Off.FName.Number'] = label
        off.InSDK.Name.FNameSize = 0x8
        prov['Off.InSDK.Name.FNameSize'] = label
    elif fname_size == 0x10:
        internal.bUseCasePreservingName = True
        prov['Settings.Internal.bUseCasePreservingName'] = label
        off.FName.Number = 0x8 if fname_first_int == fname_second_int else 0x4
        prov['Off.FName.Number'] = label
        off.InSDK.Name.FNameSize = 0xC
        prov['Off.InSDK.Name.FNameSize'] = label
    elif get_num_names_with_number_one_to_four() < fname_number_threashold:
        internal.bUseOutlineNumberName = True
        prov['Settings.Internal.bUseOutlineNumberName'] = label
        off.FName.Number = -0x1
        prov['Off.FName.Number'] = label
        off.InSDK.Name.FNameSize = 0x4
        prov['Off.InSDK.Name.FNameSize'] = label
    else:
        off.FName.Number = 0x4
        prov['Off.FName.Number'] = label
        off.InSDK.Name.FNameSize = 0x8
        prov['Off.InSDK.Name.FNameSize'] = label


def post_init_fname_settings(e: 'Engine') -> None:
    """OffsetFinder::PostInitFNameSettings @ ea0dab3."""
    label = 'auto: OffsetFinder::PostInitFNameSettings'
    off, internal, prov = e.off, e.settings.Internal, e.provenance
    player_start = e.objects.find_class_fast('PlayerStart')
    fname_size = player_start.find_member('PlayerStartTag').get_size()
    if off.InSDK.Name.FNameSize == fname_size:
        return
    off.FField.Flags = _i32((off.FField.Flags - off.InSDK.Name.FNameSize) + fname_size)
    prov['Off.FField.Flags'] = label
    name_address = player_start.get_fname().get_address()
    fname_first_int = e.mem.i32(name_address)
    fname_second_int = e.mem.i32(name_address + 0x4)
    if fname_size == 0x8 and fname_first_int == fname_second_int:
        internal.bUseCasePreservingName = True
        prov['Settings.Internal.bUseCasePreservingName'] = label
        internal.bUseOutlineNumberName = True
        prov['Settings.Internal.bUseOutlineNumberName'] = label
        off.FName.Number = -0x1
        prov['Off.FName.Number'] = label
        off.InSDK.Name.FNameSize = 0x8
        prov['Off.InSDK.Name.FNameSize'] = label
    elif fname_size > 0x8:
        internal.bUseOutlineNumberName = False
        prov['Settings.Internal.bUseOutlineNumberName'] = label
        internal.bUseCasePreservingName = True
        prov['Settings.Internal.bUseCasePreservingName'] = label
        off.FName.Number = 0x8 if fname_first_int == fname_second_int else 0x4
        prov['Off.FName.Number'] = label
        off.InSDK.Name.FNameSize = 0xC
        prov['Off.InSDK.Name.FNameSize'] = label
    elif fname_size == 0x4:
        internal.bUseOutlineNumberName = True
        prov['Settings.Internal.bUseOutlineNumberName'] = label
        internal.bUseCasePreservingName = False
        prov['Settings.Internal.bUseCasePreservingName'] = label
        off.FName.Number = -0x1
        prov['Off.FName.Number'] = label
        off.InSDK.Name.FNameSize = 0x4
        prov['Off.InSDK.Name.FNameSize'] = label
    else:
        internal.bUseOutlineNumberName = False
        prov['Settings.Internal.bUseOutlineNumberName'] = label
        internal.bUseCasePreservingName = False
        prov['Settings.Internal.bUseCasePreservingName'] = label
        off.FName.Number = 0x4
        prov['Off.FName.Number'] = label
        off.InSDK.Name.FNameSize = 0x8
        prov['Off.InSDK.Name.FNameSize'] = label


# UField

def find_ufield_next_offset(e: 'Engine') -> int:
    """OffsetFinder::FindUFieldNextOffset @ ea0dab3."""
    kismet_system_library_child = e.objects.find_object_fast('KismetSystemLibrary').cast(UEStruct).get_child().get_address()
    kismet_string_library_child = e.objects.find_object_fast('KismetStringLibrary').cast(UEStruct).get_child().get_address()
    uobject = e.off.UObject
    highest_uobject_offset = max(uobject.Index, uobject.Name, uobject.Flags, uobject.Outer, uobject.Class)
    return get_valid_pointer_offset(e, kismet_system_library_child, kismet_string_library_child, align(highest_uobject_offset + 0x4, 8), 0x60)


# FField

def find_ffield_next_offset(e: 'Engine') -> int:
    """OffsetFinder::FindFFieldNextOffset @ ea0dab3."""
    guid_children = e.objects.find_struct_fast('Guid').get_child_properties().get_address()
    vector_children = e.objects.find_struct_fast('Vector').get_child_properties().get_address()
    return get_valid_pointer_offset(e, guid_children, vector_children, e.off.FField.Owner + 0x8, 0x48)


def find_ffield_name_offset(e: 'Engine') -> int:
    """OffsetFinder::FindFFieldNameOffset @ ea0dab3."""
    label = 'auto: OffsetFinder::FindFFieldNameOffset'
    ffield = e.off.FField
    guid_child = e.objects.find_struct_fast('Guid').get_child_properties()
    vector_child = e.objects.find_struct_fast('Vector').get_child_properties()
    guid_child_name = guid_child.get_name()
    vector_child_name = vector_child.get_name()
    if guid_child_name in ('A', 'D') and vector_child_name in ('X', 'Z'):
        return ffield.Name
    ffield.Name = ffield.Owner
    e.provenance['Off.FField.Name'] = label
    while ffield.Name < 0x40:
        guid_child_name = guid_child.get_name()
        vector_child_name = vector_child.get_name()
        if guid_child_name in ('A', 'D') and vector_child_name in ('X', 'Z'):
            return ffield.Name
        ffield.Name = _i32(ffield.Name + 4)
        e.provenance['Off.FField.Name'] = label
    return OffsetNotFound


def new_find_ffield_name_offset(e: 'Engine') -> int:
    """OffsetFinder::NewFindFFieldNameOffset @ ea0dab3."""
    ffield = e.off.FField

    def is_potentially_valid_offset(offset: int) -> bool:
        return (offset != ffield.Class and offset != (ffield.Class + 4)
                and offset != ffield.Next and offset != (ffield.Next + 4)
                and offset != ffield.Vft and offset != (ffield.Vft + 4))

    return find_name_offset_for_some_class(e, is_potentially_valid_offset, AllFieldIterator(e))


def find_ffield_class_offset(e: 'Engine') -> int:
    """OffsetFinder::FindFFieldClassOffset @ ea0dab3."""
    guid_child = e.objects.find_struct_fast('Guid').get_child_properties()
    vector_child = e.objects.find_struct_fast('Vector').get_child_properties()
    return get_valid_pointer_offset(e, guid_child.get_address(), vector_child.get_address(), 0x8, 0x30, True, check_for_vft=False)


def inialize_uenum_settings(e: 'Engine', enum_obj: int, uenum_num_values_offset: int) -> None:
    """InializeUEnumSettings @ ea0dab3 (the offset is a uint32_t parameter; TPair read field by field)."""
    label = 'auto: InializeUEnumSettings'
    mem, internal, is_bad_read_ptr = e.mem, e.settings.Internal, e.platform.is_bad_read_ptr
    uenum_num_values_offset &= _M32
    possible_value_array_tagged_ptr = mem.u64((enum_obj + uenum_num_values_offset - 8) & _U64)
    possible_value_array_ptr = possible_value_array_tagged_ptr & ~0x1 & _U64
    if (not is_bad_read_ptr(possible_value_array_ptr) and not is_bad_read_ptr(possible_value_array_ptr + 8)
            and not is_bad_read_ptr(possible_value_array_ptr + 16)):
        if mem.i64(possible_value_array_ptr) == 0 and mem.i64(possible_value_array_ptr + 8) == 1 and mem.i64(possible_value_array_ptr + 16) == 2:
            internal.bIsNewUE5EnumNamesContainer = True
            e.provenance['Settings.Internal.bIsNewUE5EnumNamesContainer'] = label
            return
    array_address = (enum_obj + uenum_num_values_offset - 0x8) & _U64

    def init_enum_settings(name_size: int) -> None:
        array_of_name_value_pairs = view(TArray, array_address, e.acc)
        pair_size = name_size + 8  # TPair<NameType, int64>: First, then Second
        if mem.i64(array_of_name_value_pairs.element_address(1, pair_size) + name_size) == 1:
            return
        if e.settings.EngineCore.bCheckEnumNamesInUEnum:
            if (mem.u8(array_of_name_value_pairs.element_address(1, pair_size) + name_size) == 1
                    and mem.u8(array_of_name_value_pairs.element_address(2, pair_size) + name_size) == 2):
                internal.bIsSmallEnumValue = True
                e.provenance['Settings.Internal.bIsSmallEnumValue'] = label
                return
        internal.bIsEnumNameOnly = True
        e.provenance['Settings.Internal.bIsEnumNameOnly'] = label

    if internal.bUseCasePreservingName:
        init_enum_settings(0x10)
    else:
        init_enum_settings(0x08)


# UEnum

def find_enum_names_offset(e: 'Engine') -> int:
    """OffsetFinder::FindEnumNamesOffset @ ea0dab3."""
    objects = e.objects
    infos = [(objects.find_object_fast('ENetRole', EClassCastFlags.Enum).get_address(), 0x5),
             (objects.find_object_fast('ETraceTypeQuery', EClassCastFlags.Enum).get_address(), 0x22)]
    uenum_num_values_offset = find_offset(e, infos)
    if uenum_num_values_offset == OffsetNotFound:
        infos[0] = (objects.find_object_fast('EAlphaBlendOption', EClassCastFlags.Enum).get_address(), 0x10)
        infos[1] = (objects.find_object_fast('EUpdateRateShiftBucket', EClassCastFlags.Enum).get_address(), 0x8)
        uenum_num_values_offset = find_offset(e, infos)
    inialize_uenum_settings(e, infos[0][0], uenum_num_values_offset)
    return _i32(uenum_num_values_offset - 8)


# UStruct

def find_super_offset(e: 'Engine') -> int:
    """OffsetFinder::FindSuperOffset @ ea0dab3."""
    objects = e.objects
    infos = [[objects.find_object_fast('Struct').get_address(), objects.find_object_fast('Field').get_address()],
             [objects.find_object_fast('Class').get_address(), objects.find_object_fast('Struct').get_address()]]
    if infos[0][0] == 0:
        infos[0][0] = infos[1][1] = objects.find_object_fast('struct').get_address()
    return find_offset(e, infos, reader='ptr')


def find_child_offset(e: 'Engine') -> int:
    """OffsetFinder::FindChildOffset @ ea0dab3."""
    objects = e.objects
    if objects.find_object('ObjectProperty Engine.Controller.TransformComponent', EClassCastFlags.ObjectProperty):
        infos = [(objects.find_object_fast('Vector').get_address(), objects.find_object_fast_in_outer('X', 'Vector').get_address()),
                 (objects.find_object_fast('Vector4').get_address(), objects.find_object_fast_in_outer('X', 'Vector4').get_address()),
                 (objects.find_object_fast('Vector2D').get_address(), objects.find_object_fast_in_outer('X', 'Vector2D').get_address()),
                 (objects.find_object_fast('Guid').get_address(), objects.find_object_fast_in_outer('A', 'Guid').get_address())]
        return find_offset(e, infos, 0x14, reader='ptr')
    infos = [(objects.find_object_fast('PlayerController').get_address(),
              objects.find_object_fast_in_outer('WasInputKeyJustReleased', 'PlayerController').get_address()),
             (objects.find_object_fast('Controller').get_address(), objects.find_object_fast_in_outer('UnPossess', 'Controller').get_address())]
    e.settings.Internal.bUseFProperty = True
    e.provenance['Settings.Internal.bUseFProperty'] = 'auto: OffsetFinder::FindChildOffset'
    return find_offset(e, infos, reader='ptr')


def find_child_properties_offset(e: 'Engine') -> int:
    """OffsetFinder::FindChildPropertiesOffset @ ea0dab3."""
    obj_a = e.objects.find_struct_fast('Color').get_address()
    obj_b = e.objects.find_struct_fast('Guid').get_address()
    return get_valid_pointer_offset(e, obj_a, obj_b, e.off.UStruct.Children + 0x08, 0x80)


def find_struct_size_offset(e: 'Engine') -> int:
    """OffsetFinder::FindStructSizeOffset @ ea0dab3."""
    infos = [(e.objects.find_object_fast('Color').get_address(), 0x04), (e.objects.find_object_fast('Guid').get_address(), 0x10)]
    return find_offset(e, infos)


def find_min_alignment_offset(e: 'Engine') -> int:
    """OffsetFinder::FindMinAlignmentOffset @ ea0dab3 (x64 branch)."""
    infos = [(e.objects.find_object_fast('Transform').get_address(), 0x10), (e.objects.find_object_fast('PlayerController').get_address(), 0x8)]
    return find_offset(e, infos, reader='i16')


# UFunction

def find_function_flags_offset(e: 'Engine') -> int:
    """OffsetFinder::FindFunctionFlagsOffset @ ea0dab3."""
    objects, flags = e.objects, EFunctionFlags
    infos = [[objects.find_object_fast('WasInputKeyJustPressed', EClassCastFlags.Function).get_address(),
              int(flags.Final | flags.Native | flags.Public | flags.BlueprintCallable | flags.BlueprintPure | flags.Const)],
             [objects.find_object_fast('ToggleSpeaking', EClassCastFlags.Function).get_address(), int(flags.Exec | flags.Native | flags.Public)],
             [objects.find_object_fast('SwitchLevel', EClassCastFlags.Function).get_address(), int(flags.Exec | flags.Native | flags.Public)]]
    if infos[2][0] == 0:
        infos[2][0] = objects.find_object_fast('FOV', EClassCastFlags.Function).get_address()
    ret = find_offset(e, infos, reader='u32')
    if ret != OffsetNotFound:
        return ret
    for info in infos:
        info[1] |= int(flags.RequiredAPI)
    return find_offset(e, infos, reader='u32')


def find_function_native_func_offset(e: 'Engine') -> int:
    """OffsetFinder::FindFunctionNativeFuncOffset @ ea0dab3."""
    objects, mem, in_process_range = e.objects, e.mem, e.platform.is_address_in_process_range
    was_input_key_just_pressed = objects.find_object_fast('WasInputKeyJustPressed', EClassCastFlags.Function).get_address()
    toggle_speaking = objects.find_object_fast('ToggleSpeaking', EClassCastFlags.Function).get_address()
    switch_level_or_fov = objects.find_object_fast('SwitchLevel', EClassCastFlags.Function).get_address()
    if switch_level_or_fov == 0:
        switch_level_or_fov = objects.find_object_fast('FOV', EClassCastFlags.Function).get_address()
    for i in range(0x30, 0x140, 8):
        if (in_process_range(mem.ptr(was_input_key_just_pressed + i)) and in_process_range(mem.ptr(toggle_speaking + i))
                and in_process_range(mem.ptr(switch_level_or_fov + i))):
            return i
    return 0x0


# UClass

def find_cast_flags_offset(e: 'Engine') -> int:
    """OffsetFinder::FindCastFlagsOffset @ ea0dab3."""
    flags = EClassCastFlags
    infos = [(e.objects.find_object_fast('Actor').get_address(), int(flags.Actor)),
             (e.objects.find_object_fast('Class').get_address(), int(flags.Field | flags.Struct | flags.Class))]
    return find_offset(e, infos, reader='u64')


def find_default_object_offset(e: 'Engine') -> int:
    """OffsetFinder::FindDefaultObjectOffset @ ea0dab3."""
    objects = e.objects
    infos = [(objects.find_class_fast('Object').get_address(), objects.find_object_fast('Default__Object').get_address()),
             (objects.find_class_fast('Field').get_address(), objects.find_object_fast('Default__Field').get_address())]
    return find_offset(e, infos, 0x28, 0x200, reader='ptr')


def find_implemented_interfaces_offset(e: 'Engine') -> int:
    """OffsetFinder::FindImplementedInterfacesOffset @ ea0dab3."""
    interface_asset_user_data_class = e.objects.find_class_fast('Interface_AssetUserData')
    actor_component_class_ptr = e.objects.find_class_fast('ActorComponent').get_address()
    for i in range(e.off.UClass.ClassDefaultObject, (0x350 - 0x10) + 1, 8):
        actor_array = view(TArray, actor_component_class_ptr + i, e.acc)
        if actor_array.is_valid() and not e.platform.is_bad_read_ptr(actor_array.get_data_ptr()):
            if view(FImplementedInterface, actor_array.element_address(0, 0x10), e.acc).InterfaceClass == interface_asset_user_data_class.get_address():
                return i
    return OffsetNotFound


# Property

def find_element_size_offset(e: 'Engine') -> int:
    """OffsetFinder::FindElementSizeOffset @ ea0dab3."""
    guid = e.objects.find_struct_fast('Guid')
    infos = [(guid.find_member('A').get_address(), 0x04), (guid.find_member('C').get_address(), 0x04), (guid.find_member('D').get_address(), 0x04)]
    return find_offset(e, infos)


def find_array_dim_offset(e: 'Engine') -> int:
    """OffsetFinder::FindArrayDimOffset @ ea0dab3."""
    guid = e.objects.find_struct_fast('Guid')
    infos = [(guid.find_member('A').get_address(), 0x01), (guid.find_member('C').get_address(), 0x01), (guid.find_member('D').get_address(), 0x01)]
    min_offset = _i32(e.off.Property.ElementSize - 0x10)
    max_offset = _i32(e.off.Property.ElementSize + 0x10)
    return find_offset(e, infos, min_offset, max_offset)


def find_property_flags_offset(e: 'Engine') -> int:
    """OffsetFinder::FindPropertyFlagsOffset @ ea0dab3."""
    flags = EPropertyFlags
    guid = e.objects.find_struct_fast('Guid')
    color = e.objects.find_struct_fast('Color')
    guid_member_flags = int(flags.Edit | flags.ZeroConstructor | flags.SaveGame | flags.IsPlainOldData | flags.NoDestructor | flags.HasGetValueTypeHash)
    color_member_flags = int(flags.Edit | flags.BlueprintVisible | flags.ZeroConstructor | flags.SaveGame | flags.IsPlainOldData | flags.NoDestructor
                             | flags.HasGetValueTypeHash)
    infos = [[guid.find_member('A').get_address(), guid_member_flags], [color.find_member('R').get_address(), color_member_flags]]
    if infos[1][0] == 0:
        infos[1][0] = color.find_member('r').get_address()
    flags_offset = find_offset(e, infos, reader='u64')
    if flags_offset == OffsetNotFound:
        infos[0][1] |= int(flags.NativeAccessSpecifierPublic)
        infos[1][1] |= int(flags.NativeAccessSpecifierPublic)
        flags_offset = find_offset(e, infos, reader='u64')
    return flags_offset


def find_offset_internal_offset(e: 'Engine') -> int:
    """OffsetFinder::FindOffsetInternalOffset @ ea0dab3."""
    color = e.objects.find_struct_fast('Color')
    guid = e.objects.find_struct_fast('Guid')
    infos = [(color.find_member('B').get_address(), 0x00), (color.find_member('G').get_address(), 0x01), (guid.find_member('C').get_address(), 0x08)]
    if infos[2][0] == 0:
        infos[2] = (color.find_member('r').get_address(), infos[2][1])
    return find_offset(e, infos)


# BoolProperty

def find_bool_property_base_offset(e: 'Engine') -> int:
    """OffsetFinder::FindBoolPropertyBaseOffset @ ea0dab3."""
    engine = e.objects.find_class_fast('Engine')
    infos = [(engine.find_member('bIsOverridingSelectedColor').get_address(), 0xFF),
             (engine.find_member('bEnableOnScreenDebugMessagesDisplay').get_address(), 0b00000010),
             (e.objects.find_class_fast('PlayerController').find_member('bAutoManageActiveCameraTarget').get_address(), 0xFF)]
    return _i32(find_offset(e, infos, e.off.Property.Offset_Internal, alignment=1, reader='u8') - 0x3)


# ObjectProperty

def find_object_property_class_offset(e: 'Engine') -> int:
    """OffsetFinder::FindObjectPropertyClassOffset @ ea0dab3."""
    objects = e.objects
    controller = objects.find_class_fast('Controller')
    infos = [(controller.find_member('PlayerState').get_address(), objects.find_class_fast('PlayerState').get_address()),
             (controller.find_member('Pawn').get_address(), objects.find_class_fast('Pawn').get_address()),
             (objects.find_class_fast('World').find_member('PersistentLevel').get_address(), objects.find_class_fast('Level').get_address())]
    return find_offset(e, infos, e.off.Property.Offset_Internal, reader='ptr')


# EnumProperty

def find_enum_property_base_offset(e: 'Engine') -> int:
    """OffsetFinder::FindEnumPropertyBaseOffset @ ea0dab3."""
    objects = e.objects
    component_creation_method = objects.find_object_fast('EComponentCreationMethod', EClassCastFlags.Enum).get_address()
    auto_possess_ai = objects.find_object_fast('EAutoPossessAI', EClassCastFlags.Enum).get_address()
    if not component_creation_method or not auto_possess_ai:
        return OffsetNotFound
    creation_method_member = objects.find_class_fast('ActorComponent').find_member('CreationMethod', EClassCastFlags.EnumProperty).get_address()
    auto_possess_ai_member = objects.find_class_fast('Pawn').find_member('AutoPossessAI', EClassCastFlags.EnumProperty).get_address()
    if not creation_method_member or not auto_possess_ai_member:
        return OffsetNotFound
    infos = [(creation_method_member, component_creation_method), (auto_possess_ai_member, auto_possess_ai)]
    return _i32(find_offset(e, infos, e.off.Property.Offset_Internal, reader='ptr') - 8)


# ByteProperty

def find_byte_property_enum_offset(e: 'Engine') -> int:
    """OffsetFinder::FindBytePropertyEnumOffset @ ea0dab3."""
    collision_response_enum = e.objects.find_object_fast('ECollisionResponse', EClassCastFlags.Enum).get_address()
    collision_response_container = e.objects.find_struct_fast('CollisionResponseContainer')
    if not collision_response_enum or not collision_response_container:
        return OffsetNotFound
    game_trace_channel_1 = collision_response_container.find_member('GameTraceChannel1', EClassCastFlags.ByteProperty).get_address()
    game_trace_channel_2 = collision_response_container.find_member('GameTraceChannel2', EClassCastFlags.ByteProperty).get_address()
    if not game_trace_channel_1 or not game_trace_channel_2:
        return OffsetNotFound
    infos = [(game_trace_channel_1, collision_response_enum), (game_trace_channel_2, collision_response_enum)]
    return find_offset(e, infos, e.off.Property.Offset_Internal, reader='ptr')


# StructProperty

def find_struct_property_struct_offset(e: 'Engine') -> int:
    """OffsetFinder::FindStructPropertyStructOffset @ ea0dab3."""
    vector_class = e.objects.find_struct_fast('Vector').get_address()
    if vector_class == 0:
        vector_class = e.objects.find_class_fast('vector').get_address()
    two_vectors_struct = e.objects.find_struct_fast('TwoVectors')
    if not vector_class or not two_vectors_struct:
        return OffsetNotFound
    v1 = two_vectors_struct.find_member('v1', EClassCastFlags.StructProperty).get_address()
    v2 = two_vectors_struct.find_member('v2', EClassCastFlags.StructProperty).get_address()
    if not v1 or not v2:
        return OffsetNotFound
    return find_offset(e, [(v1, vector_class), (v2, vector_class)], e.off.Property.Offset_Internal, reader='ptr')


# DelegateProperty

def find_delegate_property_signature_function_offset(e: 'Engine') -> int:
    """OffsetFinder::FindDelegatePropertySignatureFunctionOffset @ ea0dab3."""
    objects = e.objects
    delegate_signature = objects.find_object_fast('TimerDynamicDelegate__DelegateSignature', EClassCastFlags.Function).get_address()
    two_vectors_struct = objects.find_struct_fast('TwoVectors')
    if not delegate_signature or not two_vectors_struct:
        return OffsetNotFound
    delegate_1 = (objects.find_object_fast('K2_GetTimerElapsedTimeDelegate', EClassCastFlags.Function).cast(UEFunction)
                  .find_member('Delegate', EClassCastFlags.DelegateProperty).get_address())
    delegate_2 = (objects.find_object_fast('K2_GetTimerRemainingTimeDelegate', EClassCastFlags.Function).cast(UEFunction)
                  .find_member('Delegate', EClassCastFlags.DelegateProperty).get_address())
    if not delegate_1 or not delegate_2:
        return OffsetNotFound
    return find_offset(e, [(delegate_1, delegate_signature), (delegate_2, delegate_signature)], e.off.Property.Offset_Internal, reader='ptr')


# ArrayProperty, SetProperty, MapProperty

def find_inner_type_offset(e: 'Engine', property_size: int) -> int:
    """OffsetFinder::FindInnerTypeOffset @ ea0dab3."""
    if not e.settings.Internal.bUseFProperty:
        return property_size
    if prop := e.objects.find_class_fast('GameViewportClient').find_member('DebugProperties', EClassCastFlags.ArrayProperty):
        if e.platform.is_bad_read_ptr(e.mem.ptr(prop.get_address() + property_size)):
            return _i32(property_size + 8)
    return property_size


def find_set_property_base_offset(e: 'Engine', property_size: int) -> int:
    """OffsetFinder::FindSetPropertyBaseOffset @ ea0dab3."""
    if not e.settings.Internal.bUseFProperty:
        return property_size
    if obj := e.objects.find_struct_fast('LevelCollection').find_member('Levels', EClassCastFlags.SetProperty):
        if e.platform.is_bad_read_ptr(e.mem.ptr(obj.get_address() + property_size)):
            return _i32(property_size + 8)
    return property_size


def find_map_property_base_offset(e: 'Engine', property_size: int) -> int:
    """OffsetFinder::FindMapPropertyBaseOffset @ ea0dab3."""
    if not e.settings.Internal.bUseFProperty:
        return property_size
    if obj := e.objects.find_class_fast('UserDefinedEnum').find_member('DisplayNameMap', EClassCastFlags.MapProperty):
        if e.platform.is_bad_read_ptr(e.mem.ptr(obj.get_address() + property_size)):
            return _i32(property_size + 8)
    return property_size


# InSDK

def find_level_actors_offset(e: 'Engine') -> int:
    """OffsetFinder::FindLevelActorsOffset @ ea0dab3."""
    level = UEObject(e, 0)
    lvl = 0x0
    for obj in e.objects:
        if obj.has_any_flags(EObjectFlags.ClassDefaultObject) or not obj.is_a(EClassCastFlags.Level):
            continue
        level = obj
        lvl = obj.get_address()
        break
    if lvl == 0x0:
        return OffsetNotFound
    uobject_class = e.objects.find_class_fast('Object')
    if not uobject_class:
        uobject_class = e.objects.find_class_fast('object')
    furl_struct = e.objects.find_object_fast('URL', EClassCastFlags.Struct).cast(UEStruct)
    level_owning_world_property = level.get_class().find_member('OwningWorld')
    if not uobject_class or not furl_struct or not level_owning_world_property:
        return OffsetNotFound
    search_start = _i32(uobject_class.get_struct_size() + furl_struct.get_struct_size())
    search_end = level_owning_world_property.get_offset()
    for i in range(search_start, _i32(search_end - 0x10) + 1, 8):
        actor_array = view(TArray, lvl + i, e.acc)
        if actor_array.is_valid() and not e.platform.is_bad_read_ptr(actor_array.get_data_ptr()):
            return i
    return OffsetNotFound


def find_datatable_row_map_offset(e: 'Engine') -> int:
    """OffsetFinder::FindDatatableRowMapOffset @ ea0dab3."""
    data_table = e.objects.find_class_fast('DataTable')
    uobject_outer_size = 8
    row_struct_size = 8
    if not data_table:
        e.cerr('\nDumper-7: [DataTable] Couldn\'t find "DataTable" class, assuming default layout.\n\n')
        return _i32(e.off.UObject.Outer + uobject_outer_size + row_struct_size)
    row_struct_prop = data_table.find_member('RowStruct', EClassCastFlags.ObjectProperty)
    if not row_struct_prop:
        e.cerr('\nDumper-7: [DataTable] Couldn\'t find "RowStruct" property, assuming default layout.\n\n')
        return _i32(e.off.UObject.Outer + uobject_outer_size + row_struct_size)
    return _i32(row_struct_prop.get_offset() + row_struct_prop.get_size())


def find_field_class_cast_flags_offset(e: 'Engine') -> int:
    """OffsetFinder::FindFieldClassCastFlagsOffset @ dd8fe34 (Q23 = A); 0x10 when not found."""
    flags = EClassCastFlags
    guid_child = e.objects.find_struct_fast('Guid').get_child_properties()
    colour_child = e.objects.find_struct_fast('Color').get_child_properties()
    infos = [(guid_child.get_class().get_address(), int(flags.Field | flags.Property | flags.NumericProperty | flags.IntProperty)),
             (colour_child.get_class().get_address(), int(flags.Field | flags.Property | flags.NumericProperty | flags.ByteProperty))]
    offset = find_offset(e, infos, 8, 0x30, reader='u64')
    return offset if offset != OffsetNotFound else 0x10
