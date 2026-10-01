"""UnrealObjects.h/.cpp of Dumper-7 @ ea0dab3: the UObject / FField wrappers over a MemorySource."""
import typing

from ..errors import DetectionError
from ..flags import EClassCastFlags, EPropertyFlags
from .accessor import view
from .containers import TArray
from .gnames import FName

if typing.TYPE_CHECKING:
    from .core import Engine

_U32 = 0xFFFFFFFF
_U64 = 0xFFFFFFFFFFFFFFFF


class UEFFieldClass:
    """UEFFieldClass @ ea0dab3."""
    __slots__ = ('e', 'address')

    def __init__(self, e: 'Engine', address: int):
        self.e = e
        self.address = address

    def get_address(self) -> int: return self.address

    def __bool__(self) -> bool: return self.address != 0

    def __eq__(self, other):
        return self.address == other.address if isinstance(other, UEFFieldClass) else NotImplemented

    def __hash__(self): return hash(self.address)

    def get_id(self) -> int: return self.e.mem.u64(self.address + self.e.off.FFieldClass.Id)

    def get_cast_flags(self) -> int: return self.e.mem.u64(self.address + self.e.off.FFieldClass.CastFlags)

    def get_class_flags(self) -> int: return self.e.mem.u32(self.address + self.e.off.FFieldClass.ClassFlags)

    def get_super(self) -> 'UEFFieldClass': return UEFFieldClass(self.e, self.e.mem.ptr(self.address + self.e.off.FFieldClass.SuperClass))

    def get_fname(self) -> FName: return FName(self.e, self.address + self.e.off.FFieldClass.Name)

    def is_type(self, flags: int) -> bool: return bool(self.get_cast_flags() & flags) if flags != 0 else True

    def get_name(self) -> str: return self.get_fname().to_string() if self.address else 'None'

    def get_valid_name(self) -> str: return self.get_fname().to_valid_string() if self.address else 'None'

    def get_cpp_name(self) -> str: return 'F' + self.get_valid_name()


class UEFField:
    """UEFField @ ea0dab3."""
    __slots__ = ('e', 'address')

    def __init__(self, e: 'Engine', address: int):
        self.e = e
        self.address = address

    def get_address(self) -> int: return self.address

    def get_flags(self) -> int: return self.e.mem.u32(self.address + self.e.off.FField.Flags)

    def get_owner_as_uobject(self) -> 'UEObject':
        if self.is_owner_uobject():
            if self.e.settings.Internal.bUseMaskForFieldOwner:
                return UEObject(self.e, self.e.mem.u64(self.address + self.e.off.FField.Owner) & (~0x1 & _U64))
            return UEObject(self.e, self.e.mem.ptr(self.address + self.e.off.FField.Owner))
        return UEObject(self.e, 0)

    def get_owner_as_ffield(self) -> 'UEFField':
        if not self.is_owner_uobject():
            return UEFField(self.e, self.e.mem.ptr(self.address + self.e.off.FField.Owner))
        return UEFField(self.e, 0)

    def get_owner_uobject(self) -> 'UEObject':
        field = UEFField(self.e, self.address)
        while not field.is_owner_uobject() and field.get_owner_as_ffield():
            field = field.get_owner_as_ffield()
        return field.get_owner_as_uobject()

    def get_class(self) -> UEFFieldClass: return UEFFieldClass(self.e, self.e.mem.ptr(self.address + self.e.off.FField.Class))

    def get_fname(self) -> FName: return FName(self.e, self.address + self.e.off.FField.Name)

    def get_next(self) -> 'UEFField': return UEFField(self.e, self.e.mem.ptr(self.address + self.e.off.FField.Next))

    def cast(self, cls: type):
        return cls(self.e, self.address)

    def is_owner_uobject(self) -> bool:
        if self.e.settings.Internal.bUseMaskForFieldOwner:
            return bool(self.e.mem.u64(self.address + self.e.off.FField.Owner) & 0x1)
        return self.e.mem.u8(self.address + self.e.off.FField.Owner + 0x8) != 0

    def is_a(self, flags: int) -> bool: return self.get_class().is_type(flags) if flags != 0 else True

    def get_name(self) -> str: return self.get_fname().to_string() if self.address else 'None'

    def get_valid_name(self) -> str: return self.get_fname().to_valid_string() if self.address else 'None'

    def get_cpp_name(self) -> str:
        """UEFField::GetCppName @ ea0dab3."""
        statics = self.e.statics
        if 'UEFField.GetCppName.ActorClass' not in statics:
            statics['UEFField.GetCppName.ActorClass'] = self.e.objects.find_class_fast('Actor')
        if 'UEFField.GetCppName.InterfaceClass' not in statics:
            statics['UEFField.GetCppName.InterfaceClass'] = self.e.objects.find_class_fast('Interface')
        actor_class = statics['UEFField.GetCppName.ActorClass']
        interface_class = statics['UEFField.GetCppName.InterfaceClass']

        temp = self.get_valid_name()
        if self.is_a(EClassCastFlags.Class):
            if self.cast(UEClass).has_type(actor_class):
                return 'A' + temp
            elif self.cast(UEClass).has_type(interface_class):
                return 'I' + temp
            return 'U' + temp
        return 'F' + temp

    def __bool__(self) -> bool: return self.address != 0 and (self.address + self.e.off.FField.Class) & _U64 != 0

    def __eq__(self, other):
        return self.address == other.address if isinstance(other, UEFField) else NotImplemented

    def __hash__(self): return hash(self.address)


class UEObject:
    """UEObject @ ea0dab3."""
    __slots__ = ('e', 'address')

    def __init__(self, e: 'Engine', address: int):
        self.e = e
        self.address = address

    def get_address(self) -> int: return self.address

    def get_vft(self) -> int: return self.e.mem.ptr(self.address)

    def get_flags(self) -> int: return self.e.mem.u32(self.address + self.e.off.UObject.Flags)

    def get_index(self) -> int: return self.e.mem.i32(self.address + self.e.off.UObject.Index)

    def get_class(self) -> 'UEClass': return UEClass(self.e, self.e.mem.ptr(self.address + self.e.off.UObject.Class))

    def get_fname(self) -> FName: return FName(self.e, self.address + self.e.off.UObject.Name)

    def get_outer(self) -> 'UEObject': return UEObject(self.e, self.e.mem.ptr(self.address + self.e.off.UObject.Outer))

    def get_package_index(self) -> int: return self.get_outermost().get_index()

    def has_any_flags(self, flags: int) -> bool: return bool(self.get_flags() & flags)

    def is_a(self, type_flags: int) -> bool: return self.get_class().is_type(type_flags) if type_flags != 0 else True

    def is_a_class(self, cls: 'UEClass') -> bool:
        """UEObject::IsA(UEClass) @ ea0dab3."""
        if not cls:
            return False
        clss = self.get_class()
        while clss:
            if clss == cls:
                return True
            clss = clss.get_super().cast(UEClass)
        return False

    def get_outermost(self) -> 'UEObject':
        outermost = UEObject(self.e, self.address)
        outer = UEObject(self.e, self.address)
        while outer:
            outermost = outer
            outer = outer.get_outer()
        return outermost

    def get_name(self) -> str: return self.get_fname().to_string() if self.address else 'None'

    def get_name_with_path(self) -> str: return self.get_fname().to_raw_string() if self.address else 'None'

    def get_valid_name(self) -> str: return self.get_fname().to_valid_string() if self.address else 'None'

    def get_cpp_name(self) -> str:
        """UEObject::GetCppName @ ea0dab3."""
        statics = self.e.statics
        if 'UEObject.GetCppName.ActorClass' not in statics:
            statics['UEObject.GetCppName.ActorClass'] = UEClass(self.e, 0)
        if 'UEObject.GetCppName.InterfaceClass' not in statics:
            statics['UEObject.GetCppName.InterfaceClass'] = UEClass(self.e, 0)
        if statics['UEObject.GetCppName.ActorClass'].address == 0:
            statics['UEObject.GetCppName.ActorClass'] = self.e.objects.find_class_fast('Actor')
        if statics['UEObject.GetCppName.InterfaceClass'].address == 0:
            statics['UEObject.GetCppName.InterfaceClass'] = self.e.objects.find_class_fast('Interface')

        temp = self.get_valid_name()
        if self.is_a(EClassCastFlags.Class):
            if self.cast(UEClass).has_type(statics['UEObject.GetCppName.ActorClass']):
                return 'A' + temp
            elif self.cast(UEClass).has_type(statics['UEObject.GetCppName.InterfaceClass']):
                return 'I' + temp
            return 'U' + temp
        return 'F' + temp

    def get_full_name_with_length(self) -> tuple[str, int]:
        """UEObject::GetFullName(int32&) @ ea0dab3; the length is 0 where the C++ leaves it unassigned."""
        if self:
            temp = ''
            outer = self.get_outer()
            while outer:
                temp = outer.get_name() + '.' + temp
                outer = outer.get_outer()
            name = self.get_name()
            out_name_length = len(name.encode('utf-8')) + 1  # std::string::size() counts UTF-8 bytes
            name =self.get_class().get_name() + ' ' + temp + name
            return name, out_name_length
        return 'None', 0

    def get_full_name(self) -> str:
        """UEObject::GetFullName() @ ea0dab3."""
        if self:
            temp = ''
            outer = self.get_outer()
            while outer:
                temp = outer.get_name() + '.' + temp
                outer = outer.get_outer()
            name = self.get_class().get_name()
            name += ' '
            name += temp
            name += self.get_name()
            return name
        return 'None'

    def get_path_name(self) -> str:
        """UEObject::GetPathName @ ea0dab3."""
        if self:
            temp = ''
            outer = self.get_outer()
            while outer:
                temp = outer.get_name_with_path() + '.' + temp
                outer = outer.get_outer()
            name = self.get_class().get_name_with_path()
            name += ' '
            name += temp
            name += self.get_name_with_path()
            return name
        return 'None'

    def __bool__(self) -> bool: return self.address != 0 and (self.address + self.e.off.UObject.Class) & _U64 != 0

    def __eq__(self, other):
        return self.address == other.address if isinstance(other, UEObject) else NotImplemented

    def __hash__(self): return hash(self.address)

    def cast(self, cls: type):
        return cls(self.e, self.address)


class UEField(UEObject):
    """UEField @ ea0dab3."""
    __slots__ = ()

    def get_next(self) -> 'UEField': return UEField(self.e, self.e.mem.ptr(self.address + self.e.off.UField.Next))

    def is_next_valid(self) -> bool: return bool(self.get_next())


class UEEnum(UEField):
    """UEEnum @ ea0dab3."""
    __slots__ = ()

    def _get_name_value_pairs_for_fname_data(self, enum_names_offset: int, fname_size: int) -> list[tuple[FName, int]]:
        mem = self.e.mem
        ret = []
        tagged_names_ptr = mem.u64(self.address + enum_names_offset)
        is_names_ptr_tagged = (tagged_names_ptr & 0x1) != 0
        names_ptr = tagged_names_ptr & (~0x1 & _U64)
        if not is_names_ptr_tagged:
            text = 'Dumper-7 [UEEnum::GetNameValuePairs()]: UEnum::Names pointer is tagged! This is not supported yet!'
            self.e.cerr(text + '\n')
            raise DetectionError('UEEnum::GetNameValuePairs', text, explanations=tuple(self.e.messages))
        values = mem.u64(self.address + enum_names_offset + 0x8) & (~0x1 & _U64)
        num_values = mem.i32(self.address + enum_names_offset + 0x10)
        i = 0
        while i < (num_values & _U32):
            ret.append((FName(self.e, names_ptr + ((i * fname_size) & _U32)), mem.i64(values + i * 8)))
            i += 1
        return ret

    def _get_name_value_pairs_with_index(self, name_size: int, small_value: bool) -> list[tuple[FName, int]]:
        mem = self.e.mem
        ret = []
        pairs = view(TArray, self.address + self.e.off.UEnum.Names, self.e.acc)
        element_size = name_size + 8  # TPair<NameXXByte, int64 | UInt8As64>
        i = 0
        while i < pairs.num():
            element = pairs.element_address(i, element_size)
            ret.append((FName(self.e, element), mem.u8(element + name_size) if small_value else mem.i64(element + name_size)))
            i += 1
        return ret

    def _get_name_value_pairs_names_only(self, name_size: int) -> list[tuple[FName, int]]:
        ret = []
        names = view(TArray, self.address + self.e.off.UEnum.Names, self.e.acc)
        i = 0
        while i < names.num():
            ret.append((FName(self.e, names.element_address(i, name_size)), i))
            i += 1
        return ret

    def get_name_value_pairs(self) -> list[tuple[FName, int]]:
        """UEEnum::GetNameValuePairs @ ea0dab3 (DV9 kept, DV10)."""
        internal = self.e.settings.Internal
        if internal.bIsNewUE5EnumNamesContainer:
            return self._get_name_value_pairs_for_fname_data((self.e.off.UEnum.Names - 0x8) & _U32, self.e.off.InSDK.Name.FNameSize & _U32)

        if self.e.settings.EngineCore.bCheckEnumNamesInUEnum:
            internal.bIsEnumNameOnly = False
            self.e.provenance['Settings.Internal.bIsEnumNameOnly'] = 'auto: UEEnum::GetNameValuePairs'

        name_size = 0x10 if internal.bUseCasePreservingName else 0x08
        if internal.bIsEnumNameOnly:
            return self._get_name_value_pairs_names_only(name_size)
        return self._get_name_value_pairs_with_index(name_size, internal.bIsSmallEnumValue)

    def get_single_name(self, index: int) -> str:
        pairs = self.get_name_value_pairs()
        if not 0 <= index < len(pairs):
            raise IndexError(f'enum name index {index} out of range ({len(pairs)} names)')
        return pairs[index][0].to_string()


class UEStruct(UEField):
    """UEStruct @ ea0dab3."""
    __slots__ = ()

    def get_super(self) -> 'UEStruct': return UEStruct(self.e, self.e.mem.ptr(self.address + self.e.off.UStruct.SuperStruct))

    def get_child(self) -> UEField: return UEField(self.e, self.e.mem.ptr(self.address + self.e.off.UStruct.Children))

    def get_child_properties(self) -> UEFField: return UEFField(self.e, self.e.mem.ptr(self.address + self.e.off.UStruct.ChildProperties))

    def get_struct_size(self) -> int: return self.e.mem.i32(self.address + self.e.off.UStruct.Size)

    def get_min_alignment(self) -> int: return self.e.mem.i16(self.address + self.e.off.UStruct.MinAlignment)

    def has_type(self, type_: 'UEStruct') -> bool:
        if type_.address == 0:
            return False
        s = UEStruct(self.e, self.address)
        while s:
            if s == type_:
                return True
            s = s.get_super()
        return False

    def get_properties(self) -> list['UEProperty']:
        """UEStruct::GetProperties @ ea0dab3."""
        properties = []
        if self.e.settings.Internal.bUseFProperty:
            field = self.get_child_properties()
            while field:
                if field.is_a(EClassCastFlags.Property):
                    properties.append(field.cast(UEProperty))
                field = field.get_next()
            return properties
        field = self.get_child()
        while field:
            if field.is_a(EClassCastFlags.Property):
                properties.append(field.cast(UEProperty))
            field = field.get_next()
        return properties

    def get_functions(self) -> list['UEFunction']:
        functions = []
        field = self.get_child()
        while field:
            if field.is_a(EClassCastFlags.Function):
                functions.append(field.cast(UEFunction))
            field = field.get_next()
        return functions

    def find_member(self, member_name: str, type_flags: int = 0) -> 'UEProperty':
        """UEStruct::FindMember @ ea0dab3."""
        if not self.address:
            return UEProperty(self.e, 0)
        if self.e.settings.Internal.bUseFProperty:
            ffield = self.get_child_properties()
            while ffield:
                if ffield.is_a(type_flags) and ffield.get_name() == member_name:
                    return ffield.cast(UEProperty)
                ffield = ffield.get_next()
        field = self.get_child()
        while field:
            if field.is_a(type_flags) and field.get_name() == member_name:
                return field.cast(UEProperty)
            field = field.get_next()
        return UEProperty(self.e, 0)

    def has_members(self) -> bool:
        if not self.address:
            return False
        if self.e.settings.Internal.bUseFProperty:
            ffield = self.get_child_properties()
            while ffield:
                if ffield.is_a(EClassCastFlags.Property):
                    return True
                ffield = ffield.get_next()
        else:
            f = self.get_child()
            while f:
                if f.is_a(EClassCastFlags.Property):
                    return True
                f = f.get_next()
        return False


class UEFunction(UEStruct):
    """UEFunction @ ea0dab3."""
    __slots__ = ()

    def get_function_flags(self) -> int: return self.e.mem.u32(self.address + self.e.off.UFunction.FunctionFlags)

    def has_flags(self, func_flags: int) -> bool: return bool(self.get_function_flags() & func_flags)

    def get_exec_function(self) -> int: return self.e.mem.ptr(self.address + self.e.off.UFunction.ExecFunction)

    def get_return_property(self) -> 'UEProperty':
        for prop in self.get_properties():
            if prop.has_property_flags(EPropertyFlags.ReturnParm):
                return prop
        return UEProperty(self.e, 0)


class UEClass(UEStruct):
    """UEClass @ ea0dab3."""
    __slots__ = ()

    def get_cast_flags(self) -> int: return self.e.mem.u64(self.address + self.e.off.UClass.CastFlags)

    def is_type(self, type_flag: int) -> bool: return bool(self.get_cast_flags() & type_flag) if type_flag != 0 else True

    def get_default_object(self) -> UEObject: return UEObject(self.e, self.e.mem.ptr(self.address + self.e.off.UClass.ClassDefaultObject))

    def get_implemented_interfaces(self) -> TArray: return view(TArray, self.address + self.e.off.UClass.ImplementedInterfaces, self.e.acc)

    def get_function(self, class_name: str, func_name: str) -> UEFunction:
        """UEClass::GetFunction @ ea0dab3."""
        struct = UEStruct(self.e, self.address)
        while struct:
            if struct.get_name() == class_name:
                field = struct.get_child()
                while field:
                    if field.is_a(EClassCastFlags.Function) and field.get_name() == func_name:
                        return field.cast(UEFunction)
                    field = field.get_next()
            struct = struct.get_super()
        return UEFunction(self.e, 0)


class UEProperty:
    """UEProperty @ ea0dab3."""
    __slots__ = ('e', 'address')

    def __init__(self, e: 'Engine', address: int):
        self.e = e
        self.address = address

    def get_address(self) -> int: return self.address

    def get_class(self) -> tuple[UEClass, UEFFieldClass]:
        if self.e.settings.Internal.bUseFProperty:
            return UEClass(self.e, 0), UEFField(self.e, self.address).get_class()
        return UEObject(self.e, self.address).get_class(), UEFFieldClass(self.e, 0)

    def get_cast_flags(self) -> int:
        cls, field_class = self.get_class()
        return cls.get_cast_flags() if cls else field_class.get_cast_flags()

    def __bool__(self) -> bool:
        return self.address != 0 and ((self.address + self.e.off.UObject.Class) & _U64 != 0 or (self.address + self.e.off.FField.Class) & _U64 != 0)

    def __eq__(self, other):
        return self.address == other.address if isinstance(other, UEProperty) else NotImplemented

    def __hash__(self): return hash(self.address)

    def is_a(self, type_flags: int) -> bool:
        if self.get_class()[0]:
            return self.get_class()[0].is_type(type_flags)
        return self.get_class()[1].is_type(type_flags)

    def get_fname(self) -> FName:
        if self.e.settings.Internal.bUseFProperty:
            return FName(self.e, self.address + self.e.off.FField.Name)
        return FName(self.e, self.address + self.e.off.UObject.Name)

    def get_array_dim(self) -> int:
        if self.e.settings.Internal.bUseUint8ArrayDim:
            return self.e.mem.u8(self.address + self.e.off.Property.ArrayDim)
        return self.e.mem.i32(self.address + self.e.off.Property.ArrayDim)

    def get_size(self) -> int: return self.e.mem.i32(self.address + self.e.off.Property.ElementSize)

    def get_offset(self) -> int: return self.e.mem.i32(self.address + self.e.off.Property.Offset_Internal)

    def get_property_flags(self) -> int: return self.e.mem.u64(self.address + self.e.off.Property.PropertyFlags)

    def has_property_flags(self, property_flag: int) -> bool: return bool(self.get_property_flags() & property_flag)

    def is_type(self, possible_types: int) -> bool: return (self.get_cast_flags() & possible_types) != 0

    def get_name(self) -> str: return self.get_fname().to_string() if self.address else 'None'

    def get_valid_name(self) -> str: return self.get_fname().to_valid_string() if self.address else 'None'

    def get_prop_class_name(self) -> str:
        return self.get_class()[0].get_name() if self.get_class()[0] else self.get_class()[1].get_name()

    def cast(self, cls: type):
        return cls(self.e, self.address)


class UEByteProperty(UEProperty):
    """UEByteProperty @ ea0dab3."""
    __slots__ = ()

    def get_enum(self) -> UEEnum: return UEEnum(self.e, self.e.mem.ptr(self.address + self.e.off.ByteProperty.Enum))


class UEBoolProperty(UEProperty):
    """UEBoolProperty @ ea0dab3; UBoolPropertyBase {FieldSize, ByteOffset, ByteMask, FieldMask} read field by field."""
    __slots__ = ()

    def get_field_mask(self) -> int: return self.e.mem.u8(self.address + self.e.off.BoolProperty.Base + 3)

    def get_byte_offset(self) -> int: return self.e.mem.u8(self.address + self.e.off.BoolProperty.Base + 1)

    def get_bit_index(self) -> int:
        """UEBoolProperty::GetBitIndex @ ea0dab3."""
        field_mask = self.get_field_mask()
        initial_bit_offset = (self.get_byte_offset() * 0x8) & 0xFF
        if field_mask != 0xFF:
            for bit in range(8):
                if field_mask == 1 << bit:
                    return (initial_bit_offset + bit) & 0xFF
        return 0xFF

    def is_native_bool(self) -> bool: return self.e.mem.u8(self.address + self.e.off.BoolProperty.Base + 3) == 0xFF


class UEObjectProperty(UEProperty):
    """UEObjectProperty @ ea0dab3."""
    __slots__ = ()

    def get_property_class(self) -> UEClass: return UEClass(self.e, self.e.mem.ptr(self.address + self.e.off.ObjectProperty.PropertyClass))


class UEClassProperty(UEObjectProperty):
    """UEClassProperty @ ea0dab3."""
    __slots__ = ()

    def get_meta_class(self) -> UEClass: return UEClass(self.e, self.e.mem.ptr(self.address + self.e.off.ClassProperty.MetaClass))


class UEWeakObjectProperty(UEObjectProperty):
    __slots__ = ()


class UELazyObjectProperty(UEObjectProperty):
    __slots__ = ()


class UESoftObjectProperty(UEObjectProperty):
    __slots__ = ()


class UESoftClassProperty(UEClassProperty):
    __slots__ = ()


class UEInterfaceProperty(UEObjectProperty):
    __slots__ = ()


class UEStructProperty(UEProperty):
    """UEStructProperty @ ea0dab3."""
    __slots__ = ()

    def get_underlaying_struct(self) -> UEStruct: return UEStruct(self.e, self.e.mem.ptr(self.address + self.e.off.StructProperty.Struct))


class UEArrayProperty(UEProperty):
    """UEArrayProperty @ ea0dab3."""
    __slots__ = ()

    def get_inner_property(self) -> UEProperty: return UEProperty(self.e, self.e.mem.ptr(self.address + self.e.off.ArrayProperty.Inner))


class UEDelegateProperty(UEProperty):
    """UEDelegateProperty @ ea0dab3."""
    __slots__ = ()

    def get_signature_function(self) -> UEFunction:
        return UEFunction(self.e, self.e.mem.ptr(self.address + self.e.off.DelegateProperty.SignatureFunction))


class UEMulticastInlineDelegateProperty(UEProperty):
    """UEMulticastInlineDelegateProperty @ ea0dab3."""
    __slots__ = ()

    def get_signature_function(self) -> UEFunction:
        return UEFunction(self.e, self.e.mem.ptr(self.address + self.e.off.DelegateProperty.SignatureFunction))  # DelegateProperty on purpose, as ea0dab3


class UEMapProperty(UEProperty):
    """UEMapProperty @ ea0dab3; UMapPropertyBase {KeyProperty, ValueProperty} read field by field."""
    __slots__ = ()

    def get_key_property(self) -> UEProperty: return UEProperty(self.e, self.e.mem.ptr(self.address + self.e.off.MapProperty.Base))

    def get_value_property(self) -> UEProperty: return UEProperty(self.e, self.e.mem.ptr(self.address + self.e.off.MapProperty.Base + 0x8))


class UESetProperty(UEProperty):
    """UESetProperty @ ea0dab3."""
    __slots__ = ()

    def get_element_property(self) -> UEProperty: return UEProperty(self.e, self.e.mem.ptr(self.address + self.e.off.SetProperty.ElementProp))


class UEEnumProperty(UEProperty):
    """UEEnumProperty @ ea0dab3; UEnumPropertyBase {UnderlayingProperty, Enum} read field by field."""
    __slots__ = ()

    def get_underlaying_property(self) -> UEProperty: return UEProperty(self.e, self.e.mem.ptr(self.address + self.e.off.EnumProperty.Base))

    def get_enum(self) -> UEEnum: return UEEnum(self.e, self.e.mem.ptr(self.address + self.e.off.EnumProperty.Base + 0x8))


class UEFieldPathProperty(UEProperty):
    """UEFieldPathProperty @ ea0dab3."""
    __slots__ = ()

    def get_field_class(self) -> UEFFieldClass: return UEFFieldClass(self.e, self.e.mem.ptr(self.address + self.e.off.FieldPathProperty.FieldClass))


class UEOptionalProperty(UEProperty):
    """UEOptionalProperty @ ea0dab3."""
    __slots__ = ()

    def get_value_property(self) -> UEProperty: return UEProperty(self.e, self.e.mem.ptr(self.address + self.e.off.OptionalProperty.ValueProperty))
