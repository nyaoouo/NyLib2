"""Offsets.cpp of Dumper-7 @ ea0dab3 over an Engine: Off::Init, PropertySizes, ProcessEvent, GWorld and FText (up to its call)."""
import time
import typing
from collections.abc import Mapping

from ..errors import DetectionError, MemoryReadError
from ..flags import EClassCastFlags, EObjectFlags, EPropertyFlags
from . import offset_finder as OffsetFinder
from .unreal import UEClass, UEFunction, UEObject, UEProperty, _PARENT_LINKS, _Chain

if typing.TYPE_CHECKING:
    from .core import Engine

_M32 = 0xFFFFFFFF


def _keys(namespace: str, *fields: str) -> tuple[str, ...]:
    return tuple(f'{namespace}.{field}' for field in fields)


PINNABLE_KEYS = frozenset((
    'Off.InSDK.World.GWorld', 'Off.InSDK.Properties.PropertySize', *_keys('Off.InSDK.Text', 'TextDatOffset', 'InTextDataStringOffset', 'TextSize'),
    'Off.InSDK.ULevel.Actors', 'Off.InSDK.UDataTable.RowMap',
    *_keys('Off.FField', 'Vft', 'Class', 'Owner', 'Next', 'Name', 'Flags'),
    *_keys('Off.FFieldClass', 'Name', 'Id', 'CastFlags', 'ClassFlags', 'SuperClass'),
    *_keys('Off.FName', 'CompIdx', 'Number'),
    *_keys('Off.UObject', 'Vft', 'Flags', 'Index', 'Class', 'Name', 'Outer'),
    'Off.UField.Next', 'Off.UEnum.Names',
    *_keys('Off.UStruct', 'SuperStruct', 'Children', 'ChildProperties', 'Size', 'MinAlignment'),
    *_keys('Off.UFunction', 'FunctionFlags', 'ExecFunction'),
    *_keys('Off.UClass', 'CastFlags', 'ClassDefaultObject', 'ImplementedInterfaces'),
    *_keys('Off.Property', 'ArrayDim', 'ElementSize', 'PropertyFlags', 'Offset_Internal'),
    'Off.ByteProperty.Enum', 'Off.BoolProperty.Base', 'Off.ObjectProperty.PropertyClass', 'Off.ClassProperty.MetaClass',
    'Off.StructProperty.Struct', 'Off.ArrayProperty.Inner', 'Off.DelegateProperty.SignatureFunction', 'Off.MapProperty.Base',
    'Off.SetProperty.ElementProp', 'Off.EnumProperty.Base', 'Off.FieldPathProperty.FieldClass', 'Off.OptionalProperty.ValueProperty',
    *_keys('PropertySizes', 'DelegateProperty', 'FieldPathProperty', 'MulticastInlineDelegateProperty'),
))


def _i32(value: int) -> int:
    return ((value + 0x80000000) & _M32) - 0x80000000


def _hexs(value: int) -> str:
    """model.hexs without a width."""
    return f'-0x{-value:X}' if value < 0 else f'0x{value:X}'


def _check_pins(pins, prefix: str) -> dict[str, int]:
    """O2's pin validation; returns the pins whose key starts with `prefix`."""
    if pins is None:
        return {}
    if not isinstance(pins, Mapping):
        raise TypeError(f'pins must be a Mapping, not {type(pins).__name__}')
    for key, value in pins.items():
        if key not in PINNABLE_KEYS:
            raise ValueError(f'offset {key!r} cannot be pinned')
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f'offset {key!r}: a pinned value must be an int, not {type(value).__name__}')
    return {key: value for key, value in pins.items() if key.startswith(prefix)}


def _target(e: 'Engine', key: str) -> tuple[object, str]:
    root, *path, field = key.split('.')
    obj = e.off if root == 'Off' else e.property_sizes
    for name in path:
        obj = getattr(obj, name)
    return obj, field


def _get(e: 'Engine', key: str) -> int:
    obj, field = _target(e, key)
    return getattr(obj, field)


def _assign(e: 'Engine', key: str, value: int, label: str, pins: Mapping[str, int]) -> None:
    """One recorded assignment; a pinned key then takes its pin (O2)."""
    obj, field = _target(e, key)
    setattr(obj, field, value)
    e.provenance[key] = label
    if key in pins:
        setattr(obj, field, pins[key])
        e.provenance[key] = 'profile: value'


def _finder_label(func: str, value: int, zero_is_not_found: bool = False) -> str:
    if value < 0 or (zero_is_not_found and value == 0):
        return f'not found: OffsetFinder::{func} returned {_hexs(value)}'
    return f'auto: OffsetFinder::{func}'


def _computed_label(source_key: str, value: int) -> str:
    return 'auto: Off::Init' if value >= 0 else f'fallback: Off::Init ({source_key} is {_hexs(value)})'


def _tolerated(e: 'Engine', keys: tuple[str, ...], pins: Mapping[str, int], call: typing.Callable[[], typing.Any]):
    """Runs call(); with one of `keys` pinned, a MemoryReadError / DetectionError goes to cerr and the pins apply (O2)."""
    try:
        return True, call()
    except (MemoryReadError, DetectionError) as exc:
        if not (pinned := [key for key in keys if key in pins]):
            raise
        e.cerr(f'{", ".join(pinned)}: {type(exc).__name__}: {exc}; the pinned value is used\n')
        for key in pinned:
            obj, field = _target(e, key)
            setattr(obj, field, pins[key])
            e.provenance[key] = 'profile: value'
        return False, None


def _is_property_key(key: str) -> bool:
    return key.split('.')[1].endswith('Property')


def _find(e: 'Engine', pins: Mapping[str, int], key: str, func: str, finder, *args, zero_is_not_found: bool = False) -> None:
    """`Off::X = OffsetFinder::<func>(args...)` with its Provenance label; a negative property offset is stored as OffsetNotFound."""
    ok, value = _tolerated(e, (key,), pins, lambda: finder(e, *args))
    if ok:
        label = _finder_label(func, value, zero_is_not_found)
        if value < 0 and _is_property_key(key):
            value = OffsetFinder.OffsetNotFound
        _assign(e, key, value, label, pins)


def _infer_property_base(e: 'Engine', pins: Mapping[str, int]) -> tuple[int, str]:
    """PropertySize when the Bool and Enum anchors are missing: two or more subclass finders find it and all agree.
    Raises DetectionError otherwise, unless PropertySize is pinned."""
    found, results = {}, []
    for func, finder in (('FindBytePropertyEnumOffset', OffsetFinder.find_byte_property_enum_offset),
                         ('FindObjectPropertyClassOffset', OffsetFinder.find_object_property_class_offset),
                         ('FindStructPropertyStructOffset', OffsetFinder.find_struct_property_struct_offset)):
        try:
            value = finder(e)
        except (MemoryReadError, DetectionError) as exc:
            results.append(f'{func} raised {type(exc).__name__}')
            continue
        results.append(f'{func} returned {_hexs(value)}')
        if value >= 0:
            found[func] = value
    if len(found) >= 2 and len(set(found.values())) == 1:
        value = next(iter(found.values()))
        if (key := 'Off.InSDK.Properties.PropertySize') in pins and pins[key] != value:
            e.cerr(f'{key}: pinned 0x{pins[key]:X} differs from the agreed value 0x{value:X}\n')
        return value, f'fallback: Off::Init ({", ".join(found)} agree)'
    if (key := 'Off.InSDK.Properties.PropertySize') in pins:
        return pins[key], 'fallback: Off::InSDK::Properties::PropertySize (profile)'
    raise DetectionError('Off::Init', 'cannot establish Off.BoolProperty.Base, Off.EnumProperty.Base and Off.InSDK.Properties.PropertySize: '
                         f'their anchors are missing and the subclass finders do not agree ({"; ".join(results)})'
                         '; pin Off.InSDK.Properties.PropertySize in a profile', tuple(e.messages))


def _field_class_cast_flags_found(e: 'Engine', value: int) -> bool:
    """Tells dd8fe34's found 0x10 from its 0x10 default: a found 0x10 matched at +0x10 of a non-null pair."""
    if value != 0x10:
        return True
    base = EClassCastFlags.Field | EClassCastFlags.Property | EClassCastFlags.NumericProperty
    for struct_name, flag in (('Guid', EClassCastFlags.IntProperty), ('Color', EClassCastFlags.ByteProperty)):
        address = e.objects.find_struct_fast(struct_name).get_child_properties().get_class().get_address()
        if address and e.mem.u64(address + 0x10) == base | flag:
            return True
    return False


def off_init(e: 'Engine', *, pins: Mapping[str, int] | None = None) -> None:
    """Off::Init @ ea0dab3, plus dd8fe34's FFieldClass::CastFlags finder (Q23 = A) and O2's pins."""
    pins = _check_pins(pins, 'Off.')
    off = e.off

    def overwrite_if_invalid_offset(key: str, default_value: int, expression: str) -> None:
        if _get(e, key) == OffsetFinder.OffsetNotFound:
            e.cerr(f'Defaulting to offset: 0x{default_value:X}\n')
            _assign(e, key, default_value, f'default: {expression}', pins)

    _find(e, pins, 'Off.UObject.Flags', 'FindUObjectFlagsOffset', OffsetFinder.find_uobject_flags_offset)
    overwrite_if_invalid_offset('Off.UObject.Flags', 8, 'sizeof(void*)')
    e.cerr(f'Off::UObject::Flags: 0x{off.UObject.Flags:X}\n')

    _find(e, pins, 'Off.UObject.Index', 'FindUObjectIndexOffset', OffsetFinder.find_uobject_index_offset)
    overwrite_if_invalid_offset('Off.UObject.Index', _i32(off.UObject.Flags + 4), 'Off::UObject::Flags + sizeof(int32)')
    e.cerr(f'Off::UObject::Index: 0x{off.UObject.Index:X}\n')

    _find(e, pins, 'Off.UObject.Class', 'FindUObjectClassOffset', OffsetFinder.find_uobject_class_offset)
    overwrite_if_invalid_offset('Off.UObject.Class', _i32(off.UObject.Index + 4), 'Off::UObject::Index + sizeof(int32)')
    e.cerr(f'Off::UObject::Class: 0x{off.UObject.Class:X}\n')

    _find(e, pins, 'Off.UObject.Outer', 'FindUObjectOuterOffset', OffsetFinder.find_uobject_outer_offset)
    e.cerr(f'Off::UObject::Outer: 0x{off.UObject.Outer:X}\n')

    _find(e, pins, 'Off.UObject.Name', 'FindUObjectNameOffset', OffsetFinder.find_uobject_name_offset)
    overwrite_if_invalid_offset('Off.UObject.Name', _i32(off.UObject.Class + 8), 'Off::UObject::Class + sizeof(void*)')
    e.cerr(f'Off::UObject::Name: 0x{off.UObject.Name:X}\n\n')

    overwrite_if_invalid_offset('Off.UObject.Outer', _i32(off.UObject.Name + 4 + 4), 'Off::UObject::Name + sizeof(int32) + sizeof(int32)')

    OffsetFinder.init_fname_settings(e)

    e.names.post_init()

    _find(e, pins, 'Off.UClass.CastFlags', 'FindCastFlagsOffset', OffsetFinder.find_cast_flags_offset)
    e.cerr(f'Off::UClass::CastFlags: 0x{off.UClass.CastFlags:X}\n')

    _find(e, pins, 'Off.UStruct.Children', 'FindChildOffset', OffsetFinder.find_child_offset)
    e.cerr(f'Off::UStruct::Children: 0x{off.UStruct.Children:X}\n')

    _find(e, pins, 'Off.UField.Next', 'FindUFieldNextOffset', OffsetFinder.find_ufield_next_offset)
    e.cerr(f'Off::UField::Next: 0x{off.UField.Next:X}\n')

    _find(e, pins, 'Off.UStruct.SuperStruct', 'FindSuperOffset', OffsetFinder.find_super_offset)
    e.cerr(f'Off::UStruct::SuperStruct: 0x{off.UStruct.SuperStruct:X}\n')

    _find(e, pins, 'Off.UStruct.Size', 'FindStructSizeOffset', OffsetFinder.find_struct_size_offset)
    e.cerr(f'Off::UStruct::Size: 0x{off.UStruct.Size:X}\n')

    _find(e, pins, 'Off.UStruct.MinAlignment', 'FindMinAlignmentOffset', OffsetFinder.find_min_alignment_offset)
    e.cerr(f'Off::UStruct::MinAlignment: 0x{off.UStruct.MinAlignment:X}\n')

    _find(e, pins, 'Off.UClass.CastFlags', 'FindCastFlagsOffset', OffsetFinder.find_cast_flags_offset)
    e.cerr(f'Off::UClass::CastFlags: 0x{off.UClass.CastFlags:X}\n')

    if e.settings.Internal.bUseFProperty:
        e.cerr('\nGame uses FProperty system\n\n')

        _find(e, pins, 'Off.UStruct.ChildProperties', 'FindChildPropertiesOffset', OffsetFinder.find_child_properties_offset)
        e.cerr(f'Off::UStruct::ChildProperties: 0x{off.UStruct.ChildProperties:X}\n')

        OffsetFinder.fixup_hardcoded_offsets(e)

        _find(e, pins, 'Off.FField.Next', 'FindFFieldNextOffset', OffsetFinder.find_ffield_next_offset)
        e.cerr(f'Off::FField::Next: 0x{off.FField.Next:X}\n')

        _find(e, pins, 'Off.FField.Class', 'FindFFieldClassOffset', OffsetFinder.find_ffield_class_offset)
        e.cerr(f'Off::FField::Class: 0x{off.FField.Class:X}\n')

        _find(e, pins, 'Off.FField.Name', 'FindFFieldNameOffset', OffsetFinder.find_ffield_name_offset)

        if off.FField.Name == OffsetFinder.OffsetNotFound:
            _find(e, pins, 'Off.FField.Name', 'NewFindFFieldNameOffset', OffsetFinder.new_find_ffield_name_offset)

        e.cerr(f'Off::FField::Name: 0x{off.FField.Name:X}\n')

        name = off.FField.Name
        _assign(e, 'Off.FField.Flags', _i32(name + off.InSDK.Name.FNameSize), _computed_label('Off.FField.Name', name), pins)
        e.cerr(f'Off::FField::Flags: 0x{off.FField.Flags:X}\n')

        before = off.FFieldClass.CastFlags
        ok, value = _tolerated(e, ('Off.FFieldClass.CastFlags',), pins, lambda: OffsetFinder.find_field_class_cast_flags_offset(e))
        if ok:
            if _field_class_cast_flags_found(e, value):
                _assign(e, 'Off.FFieldClass.CastFlags', value, 'auto: OffsetFinder::FindFieldClassCastFlagsOffset (dd8fe34)', pins)
            else:  # keep ea0dab3's effective value on a miss, not dd8fe34's 0x10 fallback
                _assign(e, 'Off.FFieldClass.CastFlags', before, f'default: {_hexs(before)} (dd8fe34 finder missed)', pins)
        e.cerr(f'Off::FFieldClass::CastFlags: 0x{off.FFieldClass.CastFlags:X}\n\n')

    _find(e, pins, 'Off.UClass.ClassDefaultObject', 'FindDefaultObjectOffset', OffsetFinder.find_default_object_offset)
    e.cerr(f'Off::UClass::ClassDefaultObject: 0x{off.UClass.ClassDefaultObject:X}\n')

    _find(e, pins, 'Off.UClass.ImplementedInterfaces', 'FindImplementedInterfacesOffset', OffsetFinder.find_implemented_interfaces_offset)
    e.cerr(f'Off::UClass::ImplementedInterfaces: 0x{off.UClass.ImplementedInterfaces:X}\n')

    _find(e, pins, 'Off.UEnum.Names', 'FindEnumNamesOffset', OffsetFinder.find_enum_names_offset)
    e.cerr(f'Off::UEnum::Names: 0x{off.UEnum.Names:X}\n\n')

    _find(e, pins, 'Off.UFunction.FunctionFlags', 'FindFunctionFlagsOffset', OffsetFinder.find_function_flags_offset)
    e.cerr(f'Off::UFunction::FunctionFlags: 0x{off.UFunction.FunctionFlags:X}\n')

    _find(e, pins, 'Off.UFunction.ExecFunction', 'FindFunctionNativeFuncOffset', OffsetFinder.find_function_native_func_offset,
          zero_is_not_found=True)
    e.cerr(f'Off::UFunction::ExecFunction: 0x{off.UFunction.ExecFunction:X}\n\n')

    _find(e, pins, 'Off.Property.ElementSize', 'FindElementSizeOffset', OffsetFinder.find_element_size_offset)
    e.cerr(f'Off::Property::ElementSize: 0x{off.Property.ElementSize:X}\n')

    _find(e, pins, 'Off.Property.ArrayDim', 'FindArrayDimOffset', OffsetFinder.find_array_dim_offset)
    e.cerr(f'Off::Property::ArrayDim: 0x{off.Property.ArrayDim:X}\n')

    _find(e, pins, 'Off.Property.Offset_Internal', 'FindOffsetInternalOffset', OffsetFinder.find_offset_internal_offset)
    e.cerr(f'Off::Property::Offset_Internal: 0x{off.Property.Offset_Internal:X}\n')

    _find(e, pins, 'Off.Property.PropertyFlags', 'FindPropertyFlagsOffset', OffsetFinder.find_property_flags_offset)
    e.cerr(f'Off::Property::PropertyFlags: 0x{off.Property.PropertyFlags:X}\n')

    _find(e, pins, 'Off.BoolProperty.Base', 'FindBoolPropertyBaseOffset', OffsetFinder.find_bool_property_base_offset)
    e.cerr(f'UBoolProperty::Base: 0x{off.BoolProperty.Base:X}\n\n')

    _find(e, pins, 'Off.EnumProperty.Base', 'FindEnumPropertyBaseOffset', OffsetFinder.find_enum_property_base_offset)
    e.cerr(f'Off::EnumProperty::Base: 0x{off.EnumProperty.Base:X}\n\n')

    if off.EnumProperty.Base == OffsetFinder.OffsetNotFound and off.BoolProperty.Base == OffsetFinder.OffsetNotFound:
        base, label = _infer_property_base(e, pins)
        for key in ('Off.InSDK.Properties.PropertySize', 'Off.EnumProperty.Base', 'Off.BoolProperty.Base'):
            _assign(e, key, base, label, pins)
    elif off.EnumProperty.Base == OffsetFinder.OffsetNotFound:
        label = 'fallback: Off::BoolProperty::Base (no EnumProperty)'
        _assign(e, 'Off.InSDK.Properties.PropertySize', off.BoolProperty.Base, label, pins)
        _assign(e, 'Off.EnumProperty.Base', off.BoolProperty.Base, label, pins)
    else:
        base = off.EnumProperty.Base
        _assign(e, 'Off.InSDK.Properties.PropertySize', base, _computed_label('Off.EnumProperty.Base', base), pins)
        if off.BoolProperty.Base == OffsetFinder.OffsetNotFound:
            _assign(e, 'Off.BoolProperty.Base', base, 'fallback: Off::EnumProperty::Base (no BoolProperty)', pins)

    e.cerr(f'UPropertySize: 0x{off.InSDK.Properties.PropertySize:X}\n\n')

    _find(e, pins, 'Off.ObjectProperty.PropertyClass', 'FindObjectPropertyClassOffset', OffsetFinder.find_object_property_class_offset)
    e.cerr(f'Off::ObjectProperty::PropertyClass: 0x{off.ObjectProperty.PropertyClass:X}\n')
    overwrite_if_invalid_offset('Off.ObjectProperty.PropertyClass', off.InSDK.Properties.PropertySize, 'Off::InSDK::Properties::PropertySize')

    _find(e, pins, 'Off.ByteProperty.Enum', 'FindBytePropertyEnumOffset', OffsetFinder.find_byte_property_enum_offset)
    overwrite_if_invalid_offset('Off.ByteProperty.Enum', off.InSDK.Properties.PropertySize, 'Off::InSDK::Properties::PropertySize')
    e.cerr(f'Off::ByteProperty::Enum: 0x{off.ByteProperty.Enum:X}\n')

    _find(e, pins, 'Off.StructProperty.Struct', 'FindStructPropertyStructOffset', OffsetFinder.find_struct_property_struct_offset)
    overwrite_if_invalid_offset('Off.StructProperty.Struct', off.InSDK.Properties.PropertySize, 'Off::InSDK::Properties::PropertySize')
    e.cerr(f'Off::StructProperty::Struct: 0x{off.StructProperty.Struct:X}\n\n')

    _find(e, pins, 'Off.DelegateProperty.SignatureFunction', 'FindDelegatePropertySignatureFunctionOffset',
          OffsetFinder.find_delegate_property_signature_function_offset)
    overwrite_if_invalid_offset('Off.DelegateProperty.SignatureFunction', off.InSDK.Properties.PropertySize, 'Off::InSDK::Properties::PropertySize')
    e.cerr(f'Off::DelegateProperty::SignatureFunction: 0x{off.DelegateProperty.SignatureFunction:X}\n\n')

    _find(e, pins, 'Off.ArrayProperty.Inner', 'FindInnerTypeOffset', OffsetFinder.find_inner_type_offset, off.InSDK.Properties.PropertySize)
    if e.settings.Internal.bUseFProperty and 'Off.ArrayProperty.Inner' not in pins and not OffsetFinder.has_inner_type_anchor(e):
        _find(e, pins, 'Off.ArrayProperty.Inner', 'FindInnerTypeOffset (Actor function anchors)', OffsetFinder.find_actor_array_inner_offset,
              off.InSDK.Properties.PropertySize)
        if off.ArrayProperty.Inner == OffsetFinder.OffsetNotFound:
            raise DetectionError('Off::Init', 'cannot establish Off.ArrayProperty.Inner (pin Off.ArrayProperty.Inner in a profile): '
                                 'GameViewportClient.DebugProperties is missing and '
                                 'fewer than two Actor function ArrayProperty anchors agree', tuple(e.messages))
    e.cerr(f'Off::ArrayProperty::Inner: 0x{off.ArrayProperty.Inner:X}\n')

    _find(e, pins, 'Off.SetProperty.ElementProp', 'FindSetPropertyBaseOffset', OffsetFinder.find_set_property_base_offset,
          off.InSDK.Properties.PropertySize)
    e.cerr(f'Off::SetProperty::ElementProp: 0x{off.SetProperty.ElementProp:X}\n')

    _find(e, pins, 'Off.MapProperty.Base', 'FindMapPropertyBaseOffset', OffsetFinder.find_map_property_base_offset,
          off.InSDK.Properties.PropertySize)
    e.cerr(f'Off::MapProperty::Base: 0x{off.MapProperty.Base:X}\n\n')

    _find(e, pins, 'Off.InSDK.ULevel.Actors', 'FindLevelActorsOffset', OffsetFinder.find_level_actors_offset)
    e.cerr(f'Off::InSDK::ULevel::Actors: 0x{off.InSDK.ULevel.Actors:X}\n\n')

    _find(e, pins, 'Off.InSDK.UDataTable.RowMap', 'FindDatatableRowMapOffset', OffsetFinder.find_datatable_row_map_offset)
    e.cerr(f'Off::InSDK::UDataTable::RowMap: 0x{off.InSDK.UDataTable.RowMap:X}\n\n')

    OffsetFinder.post_init_fname_settings(e)

    e.cerr('\n')

    size = off.InSDK.Properties.PropertySize
    _assign(e, 'Off.FieldPathProperty.FieldClass', size, _computed_label('Off.InSDK.Properties.PropertySize', size), pins)
    _assign(e, 'Off.OptionalProperty.ValueProperty', size, _computed_label('Off.InSDK.Properties.PropertySize', size), pins)

    prop_class = off.ObjectProperty.PropertyClass
    _assign(e, 'Off.ClassProperty.MetaClass', _i32(prop_class + 8), _computed_label('Off.ObjectProperty.PropertyClass', prop_class), pins)


def _on_property_not_found(e: 'Engine', type_flag: int, key: str, func: str, pins: Mapping[str, int]) -> None:
    """The OnPropertyNotFound lambdas of PropertySizes @ ea0dab3: the first matching property in GObjects."""
    for obj in e.objects:
        if not obj.is_a(EClassCastFlags.Struct):
            continue
        for prop in obj.cast(UEClass).get_properties():
            if prop.is_a(type_flag):
                _assign(e, key, prop.get_size(), f'fallback: PropertySizes::{func} (first matching property in GObjects)', pins)
                return


def _init_tdelegate_size(e: 'Engine', pins: Mapping[str, int]) -> None:
    key, func = 'PropertySizes.DelegateProperty', 'InitTDelegateSize'
    audio_component_class = e.objects.find_class_fast('AudioComponent')
    if not audio_component_class:
        return _on_property_not_found(e, EClassCastFlags.DelegateProperty, key, func, pins)
    on_queue_subtitles_prop = audio_component_class.find_member('OnQueueSubtitles', EClassCastFlags.DelegateProperty)
    if not on_queue_subtitles_prop:
        return _on_property_not_found(e, EClassCastFlags.DelegateProperty, key, func, pins)
    _assign(e, key, on_queue_subtitles_prop.get_size(), f'auto: PropertySizes::{func}', pins)


def _init_ffield_path_size(e: 'Engine', pins: Mapping[str, int]) -> None:
    if not e.settings.Internal.bUseFProperty:
        return
    key, func = 'PropertySizes.FieldPathProperty', 'InitFFieldPathSize'
    set_field_path_property_by_name_func = e.objects.find_object_fast('SetFieldPathPropertyByName', EClassCastFlags.Function).cast(UEFunction)
    if not set_field_path_property_by_name_func:
        return _on_property_not_found(e, EClassCastFlags.FieldPathProperty, key, func, pins)
    value_param_prop = set_field_path_property_by_name_func.find_member('Value', EClassCastFlags.FieldPathProperty)
    if not value_param_prop:
        return _on_property_not_found(e, EClassCastFlags.FieldPathProperty, key, func, pins)
    _assign(e, key, value_param_prop.get_size(), f'auto: PropertySizes::{func}', pins)


def _init_tmulticast_inline_delegate_size(e: 'Engine', pins: Mapping[str, int]) -> None:
    func = 'InitTMulticastInlineDelegateSize'
    # DV7: the fallback writes DelegateProperty, as ea0dab3 does
    fallback = 'PropertySizes.DelegateProperty'
    emitter_class = e.objects.find_class_fast('Emitter')
    if not emitter_class:
        return _on_property_not_found(e, EClassCastFlags.MulticastInlineDelegateProperty, fallback, func, pins)
    on_particle_spawn = emitter_class.find_member('OnParticleSpawn', EClassCastFlags.MulticastDelegateProperty)
    if not on_particle_spawn:
        return _on_property_not_found(e, EClassCastFlags.MulticastInlineDelegateProperty, fallback, func, pins)
    _assign(e, 'PropertySizes.MulticastInlineDelegateProperty', on_particle_spawn.get_size(), f'auto: PropertySizes::{func}', pins)


def property_sizes_init(e: 'Engine', *, pins: Mapping[str, int] | None = None) -> None:
    """PropertySizes::Init @ ea0dab3 (DV7 literal), plus O2's pins."""
    pins = _check_pins(pins, 'PropertySizes.')
    _tolerated(e, ('PropertySizes.DelegateProperty',), pins, lambda: _init_tdelegate_size(e, pins))
    _tolerated(e, ('PropertySizes.FieldPathProperty',), pins, lambda: _init_ffield_path_size(e, pins))
    _tolerated(e, ('PropertySizes.MulticastInlineDelegateProperty', 'PropertySizes.DelegateProperty'), pins,
               lambda: _init_tmulticast_inline_delegate_size(e, pins))


def init_tdelegate_size(e: 'Engine') -> None:
    """PropertySizes::InitTDelegateSize @ ea0dab3."""
    _init_tdelegate_size(e, {})


def init_ffield_path_size(e: 'Engine') -> None:
    """PropertySizes::InitFFieldPathSize @ ea0dab3."""
    _init_ffield_path_size(e, {})


def init_tmulticast_inline_delegate_size(e: 'Engine') -> None:
    """PropertySizes::InitTMulticastInlineDelegateSize @ ea0dab3 (DV7 literal)."""
    _init_tmulticast_inline_delegate_size(e, {})


def init_pe_windows(e: 'Engine') -> None:
    """Off::InSDK::ProcessEvent::InitPE_Windows @ ea0dab3 (_WIN64)."""
    p = e.platform
    vft = e.mem.ptr(e.objects.get_by_index(0).get_address())

    def is_process_event(func_address: int, index: int) -> bool:
        flags = e.off.UFunction.FunctionFlags
        return bool(p.find_pattern_in_range([0xF7, -0x1, flags, 0x0, 0x0, 0x0, 0x0, 0x04, 0x0, 0x0], func_address, 0x400)
                    and p.find_pattern_in_range([0xF7, -0x1, flags, 0x0, 0x0, 0x0, 0x0, 0x0, 0x40, 0x0], func_address, 0xF00))

    func_ptr, func_idx = p.iterate_vtable_functions(vft, is_process_event)
    process_event_addr, process_event_idx = func_ptr, func_idx
    label = 'auto: Off::InSDK::ProcessEvent::InitPE_Windows'

    if not func_ptr:
        string_ref_addr = p.find_by_string_in_all_sections('Accessed None', wide=True, start_address=0x0, range_=0x0,
                                                           only_executable=e.settings.General.bSearchOnlyExecutableSectionsForStrings)
        possible_pe_addr = p.find_next_function_start(string_ref_addr)
        process_event_addr, process_event_idx = p.iterate_vtable_functions(vft, lambda func_address, index: func_address == possible_pe_addr)
        label = 'fallback: Off::InSDK::ProcessEvent::InitPE_Windows (Accessed None)'

    if process_event_addr:
        e.off.InSDK.ProcessEvent.PEIndex = process_event_idx
        e.provenance['Off.InSDK.ProcessEvent.PEIndex'] = label
        e.off.InSDK.ProcessEvent.PEOffset = _i32(p.get_offset(process_event_addr))
        e.provenance['Off.InSDK.ProcessEvent.PEOffset'] = label

        e.cerr(f'PE-Offset: 0x{e.off.InSDK.ProcessEvent.PEOffset:X}\n')
        e.cerr(f'PE-Index: 0x{process_event_idx:X}\n\n')
        return

    e.provenance['Off.InSDK.ProcessEvent.PEIndex'] = "not found: ProcessEvent is not in object 0's vtable"
    e.provenance['Off.InSDK.ProcessEvent.PEOffset'] = "not found: ProcessEvent is not in object 0's vtable"
    e.cerr("\nCouldn't find ProcessEvent!\n\n\n")


def init_pe(e: 'Engine', index: int) -> None:
    """Off::InSDK::ProcessEvent::InitPE(Index, ModuleName = nullptr) @ ea0dab3."""
    if not isinstance(index, int) or isinstance(index, bool):
        raise TypeError(f'index must be an int, not {type(index).__name__}')
    if index < 0:
        raise ValueError(f'index must be >= 0, got {index}')
    e.off.InSDK.ProcessEvent.PEIndex = index
    e.provenance['Off.InSDK.ProcessEvent.PEIndex'] = 'profile: value'

    vft = e.mem.ptr(e.objects.get_by_index(0).get_address())

    e.off.InSDK.ProcessEvent.PEOffset = _i32(e.platform.get_offset(e.mem.ptr(vft + 8 * e.off.InSDK.ProcessEvent.PEIndex)))
    e.provenance['Off.InSDK.ProcessEvent.PEOffset'] = 'profile: value'

    e.cerr(f'PE-Offset: 0x{e.off.InSDK.ProcessEvent.PEOffset:X}\n')


def _is_a_class_memo(obj: UEObject, cls: UEClass, memo: dict[int, bool]) -> bool:
    """A13: obj.is_a_class(cls) for a non-null cls, memoized per class address; a walk that raises is not stored."""
    clss = obj.get_class()
    if (found := memo.get(start := clss.address)) is None:
        found = False
        chain = _Chain(obj.address, 'super', _PARENT_LINKS)
        while clss:
            if clss == cls:
                found = True
                break
            clss = chain.follow(clss.get_super().cast(UEClass))
        memo[start] = found
    return found


def init_gworld(e: 'Engine') -> None:
    """Off::InSDK::World::InitGWorld @ ea0dab3 (K4: the poll reads e.mem.fresh; A13: World classes memoized)."""
    uworld = e.objects.find_class_fast('World')

    worlds: dict[int, bool] = {}
    for obj in e.objects:
        if obj.has_any_flags(EObjectFlags.ClassDefaultObject) or not (_is_a_class_memo(obj, uworld, worlds) if uworld else obj.is_a_class(uworld)):
            continue

        results = e.platform.find_all_aligned_values_in_process(obj.get_address())

        result = 0
        if results:
            if len(results) == 1:
                result = results[0]
            elif len(results) == 2:
                obj_address = obj.get_address()
                possible_gworld = results[0]
                current_value = e.mem.fresh.u64(possible_gworld)

                i = 0
                while current_value == obj_address and i < 50:
                    time.sleep(0.001)
                    current_value = e.mem.fresh.u64(possible_gworld)
                    i += 1
                if current_value == obj_address:
                    result = results[0]
                else:
                    result = results[1]
                    e.cerr(f'Filter GActiveLogWorld at 0x{possible_gworld:X}\n\n')
            else:
                e.cerr(f'Detected {len(results)} GWorld \n\n')

        if result:
            e.off.InSDK.World.GWorld = _i32(e.platform.get_offset(result))
            e.provenance['Off.InSDK.World.GWorld'] = 'auto: Off::InSDK::World::InitGWorld'
            e.cerr(f'GWorld-Offset: 0x{e.off.InSDK.World.GWorld:X}\n\n')
            break

    if e.off.InSDK.World.GWorld == 0x0:
        e.provenance['Off.InSDK.World.GWorld'] = 'not found: no pointer to a UWorld in the image'
        e.cerr('\nGWorld WAS NOT FOUND!!!!!!!!!\n\n')


def init_text_offsets(e: 'Engine') -> None:
    """Off::InSDK::Text::InitTextOffsets @ ea0dab3, up to its ProcessEvent call (DV6)."""
    for key in ('Off.InSDK.Text.TextDatOffset', 'Off.InSDK.Text.InTextDataStringOffset'):
        e.provenance[key] = 'not found: needs a ProcessEvent call (--allow-calls text)'

    if not e.off.InSDK.ProcessEvent.PEIndex:
        e.cerr("\nDumper-7: Error, 'InitInSDKTextOffsets' was called before ProcessEvent was initialized!\n\n")
        return

    conv_string_to_text = e.objects.find_object_fast('Conv_StringToText', EClassCastFlags.Function).cast(UEFunction)

    in_string_prop = UEProperty(e, 0)
    return_prop = UEProperty(e, 0)

    if not conv_string_to_text:
        e.cerr('Conv_StringToText is invalid!\n')
        return

    for prop in conv_string_to_text.get_properties():
        if prop.has_property_flags(EPropertyFlags.ReturnParm):
            return_prop = prop
        else:
            in_string_prop = prop

    conv_string_to_text.get_struct_size()  # ParamSize
    ftext_size = return_prop.get_size()

    in_string_prop.get_offset()  # StringOffset
    return_prop.get_offset()  # ReturnValueOffset

    e.off.InSDK.Text.TextSize = ftext_size
    e.provenance['Off.InSDK.Text.TextSize'] = 'auto: Off::InSDK::Text::InitTextOffsets'
    # DV6: ea0dab3 calls ProcessEvent(Conv_StringToText) here; TextDatOffset and InTextDataStringOffset stay 0
