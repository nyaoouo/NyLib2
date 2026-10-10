"""Settings detection of Dumper-7 @ ea0dab3: the four Settings::Init*Settings and Generator.cpp's InitSettings."""
import typing

from ..flags import EClassCastFlags
from .unreal import UEStruct

if typing.TYPE_CHECKING:
    from .core import Engine


def _bool_str(value: bool) -> str:
    return 'true' if value else 'false'


def init_weak_object_ptr_settings(e: 'Engine') -> None:
    """Settings::InitWeakObjectPtrSettings @ ea0dab3."""
    key = 'Settings.Internal.bIsWeakObjectPtrWithoutTag'
    load_asset = e.objects.find_object_fast('LoadAsset', EClassCastFlags.Function).cast(UEStruct)
    if not load_asset:
        e.cerr("\nDumper-7: 'LoadAsset' wasn't found, could not determine value for 'bIsWeakObjectPtrWithoutTag'!\n\n")
        e.provenance[key] = "not found: 'LoadAsset' wasn't found"
        return

    asset = load_asset.find_member('Asset', EClassCastFlags.SoftObjectProperty)
    if not asset:
        e.cerr("\nDumper-7: 'Asset' wasn't found, could not determine value for 'bIsWeakObjectPtrWithoutTag'!\n\n")
        e.provenance[key] = "not found: 'Asset' wasn't found"
        return

    soft_object_path = e.objects.find_struct_fast('SoftObjectPath')
    size_of_ffweak_object_ptr = 0x08
    old_unreal_asset_ptr_size = 0x10
    size_of_soft_object_path = soft_object_path.get_struct_size() if soft_object_path else old_unreal_asset_ptr_size

    e.settings.Internal.bIsWeakObjectPtrWithoutTag = asset.get_size() <= (size_of_soft_object_path + size_of_ffweak_object_ptr)
    e.provenance[key] = 'auto: Settings::InitWeakObjectPtrSettings'


def init_large_world_coordinate_settings(e: 'Engine') -> None:
    """Settings::InitLargeWorldCoordinateSettings @ ea0dab3."""
    key = 'Settings.Internal.bUseLargeWorldCoordinates'
    fvector_struct = e.objects.find_struct_fast('Vector')
    if not fvector_struct:
        e.cerr("\nSomething went horribly wrong, FVector wasn't even found!\n\n\n")
        e.provenance[key] = "not found: FVector wasn't found"
        return

    x_property = fvector_struct.find_member('X')
    if not x_property:
        e.cerr("\nSomething went horribly wrong, FVector::X wasn't even found!\n\n\n")
        e.provenance[key] = "not found: FVector::X wasn't found"
        return

    e.settings.Internal.bUseLargeWorldCoordinates = x_property.is_a(EClassCastFlags.DoubleProperty)
    e.provenance[key] = 'auto: Settings::InitLargeWorldCoordinateSettings'


def init_object_ptr_property_settings(e: 'Engine') -> None:
    """Settings::InitObjectPtrPropertySettings @ ea0dab3."""
    key = 'Settings.Internal.bIsObjPtrInsteadOfFieldPathProperty'
    label = 'auto: Settings::InitObjectPtrPropertySettings'
    internal = e.settings.Internal
    object_ptr_property_class = e.objects.find_class_fast('ObjectPtrProperty')
    if not object_ptr_property_class:
        e.cerr(f'\nDumper-7: bIsObjPtrInsteadOfFieldPathProperty = {_bool_str(internal.bIsObjPtrInsteadOfFieldPathProperty)}\n\n')
        internal.bIsObjPtrInsteadOfFieldPathProperty = False
        e.provenance[key] = label
        return

    internal.bIsObjPtrInsteadOfFieldPathProperty = object_ptr_property_class.get_default_object().is_a(EClassCastFlags.FieldPathProperty)
    e.provenance[key] = label
    e.cerr(f'\nDumper-7: bIsObjPtrInsteadOfFieldPathProperty = {_bool_str(internal.bIsObjPtrInsteadOfFieldPathProperty)}\n\n')


def init_array_dim_size_settings(e: 'Engine') -> None:
    """Settings::InitArrayDimSizeSettings @ ea0dab3."""
    key = 'Settings.Internal.bUseUint8ArrayDim'
    label = 'auto: Settings::InitArrayDimSizeSettings'
    for obj in e.objects:
        if not obj.is_a(EClassCastFlags.Struct):
            continue
        for prop in obj.cast(UEStruct).get_properties():
            if prop.get_array_dim() >= 0x000F0001:
                e.settings.Internal.bUseUint8ArrayDim = True
                e.provenance[key] = label
                e.cerr(f'\nDumper-7: bUseUint8ArrayDim = {_bool_str(e.settings.Internal.bUseUint8ArrayDim)}\n\n')
                return

    e.settings.Internal.bUseUint8ArrayDim = False
    e.provenance[key] = label
    e.cerr(f'\nDumper-7: bUseUint8ArrayDim = {_bool_str(e.settings.Internal.bUseUint8ArrayDim)}\n\n')


def init_settings(e: 'Engine') -> None:
    """Generator.cpp InitSettings @ ea0dab3."""
    init_weak_object_ptr_settings(e)
    init_large_world_coordinate_settings(e)
    init_object_ptr_property_settings(e)
    init_array_dim_size_settings(e)
