"""Read-only access to a UE 5.7 game's IoStore assets: open_installation, textures and their regions, export listings and typed properties.

The errors import eagerly; every other name loads on first use, so importing this package opens no file and no DLL.
"""
from importlib import import_module
from typing import TYPE_CHECKING

from ..errors import (
    AssetError, InvalidKeyError, InvalidMappingError, BuildMismatchError, MissingAssetError, MissingTileError,
    UnsupportedError, UnsupportedContainerError, UnsupportedAssetError, UnsupportedPixelFormatError,
    CorruptAssetError, RegionOutOfBoundsError, ReadCancelledError, InstallationClosedError, AbsentPropertyError, AmbiguousNameError,
)

if TYPE_CHECKING:
    from ._installation import open_installation, Installation, Texture, Exports
    from ._keys import AesKey
    from ._records import ContainerInfo, BuildInfo, PackageInfo, MipInfo, VirtualTextureInfo, TextureInfo, Region, ReadStats
    from ._values import ExportInfo, Export, StructValue, Slot, MapValue, EnumValue, TextValue, ObjectRef, SoftObjectRef, DataTable, CurveTable

__all__ = [
    'open_installation', 'AesKey', 'Installation', 'Texture', 'ContainerInfo', 'BuildInfo', 'PackageInfo', 'MipInfo',
    'VirtualTextureInfo', 'TextureInfo', 'Region', 'ReadStats',
    'Exports', 'ExportInfo', 'Export', 'StructValue', 'Slot', 'MapValue', 'EnumValue', 'TextValue', 'ObjectRef', 'SoftObjectRef',
    'DataTable', 'CurveTable',
    'AssetError', 'InvalidKeyError', 'InvalidMappingError', 'BuildMismatchError', 'MissingAssetError', 'MissingTileError',
    'UnsupportedError', 'UnsupportedContainerError', 'UnsupportedAssetError', 'UnsupportedPixelFormatError',
    'CorruptAssetError', 'RegionOutOfBoundsError', 'ReadCancelledError', 'InstallationClosedError', 'AbsentPropertyError',
    'AmbiguousNameError',
]

_LAZY = {
    'open_installation': '_installation', 'Installation': '_installation', 'Texture': '_installation', 'AesKey': '_keys',
    'ContainerInfo': '_records', 'BuildInfo': '_records', 'PackageInfo': '_records', 'MipInfo': '_records',
    'VirtualTextureInfo': '_records', 'TextureInfo': '_records', 'Region': '_records', 'ReadStats': '_records',
    'Exports': '_installation', 'ExportInfo': '_values', 'Export': '_values', 'StructValue': '_values', 'Slot': '_values',
    'MapValue': '_values', 'EnumValue': '_values', 'TextValue': '_values', 'ObjectRef': '_values', 'SoftObjectRef': '_values',
    'DataTable': '_values', 'CurveTable': '_values',
}


def __getattr__(name: str):
    if (module := _LAZY.get(name)) is None:
        raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
    value = getattr(import_module(f'.{module}', __name__), name)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(_LAZY))
