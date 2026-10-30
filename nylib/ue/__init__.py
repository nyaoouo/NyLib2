"""Package entry for nylib.ue: eager errors, lazy pipeline and runtime entry points."""
import importlib
from typing import TYPE_CHECKING

from .errors import UeError, MemoryReadError, MemoryWriteError, TargetError, PeFormatError, CaptureError, SnapshotError, SchemaError, DetectionError, \
    AmbiguousTargetError, ProfileError, OutputRootError, SessionError, ReadOnlySessionError, CallsDisabledError, DumpMismatchError, \
    UnverifiedOffsetsError, PendingCallsError, AmbiguousNameError, CallError, MarshalError, \
    AssetError, InvalidKeyError, InvalidMappingError, BuildMismatchError, MissingAssetError, MissingTileError, \
    UnsupportedError, UnsupportedContainerError, UnsupportedAssetError, UnsupportedPixelFormatError, \
    CorruptAssetError, RegionOutOfBoundsError, ReadCancelledError, InstallationClosedError, AbsentPropertyError

if TYPE_CHECKING:
    from .pipeline import probe, dump
    from .runtime.session import Unreal
    from .snapshot import Snapshot as _Snapshot

__all__ = [
    'UeError', 'MemoryReadError', 'MemoryWriteError', 'TargetError', 'PeFormatError', 'CaptureError',
    'SnapshotError', 'SchemaError', 'DetectionError', 'AmbiguousTargetError', 'ProfileError', 'OutputRootError',
    'SessionError', 'ReadOnlySessionError', 'CallsDisabledError', 'DumpMismatchError', 'UnverifiedOffsetsError', 'PendingCallsError',
    'AmbiguousNameError', 'CallError', 'MarshalError',
    'AssetError', 'InvalidKeyError', 'InvalidMappingError', 'BuildMismatchError', 'MissingAssetError', 'MissingTileError',
    'UnsupportedError', 'UnsupportedContainerError', 'UnsupportedAssetError', 'UnsupportedPixelFormatError',
    'CorruptAssetError', 'RegionOutOfBoundsError', 'ReadCancelledError', 'InstallationClosedError', 'AbsentPropertyError',
    'probe', 'dump', 'load_snapshot', 'Unreal',
]

_LAZY: dict[str, str] = {
    'probe': 'pipeline',
    'dump': 'pipeline',
    'Unreal': 'runtime',
}


def load_snapshot(folder) -> '_Snapshot':
    """Open a completed snapshot folder as a `Snapshot`."""
    from .snapshot import Snapshot
    return Snapshot.load(folder)


if not TYPE_CHECKING:
    def __getattr__(name: str):
        if name not in _LAZY:
            raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
        module = importlib.import_module(f'{__name__}.{_LAZY[name]}')
        value = getattr(module, name)
        globals()[name] = value
        return value

    def __dir__():
        return sorted(set(globals()) | {'probe', 'dump', 'Unreal'})
