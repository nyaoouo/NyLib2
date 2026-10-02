"""Package entry for nylib.ue.runtime: eager errors, every other name lazy."""
import importlib

from ..errors import UeError, MemoryReadError, MemoryWriteError, TargetError, PeFormatError, CaptureError, \
    SnapshotError, SchemaError, DetectionError, AmbiguousTargetError, ProfileError, OutputRootError, \
    SessionError, ReadOnlySessionError, CallsDisabledError, DumpMismatchError, UnverifiedOffsetsError, \
    AmbiguousNameError, CallError, MarshalError

_LAZY: dict[str, str] = {
    'Unreal': 'session',
    'FNameValue': 'names',
    'UObjectProxy': 'types',
    'StructView': 'types',
    'RawPointer': 'types',
    'WeakObjectPtr': 'codecs',
    'LazyObjectPtr': 'codecs',
    'SoftObjectPtr': 'codecs',
    'FTextValue': 'codecs',
    'DelegateBinding': 'codecs',
    'DelegateValue': 'codecs',
    'TArrayValue': 'containers',
    'TSetValue': 'containers',
    'TMapValue': 'containers',
    'FixedArrayValue': 'containers',
    'MulticastDelegateValue': 'containers',
    'StructValue': 'invoke',
}


def __getattr__(name: str):
    if name not in _LAZY:
        raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
    module = importlib.import_module(f'{__name__}.{_LAZY[name]}')
    value = getattr(module, name)
    globals()[name] = value
    return value
