"""Generator::InitEngineCore of Dumper-7 @ ea0dab3 over an Engine, and EngineContext (offsets.json / meta.json shapes)."""
import dataclasses
from collections.abc import Mapping
from typing import Callable

from ..errors import DetectionError
from ..memory import MemorySource
from ..model import hexs, unhex
from .core import Engine
from .offsets import PINNABLE_KEYS, init_gworld, init_pe, init_pe_windows, init_text_offsets, off_init, property_sizes_init
from .settings import init_settings
from .state import FChunkedFixedUObjectArrayLayout, FChunkedFixedUObjectArrayLayouts, FFixedUObjectArrayLayout, FFixedUObjectArrayLayouts, Off, PropertySizes, Settings
from .stem import Stem, detect_stem

ENGINE_REST_STEPS = ('Off::Init', 'PropertySizes::Init', 'InitPE', 'InitGWorld', 'InitTextOffsets', 'InitSettings', 'Stem')
ENGINE_CORE_STEPS = ('ObjectArray::Init', 'FName::Init') + ENGINE_REST_STEPS
HEADER_DEFAULT_LABELS = ('default: Offsets.h', 'default: Settings.h', 'default: NameArray.h')
COUNT_KEYS = ('Off.InSDK.ProcessEvent.PEIndex', 'Off.InSDK.ObjArray.ChunkSize', 'Off.InSDK.NameArray.FNamePoolBlockOffsetBits',
              'Off.InSDK.NameArray.FNameEntryStride', 'FNameEntry.FNameEntryLengthShiftCount')

_GAME_VERSION_KEY = 'Settings.Generator.GameVersion'
_GAME_NAME_KEY = 'Settings.Generator.GameName'
_PE_KEYS = ('Off.InSDK.ProcessEvent.PEIndex', 'Off.InSDK.ProcessEvent.PEOffset')
_LAYOUT_TYPES = {'Off.FUObjectArray.FixedLayout': FFixedUObjectArrayLayout, 'Off.FUObjectArray.ChunkedFixedLayout': FChunkedFixedUObjectArrayLayout}
_CHUNKED_LAYOUT_NAMES = dict(zip(FChunkedFixedUObjectArrayLayouts, ('chunked_default', 'chunked_ue58', 'chunked_back4blood', 'chunked_multiversus',
                                                                    'chunked_mindseye'), strict=True))
_ENGINE_FLAGS = (
    ('use_fproperty', 'bUseFProperty'), ('use_name_pool', 'bUseNamePool'), ('case_preserving_name', 'bUseCasePreservingName'),
    ('outline_number_name', 'bUseOutlineNumberName'), ('mask_for_field_owner', 'bUseMaskForFieldOwner'),
    ('large_world_coordinates', 'bUseLargeWorldCoordinates'), ('uint8_array_dim', 'bUseUint8ArrayDim'), ('enum_names_only', 'bIsEnumNameOnly'),
    ('small_enum_value', 'bIsSmallEnumValue'), ('ue56_enum_name_arrays', 'bIsNewUE5EnumNamesContainer'),
    ('weak_object_ptr_without_tag', 'bIsWeakObjectPtrWithoutTag'), ('objptr_instead_of_fieldpath', 'bIsObjPtrInsteadOfFieldPathProperty'),
    ('object_name_before_class', 'bIsObjectNameBeforeClass'),
)


def _walk(prefix: str, namespace) -> list[tuple[str, object]]:
    leaves = []
    for name in type(namespace).__slots__:
        value = getattr(namespace, name)
        if isinstance(value, int) or dataclasses.is_dataclass(value):
            leaves.append((f'{prefix}.{name}', value))
        else:
            leaves.extend(_walk(f'{prefix}.{name}', value))
    return leaves


def _kind(key: str, default) -> str:
    if key in _LAYOUT_TYPES:
        return 'layout'
    if isinstance(default, bool):
        return 'bool'
    return 'count' if key in COUNT_KEYS else 'hex'


_DEFAULTS = _walk('Off', Off()) + _walk('Settings.Internal', Settings().Internal) + _walk('PropertySizes', PropertySizes()) + \
    [('FNameEntry.FNameEntryLengthShiftCount', 0)]
_KINDS = {key: _kind(key, default) for key, default in _DEFAULTS}


def _holder(e: Engine, key: str) -> tuple[object, str]:
    head, *path, attr = key.split('.')
    obj = {'Off': e.off, 'Settings': e.settings, 'PropertySizes': e.property_sizes, 'FNameEntry': e.names}[head]
    for name in path:
        obj = getattr(obj, name)
    return obj, attr


def _header_default(key: str) -> str:
    if key.startswith('Settings.'):
        return 'default: Settings.h'
    return 'default: NameArray.h' if key.startswith('FNameEntry.') else 'default: Offsets.h'


def _is_unverified(label: str) -> bool:
    return label.startswith(('fallback:', 'not found:')) or (label.startswith('default:') and label not in HEADER_DEFAULT_LABELS)


def _encode(kind: str, value):
    if kind == 'bool':
        return bool(value)
    if kind == 'count':
        return value
    if kind == 'layout':
        return {f.name: hexs(getattr(value, f.name)) for f in dataclasses.fields(value)}
    return hexs(value)


def _validate(offsets_pins, pe_index, on_step) -> None:
    if offsets_pins is not None:
        if not isinstance(offsets_pins, Mapping):
            raise TypeError(f'offsets_pins must be a mapping, got {type(offsets_pins).__name__}')
        for key, value in offsets_pins.items():
            if key not in PINNABLE_KEYS:
                raise ValueError(f'offset {key!r} cannot be pinned')
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f'offset {key!r}: pin value must be an int, got {type(value).__name__}')
    if pe_index is not None:
        if not isinstance(pe_index, int) or isinstance(pe_index, bool):
            raise TypeError(f'pe_index must be an int, got {type(pe_index).__name__}')
        if pe_index < 0:
            raise ValueError(f'pe_index must be >= 0, got {pe_index}')
    if on_step is not None and not callable(on_step):
        raise TypeError(f'on_step must be callable, got {type(on_step).__name__}')


def init_engine_rest(e: Engine, *, offsets_pins: Mapping[str, int] | None = None, pe_index: int | None = None,
                     on_step: Callable[[str], None] | None = None) -> 'EngineContext':
    """Generator::InitEngineCore @ ea0dab3 from Off::Init on, plus the stem; ObjectArray::Init and FName::Init must have run."""
    _validate(offsets_pins, pe_index, on_step)
    step = on_step or (lambda name: None)
    step('Off::Init')
    off_init(e, pins=offsets_pins)
    step('PropertySizes::Init')
    property_sizes_init(e, pins=offsets_pins)
    step('InitPE')
    if pe_index is not None:
        init_pe(e, pe_index)
        for key in _PE_KEYS:
            e.provenance[key] = 'profile: value'
    else:
        init_pe_windows(e)
    step('InitGWorld')
    init_gworld(e)
    step('InitTextOffsets')
    init_text_offsets(e)
    step('InitSettings')
    init_settings(e)
    for key, value in (offsets_pins or {}).items():
        setattr(*_holder(e, key), value)
        e.provenance[key] = 'profile: value'
    step('Stem')
    return EngineContext(e, detect_stem(e))


def init_engine_core(e: Engine, *, offsets_pins: Mapping[str, int] | None = None, pe_index: int | None = None,
                     on_step: Callable[[str], None] | None = None) -> 'EngineContext':
    """Generator::InitEngineCore @ ea0dab3 (FName::Init under DV5), plus the stem."""
    _validate(offsets_pins, pe_index, on_step)
    step = on_step or (lambda name: None)
    step('ObjectArray::Init')
    e.objects.init()
    step('FName::Init')
    e.fname.init_windows()
    return init_engine_rest(e, offsets_pins=offsets_pins, pe_index=pe_index, on_step=on_step)


def _decode(kind: str, key: str, value):
    def problem(text: str):
        return ValueError(f'offsets.json: {key}: {text}')

    if kind == 'bool':
        if not isinstance(value, bool):
            raise problem(f'expected a JSON boolean, got {type(value).__name__}')
        return value
    if kind == 'count':
        if not isinstance(value, int) or isinstance(value, bool):
            raise problem(f'expected a JSON integer, got {type(value).__name__}')
        return value
    if kind == 'layout':
        cls = _LAYOUT_TYPES[key]
        names = [f.name for f in dataclasses.fields(cls)]
        if not isinstance(value, Mapping) or set(value) != set(names):
            raise problem(f'expected an object with the fields {", ".join(names)}')
        return cls(**{name: _decode('hex', f'{key}.{name}', value[name]) for name in names})
    try:
        return unhex(value)
    except ValueError:
        raise problem(f'expected a hexs string, got {value!r}') from None


class EngineContext:
    """One initialised Engine with its stem; serialises to the offsets.json / meta.json parts stage 5 owns."""
    __slots__ = ('engine', 'stem')

    def __init__(self, engine: Engine, stem: Stem):
        self.engine = engine
        self.stem = stem

    def _label(self, key: str) -> str:
        return self.engine.provenance.get(key, _header_default(key))

    def to_offsets(self) -> dict:
        """offsets.json without `schema`: every E3 key at its dotted path, plus `sources`."""
        e = self.engine
        doc = {}
        for key, kind in _KINDS.items():
            *path, attr = key.split('.')
            node = doc
            for name in path:
                node = node.setdefault(name, {})
            node[attr] = _encode(kind, getattr(*_holder(e, key)))
        doc['sources'] = {key: self._label(key) for key in _KINDS}
        return doc

    def to_meta(self) -> dict:
        """The meta.json parts stage 5 owns; reads ObjectArray::Num()."""
        e, o, stem = self.engine, self.engine.off, self.stem
        image = e.platform.image
        objarr, fuoa, name = o.InSDK.ObjArray, o.FUObjectArray, o.InSDK.Name
        if fuoa.bIsChunked:
            layout = _CHUNKED_LAYOUT_NAMES.get(fuoa.ChunkedFixedLayout, 'chunked_custom')
        else:
            layout = 'fixed_default' if fuoa.FixedLayout in FFixedUObjectArrayLayouts else 'fixed_custom'
        pe_found = o.InSDK.ProcessEvent.PEOffset != 0
        return {
            'target': {
                'module': {'base': hexs(image.base), 'size': hexs(image.size), 'pe_timestamp': hexs(image.timestamp)},
                'engine_version': stem.engine_version, 'engine_version_from': e.provenance.get(_GAME_VERSION_KEY),
                'game_name': stem.game_name, 'game_name_from': e.provenance.get(_GAME_NAME_KEY),
                'game_version': None, 'stem': stem.stem, 'branch': stem.branch,
            },
            'engine': {meta_key: bool(getattr(e.settings.Internal, flag)) for meta_key, flag in _ENGINE_FLAGS},
            'globals': {
                'GObjects': {'rva': hexs(objarr.GObjects), 'layout': layout, 'elements_per_chunk': objarr.ChunkSize if fuoa.bIsChunked else None,
                             'item_size': hexs(objarr.FUObjectItemSize), 'item_object_offset': hexs(objarr.FUObjectItemInitialOffset),
                             'num_elements': e.objects.num()},
                'GNames': {'rva': hexs(o.InSDK.NameArray.GNames), 'kind': 'FNamePool' if e.settings.Internal.bUseNamePool else 'TNameEntryArray',
                           'block_offset_bits': o.InSDK.NameArray.FNamePoolBlockOffsetBits, 'entry_stride': o.InSDK.NameArray.FNameEntryStride,
                           'length_shift': e.names.FNameEntryLengthShiftCount},
                'GWorld': {'rva': hexs(o.InSDK.World.GWorld) if o.InSDK.World.GWorld else None},
                'ProcessEvent': {'vtable_index': o.InSDK.ProcessEvent.PEIndex if pe_found else None,
                                 'rva': hexs(o.InSDK.ProcessEvent.PEOffset) if pe_found else None},
                'AppendString': {'rva': hexs(name.AppendNameToString) if name.AppendNameToString else None,
                                 'kind': 'AppendString' if name.bIsUsingAppendStringOverToString else 'ToString',
                                 'inlined': bool(name.bIsAppendStringInlinedAndUsed), 'called': False},
            },
        }

    def unverified(self) -> list[str]:
        """Keys whose label is fallback:, not found: or a non-header default:, in document order, then the stem keys."""
        keys = [key for key in _KINDS if _is_unverified(self._label(key))]
        provenance = self.engine.provenance
        keys += [key for key in (_GAME_VERSION_KEY, _GAME_NAME_KEY) if (label := provenance.get(key)) is not None and _is_unverified(label)]
        return keys

    @classmethod
    def from_snapshot(cls, meta: Mapping, offsets: Mapping, source: MemorySource) -> 'EngineContext':
        """Re-attach to `source` from a snapshot's meta.json / offsets.json without running the finders (chunked GObjects only)."""
        e = Engine(source)

        values = {}
        for key, kind in _KINDS.items():
            node = offsets
            for name in key.split('.'):
                if not isinstance(node, Mapping) or name not in node:
                    raise ValueError(f'offsets.json: {key}: missing')
                node = node[name]
            values[key] = _decode(kind, key, node)
        sources = offsets.get('sources') if isinstance(offsets, Mapping) else None
        if not isinstance(sources, Mapping):
            raise ValueError('offsets.json: sources: missing or not an object')
        target = meta.get('target') if isinstance(meta, Mapping) else None
        target = target if isinstance(target, Mapping) else {}
        for key in ('engine_version', 'engine_version_from', 'game_name', 'game_name_from', 'branch'):
            if key not in target:
                raise ValueError(f'meta.json: target.{key}: missing')
            if not isinstance(target[key], str) and not (key == 'branch' and target[key] is None):
                raise ValueError(f'meta.json: target.{key}: expected a string, got {type(target[key]).__name__}')

        if not values['Off.FUObjectArray.bIsChunked']:
            raise DetectionError('EngineContext.from_snapshot', 'a fixed GObjects layout cannot be re-attached')
        e.objects.init_chunked(values['Off.InSDK.ObjArray.GObjects'], values['Off.InSDK.ObjArray.ChunkSize'], values['Off.FUObjectArray.ChunkedFixedLayout'])
        objarr = e.off.InSDK.ObjArray
        if (objarr.FUObjectItemSize != values['Off.InSDK.ObjArray.FUObjectItemSize']
                or objarr.FUObjectItemInitialOffset != values['Off.InSDK.ObjArray.FUObjectItemInitialOffset']):
            raise DetectionError('EngineContext.from_snapshot', 'FUObjectItem layout differs from the snapshot')

        gnames = values['Off.InSDK.NameArray.GNames']
        use_name_pool = values['Settings.Internal.bUseNamePool']
        try:
            e.fname.init_override(gnames, 'GNames', use_name_pool)
        except DetectionError as err:
            raise DetectionError('EngineContext.from_snapshot', f'GNames at {hexs(gnames)} does not validate on this target') from err

        for key, value in values.items():
            setattr(*_holder(e, key), value)
        if use_name_pool:
            e.names.FNameBlockOffsetBits = values['Off.InSDK.NameArray.FNamePoolBlockOffsetBits']
        e.provenance = dict(sources)

        stem = Stem(engine_version=target['engine_version'], game_name=target['game_name'], branch=target['branch'])
        e.settings.Generator.GameVersion = stem.engine_version
        e.settings.Generator.GameName = stem.game_name
        e.provenance[_GAME_VERSION_KEY] = target['engine_version_from']
        e.provenance[_GAME_NAME_KEY] = target['game_name_from']
        return cls(e, stem)
