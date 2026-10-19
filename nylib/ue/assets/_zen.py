"""Zen (IoStore) package headers, the global ScriptObjects table, and the unversioned property skipper.

Only the unversioned, UE 5.3+ zen layout (UE5 object version 1018, the UE 5.7 profile) is read.
"""
import bisect
import re
import struct
from array import array
from typing import NamedTuple

from ..errors import CorruptAssetError, InvalidMappingError, UnsupportedAssetError

_UE5_OBJECT_VERSION = 1018  # the stage-1 profile; implies VERSE_CELLS offsets and the DATA_RESOURCES bulk map
_NAME_INDEX_MASK = (1 << 30) - 1
_SUMMARY_FMT = '<IIIIIIiiiiiii'  # has_versioning, header_size, name(2xu32), flags, cooked_size, 7 section offsets
_SUMMARY_SIZE = struct.calcsize(_SUMMARY_FMT)
_BULK_ENTRY_FMT = '<QQQIBhB'
_BULK_ENTRY_SIZE = struct.calcsize(_BULK_ENTRY_FMT)
_EXPORT_FMT = '<QQIIQQQQQIB'
_EXPORT_SIZE = 72  # the struct above is 69 bytes; 3 trailing pad bytes are skipped per entry
_SCRIPT_ENTRY_FMT = '<IIQQQ'
_SCRIPT_ENTRY_SIZE = struct.calcsize(_SCRIPT_ENTRY_FMT)
_CONTROL = re.compile('[\x00-\x1f\x7f]')

MAX_PACKAGE_CHUNK = 64 << 20  # an ExportBundleData chunk is read whole only up to this many bytes


def check_package_chunk_size(length: int, container: str, chunk_id: int) -> None:
    """Raise before a caller reads an ExportBundleData chunk whole, when its TOC-declared length exceeds the cap."""
    if length > MAX_PACKAGE_CHUNK:
        detail = f'package chunk of {length} bytes exceeds the {MAX_PACKAGE_CHUNK}-byte limit'
        raise CorruptAssetError(f'{container} chunk {chunk_id:016x} (ExportBundleData): {detail}',
                                container=container, detail=detail)


class Reader:
    """A bounds-checked cursor over raw bytes; every out-of-range read raises ValueError, never struct.error."""
    __slots__ = ('data', 'pos')

    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError(f'read of {n} bytes at {self.pos} past the end ({len(self.data)} available)')
        b = self.data[self.pos:self.pos + n]
        self.pos += n
        return b

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack('<H', self.take(2))[0]

    def i32(self) -> int:
        return struct.unpack('<i', self.take(4))[0]

    def u32(self) -> int:
        return struct.unpack('<I', self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack('<Q', self.take(8))[0]

    def i64(self) -> int:
        return struct.unpack('<q', self.take(8))[0]


def _load_name_batch(r: Reader) -> tuple:
    """FNameEntrySerialized.LoadNameBatch: count, string-byte total, hash version, hashes, 2-byte headers, strings.

    A name that does not decode, or holds a control character, raises ValueError.
    """
    count = r.i32()
    if count <= 0:
        return ()
    r.u32()  # total string bytes; not needed to decode
    r.u64()  # hash version
    r.take(8 * count)  # per-name hashes, not needed to decode
    headers = r.take(2 * count)
    names = []
    for i in range(count):
        d0, d1 = headers[2 * i], headers[2 * i + 1]
        length = ((d0 & 0x7F) << 8) + d1
        wide = d0 & 0x80
        try:
            name = r.take(2 * length).decode('utf-16-le') if wide else r.take(length).decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError(f"name {i} is not valid {'UTF-16' if wide else 'UTF-8'}") from None
        if _CONTROL.search(name):
            raise ValueError(f'name {i} contains a control character')
        names.append(name)
    return tuple(names)


def _local_name(idx_and_type: int, extra: int, names: tuple) -> str:
    """A package-local FMappedName: the package's own name and its exports' names are never global references."""
    if idx_and_type >> 30:
        raise ValueError(f'name {idx_and_type:#x} is a global reference, not a local one')
    idx = idx_and_type & _NAME_INDEX_MASK
    if not 0 <= idx < len(names):
        raise ValueError(f'name index {idx} out of range for {len(names)} names')
    s = names[idx]
    return s if extra == 0 else f'{s}_{extra - 1}'


class BulkDataEntry(NamedTuple):
    serial_offset: int
    duplicate_serial_offset: int
    serial_size: int
    flags: int
    cooked_index: int


class Export(NamedTuple):
    offset: int  # CookedSerialOffset, relative to the header size
    size: int  # CookedSerialSize
    name: str
    outer: int  # raw FPackageObjectIndex (u64)
    cls: int
    super: int
    template: int
    public_export_hash: int
    object_flags: int
    filter_flags: int


class ZenHeader:
    """A parsed zen package header (summary, name batch, bulk-data map, import and export maps)."""

    def __init__(self, data: bytes):
        self.data = data
        pkg = None

        def corrupt(detail: str) -> CorruptAssetError:
            message = detail if pkg is None else f'{pkg}: {detail}'
            return CorruptAssetError(message, package=pkg, detail=detail)

        try:
            r = Reader(data)
            has_versioning, header_size, n0, n1, package_flags, _cooked_header_size, hashes_off, import_off, \
                export_off, bundle_off, _dep_headers_off, _dep_entries_off, _pkg_names_off = \
                struct.unpack('<IIIIIIiiiiiii', r.take(_SUMMARY_SIZE))
        except ValueError as e:
            raise corrupt(str(e)) from None
        if has_versioning:
            raise UnsupportedAssetError('a versioned zen package is not supported by this nylib version',
                                         feature='versioned zen package')
        if _UE5_OBJECT_VERSION >= 1015:  # VERSE_CELLS: two more i32 section offsets, unused in stage 1
            try:
                r.take(8)
            except ValueError as e:
                raise corrupt(str(e)) from None
        try:
            names = _load_name_batch(r)
            pkg = _local_name(n0, n1, names)
        except ValueError as e:
            raise corrupt(str(e)) from None

        try:
            pad = r.u64()
            r.take(pad)  # UE5.4+ padding before the bulk-data map; content unused
            bulk_bytes_len = r.i64()
            if bulk_bytes_len < 0 or bulk_bytes_len % _BULK_ENTRY_SIZE:
                raise ValueError(f'bulk-data map size {bulk_bytes_len} is not a multiple of {_BULK_ENTRY_SIZE}')
            bulk_bytes = r.take(bulk_bytes_len)
        except ValueError as e:
            raise corrupt(str(e)) from None
        bulk_data_map = tuple(
            BulkDataEntry(*struct.unpack_from(_BULK_ENTRY_FMT, bulk_bytes, i)[:5])
            for i in range(0, bulk_bytes_len, _BULK_ENTRY_SIZE))

        n = len(data)
        for off_name, off in (('imported hashes', hashes_off), ('import map', import_off),
                              ('export map', export_off), ('export bundle entries', bundle_off)):
            if not 0 <= off <= n:
                raise corrupt(f'the {off_name} offset {off} is outside the header chunk')
        if not hashes_off <= import_off <= export_off <= bundle_off:
            raise corrupt('the zen header section offsets are out of order')
        if (import_off - hashes_off) % 8 or (export_off - import_off) % 8:
            raise corrupt('the import map or imported-hashes size is not a multiple of 8')
        if (bundle_off - export_off) % _EXPORT_SIZE:
            raise corrupt(f'the export map size is not a multiple of {_EXPORT_SIZE}')

        n_imports = (export_off - import_off) // 8
        self.imports = struct.unpack_from(f'<{n_imports}Q', data, import_off) if n_imports else ()

        n_exports = (bundle_off - export_off) // _EXPORT_SIZE
        exports = []
        for i in range(n_exports):
            fields = struct.unpack_from(_EXPORT_FMT, data, export_off + _EXPORT_SIZE * i)
            try:
                name = _local_name(fields[2], fields[3], names)
            except ValueError as e:
                raise corrupt(str(e)) from None
            exports.append(Export(fields[0], fields[1], name, *fields[4:9], *fields[9:11]))

        for e in exports:
            start, end = header_size + e.offset, header_size + e.offset + e.size
            if not 0 <= start <= end <= n:
                raise corrupt(f"export {e.name!r}'s data range is outside the header chunk")

        self.name = pkg
        self.header_size = header_size
        self.package_flags = package_flags
        self.names = names
        self.bulk_data_map = bulk_data_map
        self.exports = tuple(exports)

    def export_range(self, i: int) -> tuple:
        """(start, end) of export `i`'s cooked data, absolute within the header chunk."""
        e = self.exports[i]
        start = self.header_size + e.offset
        return start, start + e.size


class ScriptObjects:
    """global.utoc's ScriptObjects chunk: the global name batch plus the FScriptObjectEntry table.

    Kept compact: entries stay as one raw bytes block, decoded per lookup; a single sorted index
    supports `class_name` by global index. `index_of` is a one-time linear scan (called at most once
    per installation) and does not need its own index.
    """

    def __init__(self, data: bytes):
        try:
            r = Reader(data)
            names = _load_name_batch(r)
            count = r.i32()
            if count < 0 or count * _SCRIPT_ENTRY_SIZE > r.remaining():
                raise ValueError(f'entry count {count} exceeds the chunk')
            entries = r.take(count * _SCRIPT_ENTRY_SIZE)
        except ValueError as e:
            raise CorruptAssetError(f'the global ScriptObjects chunk is truncated or malformed: {e}',
                                     detail=str(e)) from None
        self._names = names
        self._entries = entries
        self._count = count
        order = sorted(range(count), key=lambda i: struct.unpack_from('<Q', entries, _SCRIPT_ENTRY_SIZE * i + 8)[0])
        self._keys = array('Q', (struct.unpack_from('<Q', entries, _SCRIPT_ENTRY_SIZE * i + 8)[0] for i in order))
        self._order = array('L', order)

    def _entry(self, i: int) -> tuple:
        name_idx, extra, gidx, outer, cdo_class = struct.unpack_from(_SCRIPT_ENTRY_FMT, self._entries, _SCRIPT_ENTRY_SIZE * i)
        return name_idx, extra, gidx, outer, cdo_class

    def _name(self, name_idx_and_type: int, extra: int) -> str:
        idx = name_idx_and_type & _NAME_INDEX_MASK
        if not 0 <= idx < len(self._names):
            detail = 'a name index is out of range'
            raise CorruptAssetError(f'the global ScriptObjects chunk is truncated or malformed: {detail}', detail=detail)
        s = self._names[idx]
        return s if extra == 0 else f'{s}_{extra - 1}'

    def _by_global_index(self, gidx: int):
        i = bisect.bisect_left(self._keys, gidx)
        if i == len(self._keys) or self._keys[i] != gidx:
            return None
        return self._entry(self._order[i])

    def class_name(self, index: int) -> 'str | None':
        """The script object's own name at global index `index`, or None when there is no such entry."""
        e = self._by_global_index(index)
        return None if e is None else self._name(e[0], e[1])

    def index_of(self, path: str) -> 'int | None':
        """The global index of `path` ('/Script/Package.Object'), or None when there is no such entry."""
        pkg, sep, obj = path.rpartition('.')
        if not sep or not pkg or not obj:
            return None
        for i in range(self._count):
            name_idx, extra, gidx, outer, _cdo = self._entry(i)
            if self._name(name_idx, extra) != obj:
                continue
            outer_entry = self._by_global_index(outer)
            if outer_entry is not None and self._name(outer_entry[0], outer_entry[1]) == pkg:
                return gidx
        return None


_FIXED_TYPE_SIZES = {
    0: 1,  # Byte
    2: 4,  # Int
    3: 4,  # Float
    4: 4,  # Object
    7: 8,  # Double
    14: 4,  # WeakObject
    18: 8,  # UInt64
    19: 4,  # UInt32
    20: 2,  # UInt16
    21: 8,  # Int64
    22: 2,  # Int16
    23: 1,  # Int8
}
_UNIMPLEMENTED_TYPE_NAMES = {
    6: 'Delegate', 11: 'Text', 12: 'Interface', 13: 'MulticastDelegate', 15: 'LazyObject',
    16: 'AssetObject', 24: 'Map', 25: 'Set', 27: 'FieldPath', 28: 'Optional',
}
_NATIVE_FIXED_STRUCTS = {
    'Guid': 16, 'IntPoint': 8, 'Int32Point': 8, 'LinearColor': 16, 'Color': 4, 'Vector': 24,
    'PerPlatformFloat': 8, 'PerPlatformInt': 8,
}
# CUE4Parse's native FScriptStruct switch ($REFS/CUE4Parse/UE4/Assets/Objects/FScriptStruct.cs), minus the
# natives this nylib version implements (_NATIVE_FIXED_STRUCTS plus PerQualityLevelInt): a reflected struct
# reads through its mapping record; one of these names instead raises UnsupportedAssetError.
_UNIMPLEMENTED_NATIVE_STRUCTS = frozenset({
    'AIBehaviorTreeReference', 'AIGroupBehaviorClassSelector', 'AISensingStatusTransition', 'AISensingStatusTransitionStruct', 'AbstractEnum', 'ActorReference',
    'AlkimiaLightweightStaticMeshProxyDesc', 'AnimMontageContainer', 'AnimationAttributeIdentifier', 'AnnotationPointData2', 'AnyValue', 'AssetDataSerializable',
    'AttributeCurve', 'BHVRVariantConfigurator', 'BRGuid', 'BhvrBarkNodeTemplate', 'BlueprintDefinedScript', 'BlueprintFunctionLibraryConditional',
    'BodyInstance', 'Box', 'Box2D', 'Box2f', 'Box3f', 'BrickStudGroup',
    'CacheEventTrack', 'CapsuleShape', 'ChalkboardSectionKey', 'ClothLODData', 'ClothLODDataCommon', 'ClothTetherData',
    'ColorMaterialInput', 'CompressedRichCurve', 'ConnectivityCube', 'ControlRigOverrideContainer', 'Core1047ReleaseFlag', 'DataCacheDuplicatedObjectData',
    'DateTime', 'DeprecateSlateVector2D', 'DistanceQuantity', 'EdGraphPinType', 'EncVector', 'EnumName',
    'EveryPlatformBool', 'EveryPlatformFloat', 'EveryPlatformInt', 'ExpressionInput', 'FWAbilityResourceFloatMapping', 'FWPerkContextFloatMapping',
    'FixedPoint', 'FoWAgentHandle', 'FontCharacter', 'FontData', 'ForceQuantity', 'FortActorRecord',
    'FrameNumber', 'GG_CrowdGeneratorLocations', 'GPRowName', 'GameplayEffectApplicationDataHandle', 'GameplayEffectFloatMapping', 'GameplayEffectVersion',
    'GameplayEventDescriptor', 'GameplayEventFunction', 'GameplayTagContainer', 'HavokAIAnyArray', 'HavokNavAnyArray', 'HexCell',
    'HexOffsetCoord', 'InstancedOverridablePropertyBag', 'InstancedPropertyBag', 'InstancedStruct', 'InstancedStructArray', 'InstancedStructContainer',
    'Int32Vector2', 'Int64Point', 'Int64Vector', 'Int64Vector2', 'Int64Vector4', 'IntVector',
    'IntVector2', 'IntVector4', 'ItemDataContainer', 'ItemStack', 'ItemsBitArray', 'JsonObjectWrapper',
    'JumpParams', 'KGVariantValue', 'KeyHandleMap', 'KosmosHangTraversalData', 'LSAAudioSectionkey', 'LedgeMetaData',
    'LegoConnectionPoint', 'LegoGraphPartInstance', 'LegoPartInstance', 'LegoPartLODGeometry', 'LevelSequenceObjectReferenceMap', 'Linecode',
    'MGEPassiveEquipStruct', 'MarvelSoftObjectPath', 'MassQuantity', 'MaterialAttributesInput', 'MaterialLayersFunctionsTree', 'MaterialOverrideNanite',
    'MaterialTextureInfo', 'Matrix', 'Matrix44f', 'MercunaNavUsageTypes', 'MercunaPawnUsageFlags', 'MercunaUsageSpec',
    'MercunaUsageTypes', 'MidiEvent', 'MovieSceneDoubleChannel', 'MovieSceneDoubleValue', 'MovieSceneEvalTemplatePtr', 'MovieSceneEvaluationFieldEntityTree',
    'MovieSceneEvaluationKey', 'MovieSceneEventParameters', 'MovieSceneFloatChannel', 'MovieSceneFloatValue', 'MovieSceneFrameRange', 'MovieSceneSegment',
    'MovieSceneSegmentIdentifier', 'MovieSceneSequenceID', 'MovieSceneSequenceInstanceDataPtr', 'MovieSceneSubSectionFieldData', 'MovieSceneSubSequenceTree', 'MovieSceneTangentData',
    'MovieSceneTimeWarpVariant', 'MovieSceneTrackFieldData', 'MovieSceneTrackIdentifier', 'MovieSceneTrackIdentifiers', 'MovieSceneTrackImplementationPtr', 'NameCurveKey',
    'NamedGuid', 'NavAgentSelector', 'NiagaraDataChannelVariable', 'NiagaraDataInterfaceGPUParamInfo', 'NiagaraEventGeneratorProperties', 'NiagaraUserParameterModifier',
    'NiagaraVariable', 'NiagaraVariableBase', 'NiagaraVariableWithOffset', 'OffsetCoords', 'P2Attribute', 'PCGDataPtrWrapper',
    'PCGPoint', 'PCGPointArray', 'PMBoundFloatMapping', 'PMFloatMapping', 'PMTimelineFloatMapping', 'PMTimelineObjectBindingDef',
    'PMTimelineRelevancy', 'PMTimelineSectionEventFloatMapping', 'PMTimelineSectionFloatMapping', 'PackedNormal', 'PannerDetails', 'ParamRegistryInfo',
    'ParameterWrapperArray', 'PerPlatformBool', 'PerPlatformERigLogicCalculationType', 'PerPlatformERigLogicFloatingPointType', 'PerPlatformFString', 'PerPlatformFrameRate',
    'PerPlatformMediaSource', 'PerPlatformSoftObjectPtr', 'PerPlatformUObject', 'PerQualityLevelFloat', 'Plane', 'Plane4d',
    'Plane4f', 'PowerQuantity', 'PressureQuantity', 'Quat', 'Quat4d', 'Quat4f',
    'R5CollisionApproximation', 'R5SoftAssetPath', 'RDialogueFactValue', 'RRotationTranslation', 'RawAnimSequenceTrack', 'RichCurveKey',
    'RigVMPropertyBag', 'Rotator', 'Rotator3d', 'Rotator3f', 'RsBitfield_HeroBufferFlags', 'RsBitfield_HeroInputFlags',
    'RsBitfield_HeroLoadoutFlags', 'RsBitfield_HeroUpgradeFlags', 'RsBitfield_NavPermissionDetailFlags', 'RsBitfield_NavPermissionFlags', 'RsBitfield_NavState', 'RsBitfield_RsIkBoneTypes',
    'RsBitfield_UINavigationInput', 'RsBitfield_WorldMapLODLevel', 'RsBitfield_WorldMapLevelType', 'RsBitfield_WorldMapWidgetFilterType', 'RulesetActorCreationParams', 'RulesetId',
    'SOS_GDValue', 'SPBattleGenericID', 'SUDSValue', 'ScalarMaterialInput', 'ScalarParameterValue', 'SceneFaceDefSeamline',
    'SectionEvaluationDataTree', 'SerializablePropertySoftPath', 'ShaderValueTypeHandle', 'SimpleBox', 'SimpleCurveKey', 'SkeletalMeshSamplingLODBuiltData',
    'SkeletalMeshSamplingRegionBuiltData', 'SmartName', 'SoftClassPath', 'SoftEnumName', 'SoftObjectPath', 'SoundAttenuationPluginSettingsWithOverride',
    'SpeedQuantity', 'Sphere', 'Sphere3d', 'Sphere3f', 'Spline', 'StateTreeInstanceData',
    'StringAssetReference', 'StringClassReference', 'StringCurveKey', 'SwBitfield_TargetRotatorMask', 'TCGameplayBlackboardNamedParam_Float', 'TCGameplayBlackboardNamedParam_Vector',
    'TCPresentationCueNamedParam_Bool', 'TCPresentationCueNamedParam_Float', 'TCPresentationCueNamedParam_LinearColor', 'TCPresentationCueNamedParam_Material', 'TCPresentationCueNamedParam_StaticMesh', 'TCPresentationCueNamedParam_Texture',
    'TCPresentationCueNamedParam_Vector', 'TCPresentationCueNamedParam_Vector2D', 'TLJsonGuid', 'TLJsonVector', 'TLJsonVector2D', 'TedInstancedStruct',
    'TedMarkerHandle', 'TextureParameterValue', 'TimeUnit', 'Timespan', 'Transform3f', 'TslSomeSKStruct',
    'TtScalableLightFloat', 'TtScalableShadowBool', 'TtScalableShadowFloat', 'TwoVectors', 'TypedParameter', 'UGCPropertyDefaultValueOverride',
    'UInt32Property', 'UInt64Point', 'UInt64Vector', 'UInt64Vector2', 'UInt64Vector4', 'UWEWorldPopSpatialLayer',
    'UgcData', 'Uint32Point', 'Uint32Vector4', 'UintVector', 'UintVector2', 'UintVector4',
    'UniqueNetIdRepl', 'UniversalObjectLocatorFragment', 'VAL_CharacterCustomizationVariantOptionsArray', 'VGCoverDataPoint', 'Vector2D', 'Vector2MaterialInput',
    'Vector2f', 'Vector3d', 'Vector3f', 'Vector4', 'Vector4d', 'Vector4f',
    'VectorDouble', 'VectorMaterialInput', 'VectorParameterValue', 'Vector_NetQuantize', 'Vector_NetQuantize10', 'Vector_NetQuantize100',
    'Vector_NetQuantizeNormal', 'Vector_NetQuantize_AsStruct', 'VinInstancedPropertyBag', 'VinInstancedStruct', 'VolumeQuantity', 'VoyageFloat16',
    'VoyagePackedLocalTransform', 'WaynetNode', 'WaynetPath', 'WeaponPassiveID', 'WorldConditionQueryDefinition', 'ZeroSizeProperty',
})
_MAX_STRUCT_DEPTH = 16
_MAX_SCHEMA_SLOTS = 1 << 16  # schema slots one unversioned header may describe


class PropertySkipper:
    """Skips an unversioned property block without materialising values, per the stage-1 type/native profile."""

    def __init__(self, mappings, names: tuple, usmap: str):
        self._mappings = mappings
        self._names = names
        self._usmap = usmap

    def skip(self, reader: Reader, class_name: str, *, package: str, size: int) -> None:
        """Skip one class's unversioned property block; `size` is the whole export's length, for messages."""
        self._pkg = package
        self._size = size
        self._skip_properties(reader, class_name, 0)

    def _fail(self, reader: Reader, class_name: str, reason: str) -> None:
        message = (f'{self._usmap} does not fit {self._pkg}: the {class_name} properties cannot be read at '
                   f'{reader.pos:#x} ({reason}; export is {self._size} bytes)')
        raise InvalidMappingError(message, usmap=self._usmap, class_name=class_name, reason=reason)

    def _lookup_fail(self, class_name: str, index: int, kind: str) -> None:
        if kind == 'no_property':
            message = f'{self._usmap} cannot read {self._pkg}: {class_name} has no property at index {index}'
            reason = 'no property'
        elif kind == 'unknown_type':
            message = f'{self._usmap} cannot read {self._pkg}: {class_name} property {index} has an unknown type'
            reason = 'unknown type'
        else:
            message = (f'{self._usmap} cannot read {self._pkg}: {class_name} property {index} is a StructProperty '
                       f"of struct 'None' (size unknown)")
            reason = "struct 'None'"
        raise InvalidMappingError(message, usmap=self._usmap, class_name=class_name, property_index=index, reason=reason)

    def _read_header(self, reader: Reader, class_name: str):
        """Read an unversioned header; yields (schema index, nonzero) lazily once the header and its zero mask are read."""
        fragments = []
        zero_num = 0
        span = 0
        while True:
            try:
                packed = reader.u16()
            except ValueError:
                self._fail(reader, class_name, 'bad property header')
            skip, has_zero, value_num, is_last = packed & 0x7F, bool(packed & 0x80), packed >> 9, bool(packed & 0x100)
            span += skip + value_num
            if span > _MAX_SCHEMA_SLOTS or (not is_last and skip + value_num == 0):
                self._fail(reader, class_name, 'bad property header')
            fragments.append((skip, has_zero, value_num))
            if has_zero:
                zero_num += value_num
            if is_last:
                break
        raw = b''
        if zero_num:
            nbytes = 1 if zero_num <= 8 else 2 if zero_num <= 16 else 4 * ((zero_num + 31) // 32)
            try:
                raw = reader.take(nbytes)
            except ValueError:
                self._fail(reader, class_name, 'bad property header')
        return self._entries(fragments, raw)

    @staticmethod
    def _entries(fragments, raw):
        schema = 0
        zi = 0
        for skip, has_zero, value_num in fragments:
            schema += skip
            for _ in range(value_num):
                nonzero = True
                if has_zero:
                    nonzero = not ((raw[zi >> 3] >> (zi & 7)) & 1)
                    zi += 1
                yield schema, nonzero
                schema += 1

    def _skip_properties(self, reader: Reader, class_name: str, depth: int) -> None:
        if depth > _MAX_STRUCT_DEPTH:
            self._fail(reader, class_name, 'struct nesting')
        for schema, nonzero in self._read_header(reader, class_name):
            if not nonzero:
                continue
            try:
                found = self._mappings.lookup(class_name, schema)
            except InvalidMappingError as e:
                if e.reason != 'no record':
                    raise
                message = f'{self._usmap} cannot read {self._pkg}: it has no record for {e.class_name}'
                raise InvalidMappingError(message, usmap=self._usmap, class_name=e.class_name,
                                          property_index=e.property_index, reason='no record') from None
            if found is None:
                self._lookup_fail(class_name, schema, 'no_property')
            _owner, _name, ptype = found
            if ptype.code == 0xFF:
                self._lookup_fail(class_name, schema, 'unknown_type')
            self._skip_value(reader, ptype, depth, class_name, schema)

    def _skip_value(self, reader: Reader, ptype, depth: int, class_name: str, index: int) -> None:
        code = ptype.code
        size = _FIXED_TYPE_SIZES.get(code)
        if size is not None:
            try:
                reader.take(size)
            except ValueError:
                self._fail(reader, class_name, 'read past the export end')
            return
        if code == 1:  # Bool
            try:
                value = reader.u8()
            except ValueError:
                self._fail(reader, class_name, 'read past the export end')
            if value not in (0, 1):
                self._fail(reader, class_name, f'bool value {value}')
            return
        if code == 5:  # Name
            self._skip_name(reader, class_name)
            return
        if code == 17:  # SoftObject: FTopLevelAssetPath (2 FNames) + a UTF-8 sub-path (no terminator)
            self._skip_name(reader, class_name)
            self._skip_name(reader, class_name)
            self._skip_utf8_string(reader, class_name)
            return
        if code == 10:  # Str
            self._skip_string(reader, class_name)
            return
        if code == 26:  # Enum: the underlying integer value
            self._skip_value(reader, ptype.inner, depth, class_name, index)
            return
        if code == 8:  # Array
            self._skip_array(reader, ptype.inner, depth, class_name, index)
            return
        if code == 9:  # Struct
            self._skip_struct(reader, ptype.struct_name, depth, class_name, index)
            return
        feature = f'property type {_UNIMPLEMENTED_TYPE_NAMES.get(code, code)}'
        raise UnsupportedAssetError(f'{self._pkg}: {class_name} uses a {feature} property, which this nylib version does not read',
                                    feature=feature)

    def _skip_name(self, reader: Reader, class_name: str) -> None:
        try:
            idx, num = struct.unpack('<ii', reader.take(8))
        except ValueError:
            self._fail(reader, class_name, 'read past the export end')
        if not 0 <= idx < len(self._names):
            self._fail(reader, class_name, f'name index {idx}')
        if num < 0:
            self._fail(reader, class_name, f'name index {num}')

    def _skip_string(self, reader: Reader, class_name: str) -> None:
        try:
            length = reader.i32()
        except ValueError:
            self._fail(reader, class_name, 'read past the export end')
        if length == 0:
            return
        if length > 0:
            if length > reader.remaining():
                self._fail(reader, class_name, 'bad string')
            raw = reader.take(length)
            if raw[-1] != 0:
                self._fail(reader, class_name, 'bad string')
        else:
            need = -2 * length
            if need > reader.remaining():
                self._fail(reader, class_name, 'bad string')
            raw = reader.take(need)
            if raw[-2:] != b'\0\0':
                self._fail(reader, class_name, 'bad string')

    def _skip_utf8_string(self, reader: Reader, class_name: str) -> None:
        """FUtf8String: a byte count (no sign flip for width, no terminator), then exactly that many bytes."""
        try:
            length = reader.i32()
        except ValueError:
            self._fail(reader, class_name, 'read past the export end')
        if length == 0:
            return
        if length < 0 or length > reader.remaining():
            self._fail(reader, class_name, 'bad string')
        reader.take(length)

    def _skip_array(self, reader: Reader, inner, depth: int, class_name: str, index: int) -> None:
        try:
            count = reader.i32()
        except ValueError:
            self._fail(reader, class_name, 'read past the export end')
        if count < 0 or count > reader.remaining():
            self._fail(reader, class_name, f'array count {count}')
        for _ in range(count):
            self._skip_value(reader, inner, depth + 1, class_name, index)

    def _skip_struct(self, reader: Reader, struct_name, depth: int, class_name: str, index: int) -> None:
        if struct_name is None or struct_name == 'None':
            self._lookup_fail(class_name, index, 'struct_none')
        fixed = _NATIVE_FIXED_STRUCTS.get(struct_name)
        if fixed is not None:
            try:
                reader.take(fixed)
            except ValueError:
                self._fail(reader, class_name, 'read past the export end')
            return
        if struct_name == 'PerQualityLevelInt':
            try:
                reader.take(8)  # cooked bool32 + default int32
                n = reader.i32()
            except ValueError:
                self._fail(reader, class_name, 'read past the export end')
            if n < 0 or n * 8 > reader.remaining():
                self._fail(reader, class_name, 'read past the export end')
            reader.take(n * 8)
            return
        if struct_name in _UNIMPLEMENTED_NATIVE_STRUCTS:
            raise UnsupportedAssetError(f"{self._pkg}: {class_name} uses struct {struct_name!r}, which this nylib version does not read",
                                        feature=f'struct {struct_name}')
        self._skip_properties(reader, struct_name, depth + 1)
