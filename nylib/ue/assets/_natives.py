"""The native struct layouts of the typed export reader: fixed layouts, variable layouts and their zero values."""
import struct

from ._usmap import PropertyType
from ._values import MapValue, ObjectRef, Slot, SoftObjectRef, StructValue, _layout

_LABELS = {'B': 'Byte', 'b': 'Int8', 'H': 'UInt16', 'h': 'Int16', 'i': 'Int', 'I': 'UInt32', 'q': 'Int64', 'Q': 'UInt64',
           'f': 'Float', 'd': 'Double'}
EMPTY_SOFT = SoftObjectRef('', '', '', '')


class Fixed:
    """A fixed-layout native: its fields are scalars, nested fixed natives, or a 4x4 matrix ('M' plus a scalar code)."""
    __slots__ = ('name', 'size', 'fields', 'flat', 'layout', 'zero_slots', 'zero_values')

    def __init__(self, name: str, fields: tuple):
        self.name = name
        out, off = [], 0
        for fname, sub in fields:
            if isinstance(sub, Fixed):
                out.append((fname, f'Struct<{sub.name}>', off, sub))
                off += sub.size
            elif sub[0] == 'M':
                out.append((fname, f'Array<Array<{_LABELS[sub[1]]}>>', off, sub))
                off += 16 * struct.calcsize('<' + sub[1])
            else:
                out.append((fname, _LABELS[sub], off, sub))
                off += struct.calcsize('<' + sub)
        self.size = off
        self.fields = tuple(out)
        self.flat = struct.Struct('<' + ''.join(f[1] for f in fields)) if all(isinstance(s, str) and len(s) == 1 for _f, s in fields) else None
        self.zero_slots = tuple(Slot(i, name, f, label, 'zero', None) for i, (f, label, _o, _s) in enumerate(self.fields))
        self.layout = _layout(self.zero_slots)
        self.zero_values = tuple(_zero_field(sub) for _f, _l, _o, sub in self.fields)

    def read(self, data, pos: int, ctx: tuple) -> StructValue:
        """The value at `pos`; the caller has checked that `size` bytes remain."""
        name = self.name
        if self.flat is not None:
            values = self.flat.unpack_from(data, pos)
        else:
            values = tuple(_read_field(sub, data, pos + off, ctx) for _f, _l, off, sub in self.fields)
        slots = tuple(Slot(i, name, f, label, 'serialized', pos + off) for i, (f, label, off, _s) in enumerate(self.fields))
        return StructValue._new(name, True, slots, values, ctx, None, self.layout)

    def zero(self, ctx: tuple) -> StructValue:
        values = tuple(v.zero(ctx) if isinstance(v, Fixed) else v for v in self.zero_values)
        return StructValue._new(self.name, True, self.zero_slots, values, ctx, None, self.layout)


def _zero_field(sub):
    if isinstance(sub, Fixed):
        return sub
    if sub[0] == 'M':
        return ((0.0,) * 4,) * 4 if sub[1] in 'fd' else ((0,) * 4,) * 4
    return 0.0 if sub in 'fd' else 0


def _read_field(sub, data, pos: int, ctx: tuple):
    if isinstance(sub, Fixed):
        return sub.read(data, pos, ctx)
    if sub[0] == 'M':
        m = struct.unpack_from('<' + sub[1] * 16, data, pos)
        return tuple(m[r * 4:r * 4 + 4] for r in range(4))
    return struct.unpack_from('<' + sub, data, pos)[0]


def _fields(names: str, code: str) -> tuple:
    return tuple((n, code) for n in names.split())


FIXED: dict[str, Fixed] = {}


def _add(names: str, fields: tuple) -> Fixed:
    """Register each of `names` with `fields`; returns the first name's spec."""
    for n in names.split():
        FIXED[n] = Fixed(n, fields)
    return FIXED[names.split()[0]]


_vector = _add('Vector Vector3d', _fields('X Y Z', 'd'))
_vector2d = _add('Vector2D', _fields('X Y', 'd'))
_add('Vector4 Vector4d', _fields('X Y Z W', 'd'))
_vector2f = _add('Vector2f DeprecateSlateVector2D', _fields('X Y', 'f'))
_vector3f = _add('Vector3f', _fields('X Y Z', 'f'))
_add('Vector4f', _fields('X Y Z W', 'f'))
_add('Vector_NetQuantize Vector_NetQuantize10 Vector_NetQuantize100 Vector_NetQuantizeNormal', _fields('X Y Z', 'd'))
_add('Rotator Rotator3d', _fields('Pitch Yaw Roll', 'd'))
_add('Rotator3f', _fields('Pitch Yaw Roll', 'f'))
_add('Quat Quat4d', _fields('X Y Z W', 'd'))
_add('Quat4f', _fields('X Y Z W', 'f'))
_add('Plane Plane4d', _fields('X Y Z W', 'd'))
_add('Plane4f', _fields('X Y Z W', 'f'))
_add('Sphere Sphere3d', (('Center', _vector), ('W', 'd')))
_add('Sphere3f', (('Center', _vector3f), ('W', 'f')))
_add('Box', (('Min', _vector), ('Max', _vector), ('IsValid', 'B')))
_add('Box2D', (('Min', _vector2d), ('Max', _vector2d), ('bIsValid', 'B')))
_add('Box2f', (('Min', _vector2f), ('Max', _vector2f), ('bIsValid', 'B')))
_add('Box3f', (('Min', _vector3f), ('Max', _vector3f), ('IsValid', 'B')))
_add('TwoVectors', (('v1', _vector), ('v2', _vector)))
_add('CapsuleShape', (('Center', _vector), ('Radius', 'd'), ('Orientation', _vector), ('Length', 'd')))
_add('Matrix', (('M', 'Md'),))
_add('Matrix44f', (('M', 'Mf'),))
_add('LinearColor', _fields('R G B A', 'f'))
_add('Color', _fields('B G R A', 'B'))
_add('Guid', _fields('A B C D', 'I'))
_add('IntPoint Int32Point IntVector2 Int32Vector2', _fields('X Y', 'i'))
_add('UintVector2 Uint32Point', _fields('X Y', 'I'))
_add('Int64Vector2 Int64Point', _fields('X Y', 'q'))
_add('UInt64Vector2 UInt64Point', _fields('X Y', 'Q'))
_add('IntVector', _fields('X Y Z', 'i'))
_add('UintVector', _fields('X Y Z', 'I'))
_add('Int64Vector', _fields('X Y Z', 'q'))
_add('UInt64Vector', _fields('X Y Z', 'Q'))
_add('IntVector4', _fields('X Y Z W', 'i'))
_add('UintVector4 Uint32Vector4', _fields('X Y Z W', 'I'))
_add('Int64Vector4', _fields('X Y Z W', 'q'))
_add('UInt64Vector4', _fields('X Y Z W', 'Q'))
_add('IntRect', (('Min', FIXED['IntPoint']), ('Max', FIXED['IntPoint'])))
_add('DateTime Timespan', (('Ticks', 'q'),))
_add('FrameNumber', (('Value', 'i'),))
_add('NavAgentSelector', (('PackedBits', 'I'),))
_add('FontCharacter', (('StartU', 'i'), ('StartV', 'i'), ('USize', 'i'), ('VSize', 'i'), ('TextureIndex', 'B'), ('VerticalOffset', 'i')))
_add('RichCurveKey', (('InterpMode', 'B'), ('TangentMode', 'B'), ('TangentWeightMode', 'B'), ('Time', 'f'), ('Value', 'f'),
                      ('ArriveTangent', 'f'), ('ArriveTangentWeight', 'f'), ('LeaveTangent', 'f'), ('LeaveTangentWeight', 'f')))
_add('SimpleCurveKey', _fields('Time Value', 'f'))
_add('KeyHandleMap', ())
_add('MovieSceneFrameRange', (('LowerBoundType', 'B'), ('LowerBoundValue', 'i'), ('UpperBoundType', 'B'), ('UpperBoundValue', 'i')))
_add('MovieSceneEvaluationKey', _fields('SequenceID TrackIdentifier SectionIndex', 'I'))
_add('MovieSceneSegmentIdentifier', (('IdentifierIndex', 'i'),))
_add('MovieSceneSequenceID MovieSceneTrackIdentifier', (('Value', 'I'),))

SOFT_PATHS = frozenset({'SoftObjectPath', 'SoftClassPath', 'StringAssetReference', 'StringClassReference'})
# Natives of other engine features and of other games, which this nylib version does not read.
UNSUPPORTED = frozenset({
    'ColorMaterialInput', 'CompressedRichCurve', 'ExpressionInput', 'ScalarMaterialInput', 'VectorMaterialInput',
    'Vector2MaterialInput', 'MaterialAttributesInput', 'SkeletalMeshSamplingRegionBuiltData', 'PannerDetails',
    'LevelSequenceObjectReferenceMap', 'MaterialLayersFunctionsTree', 'MidiEvent', 'RawAnimSequenceTrack',
    'SectionEvaluationDataTree', 'Transform3f', 'TypedParameter', 'UniqueNetIdRepl', 'ClothLODDataCommon', 'ClothLODData',
    'ClothTetherData', 'AnimationAttributeIdentifier', 'AttributeCurve', 'PCGPoint', 'CacheEventTrack',
    'DataCacheDuplicatedObjectData', 'EdGraphPinType', 'ControlRigOverrideContainer', 'UInt32Property', 'ZeroSizeProperty',
    'AnimMontageContainer', 'AnyValue', 'ConnectivityCube', 'Core1047ReleaseFlag', 'DistanceQuantity', 'EveryPlatformBool',
    'EveryPlatformFloat', 'EveryPlatformInt', 'FWAbilityResourceFloatMapping', 'FWPerkContextFloatMapping', 'FixedPoint',
    'FoWAgentHandle', 'ForceQuantity', 'FortActorRecord', 'GG_CrowdGeneratorLocations', 'GameplayEffectApplicationDataHandle',
    'GameplayEffectFloatMapping', 'GameplayEventDescriptor', 'GameplayEventFunction', 'HavokAIAnyArray', 'HavokNavAnyArray',
    'LSAAudioSectionkey', 'LegoGraphPartInstance', 'MassQuantity', 'MercunaUsageSpec', 'MercunaUsageTypes', 'NamedGuid',
    'NiagaraUserParameterModifier', 'PMBoundFloatMapping', 'PMFloatMapping', 'PMTimelineFloatMapping',
    'PMTimelineObjectBindingDef', 'PMTimelineRelevancy', 'PMTimelineSectionEventFloatMapping', 'PMTimelineSectionFloatMapping',
    'ParamRegistryInfo', 'PowerQuantity', 'PressureQuantity', 'R5CollisionApproximation', 'R5SoftAssetPath',
    'RDialogueFactValue', 'RsBitfield_HeroBufferFlags', 'RsBitfield_HeroInputFlags', 'RsBitfield_HeroLoadoutFlags',
    'RsBitfield_HeroUpgradeFlags', 'RsBitfield_NavPermissionDetailFlags', 'RsBitfield_NavPermissionFlags',
    'RsBitfield_NavState', 'RsBitfield_RsIkBoneTypes', 'RsBitfield_UINavigationInput', 'RsBitfield_WorldMapLODLevel',
    'RsBitfield_WorldMapLevelType', 'RsBitfield_WorldMapWidgetFilterType', 'SOS_GDValue', 'SUDSValue', 'SceneFaceDefSeamline',
    'SoundAttenuationPluginSettingsWithOverride', 'SpeedQuantity', 'SwBitfield_TargetRotatorMask', 'TLJsonGuid',
    'TLJsonVector', 'TLJsonVector2D', 'TedInstancedStruct', 'TedMarkerHandle', 'TimeUnit', 'TslSomeSKStruct',
    'VAL_CharacterCustomizationVariantOptionsArray', 'VGCoverDataPoint', 'VectorDouble', 'VinInstancedPropertyBag',
    'VinInstancedStruct', 'VolumeQuantity', 'VoyageFloat16', 'VoyagePackedLocalTransform',
})

_U16, _I32, _U32, _I64, _F32, _F64 = (struct.Struct(f) for f in ('<H', '<i', '<I', '<q', '<f', '<d'))
_GUID = FIXED['Guid']
_FRAME_RATE = Fixed('FrameRate', (('Numerator', 'i'), ('Denominator', 'i')))
_RANGE = Fixed('FrameNumberRange', (('LowerBoundType', 'B'), ('LowerBoundValue', 'i'), ('UpperBoundType', 'B'), ('UpperBoundValue', 'i')))
_HANDLE = Fixed('MovieSceneEvaluationTreeNodeHandle', (('ChildrenHandle', 'i'), ('Index', 'i')))
_NODE = Fixed('MovieSceneEvaluationTreeNode', (('Range', _RANGE), ('Parent', _HANDLE), ('ChildrenID', 'i'), ('DataID', 'i')))
_ENTRY = Fixed('EvaluationTreeEntry', (('StartIndex', 'i'), ('Size', 'i'), ('Capacity', 'i')))
_ENTITY = Fixed('EntityAndMetaDataIndex', (('EntityIndex', 'i'), ('MetaDataIndex', 'i')))
_SUB_SEQUENCE = Fixed('MovieSceneSubSequenceTreeEntry', (('SequenceID', 'I'), ('Flags', 'B')))
_TRANSFORM = Fixed('Transform', (('Rotation', FIXED['Quat']), ('Translation', _vector), ('Scale3D', _vector)))
_MAX_TYPE_NAME = 1024
_BAG_CONTAINER_DEPTH = 32
_BAG_TYPES = {1: (1, 'Bool'), 2: (0, 'Byte'), 3: (2, 'Int'), 4: (21, 'Int64'), 5: (3, 'Float'), 6: (7, 'Double'), 7: (5, 'Name'),
              8: (10, 'Str'), 9: (11, 'Text'), 12: (4, 'Object'), 13: (17, 'SoftObject'), 14: (4, 'Object'), 15: (17, 'SoftObject'),
              16: (19, 'UInt32'), 17: (18, 'UInt64')}
_TIME_WARPS = {2: 'MovieSceneTimeWarpFixedFrame', 3: 'FrameRate', 4: 'MovieSceneTimeWarpLoop', 5: 'MovieSceneTimeWarpClamp',
               6: 'MovieSceneTimeWarpLoopFloat', 7: 'MovieSceneTimeWarpClampFloat'}
_FRAGMENTS = {'actor': 'DirectPathObjectLocator', 'animinst': 'AnimInstanceLocatorFragment', 'subobj': 'SubObjectLocator',
              'ls_lazy_obj_ptr': 'LegacyLazyObjectPtrFragment'}
_NO_STRUCT = 'Optional<Struct<None>>'
_EMPTY_LAYOUT = _layout(())
_EMPTY_MAP = MapValue()
_NULL_REF = ObjectRef('null', None, None, None)

_TAGS_ZERO = (Slot(0, 'GameplayTagContainer', 'GameplayTags', 'Array<Name>', 'zero', None),)
_TAGS_LAYOUT = _layout(_TAGS_ZERO)
_PCG_ZERO = (Slot(0, 'PCGDataPtrWrapper', 'Data', 'Object', 'zero', None),)
_PCG_LAYOUT = _layout(_PCG_ZERO)


def _fixed(r, spec: Fixed) -> StructValue:
    return spec.read(r.data, r.need(spec.size), r.ctx)


def _scalar(r, fmt):
    return fmt.unpack_from(r.data, r.need(fmt.size))[0]


def _byte(r) -> int:
    return r.data[r.need(1)]


def _counted(r, read_item, what: str = 'array count') -> tuple:
    """(position of the count, tuple of items) of an i32 count, then that many items, each one decoded value."""
    pos, n = r.count(1, what)
    out = []
    for _ in range(n):
        r.tick()
        out.append(read_item(r))
    return pos, tuple(out)


def _bytes(r) -> tuple:
    """(position, bytes) of an i32 count and that many bytes, one decoded value."""
    pos = r.pos
    r.tick()
    _p, n = r.count(1, 'array count')
    q = r.need(n)
    return pos, r.data[q:q + n]


def read_tags(r, level: int, depth: int) -> StructValue:
    """GameplayTagContainer: an i32 count (8 bytes per tag must remain), then that many FNames."""
    pos, n = r.count(8, 'array count')
    tags = []
    for _ in range(n):
        r.tick()
        tags.append(r.fname())
    return StructValue._new('GameplayTagContainer', True, (Slot(0, 'GameplayTagContainer', 'GameplayTags', 'Array<Name>', 'serialized', pos),),
                            (tuple(tags),), r.ctx, None, _TAGS_LAYOUT)


def read_soft_path(r, level: int, depth: int) -> SoftObjectRef:
    return r.soft()


def read_pcg_data(r, level: int, depth: int) -> StructValue:
    pos = r.pos
    return StructValue._new('PCGDataPtrWrapper', True, (Slot(0, 'PCGDataPtrWrapper', 'Data', 'Object', 'serialized', pos),),
                            (r.object(),), r.ctx, None, _PCG_LAYOUT)


def read_smart_name(r, level: int, depth: int) -> StructValue:
    pos = r.pos
    return r.nat('SmartName', (('DisplayName', 'Name', pos, r.fname()),))


def _curve_key(name: str, label: str, read_value):
    def read(r, level: int, depth: int) -> StructValue:
        p = r.pos
        time = _scalar(r, _F32)
        q = r.pos
        return r.nat(name, (('Time', 'Float', p, time), ('Value', label, q, read_value(r))))
    return read


def _per_platform(name: str, label: str, read_value):
    def read(r, level: int, depth: int) -> StructValue:
        p = r.pos
        cooked = r.bool32()
        q = r.pos
        default = read_value(r)
        m, pairs = r.pos, []
        if not cooked:
            m, n = r.count(1, 'map count')
            for _ in range(n):
                r.tick()
                key = r.fname()
                pairs.append((key, read_value(r)))
        return r.nat(name, (('bCooked', 'Bool', p, cooked), ('Default', label, q, default),
                            ('PerPlatform', f'Map<Name,{label}>', m, MapValue(pairs))))
    return read


def _per_quality(name: str, label: str, fmt):
    def read(r, level: int, depth: int) -> StructValue:
        p = r.pos
        cooked = r.bool32()
        q = r.pos
        default = _scalar(r, fmt)
        m, n = r.count(1, 'map count')
        pairs = []
        for _ in range(n):
            r.tick()
            key = _scalar(r, _I32)
            pairs.append((key, _scalar(r, fmt)))
        return r.nat(name, (('bCooked', 'Bool', p, cooked), ('Default', label, q, default), ('PerQuality', f'Map<Int,{label}>', m, MapValue(pairs))))
    return read


def read_spline(r, level: int, depth: int) -> StructValue:
    p = r.need(1)
    if (impl := struct.unpack_from('<b', r.data, p)[0]) != 0:
        r.unsupported(f'Spline implementation {impl}', p)
    return r.nat('Spline', (('Implementation', 'Int8', p, 0),))


def _payload(r, ref, level: int, depth: int):
    """An i32 size, then the value of the struct `ref` names, which must end at that size; None for the null ref."""
    p = r.need(4)
    size = _I32.unpack_from(r.data, p)[0]
    if size < 0 or size > r.end - r.pos or (not ref and size):
        r.fail(f'instanced struct size {size}', p)
    if not ref:
        return None
    name = r.named(ref)
    start = r.pos
    value = r.struct(name, level, depth)
    if r.pos != start + size:
        r.fail(f'instanced struct ends at {r.pos:#x}', start)
    return value


def read_instanced(r, level: int, depth: int):
    return _payload(r, r.object(), level, depth)


def _instanced_items(kind: str):
    def read(r, level: int, depth: int) -> tuple:
        p = r.need(1)
        if version := r.data[p]:
            r.unsupported(f'instanced struct {kind} version {version}', p)
        _q, types = _counted(r, lambda r: r.object())
        out = []
        for t in types:
            r.payload()
            out.append(_payload(r, t, level, depth))
        return tuple(out)
    return read


def _bag_descriptor(r, owner: str, index: int) -> tuple:
    """The slot template (index, 0, owner, name, label, type) of one property bag descriptor."""
    o = r.need(4)
    raw = _I32.unpack_from(r.data, o)[0]
    r.need(16)  # ID
    name = r.fname()
    p = r.need(1)
    vt = r.data[p]
    if vt in (10, 11):
        if not raw:
            r.unsupported(f"a property bag {'Enum' if vt == 10 else 'Struct'} without a type object", o)
        if (ref := r.ref(raw)) is None:
            r.fail(f'object index {raw}', o)
        typed = r.named(ref)
        t, label = ((PropertyType(26, inner=PropertyType(0), enum_name=typed), f'Enum<{typed}:Byte>') if vt == 10 else
                    (PropertyType(9, struct_name=typed), f'Struct<{typed}>'))
    elif (form := _BAG_TYPES.get(vt)) is not None:
        t, label = PropertyType(form[0]), form[1]
    else:
        r.unsupported(f'property bag value type {vt}', p)
    p = r.need(1)
    if (k := r.data[p]) > _BAG_CONTAINER_DEPTH:
        r.fail(f'property bag container depth {k}', p)
    for _ in range(k):
        p = r.need(1)
        if (ct := r.data[p]) != 1:
            r.unsupported(f'property bag container type {ct}', p)
        t, label = PropertyType(8, inner=t), f'Array<{label}>'
    if r.bool32():
        _counted(r, lambda r: (r.fname(), r.fstring()))
        r.need(4)  # meta class
    return index, 0, owner, name, label, t


def _bag(r, name: str, level: int, depth: int) -> StructValue:
    """A property bag's value: a block whose schema is the bag's own descriptors, ending at its serialized size."""
    if not r.bool32():
        return StructValue._new(name, False, (), (), r.ctx, None, _EMPTY_LAYOUT)
    _p, n = r.count(1, 'array count')
    templates = []
    for i in range(n):
        r.tick()
        templates.append(_bag_descriptor(r, name, i))
    p = r.need(4)
    size = _I32.unpack_from(r.data, p)[0]
    if size < 0 or size > r.end - r.pos:
        r.fail(f'property bag size {size}', p)
    start = r.pos
    value = r.block(r.bag_schema(tuple(templates)), name, level, depth)
    if r.pos != start + size:
        r.fail(f'property bag ends at {r.pos:#x}', start)
    return value


def read_bag(r, level: int, depth: int) -> StructValue:
    return _bag(r, r.native, level, depth)


def read_overridable_bag(r, level: int, depth: int) -> StructValue:
    p = r.pos
    bag = _bag(r, 'InstancedPropertyBag', level, depth)
    q, ids = _counted(r, lambda r: _fixed(r, _GUID))
    return r.nat('InstancedOverridablePropertyBag', (('Bag', 'Struct<InstancedPropertyBag>', p, bag),
                                                     ('OverriddenPropertyIDs', 'Array<Struct<Guid>>', q, ids)))


_VALUE_FIELDS = ('Value', 'ArriveTangent', 'LeaveTangent', 'ArriveTangentWeight', 'LeaveTangentWeight', 'TangentWeightMode', 'InterpMode',
                 'TangentMode')


def _movie_value(name: str, code: str, compact: bool):
    """A reader of one MovieSceneFloatValue or MovieSceneDoubleValue: the value, 4 f32 tangents, then the modes and padding."""
    fmt = struct.Struct(f'<{code}4fBBBx' if compact else f'<{code}4fB3xBB2x')
    s = struct.calcsize('<' + code)
    offsets = (0, s, s + 4, s + 8, s + 12, s + 16) + ((s + 17, s + 18) if compact else (s + 20, s + 21))
    labels = ('Double' if code == 'd' else 'Float',) + ('Float',) * 4 + ('Byte',) * 3

    def read(r) -> StructValue:
        p = r.need(fmt.size)
        return r.nat(name, tuple(zip(_VALUE_FIELDS, labels, (p + o for o in offsets), fmt.unpack_from(r.data, p))))
    read.size = fmt.size
    read.labels = labels
    return read


_FLOAT_VALUE, _DOUBLE_VALUE = _movie_value('MovieSceneFloatValue', 'f', False), _movie_value('MovieSceneDoubleValue', 'd', False)
_COMPACT = {'MovieSceneFloatValue': _movie_value('MovieSceneFloatValue', 'f', True),
            'MovieSceneDoubleValue': _movie_value('MovieSceneDoubleValue', 'd', True)}


def read_compact_value(r, level: int, depth: int) -> StructValue:
    return _COMPACT[r.native](r)


def _channel(name: str, read_value, fmt, label: str):
    value_struct = 'MovieSceneDoubleValue' if label == 'Double' else 'MovieSceneFloatValue'

    def read(r, level: int, depth: int) -> StructValue:
        p = r.need(2)
        q = r.need(4)
        if (size := _I32.unpack_from(r.data, q)[0]) != 4:
            r.fail(f'channel element size {size}', q)
        t, times = _counted(r, lambda r: _scalar(r, _I32))
        q = r.need(4)
        if (size := _I32.unpack_from(r.data, q)[0]) != read_value.size:
            r.fail(f'channel element size {size}', q)
        v, values = _counted(r, read_value)
        d = r.pos
        default = _scalar(r, fmt)
        b = r.pos
        has_default = r.bool32()
        f = r.pos
        rate = _fixed(r, _FRAME_RATE)
        s = r.pos
        return r.nat(name, (('PreInfinityExtrap', 'Byte', p, r.data[p]), ('PostInfinityExtrap', 'Byte', p + 1, r.data[p + 1]),
                            ('Times', 'Array<Int>', t, times), ('Values', f'Array<Struct<{value_struct}>>', v, values),
                            ('DefaultValue', label, d, default), ('bHasDefaultValue', 'Bool', b, has_default),
                            ('TickResolution', 'Struct<FrameRate>', f, rate), ('bShowCurve', 'Bool', s, r.bool32())))
    return read


def _type_name(r) -> tuple:
    """(position, text, struct name or None) of an FString type name: 0 to 1,024 printable ASCII characters, not ending in '.'."""
    p = r.pos
    text = r.fstring()
    if not text:
        return p, text, None
    if len(text) > _MAX_TYPE_NAME or not text.isascii() or not text.isprintable() or text.endswith('.'):
        r.fail('bad type name', p)
    return p, text, text.rsplit('.', 1)[-1]


def _typed_pointer(name: str):
    def read(r, level: int, depth: int) -> StructValue:
        p, text, s = _type_name(r)
        if s is None:
            return r.nat(name, (('TypeName', 'Str', p, text), ('Data', _NO_STRUCT, None, None)))
        if s == 'MovieSceneLiveLinkSectionTemplate':
            r.unsupported('a MovieSceneLiveLinkSectionTemplate', p)
        q = r.pos
        return r.nat(name, (('TypeName', 'Str', p, text), ('Data', f'Optional<Struct<{s}>>', q, r.reflected(s, level, depth))))
    return read


def _entry_container(r, label: str, read_item) -> StructValue:
    q, entries = _counted(r, lambda r: _fixed(r, _ENTRY))
    s, items = _counted(r, read_item)
    return r.nat('EvaluationTreeEntryContainer', (('Entries', 'Array<Struct<EvaluationTreeEntry>>', q, entries), ('Items', f'Array<{label}>', s, items)))


def _sub_section(r) -> StructValue:
    p = r.pos
    section = r.object()
    q = r.pos
    guid = _fixed(r, _GUID)
    f = r.need(1)
    return r.nat('MovieSceneSubSectionData', (('Section', 'Object', p, section), ('ObjectBindingId', 'Struct<Guid>', q, guid),
                                              ('Flags', 'Byte', f, r.data[f])))


_TREE_ITEMS = {
    'MovieSceneEvaluationFieldEntityTree': ('Struct<EntityAndMetaDataIndex>', lambda r: _fixed(r, _ENTITY)),
    'MovieSceneTrackFieldData': ('UInt32', lambda r: _scalar(r, _U32)),
    'MovieSceneSubSectionFieldData': ('Struct<MovieSceneSubSectionData>', _sub_section),
    'MovieSceneSubSequenceTree': ('Struct<MovieSceneSubSequenceTreeEntry>', lambda r: _fixed(r, _SUB_SEQUENCE)),
}


def read_tree(r, level: int, depth: int) -> StructValue:
    """An evaluation tree: the root node, the child nodes, then the data items of the tree's type."""
    label, read_item = _TREE_ITEMS[r.native]
    p = r.pos
    root = _fixed(r, _NODE)
    c = r.pos
    children = _entry_container(r, 'Struct<MovieSceneEvaluationTreeNode>', lambda r: _fixed(r, _NODE))
    d = r.pos
    return r.nat(r.native, (('RootNode', 'Struct<MovieSceneEvaluationTreeNode>', p, root),
                            ('ChildNodes', 'Struct<EvaluationTreeEntryContainer>', c, children),
                            ('Data', 'Struct<EvaluationTreeEntryContainer>', d, _entry_container(r, label, read_item))))


def read_segment(r, level: int, depth: int) -> StructValue:
    p = r.pos
    rng = _fixed(r, _RANGE)
    q = r.pos
    ident = _fixed(r, FIXED['MovieSceneSegmentIdentifier'])
    b = r.pos
    allow_empty = r.bool32()
    s, impls = _counted(r, lambda r: r.reflected('SectionEvaluationData', level, depth))
    return r.nat('MovieSceneSegment', (('Range', 'Struct<FrameNumberRange>', p, rng), ('ID', 'Struct<MovieSceneSegmentIdentifier>', q, ident),
                                       ('bAllowEmpty', 'Bool', b, allow_empty), ('Impls', 'Array<Struct<SectionEvaluationData>>', s, impls)))


def read_event_parameters(r, level: int, depth: int) -> StructValue:
    p = r.pos
    soft = r.soft()
    q, raw = _bytes(r)
    return r.nat('MovieSceneEventParameters', (('StructType', 'SoftObject', p, soft), ('StructBytes', 'Array<Byte>', q, raw)))


def read_time_warp(r, level: int, depth: int) -> StructValue:
    p = r.pos
    t, kind = (p, 0) if r.bool32() else (r.pos, _byte(r))
    q = r.pos
    if kind == 0:
        field = ('Value', 'Double', q, _scalar(r, _F64))
    elif kind == 1:
        field = ('Value', 'Object', q, r.object())
    elif (s := _TIME_WARPS.get(kind)) is not None:
        field = ('Value', f'Struct<{s}>', q, r.reflected(s, level, depth))
    else:
        r.unsupported(f'time warp type {kind}', t)
    return r.nat('MovieSceneTimeWarpVariant', (('Type', 'Byte', t, kind), field))


def _niagara_base(r, level: int, depth: int) -> tuple:
    p = r.pos
    name = r.fname()
    q = r.pos
    return ('Name', 'Name', p, name), ('TypeDef', 'Struct<NiagaraTypeDefinition>', q, r.reflected('NiagaraTypeDefinition', level, depth))


def read_niagara_base(r, level: int, depth: int) -> StructValue:
    return r.nat(r.native, _niagara_base(r, level, depth))


def read_niagara_variable(r, level: int, depth: int) -> StructValue:
    fields = _niagara_base(r, level, depth)
    q, raw = _bytes(r)
    return r.nat('NiagaraVariable', fields + (('VarData', 'Array<Byte>', q, raw),))


def read_niagara_offset(r, level: int, depth: int) -> StructValue:
    fields = _niagara_base(r, level, depth)
    q = r.pos
    return r.nat('NiagaraVariableWithOffset', fields + (('Offset', 'Int', q, _scalar(r, _I32)),))


def _specifier(r) -> StructValue:
    p = r.pos
    key = r.fname()
    q = r.pos
    return r.nat('NiagaraFunctionSpecifier', (('Key', 'Name', p, key), ('Value', 'Name', q, r.fname())))


def _common_reference(r) -> StructValue:
    p = r.pos
    name = r.fname()
    q = r.pos
    return r.nat('NiagaraVariableCommonReference', (('Name', 'Name', p, name), ('UnderlyingType', 'Object', q, r.object())))


def _generated_function(r) -> StructValue:
    p = r.pos
    definition = r.fname()
    q = r.pos
    instance = r.fstring()
    s, specifiers = _counted(r, _specifier)
    i, inputs = _counted(r, _common_reference)
    o, outputs = _counted(r, _common_reference)
    m = r.pos
    common = 'Array<Struct<NiagaraVariableCommonReference>>'
    return r.nat('NiagaraDataInterfaceGeneratedFunction', (
        ('DefinitionName', 'Name', p, definition), ('InstanceName', 'Str', q, instance),
        ('Specifiers', 'Array<Struct<NiagaraFunctionSpecifier>>', s, specifiers), ('VariadicInputs', common, i, inputs),
        ('VariadicOutputs', common, o, outputs), ('MiscUsageBitMask', 'UInt16', m, _scalar(r, _U16))))


def read_gpu_param_info(r, level: int, depth: int) -> StructValue:
    p = r.pos
    symbol = r.fstring()
    q = r.pos
    class_name = r.fstring()
    g, functions = _counted(r, _generated_function)
    return r.nat('NiagaraDataInterfaceGPUParamInfo', (('DataInterfaceHLSLSymbol', 'Str', p, symbol), ('DIClassName', 'Str', q, class_name),
                                                      ('GeneratedFunctions', 'Array<Struct<NiagaraDataInterfaceGeneratedFunction>>', g, functions)))


_PCG_PROPERTIES = (('Transform', 'Struct<Transform>', _TRANSFORM), ('Density', 'Float', _F32), ('BoundsMin', 'Struct<Vector>', _vector),
                   ('BoundsMax', 'Struct<Vector>', _vector), ('Color', 'Struct<Vector4>', FIXED['Vector4']), ('Steepness', 'Float', _F32),
                   ('Seed', 'Int', _I32), ('MetadataEntry', 'Int64', _I64))


def read_pcg_points(r, level: int, depth: int) -> StructValue:
    p = r.pos
    fields = [('NumPoints', 'Int', p, _scalar(r, _I32))]
    for name, label, t in _PCG_PROPERTIES:
        read_item = (lambda r, t=t: _fixed(r, t)) if isinstance(t, Fixed) else (lambda r, t=t: _scalar(r, t))
        a = r.pos
        num = _scalar(r, _I32)
        v = r.pos
        value = read_item(r)
        s, values = _counted(r, read_item)
        fields.append((name, 'Struct<PCGPointArrayProperty>', a, r.nat('PCGPointArrayProperty', (
            ('NumValues', 'Int', a, num), ('Value', label, v, value), ('Values', f'Array<{label}>', s, values)))))
    return r.nat('PCGPointArray', tuple(fields))


def read_world_condition(r, level: int, depth: int) -> StructValue:
    p = r.pos
    static = r.reflected('WorldConditionQueryDefinition', level, depth)
    q = r.pos
    shared = r.reflected('WorldConditionQuerySharedDefinition', level, depth) if r.bool32() else None
    return r.nat('WorldConditionQueryDefinition', (('StaticStruct', 'Struct<WorldConditionQueryDefinition>', p, static),
                                                   ('SharedDefinition', 'Optional<Struct<WorldConditionQuerySharedDefinition>>',
                                                    None if shared is None else q, shared)))


def read_state_tree(r, level: int, depth: int) -> StructValue:
    p = r.pos
    return r.nat('StateTreeInstanceData', (('Data', 'Struct<StateTreeInstanceStorage>', p, r.reflected('StateTreeInstanceStorage', level, depth)),))


def read_sampling_lod(r, level: int, depth: int) -> StructValue:
    p, prob = _counted(r, lambda r: _scalar(r, _F32))
    q, alias = _counted(r, lambda r: _scalar(r, _I32))
    t = r.pos
    return r.nat('SkeletalMeshSamplingLODBuiltData', (('Prob', 'Array<Float>', p, prob), ('Alias', 'Array<Int>', q, alias),
                                                      ('TotalWeight', 'Float', t, _scalar(r, _F32))))


def read_nanite_override(r, level: int, depth: int) -> StructValue:
    p = r.pos
    material = r.object() if r.bool32() else None
    q = r.pos
    return r.nat('MaterialOverrideNanite', (('OverrideMaterial', 'Optional<Object>', None if material is None else p, material),
                                            ('Properties', 'Struct<MaterialOverrideNanite>', q, r.reflected('MaterialOverrideNanite', level, depth))))


def read_font_data(r, level: int, depth: int) -> StructValue:
    p = r.pos
    cooked = r.bool32()
    face = filename = hinting = policy = sub_face = None
    a = b = h = s = None
    if cooked:
        a = r.pos
        face = r.object()
        if not face:
            b = r.pos
            filename = r.fstring()
            h = r.need(2)
            hinting, policy = r.data[h], r.data[h + 1]
        s = r.pos
        sub_face = _scalar(r, _I32)
    return r.nat('FontData', (('bIsCooked', 'Bool', p, cooked), ('LocalFontFaceAsset', 'Optional<Object>', a, face),
                              ('FontFilename', 'Optional<Str>', b, filename), ('Hinting', 'Optional<Byte>', h, hinting),
                              ('LoadingPolicy', 'Optional<Byte>', None if h is None else h + 1, policy),
                              ('SubFaceIndex', 'Optional<Int>', s, sub_face)))


def read_locator_fragment(r, level: int, depth: int) -> StructValue:
    p = r.pos
    kind = r.fname()
    if kind == 'None':
        return r.nat('UniversalObjectLocatorFragment', (('FragmentTypeID', 'Name', p, kind), ('Fragment', _NO_STRUCT, None, None)))
    if (s := _FRAGMENTS.get(kind)) is None:
        r.unsupported('a universal object locator fragment of another type', p)
    q = r.pos
    return r.nat('UniversalObjectLocatorFragment', (('FragmentTypeID', 'Name', p, kind),
                                                    ('Fragment', f'Optional<Struct<{s}>>', q, r.reflected(s, level, depth))))


def read_shader_type(r, level: int, depth: int) -> StructValue:
    """ShaderValueTypeHandle: a type byte and a dynamic-array flag, then a struct's named elements or a dimension."""
    p = r.need(1)
    kind = r.data[p]
    b = r.pos
    dynamic = r.bool32()
    name = elements = dim = vec = rows = cols = None
    n = s = d = v = m = None
    if kind == 4:
        n = r.pos
        name = r.fname()

        def element(r) -> StructValue:
            x = r.pos
            ename = r.fname()
            y = r.pos
            return r.nat('ShaderValueTypeStructElement', (('Name', 'Name', x, ename),
                                                          ('Type', 'Struct<ShaderValueTypeHandle>', y, r.struct('ShaderValueTypeHandle', level, depth))))
        s, elements = _counted(r, element)
    else:
        d = r.need(1)
        if (dim := r.data[d]) > 2:
            r.unsupported(f'shader value dimension {dim}', d)
        if dim == 1:
            v = r.need(1)
            vec = r.data[v]
        elif dim == 2:
            m = r.need(2)
            rows, cols = r.data[m], r.data[m + 1]
    return r.nat('ShaderValueTypeHandle', (
        ('Type', 'Byte', p, kind), ('bIsDynamicArray', 'Bool', b, dynamic), ('Name', 'Optional<Name>', n, name),
        ('StructElements', 'Optional<Array<Struct<ShaderValueTypeStructElement>>>', s, elements), ('DimensionType', 'Optional<Byte>', d, dim),
        ('VectorElemCount', 'Optional<Byte>', v, vec), ('MatrixRowCount', 'Optional<Byte>', m, rows),
        ('MatrixColumnCount', 'Optional<Byte>', None if m is None else m + 1, cols)))


_PER_PLATFORM = {
    'PerPlatformBool': ('Bool', lambda r: r.bool32()), 'PerPlatformFloat': ('Float', lambda r: _scalar(r, _F32)),
    'PerPlatformInt': ('Int', lambda r: _scalar(r, _I32)), 'PerPlatformFrameRate': ('Struct<FrameRate>', lambda r: _fixed(r, _FRAME_RATE)),
    'PerPlatformFString': ('Str', lambda r: r.fstring()), 'PerPlatformERigLogicFloatingPointType': ('Int', lambda r: _scalar(r, _I32)),
    'PerPlatformERigLogicCalculationType': ('Int', lambda r: _scalar(r, _I32)),
}

VARIABLE = {
    'GameplayTagContainer': read_tags, 'PCGDataPtrWrapper': read_pcg_data, **{n: read_soft_path for n in SOFT_PATHS},
    'SmartName': read_smart_name, 'NameCurveKey': _curve_key('NameCurveKey', 'Name', lambda r: r.fname()),
    'StringCurveKey': _curve_key('StringCurveKey', 'Str', lambda r: r.fstring()),
    **{n: _per_platform(n, label, fn) for n, (label, fn) in _PER_PLATFORM.items()},
    'PerQualityLevelInt': _per_quality('PerQualityLevelInt', 'Int', _I32), 'PerQualityLevelFloat': _per_quality('PerQualityLevelFloat', 'Float', _F32),
    'Spline': read_spline, 'InstancedStruct': read_instanced, 'InstancedStructContainer': _instanced_items('container'),
    'InstancedStructArray': _instanced_items('array'), 'InstancedPropertyBag': read_bag, 'RigVMPropertyBag': read_bag,
    'InstancedOverridablePropertyBag': read_overridable_bag,
    'MovieSceneFloatChannel': _channel('MovieSceneFloatChannel', _FLOAT_VALUE, _F32, 'Float'),
    'MovieSceneDoubleChannel': _channel('MovieSceneDoubleChannel', _DOUBLE_VALUE, _F64, 'Double'),
    'MovieSceneFloatValue': read_compact_value, 'MovieSceneDoubleValue': read_compact_value,
    **{n: _typed_pointer(n) for n in ('MovieSceneEvalTemplatePtr', 'MovieSceneTrackImplementationPtr', 'MovieSceneSequenceInstanceDataPtr')},
    **{n: read_tree for n in _TREE_ITEMS}, 'MovieSceneSegment': read_segment, 'MovieSceneEventParameters': read_event_parameters,
    'MovieSceneTimeWarpVariant': read_time_warp, 'NiagaraVariableBase': read_niagara_base, 'NiagaraDataChannelVariable': read_niagara_base,
    'NiagaraVariable': read_niagara_variable, 'NiagaraVariableWithOffset': read_niagara_offset,
    'NiagaraDataInterfaceGPUParamInfo': read_gpu_param_info, 'PCGPointArray': read_pcg_points,
    'WorldConditionQueryDefinition': read_world_condition, 'StateTreeInstanceData': read_state_tree,
    'SkeletalMeshSamplingLODBuiltData': read_sampling_lod, 'MaterialOverrideNanite': read_nanite_override, 'FontData': read_font_data,
    'UniversalObjectLocatorFragment': read_locator_fragment, 'ShaderValueTypeHandle': read_shader_type,
}

# ---- zero values: (value, levels below it) of a zero-masked native, given the native's own level and depth

_ZERO_LABELS = {'Bool': False, 'Byte': 0, 'Int8': 0, 'Int': 0, 'UInt16': 0, 'UInt32': 0, 'Int64': 0, 'Float': 0.0, 'Double': 0.0,
                'Name': 'None', 'Str': ''}


def _zero_fields(r, fields: tuple) -> tuple:
    """(name, label, zero) per field: (name, label) takes its label's zero, (name, label, f) the zero f(ctx) of a nested shape."""
    out = []
    for f in fields:
        label = f[1]
        if len(f) == 3:
            v = f[2](r.ctx)
        elif label.startswith('Optional<'):
            v = None
        elif label.startswith('Array<'):
            v = b'' if label == 'Array<Byte>' else ()
        else:
            v = _EMPTY_MAP if label.startswith('Map<') else _ZERO_LABELS[label]
        out.append((f[0], label, v))
    return tuple(out)


def _zero(name: str, *fields):
    return lambda r, level, depth: (r._zero_nat(name, _zero_fields(r, fields)), 0)


def _zero_reflected(name: str, before: tuple, field: str, struct_name: str, after: tuple = ()):
    """The zero of a native that holds the all-zero value of a reflected block of `struct_name` in `field`."""
    def zero(r, level: int, depth: int) -> tuple:
        value, below = r._zero_struct(struct_name, level, depth, reflected=True)
        return r._zero_nat(name, _zero_fields(r, before) + ((field, f'Struct<{struct_name}>', value),) + _zero_fields(r, after)), below + 1
    return zero


def _zero_bag(name: str):
    return lambda r, level, depth: (StructValue._new(name, False, (), (), r.ctx, None, _EMPTY_LAYOUT), 0)


def _zero_pcg_points(r, level: int, depth: int) -> tuple:
    fields = [('NumPoints', 'Int', 0)]
    for name, label, t in _PCG_PROPERTIES:
        value = t.zero(r.ctx) if isinstance(t, Fixed) else _ZERO_LABELS[label]
        fields.append((name, 'Struct<PCGPointArrayProperty>',
                       r._zero_nat('PCGPointArrayProperty', (('NumValues', 'Int', 0), ('Value', label, value), ('Values', f'Array<{label}>', ())))))
    return r._zero_nat('PCGPointArray', tuple(fields)), 0


def _zero_tree(name: str, label: str):
    def zero(r, level: int, depth: int) -> tuple:
        def container(item: str) -> StructValue:
            return r._zero_nat('EvaluationTreeEntryContainer', (('Entries', 'Array<Struct<EvaluationTreeEntry>>', ()), ('Items', f'Array<{item}>', ())))
        return r._zero_nat(name, (('RootNode', 'Struct<MovieSceneEvaluationTreeNode>', _NODE.zero(r.ctx)),
                                  ('ChildNodes', 'Struct<EvaluationTreeEntryContainer>', container('Struct<MovieSceneEvaluationTreeNode>')),
                                  ('Data', 'Struct<EvaluationTreeEntryContainer>', container(label)))), 0
    return zero


def _zero_channel(name: str, label: str):
    value_struct = 'MovieSceneDoubleValue' if label == 'Double' else 'MovieSceneFloatValue'
    return _zero(name, ('PreInfinityExtrap', 'Byte'), ('PostInfinityExtrap', 'Byte'), ('Times', 'Array<Int>'),
                 ('Values', f'Array<Struct<{value_struct}>>'), ('DefaultValue', label), ('bHasDefaultValue', 'Bool'),
                 ('TickResolution', 'Struct<FrameRate>', _FRAME_RATE.zero), ('bShowCurve', 'Bool'))


def _zero_per_platform(name: str, label: str):
    default = ('Default', label, _FRAME_RATE.zero) if label == 'Struct<FrameRate>' else ('Default', label)
    return _zero(name, ('bCooked', 'Bool'), default, ('PerPlatform', f'Map<Name,{label}>'))


def _zero_tags(r, level: int, depth: int) -> tuple:
    return StructValue._new('GameplayTagContainer', True, _TAGS_ZERO, ((),), r.ctx, None, _TAGS_LAYOUT), 0


def _zero_pcg_data(r, level: int, depth: int) -> tuple:
    return StructValue._new('PCGDataPtrWrapper', True, _PCG_ZERO, (_NULL_REF,), r.ctx, None, _PCG_LAYOUT), 0


_NIAGARA_NAME = (('Name', 'Name'),)
ZEROS = {
    'GameplayTagContainer': _zero_tags, 'PCGDataPtrWrapper': _zero_pcg_data, **{n: (lambda r, level, depth: (EMPTY_SOFT, 0)) for n in SOFT_PATHS},
    'SmartName': _zero('SmartName', ('DisplayName', 'Name')), 'NameCurveKey': _zero('NameCurveKey', ('Time', 'Float'), ('Value', 'Name')),
    'StringCurveKey': _zero('StringCurveKey', ('Time', 'Float'), ('Value', 'Str')),
    **{n: _zero_per_platform(n, label) for n, (label, _fn) in _PER_PLATFORM.items()},
    'PerQualityLevelInt': _zero('PerQualityLevelInt', ('bCooked', 'Bool'), ('Default', 'Int'), ('PerQuality', 'Map<Int,Int>')),
    'PerQualityLevelFloat': _zero('PerQualityLevelFloat', ('bCooked', 'Bool'), ('Default', 'Float'), ('PerQuality', 'Map<Int,Float>')),
    'Spline': _zero('Spline', ('Implementation', 'Int8')), 'InstancedStruct': lambda r, level, depth: (None, 0),
    'InstancedStructContainer': lambda r, level, depth: ((), 0), 'InstancedStructArray': lambda r, level, depth: ((), 0),
    'InstancedPropertyBag': _zero_bag('InstancedPropertyBag'), 'RigVMPropertyBag': _zero_bag('RigVMPropertyBag'),
    'InstancedOverridablePropertyBag': _zero('InstancedOverridablePropertyBag', (
        'Bag', 'Struct<InstancedPropertyBag>', lambda ctx: StructValue._new('InstancedPropertyBag', False, (), (), ctx, None, _EMPTY_LAYOUT)),
        ('OverriddenPropertyIDs', 'Array<Struct<Guid>>')),
    'MovieSceneFloatChannel': _zero_channel('MovieSceneFloatChannel', 'Float'),
    'MovieSceneDoubleChannel': _zero_channel('MovieSceneDoubleChannel', 'Double'),
    'MovieSceneFloatValue': _zero('MovieSceneFloatValue', *zip(_VALUE_FIELDS, _FLOAT_VALUE.labels)),
    'MovieSceneDoubleValue': _zero('MovieSceneDoubleValue', *zip(_VALUE_FIELDS, _DOUBLE_VALUE.labels)),
    **{n: _zero(n, ('TypeName', 'Str'), ('Data', _NO_STRUCT))
       for n in ('MovieSceneEvalTemplatePtr', 'MovieSceneTrackImplementationPtr', 'MovieSceneSequenceInstanceDataPtr')},
    **{n: _zero_tree(n, label) for n, (label, _fn) in _TREE_ITEMS.items()},
    'MovieSceneSegment': _zero('MovieSceneSegment', ('Range', 'Struct<FrameNumberRange>', _RANGE.zero),
                               ('ID', 'Struct<MovieSceneSegmentIdentifier>', FIXED['MovieSceneSegmentIdentifier'].zero),
                               ('bAllowEmpty', 'Bool'), ('Impls', 'Array<Struct<SectionEvaluationData>>')),
    'MovieSceneEventParameters': _zero('MovieSceneEventParameters', ('StructType', 'SoftObject', lambda ctx: EMPTY_SOFT),
                                       ('StructBytes', 'Array<Byte>')),
    'MovieSceneTimeWarpVariant': _zero('MovieSceneTimeWarpVariant', ('Type', 'Byte'), ('Value', 'Double')),
    'NiagaraVariableBase': _zero_reflected('NiagaraVariableBase', _NIAGARA_NAME, 'TypeDef', 'NiagaraTypeDefinition'),
    'NiagaraDataChannelVariable': _zero_reflected('NiagaraDataChannelVariable', _NIAGARA_NAME, 'TypeDef', 'NiagaraTypeDefinition'),
    'NiagaraVariable': _zero_reflected('NiagaraVariable', _NIAGARA_NAME, 'TypeDef', 'NiagaraTypeDefinition',
                                       (('VarData', 'Array<Byte>'),)),
    'NiagaraVariableWithOffset': _zero_reflected('NiagaraVariableWithOffset', _NIAGARA_NAME, 'TypeDef', 'NiagaraTypeDefinition',
                                                 (('Offset', 'Int'),)),
    'NiagaraDataInterfaceGPUParamInfo': _zero('NiagaraDataInterfaceGPUParamInfo', ('DataInterfaceHLSLSymbol', 'Str'), ('DIClassName', 'Str'),
                                              ('GeneratedFunctions', 'Array<Struct<NiagaraDataInterfaceGeneratedFunction>>')),
    'PCGPointArray': _zero_pcg_points,
    'WorldConditionQueryDefinition': _zero_reflected('WorldConditionQueryDefinition', (), 'StaticStruct', 'WorldConditionQueryDefinition',
                                                     (('SharedDefinition', 'Optional<Struct<WorldConditionQuerySharedDefinition>>'),)),
    'StateTreeInstanceData': _zero_reflected('StateTreeInstanceData', (), 'Data', 'StateTreeInstanceStorage'),
    'SkeletalMeshSamplingLODBuiltData': _zero('SkeletalMeshSamplingLODBuiltData', ('Prob', 'Array<Float>'), ('Alias', 'Array<Int>'),
                                              ('TotalWeight', 'Float')),
    'MaterialOverrideNanite': _zero_reflected('MaterialOverrideNanite', (('OverrideMaterial', 'Optional<Object>'),), 'Properties',
                                              'MaterialOverrideNanite'),
    'FontData': _zero('FontData', ('bIsCooked', 'Bool'), ('LocalFontFaceAsset', 'Optional<Object>'), ('FontFilename', 'Optional<Str>'),
                      ('Hinting', 'Optional<Byte>'), ('LoadingPolicy', 'Optional<Byte>'), ('SubFaceIndex', 'Optional<Int>')),
    'UniversalObjectLocatorFragment': _zero('UniversalObjectLocatorFragment', ('FragmentTypeID', 'Name'), ('Fragment', _NO_STRUCT)),
    'ShaderValueTypeHandle': _zero('ShaderValueTypeHandle', ('Type', 'Byte'), ('bIsDynamicArray', 'Bool'), ('Name', 'Optional<Name>'),
                                   ('StructElements', 'Optional<Array<Struct<ShaderValueTypeStructElement>>>'),
                                   ('DimensionType', 'Optional<Byte>'), ('VectorElemCount', 'Optional<Byte>'),
                                   ('MatrixRowCount', 'Optional<Byte>'), ('MatrixColumnCount', 'Optional<Byte>')),
}


def is_native(name: str) -> bool:
    """True iff `name` is a native of this profile, read or not."""
    return name in FIXED or name in VARIABLE or name in UNSUPPORTED
