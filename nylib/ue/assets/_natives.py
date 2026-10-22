"""The native struct layouts of the typed export reader: fixed layouts, tag containers and soft object paths."""
import struct

from ._values import Slot, SoftObjectRef, StructValue, _layout

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
# The natives of this profile whose variable layouts this nylib version does not read yet.
PENDING = frozenset({
    'SmartName', 'NameCurveKey', 'StringCurveKey', 'PerPlatformBool', 'PerPlatformFloat', 'PerPlatformInt', 'PerPlatformFrameRate',
    'PerPlatformFString', 'PerPlatformERigLogicFloatingPointType', 'PerPlatformERigLogicCalculationType', 'PerQualityLevelInt',
    'PerQualityLevelFloat', 'Spline', 'InstancedStruct', 'InstancedStructContainer', 'InstancedStructArray', 'InstancedPropertyBag',
    'RigVMPropertyBag', 'InstancedOverridablePropertyBag', 'MovieSceneFloatChannel', 'MovieSceneDoubleChannel',
    'MovieSceneFloatValue', 'MovieSceneDoubleValue', 'MovieSceneEvalTemplatePtr', 'MovieSceneTrackImplementationPtr',
    'MovieSceneSequenceInstanceDataPtr', 'MovieSceneEvaluationFieldEntityTree', 'MovieSceneTrackFieldData',
    'MovieSceneSubSectionFieldData', 'MovieSceneSubSequenceTree', 'MovieSceneSegment', 'MovieSceneEventParameters',
    'MovieSceneTimeWarpVariant', 'NiagaraVariableBase', 'NiagaraDataChannelVariable', 'NiagaraVariable', 'NiagaraVariableWithOffset',
    'NiagaraDataInterfaceGPUParamInfo', 'PCGPointArray', 'WorldConditionQueryDefinition', 'StateTreeInstanceData',
    'SkeletalMeshSamplingLODBuiltData', 'MaterialOverrideNanite', 'FontData', 'UniversalObjectLocatorFragment', 'ShaderValueTypeHandle',
})

_TAGS_ZERO = (Slot(0, 'GameplayTagContainer', 'GameplayTags', 'Array<Name>', 'zero', None),)
_TAGS_LAYOUT = _layout(_TAGS_ZERO)
_PCG_ZERO = (Slot(0, 'PCGDataPtrWrapper', 'Data', 'Object', 'zero', None),)
_PCG_LAYOUT = _layout(_PCG_ZERO)


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


VARIABLE = {'GameplayTagContainer': read_tags, 'PCGDataPtrWrapper': read_pcg_data, **{n: read_soft_path for n in SOFT_PATHS}}


def zero(name: str, ctx: tuple, null_ref):
    """The zero value of a native this module reads, or None for a name it does not read."""
    if (spec := FIXED.get(name)) is not None:
        return spec.zero(ctx)
    if name == 'GameplayTagContainer':
        return StructValue._new(name, True, _TAGS_ZERO, ((),), ctx, None, _TAGS_LAYOUT)
    if name == 'PCGDataPtrWrapper':
        return StructValue._new(name, True, _PCG_ZERO, (null_ref,), ctx, None, _PCG_LAYOUT)
    if name in SOFT_PATHS:
        return EMPTY_SOFT
    return None
