"""Per-engine state of Dumper-7 @ ea0dab3: Offsets.h (Off, PropertySizes, GObjects layouts) and Settings.h."""
import dataclasses


@dataclasses.dataclass(frozen=True)
class FFixedUObjectArrayLayout:
    ObjectsOffset: int = -1
    MaxObjectsOffset: int = -1
    NumObjectsOffset: int = -1

    def is_valid(self) -> bool:
        return self.ObjectsOffset != -1 and self.MaxObjectsOffset != -1 and self.NumObjectsOffset != -1


@dataclasses.dataclass(frozen=True)
class FChunkedFixedUObjectArrayLayout:
    ObjectsOffset: int = -1
    MaxElementsOffset: int = -1
    NumElementsOffset: int = -1
    MaxChunksOffset: int = -1
    NumChunksOffset: int = -1

    def is_valid(self) -> bool:
        return (self.ObjectsOffset != -1 and self.MaxElementsOffset != -1 and self.NumElementsOffset != -1
                and self.MaxChunksOffset != -1 and self.NumChunksOffset != -1)


FFixedUObjectArrayLayouts = (
    FFixedUObjectArrayLayout(0x0, 0x8, 0xC),  # Default UE4.11 - UE4.20
)

FChunkedFixedUObjectArrayLayouts = (
    FChunkedFixedUObjectArrayLayout(0x00, 0x10, 0x14, 0x18, 0x1C),  # Default UE4.21 and above
    FChunkedFixedUObjectArrayLayout(0x00, 0x0C, 0x08, 0x14, 0x10),  # UE5.8 Developement Build (dd8fe34 addition, Q23 = A)
    FChunkedFixedUObjectArrayLayout(0x10, 0x00, 0x04, 0x08, 0x0C),  # Back4Blood
    FChunkedFixedUObjectArrayLayout(0x18, 0x10, 0x00, 0x14, 0x20),  # Mutliversus
    FChunkedFixedUObjectArrayLayout(0x18, 0x00, 0x14, 0x10, 0x04),  # MindsEye
)


def _namespace(name: str, **fields) -> type:
    """A slotted namespace class; a field whose default is a class gets a fresh instance of it."""

    def __init__(self):
        for key, value in fields.items():
            setattr(self, key, value() if isinstance(value, type) else value)

    def __repr__(self):
        return f'{name}({", ".join(f"{key}={getattr(self, key)!r}" for key in fields)})'

    return type(name, (), {'__slots__': tuple(fields), '__init__': __init__, '__repr__': __repr__, '__qualname__': name})


class _FUObjectArray:
    """Off::FUObjectArray @ ea0dab3."""
    __slots__ = ('FixedLayout', 'ChunkedFixedLayout', 'bIsChunked')

    def __init__(self):
        self.FixedLayout = FFixedUObjectArrayLayout()
        self.ChunkedFixedLayout = FChunkedFixedUObjectArrayLayout()
        self.bIsChunked = False

    def __repr__(self):
        return f'Off.FUObjectArray(FixedLayout={self.FixedLayout!r}, ChunkedFixedLayout={self.ChunkedFixedLayout!r}, bIsChunked={self.bIsChunked!r})'

    def get_objects_offset(self) -> int:
        return self.ChunkedFixedLayout.ObjectsOffset if self.bIsChunked else self.FixedLayout.ObjectsOffset

    def get_num_elements_offset(self) -> int:
        return self.ChunkedFixedLayout.NumElementsOffset if self.bIsChunked else self.FixedLayout.NumObjectsOffset

    def get_max_elements_offset(self) -> int:
        return self.ChunkedFixedLayout.MaxElementsOffset if self.bIsChunked else self.FixedLayout.MaxObjectsOffset

    def get_num_chunks_offset(self) -> int:
        return self.ChunkedFixedLayout.NumChunksOffset if self.bIsChunked else 0x0

    def get_max_chunks_offset(self) -> int:
        return self.ChunkedFixedLayout.MaxChunksOffset if self.bIsChunked else 0x0


_InSDK = _namespace(
    'Off.InSDK',
    ProcessEvent=_namespace('Off.InSDK.ProcessEvent', PEIndex=0, PEOffset=0),
    World=_namespace('Off.InSDK.World', GWorld=0x0),
    ObjArray=_namespace('Off.InSDK.ObjArray', GObjects=0, ChunkSize=0, FUObjectItemSize=0, FUObjectItemInitialOffset=0),
    Name=_namespace('Off.InSDK.Name', bIsUsingAppendStringOverToString=True, bIsAppendStringInlinedAndUsed=False,
                    AppendNameToString=0, GetNameEntryFromName=0, FNameSize=0),
    NameArray=_namespace('Off.InSDK.NameArray', GNames=0x0, FNamePoolBlockOffsetBits=0x0, FNameEntryStride=0x0),
    Properties=_namespace('Off.InSDK.Properties', PropertySize=0),
    Text=_namespace('Off.InSDK.Text', TextDatOffset=0x0, InTextDataStringOffset=0x0, TextSize=0x0),
    ULevel=_namespace('Off.InSDK.ULevel', Actors=0),
    UDataTable=_namespace('Off.InSDK.UDataTable', RowMap=0),
)

_OFF_FIELDS = dict(
    InSDK=_InSDK,
    FUObjectArray=_FUObjectArray,
    NameArray=_namespace('Off.NameArray', ChunksStart=0, MaxChunkIndex=0, NumElements=0, ByteCursor=0),
    FField=_namespace('Off.FField', Vft=0x00, Class=0x08, Owner=0x10, Next=0x20, Name=0x28, Flags=0x30),
    FFieldClass=_namespace('Off.FFieldClass', Name=0x00, Id=0x08, CastFlags=0x10, ClassFlags=0x18, SuperClass=0x20),
    FName=_namespace('Off.FName', CompIdx=0x0, Number=0x4),
    FNameEntry=_namespace(
        'Off.FNameEntry',
        NameArray=_namespace('Off.FNameEntry.NameArray', StringOffset=0, IndexOffset=0),
        NamePool=_namespace('Off.FNameEntry.NamePool', HeaderOffset=0, StringOffset=0),
    ),
    UObject=_namespace('Off.UObject', Vft=0, Flags=0, Index=0, Class=0, Name=0, Outer=0),
    UField=_namespace('Off.UField', Next=0),
    UEnum=_namespace('Off.UEnum', Names=0),
    UStruct=_namespace('Off.UStruct', SuperStruct=0, Children=0, ChildProperties=0, Size=0, MinAlignment=0),
    UFunction=_namespace('Off.UFunction', FunctionFlags=0, ExecFunction=0),
    UClass=_namespace('Off.UClass', CastFlags=0, ClassDefaultObject=0, ImplementedInterfaces=0),
    Property=_namespace('Off.Property', ArrayDim=0, ElementSize=0, PropertyFlags=0, Offset_Internal=0),
    ByteProperty=_namespace('Off.ByteProperty', Enum=0),
    BoolProperty=_namespace('Off.BoolProperty', Base=0),
    ObjectProperty=_namespace('Off.ObjectProperty', PropertyClass=0),
    ClassProperty=_namespace('Off.ClassProperty', MetaClass=0),
    StructProperty=_namespace('Off.StructProperty', Struct=0),
    ArrayProperty=_namespace('Off.ArrayProperty', Inner=0),
    DelegateProperty=_namespace('Off.DelegateProperty', SignatureFunction=0),
    MapProperty=_namespace('Off.MapProperty', Base=0),
    SetProperty=_namespace('Off.SetProperty', ElementProp=0),
    EnumProperty=_namespace('Off.EnumProperty', Base=0),
    FieldPathProperty=_namespace('Off.FieldPathProperty', FieldClass=0),
    OptionalProperty=_namespace('Off.OptionalProperty', ValueProperty=0),
)

_SETTINGS_FIELDS = dict(
    General=_namespace('Settings.General', bSearchOnlyExecutableSectionsForStrings=True, DefaultModuleName=None),
    EngineCore=_namespace('Settings.EngineCore', bCheckEnumNamesInUEnum=False, bEnableEncryptedObjectPropertySupport=False),
    Generator=_namespace('Settings.Generator', GameName='', GameVersion=''),
    Internal=_namespace(
        'Settings.Internal', bIsEnumNameOnly=False, bIsSmallEnumValue=False, bIsNewUE5EnumNamesContainer=False,
        bIsWeakObjectPtrWithoutTag=False, bUseFProperty=False, bUseNamePool=False, bIsObjectNameBeforeClass=False,
        bUseCasePreservingName=False, bUseOutlineNumberName=False, bIsObjPtrInsteadOfFieldPathProperty=False,
        bUseMaskForFieldOwner=False, bUseLargeWorldCoordinates=False, bUseUint8ArrayDim=False,
    ),
)

_PROPERTY_SIZES_FIELDS = dict(DelegateProperty=0x10, FieldPathProperty=0x20, MulticastInlineDelegateProperty=0x10)

Off = _namespace('Off', **_OFF_FIELDS)
Off.__doc__ = 'namespace Off of Offsets.h @ ea0dab3, per engine.'
Settings = _namespace('Settings', **_SETTINGS_FIELDS)
Settings.__doc__ = 'Settings.h @ ea0dab3 (General, EngineCore, Generator, Internal), per engine.'
PropertySizes = _namespace('PropertySizes', **_PROPERTY_SIZES_FIELDS)
PropertySizes.__doc__ = 'namespace PropertySizes of Offsets.h @ ea0dab3, per engine.'
