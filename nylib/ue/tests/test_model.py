import json
import unittest

from nylib.ue import flags, model, names
from nylib.ue.flags import EClassCastFlags, EFunctionFlags, EPropertyFlags

# Full name->value tables for the five flag enums, transcribed independently from Enums.h @
# dd8fe34 (review M8): a swap or edit of a non-anchor member in flags.py must still go red here.
_EPROPERTYFLAGS_TABLE = {
    'Edit': 0x1, 'ConstParm': 0x2, 'BlueprintVisible': 0x4,
    'ExportObject': 0x8, 'BlueprintReadOnly': 0x10, 'Net': 0x20,
    'EditFixedSize': 0x40, 'Parm': 0x80, 'OutParm': 0x100,
    'ZeroConstructor': 0x200, 'ReturnParm': 0x400, 'DisableEditOnTemplate': 0x800,
    'Transient': 0x2000, 'Config': 0x4000, 'DisableEditOnInstance': 0x10000,
    'EditConst': 0x20000, 'GlobalConfig': 0x40000, 'InstancedReference': 0x80000,
    'DuplicateTransient': 0x200000, 'SubobjectReference': 0x400000, 'SaveGame': 0x1000000,
    'NoClear': 0x2000000, 'ReferenceParm': 0x8000000, 'BlueprintAssignable': 0x10000000,
    'Deprecated': 0x20000000, 'IsPlainOldData': 0x40000000, 'RepSkip': 0x80000000,
    'RepNotify': 0x100000000, 'Interp': 0x200000000, 'NonTransactional': 0x400000000,
    'EditorOnly': 0x800000000, 'NoDestructor': 0x1000000000, 'AutoWeak': 0x4000000000,
    'ContainsInstancedReference': 0x8000000000, 'AssetRegistrySearchable': 0x10000000000, 'SimpleDisplay': 0x20000000000,
    'AdvancedDisplay': 0x40000000000, 'Protected': 0x80000000000, 'BlueprintCallable': 0x100000000000,
    'BlueprintAuthorityOnly': 0x200000000000, 'TextExportTransient': 0x400000000000, 'NonPIEDuplicateTransient': 0x800000000000,
    'ExposeOnSpawn': 0x1000000000000, 'PersistentInstance': 0x2000000000000, 'UObjectWrapper': 0x4000000000000,
    'HasGetValueTypeHash': 0x8000000000000, 'NativeAccessSpecifierPublic': 0x10000000000000, 'NativeAccessSpecifierProtected': 0x20000000000000,
    'NativeAccessSpecifierPrivate': 0x40000000000000, 'SkipSerialization': 0x80000000000000, 'TObjectPtr': 0x100000000000000,
    'ExperimentalOverridableLogic': 0x200000000000000, 'ExperimentalAlwaysOverriden': 0x400000000000000, 'ExperimentalNeverOverriden': 0x800000000000000,
    'AllowSelfReference': 0x1000000000000000,
}
_EFUNCTIONFLAGS_TABLE = {
    'Final': 0x1, 'RequiredAPI': 0x2, 'BlueprintAuthorityOnly': 0x4,
    'BlueprintCosmetic': 0x8, 'Net': 0x40, 'NetReliable': 0x80,
    'NetRequest': 0x100, 'Exec': 0x200, 'Native': 0x400,
    'Event': 0x800, 'NetResponse': 0x1000, 'Static': 0x2000,
    'NetMulticast': 0x4000, 'UbergraphFunction': 0x8000, 'MulticastDelegate': 0x10000,
    'Public': 0x20000, 'Private': 0x40000, 'Protected': 0x80000,
    'Delegate': 0x100000, 'NetServer': 0x200000, 'HasOutParms': 0x400000,
    'HasDefaults': 0x800000, 'NetClient': 0x1000000, 'DLLImport': 0x2000000,
    'BlueprintCallable': 0x4000000, 'BlueprintEvent': 0x8000000, 'BlueprintPure': 0x10000000,
    'EditorOnly': 0x20000000, 'Const': 0x40000000, 'NetValidate': 0x80000000,
}
_EOBJECTFLAGS_TABLE = {
    'Public': 0x1, 'Standalone': 0x2, 'MarkAsNative': 0x4,
    'Transactional': 0x8, 'ClassDefaultObject': 0x10, 'ArchetypeObject': 0x20,
    'Transient': 0x40, 'MarkAsRootSet': 0x80, 'TagGarbageTemp': 0x100,
    'NeedInitialization': 0x200, 'NeedLoad': 0x400, 'KeepForCooker': 0x800,
    'NeedPostLoad': 0x1000, 'NeedPostLoadSubobjects': 0x2000, 'NewerVersionExists': 0x4000,
    'BeginDestroyed': 0x8000, 'FinishDestroyed': 0x10000, 'BeingRegenerated': 0x20000,
    'DefaultSubObject': 0x40000, 'WasLoaded': 0x80000, 'TextExportTransient': 0x100000,
    'LoadCompleted': 0x200000, 'InheritableComponentTemplate': 0x400000, 'DuplicateTransient': 0x800000,
    'StrongRefOnFrame': 0x1000000, 'NonPIEDuplicateTransient': 0x2000000, 'Dynamic': 0x4000000,
    'WillBeLoaded': 0x8000000,
}
_ECLASSCASTFLAGS_TABLE = {
    'Field': 0x1, 'Int8Property': 0x2, 'Enum': 0x4,
    'Struct': 0x8, 'ScriptStruct': 0x10, 'Class': 0x20,
    'ByteProperty': 0x40, 'IntProperty': 0x80, 'FloatProperty': 0x100,
    'UInt64Property': 0x200, 'ClassProperty': 0x400, 'UInt32Property': 0x800,
    'InterfaceProperty': 0x1000, 'NameProperty': 0x2000, 'StrProperty': 0x4000,
    'Property': 0x8000, 'ObjectProperty': 0x10000, 'BoolProperty': 0x20000,
    'UInt16Property': 0x40000, 'Function': 0x80000, 'StructProperty': 0x100000,
    'ArrayProperty': 0x200000, 'Int64Property': 0x400000, 'DelegateProperty': 0x800000,
    'NumericProperty': 0x1000000, 'MulticastDelegateProperty': 0x2000000, 'ObjectPropertyBase': 0x4000000,
    'WeakObjectProperty': 0x8000000, 'LazyObjectProperty': 0x10000000, 'SoftObjectProperty': 0x20000000,
    'TextProperty': 0x40000000, 'Int16Property': 0x80000000, 'DoubleProperty': 0x100000000,
    'SoftClassProperty': 0x200000000, 'Package': 0x400000000, 'Level': 0x800000000,
    'Actor': 0x1000000000, 'PlayerController': 0x2000000000, 'Pawn': 0x4000000000,
    'SceneComponent': 0x8000000000, 'PrimitiveComponent': 0x10000000000, 'SkinnedMeshComponent': 0x20000000000,
    'SkeletalMeshComponent': 0x40000000000, 'Blueprint': 0x80000000000, 'DelegateFunction': 0x100000000000,
    'StaticMeshComponent': 0x200000000000, 'MapProperty': 0x400000000000, 'SetProperty': 0x800000000000,
    'EnumProperty': 0x1000000000000, 'SparseDelegateFunction': 0x2000000000000, 'MulticastInlineDelegateProperty': 0x4000000000000,
    'MulticastSparseDelegateProperty': 0x8000000000000, 'FieldPathProperty': 0x10000000000000, 'LargeWorldCoordinatesRealProperty': 0x80000000000000,
    'OptionalProperty': 0x100000000000000, 'VValueProperty': 0x200000000000000, 'VerseVMClass': 0x400000000000000,
    'VRestValueProperty': 0x800000000000000, 'Utf8StrProperty': 0x1000000000000000, 'AnsiStrProperty': 0x2000000000000000,
    'VCellProperty': 0x4000000000000000,
}
_ECLASSFLAGS_TABLE = {
    'Abstract': 0x1, 'DefaultConfig': 0x2, 'Config': 0x4,
    'Transient': 0x8, 'Parsed': 0x10, 'MatchedSerializers': 0x20,
    'ProjectUserConfig': 0x40, 'Native': 0x80, 'NoExport': 0x100,
    'NotPlaceable': 0x200, 'PerObjectConfig': 0x400, 'ReplicationDataIsSetUp': 0x800,
    'EditInlineNew': 0x1000, 'CollapseCategories': 0x2000, 'Interface': 0x4000,
    'CustomConstructor': 0x8000, 'Const': 0x10000, 'LayoutChanging': 0x20000,
    'CompiledFromBlueprint': 0x40000, 'MinimalAPI': 0x80000, 'RequiredAPI': 0x100000,
    'DefaultToInstanced': 0x200000, 'TokenStreamAssembled': 0x400000, 'HasInstancedReference': 0x800000,
    'Hidden': 0x1000000, 'Deprecated': 0x2000000, 'HideDropDown': 0x4000000,
    'GlobalUserConfig': 0x8000000, 'Intrinsic': 0x10000000, 'Constructed': 0x20000000,
    'ConfigDoNotCheckDefaults': 0x40000000, 'NewerVersionExists': 0x80000000,
}


class FlagsTests(unittest.TestCase):
    def test_anchors(self):
        self.assertEqual(flags.EClassCastFlags.Class, 0x20)
        self.assertEqual(flags.EClassCastFlags.Struct, 0x8)
        self.assertEqual(flags.EClassCastFlags.Function, 0x80000)
        self.assertEqual(flags.EClassCastFlags.Enum, 0x4)
        self.assertEqual(flags.EClassCastFlags.Property, 0x8000)
        self.assertEqual(flags.EClassCastFlags.Actor, 0x1000000000)
        self.assertEqual(flags.EClassCastFlags.OptionalProperty, 0x0100000000000000)
        self.assertEqual(flags.EClassCastFlags.VCellProperty, 0x4000000000000000)
        self.assertEqual(flags.EFunctionFlags.Native, 0x400)
        self.assertEqual(flags.EFunctionFlags.Static, 0x2000)
        self.assertEqual(flags.EFunctionFlags.HasOutParms, 0x400000)
        self.assertEqual(flags.EObjectFlags.ClassDefaultObject, 0x10)
        self.assertEqual(flags.EPropertyFlags.Parm, 0x80)
        self.assertEqual(flags.EPropertyFlags.OutParm, 0x100)
        self.assertEqual(flags.EPropertyFlags.ReturnParm, 0x400)
        self.assertEqual(flags.EPropertyFlags.ReferenceParm, 0x8000000)
        self.assertEqual(flags.EClassFlags.Interface, 0x4000)
        self.assertEqual(len(flags.EPropertyFlags.__members__), 55)
        self.assertEqual(len(flags.EFunctionFlags.__members__), 30)
        self.assertEqual(len(flags.EObjectFlags.__members__), 28)
        self.assertEqual(len(flags.EClassCastFlags.__members__), 61)
        self.assertEqual(len(flags.EClassFlags.__members__), 32)

    def test_keep(self):
        value = flags.EFunctionFlags(0x1_0000_0000 | 0x400)
        self.assertEqual(int(value), 0x1_0000_0400)

    def test_full_member_tables(self):
        for enum_cls, expected in (
            (flags.EPropertyFlags, _EPROPERTYFLAGS_TABLE),
            (flags.EFunctionFlags, _EFUNCTIONFLAGS_TABLE),
            (flags.EObjectFlags, _EOBJECTFLAGS_TABLE),
            (flags.EClassCastFlags, _ECLASSCASTFLAGS_TABLE),
            (flags.EClassFlags, _ECLASSFLAGS_TABLE),
        ):
            actual = {name: int(value) for name, value in enum_cls.__members__.items()}
            self.assertEqual(actual, expected, enum_cls.__name__)


class NamesTests(unittest.TestCase):
    def test_make_name_valid(self):
        cases = [
            ('bool', 'Bool'), ('NULL', 'NULLL'), ('bool ', 'bool_'), ('3DWidget', 'ThreeDWidget'),
            ('9', 'Nine'), ('My Name-1', 'My_Name_1'), ('a$b', 'a_b'), ('Ünïcode', 'Ünïcode'),
            ('', ''), ('_x', '_x'),
            ('é', 'é'), ('x²', 'x_'), ('$x', '_x'), (' x', '_x'),
            ('BOOL', 'BOOL'), ('Bool', 'Bool'), ('A・B', 'A・B'),
        ]
        for raw, expected in cases:
            self.assertEqual(names.make_name_valid(raw), expected, raw)

    def test_cpp_name(self):
        self.assertEqual(names.cpp_name('Actor', 'class', is_actor=True), 'AActor')
        self.assertEqual(names.cpp_name('Interface', 'class', is_interface=True), 'IInterface')
        self.assertEqual(names.cpp_name('Actor', 'class', is_actor=True, is_interface=True), 'AActor')
        self.assertEqual(names.cpp_name('Object', 'class'), 'UObject')
        self.assertEqual(names.cpp_name('Vector', 'struct'), 'FVector')
        self.assertEqual(names.cpp_name('/Script/Engine.Foo', 'struct'), 'FEngine_Foo')
        self.assertEqual(names.cpp_name('ENetRole', 'enum'), 'ENetRole')
        self.assertEqual(names.cpp_name('NetRole', 'enum'), 'ENetRole')
        self.assertEqual(names.cpp_name('eX', 'enum'), 'EeX')
        with self.assertRaises(ValueError):
            names.cpp_name('X', 'package')
        with self.assertRaises(TypeError):
            names.cpp_name('X', 3)

    def test_mangle_exec(self):
        self.assertEqual(names.mangle_exec('AActor', 'K2_DestroyActor'), '_ZN6AActor19execK2_DestroyActorEv')
        self.assertEqual(names.mangle_exec('UÄ', 'f'), '_ZN3UÄ5execfEv')

    def test_misc(self):
        self.assertEqual(names.valid_file_name('5.3-A:B/C'), '5.3-A_B_C')
        self.assertEqual(names.valid_file_name('CON'), 'CON')
        self.assertEqual(names.valid_file_name('<>:"/\\|?*'), '_' * 9)
        self.assertEqual(names.fname_display('X', 0), 'X')
        self.assertEqual(names.fname_display('X', 1), 'X_0')
        self.assertEqual(names.fname_display('X', 5), 'X_4')
        # F7 amendment: number is read as uint32 (Number & 0xFFFFFFFF), so a negative int
        # wraps instead of collapsing to the base name.
        self.assertEqual(names.fname_display('X', -3), 'X_4294967292')
        self.assertEqual(names.fname_display('X', -1), 'X_4294967294')
        self.assertEqual(names.strip_path('/Script/Engine'), 'Engine')

    def test_types(self):
        for fn, args in [
            (names.strip_path, (1,)),
            (names.make_name_valid, (1,)),
            (names.cpp_name, (1, 'class')),
            (names.mangle_exec, (1, 'x')),
            (names.mangle_exec, ('x', 1)),
            (names.valid_file_name, (1,)),
            (names.fname_display, (1, 1)),
            (names.fname_display, ('X', 1.0)),
        ]:
            with self.assertRaises(TypeError, msg=(fn, args)):
                fn(*args)


class ModelJsonTests(unittest.TestCase):
    def test_property_golden(self):
        rec = model.PropertyRecord('X', 0, 8, 1, 0x0018001040000205,
                                    model.PropType(prop='DoubleProperty', kind='DoubleProperty'))
        expected = ('{"name":"X","offset":"0x0","size":"0x8","array_dim":1,'
                    '"flags":"0x0018001040000205","type":{"prop":"DoubleProperty"}}')
        self.assertEqual(json.dumps(rec.to_json(), separators=(',', ':')), expected)

    def test_property_no_address(self):
        rec = model.PropertyRecord('X', 0, 8, 1, 0x0018001040000205,
                                    model.PropType(prop='DoubleProperty', kind='DoubleProperty'), address=0x1234)
        expected = ('{"name":"X","offset":"0x0","size":"0x8","array_dim":1,'
                    '"flags":"0x0018001040000205","type":{"prop":"DoubleProperty"}}')
        self.assertEqual(json.dumps(rec.to_json(), separators=(',', ':')), expected)
        rebuilt = model.PropertyRecord.from_json({**json.loads(expected), 'address': '0x1234'})
        self.assertIsNone(rebuilt.address)

    def test_kinds(self):
        cases = [
            (model.PropType(prop='ByteProperty', kind='ByteProperty'),
             {'prop': 'ByteProperty', 'enum': None}),
            (model.PropType(prop='ByteProperty', kind='ByteProperty', enum='EColor'),
             {'prop': 'ByteProperty', 'enum': 'EColor'}),
            (model.PropType(prop='BoolProperty', kind='BoolProperty'),
             {'prop': 'BoolProperty', 'field_size': None, 'byte_offset': None, 'byte_mask': None,
              'field_mask': None, 'bit': None}),
            (model.PropType(prop='BoolProperty', kind='BoolProperty', field_size=1, byte_offset=1,
                             byte_mask=0x04, field_mask=0x04),
             {'prop': 'BoolProperty', 'field_size': 1, 'byte_offset': 1, 'byte_mask': 4,
              'field_mask': 4, 'bit': 10}),
            (model.PropType(prop='EnumProperty', kind='EnumProperty', enum='ENetRole',
                             underlying=model.PropType(prop='ByteProperty', kind='ByteProperty')),
             {'prop': 'EnumProperty', 'enum': 'ENetRole',
              'underlying': {'prop': 'ByteProperty', 'enum': None}}),
            (model.PropType(prop='ObjectProperty', kind='ObjectProperty', cls='AActor'),
             {'prop': 'ObjectProperty', 'class': 'AActor'}),
            (model.PropType(prop='ClassProperty', kind='ClassProperty', cls='UClass', meta_class='UObject'),
             {'prop': 'ClassProperty', 'class': 'UClass', 'meta_class': 'UObject'}),
            (model.PropType(prop='StructProperty', kind='StructProperty', struct='FVector'),
             {'prop': 'StructProperty', 'struct': 'FVector'}),
            (model.PropType(prop='ArrayProperty', kind='ArrayProperty',
                             inner=model.PropType(prop='IntProperty', kind='IntProperty')),
             {'prop': 'ArrayProperty', 'inner': {'prop': 'IntProperty'}}),
            (model.PropType(prop='SetProperty', kind='SetProperty',
                             element=model.PropType(prop='NameProperty', kind='NameProperty')),
             {'prop': 'SetProperty', 'element': {'prop': 'NameProperty'}}),
            (model.PropType(prop='OptionalProperty', kind='OptionalProperty',
                             value=model.PropType(prop='FloatProperty', kind='FloatProperty')),
             {'prop': 'OptionalProperty', 'value': {'prop': 'FloatProperty'}}),
            (model.PropType(prop='MapProperty', kind='MapProperty',
                             key=model.PropType(prop='StructProperty', kind='StructProperty', struct='FGuid'),
                             value=model.PropType(prop='ArrayProperty', kind='ArrayProperty',
                                                  inner=model.PropType(prop='ObjectProperty', kind='ObjectProperty',
                                                                       cls='AActor'))),
             {'prop': 'MapProperty',
              'key': {'prop': 'StructProperty', 'struct': 'FGuid'},
              'value': {'prop': 'ArrayProperty', 'inner': {'prop': 'ObjectProperty', 'class': 'AActor'}}}),
            (model.PropType(prop='DelegateProperty', kind='DelegateProperty', signature='FMyDelegate'),
             {'prop': 'DelegateProperty', 'signature': 'FMyDelegate'}),
            (model.PropType(prop='FieldPathProperty', kind='FieldPathProperty', field_class='FProperty'),
             {'prop': 'FieldPathProperty', 'field_class': 'FProperty'}),
            (model.PropType(prop='IntProperty', kind='IntProperty'),
             {'prop': 'IntProperty'}),
            (model.PropType(prop='VValueProperty', kind=model.UNKNOWN_KIND),
             {'prop': 'VValueProperty', 'unknown': True}),
            (model.PropType(prop='LargeWorldCoordinatesRealProperty', kind='DoubleProperty'),
             {'prop': 'LargeWorldCoordinatesRealProperty', 'kind': 'DoubleProperty'}),
        ]
        for pt, expected in cases:
            self.assertEqual(pt.to_json(), expected, pt)

    def test_bool_bit(self):
        def bit(byte_offset, field_mask):
            return model.PropType(prop='BoolProperty', kind='BoolProperty',
                                   byte_offset=byte_offset, field_mask=field_mask).bit
        self.assertIsNone(bit(0, 0xFF))
        self.assertEqual(bit(1, 0x04), 10)
        self.assertIsNone(bit(1, 0x06))
        self.assertIsNone(bit(1, 0))

    def test_roundtrip(self):
        prop_bitfield = model.PropertyRecord(
            'bEnabled', 0x10, 1, 1, int(EPropertyFlags.Edit),
            model.PropType(prop='BoolProperty', kind='BoolProperty', field_size=1, byte_offset=0,
                           byte_mask=1, field_mask=1))
        prop_map = model.PropertyRecord(
            'Lookup', 0x20, 0x50, 1, 0,
            model.PropType(prop='MapProperty', kind='MapProperty',
                           key=model.PropType(prop='StructProperty', kind='StructProperty', struct='FGuid'),
                           value=model.PropType(prop='ArrayProperty', kind='ArrayProperty',
                                                inner=model.PropType(prop='ObjectProperty', kind='ObjectProperty',
                                                                     cls='AActor'))))
        func_a = model.FunctionRecord('Pkg.C:Foo', 'Foo', 'Pkg', int(EFunctionFlags.Native), 0, [], None)
        ret_param = model.PropertyRecord(
            'ReturnValue', 0, 4, 1, int(EPropertyFlags.Parm | EPropertyFlags.ReturnParm),
            model.PropType(prop='IntProperty', kind='IntProperty'))
        func_b = model.FunctionRecord('Pkg.C:Bar', 'Bar', 'Pkg', int(EFunctionFlags.Native | EFunctionFlags.Static),
                                       4, [ret_param], 0x1000)
        iface = model.InterfaceRecord('IMyInterface', 0x18, True)
        cls_rec = model.ClassRecord(
            path='Pkg.C', name='C', cpp_name='UC', package='Pkg', super='Object', size=0x60, min_alignment=8,
            properties=[prop_bitfield, prop_map], cast_flags=int(EClassCastFlags.Class), cdo='Default__C',
            interfaces=[iface], functions={'Foo': func_a, 'Bar': func_b})
        rebuilt = model.type_from_json(cls_rec.to_json())
        self.assertEqual(rebuilt, cls_rec)
        self.assertEqual(list(rebuilt.functions), ['Foo', 'Bar'])

        struct_rec = model.StructRecord('Pkg.S', 'S', 'FS', 'Pkg', None, 0x10, 4, [prop_map])
        self.assertEqual(model.type_from_json(struct_rec.to_json()), struct_rec)

        for source in model.ENUM_SIZE_SOURCES:
            enum_rec = model.EnumRecord('Pkg.E', 'E', 'EE', 'Pkg', 1, source, False, [('A', 0), ('B', 1)])
            self.assertEqual(model.type_from_json(enum_rec.to_json()), enum_rec)

        top_func = model.FunctionRecord('Pkg.C:Baz', 'Baz', 'Pkg', int(EFunctionFlags.Native), 0, [], None)
        self.assertEqual(model.type_from_json(top_func.to_json()), top_func)

    def test_function_none_fields(self):
        rec = model.FunctionRecord('Pkg.C:Baz', 'Baz', 'Pkg', int(EFunctionFlags.Native), 0, [], None)
        d = rec.to_json()
        self.assertIsNone(d['return'])
        self.assertIsNone(d['exec_rva'])
        self.assertEqual(model.FunctionRecord.from_json(d), rec)

    def test_function_nested(self):
        local_param = model.PropertyRecord('Temp', 0, 4, 1, 0, model.PropType(prop='IntProperty', kind='IntProperty'))
        ret_param = model.PropertyRecord(
            'ReturnValue', 4, 4, 1, int(EPropertyFlags.Parm | EPropertyFlags.ReturnParm),
            model.PropType(prop='IntProperty', kind='IntProperty'))
        func = model.FunctionRecord('Pkg.C:Foo', 'Foo', 'Pkg', int(EFunctionFlags.Native), 8,
                                     [local_param, ret_param], None)
        nested = func.to_json(nested=True)
        for key in ('kind', 'path', 'name', 'package'):
            self.assertNotIn(key, nested)
        self.assertEqual(nested['return'], 'ReturnValue')
        rebuilt = model.FunctionRecord.from_json(nested, path='Pkg.C:Foo', name='Foo', package='Pkg')
        self.assertEqual(rebuilt, func)
        self.assertEqual([p.name for p in rebuilt.params], ['Temp', 'ReturnValue'])

    def test_errors(self):
        with self.assertRaises(ValueError) as cm:
            model.PropertyRecord.from_json({})
        self.assertIn('name', str(cm.exception))
        with self.assertRaises(ValueError):
            model.type_from_json({'kind': 'bogus'})
        with self.assertRaises(ValueError):
            model.type_from_json([])
        with self.assertRaises(ValueError):
            model.PropType(prop='X', kind='NotAKind')
        with self.assertRaises(ValueError):
            model.EnumRecord('P.E', 'E', 'EE', 'P', 3, 'reflection', False, [])
        bad_array_dim = {
            'name': 'X', 'offset': '0x0', 'size': '0x4', 'array_dim': True, 'flags': '0x0',
            'type': {'prop': 'IntProperty'},
        }
        with self.assertRaises(ValueError):
            model.PropertyRecord.from_json(bad_array_dim)

    def test_hex_helpers(self):
        self.assertEqual(model.hexs(255, 4), '0x00FF')
        self.assertEqual(model.hexs(-16), '-0x10')
        with self.assertRaises(ValueError):
            model.hexs(1, -1)
        with self.assertRaises(TypeError):
            model.hexs(1.5)
        self.assertEqual(model.unhex('0x1F'), 31)
        self.assertEqual(model.unhex('0X1f'), 31)
        self.assertEqual(model.unhex('-0x10'), -16)
        for bad in ('12', '0x', ' 0x1', '0x1_0', 16):
            with self.assertRaises(ValueError, msg=bad):
                model.unhex(bad)

    def test_json_key_order(self):
        # Order-sensitive: dict equality alone would not catch a reordered key set.
        b = model.PropType('BoolProperty', 'BoolProperty', field_size=1, byte_offset=1, byte_mask=4, field_mask=4)
        self.assertEqual(json.dumps(b.to_json(), separators=(',', ':')),
                          '{"prop":"BoolProperty","field_size":1,"byte_offset":1,"byte_mask":4,"field_mask":4,"bit":10}')
        m = model.PropType('MapProperty', 'MapProperty', key=model.PropType('IntProperty', 'IntProperty'),
                            value=model.PropType('NameProperty', 'NameProperty'))
        self.assertEqual(json.dumps(m.to_json(), separators=(',', ':')),
                          '{"prop":"MapProperty","key":{"prop":"IntProperty"},"value":{"prop":"NameProperty"}}')
        s = model.PropType('SoftClassProperty', 'SoftClassProperty', cls='UClass', meta_class='AActor')
        self.assertEqual(list(s.to_json()), ['prop', 'class', 'meta_class'])
        self.assertEqual(list(model.PropType('X', 'EnumProperty', enum='E').to_json()),
                          ['prop', 'kind', 'enum', 'underlying'])
        f = model.FunctionRecord('P.C:F', 'F', 'P', 0x400, 4, [], 0x1234)
        self.assertEqual(json.dumps(f.to_json(), separators=(',', ':')),
                          '{"kind":"function","path":"P.C:F","name":"F","package":"P","flags":"0x00000400",'
                          '"params_size":"0x4","return":null,"params":[],"exec_rva":"0x1234"}')
        cr = model.ClassRecord('P.C', 'C', 'UC', 'P', None, 8, 8, [], cast_flags=0x20, functions={'F': f})
        self.assertEqual(json.dumps(cr.to_json(), separators=(',', ':')),
                          '{"kind":"class","path":"P.C","name":"C","cpp_name":"UC","package":"P","super":null,'
                          '"size":"0x8","min_alignment":8,"cast_flags":"0x0000000000000020","cdo":null,'
                          '"interfaces":[],"properties":[],"functions":{"F":{"flags":"0x00000400",'
                          '"params_size":"0x4","return":null,"params":[],"exec_rva":"0x1234"}}}')

    def test_stray_field(self):
        with self.assertRaises(ValueError):
            model.PropType('IntProperty', 'IntProperty', enum='Stray')

    def test_from_json_edges(self):
        with self.assertRaises(ValueError):
            model.PropType.from_json({'prop': 'IntProperty', 'kind': 'Bogus'})
        with self.assertRaises(ValueError):
            model.PropType.from_json({'prop': 'BoolProperty', 'byte_offset': True})
        self.assertEqual(model.PropType.from_json({'prop': 'IntProperty', 'unknown': True}).kind, 'unknown')

    def test_function_keyword_precedence(self):
        data = {'path': 'X', 'name': 'Y', 'package': 'Z', 'flags': '0x0', 'params_size': '0x0',
                'params': [], 'exec_rva': None}
        f = model.FunctionRecord.from_json(data, path='A', name='B', package='C')
        self.assertEqual((f.path, f.name, f.package), ('A', 'B', 'C'))

    def test_return_param_first_return(self):
        parm = model.PropertyRecord('In', 0, 4, 1, int(EPropertyFlags.Parm),
                                     model.PropType('IntProperty', 'IntProperty'))
        r1 = model.PropertyRecord('ReturnValue', 4, 4, 1, int(EPropertyFlags.Parm | EPropertyFlags.ReturnParm),
                                   model.PropType('IntProperty', 'IntProperty'))
        r2 = model.PropertyRecord('R2', 8, 4, 1, int(EPropertyFlags.ReturnParm),
                                   model.PropType('IntProperty', 'IntProperty'))
        func = model.FunctionRecord('p', 'n', 'k', 0, 12, [parm, r1, r2], None)
        self.assertIs(func.return_param, r1)

    def test_enum_record_validation(self):
        with self.assertRaises(ValueError):
            model.EnumRecord('p', 'n', 'c', 'k', 1, 'guess', None, [])
        with self.assertRaises(ValueError):
            model.EnumRecord.from_json({
                'kind': 'enum', 'path': 'p', 'name': 'n', 'cpp_name': 'c', 'package': 'k',
                'underlying_size': 1, 'underlying_size_from': 'reflection', 'underlying_signed': None,
                'values': [['A', True]],
            })

    def test_row_8_elements(self):
        with self.assertRaises(ValueError):
            model.ObjectRecord.from_row([1, '0x1', '0x0', -1, -1, 'x', '0x1', 'extra'])


def _make_main_table() -> model.ObjectTable:
    records = [
        model.ObjectRecord(0, 0x1000, 0, 3, -1, '/Script/CoreUObject'),
        model.ObjectRecord(1, 0x1010, 0, 2, 0, 'Object'),
        model.ObjectRecord(2, 0x1020, 0, -1, 0, 'Class'),
        model.ObjectRecord(3, 0x1030, 0, 2, 0, 'Package'),
        model.ObjectRecord(4, 0x1040, 0, 3, -1, '/Game/Maps/L_Expanse'),
        model.ObjectRecord(5, 0x1050, 0, -1, 4, 'L_Expanse'),
        model.ObjectRecord(6, 0x1060, 0, -1, 5, 'PersistentLevel'),
        model.ObjectRecord(7, 0x1070, 0, 8, 6, 'B_Hero_C_2147482077'),
        model.ObjectRecord(8, 0x1080, 0, -1, -1, 'BP_Hero_C'),
    ]
    return model.ObjectTable(records)


class ObjectTableTests(unittest.TestCase):
    def test_paths(self):
        t = _make_main_table()
        self.assertEqual(t.path(7), '/Game/Maps/L_Expanse.L_Expanse:PersistentLevel.B_Hero_C_2147482077')
        self.assertEqual(t.path(1), '/Script/CoreUObject.Object')

    def test_full_name(self):
        t = _make_main_table()
        self.assertEqual(t.full_name(7), 'BP_Hero_C L_Expanse.L_Expanse.PersistentLevel.B_Hero_C_2147482077')
        self.assertEqual(t.full_name(6), 'None L_Expanse.L_Expanse.PersistentLevel')
        self.assertEqual(t.full_name(0), 'Package CoreUObject')
        self.assertEqual(t.full_name(4), 'Package L_Expanse')
        t2 = model.ObjectTable([
            model.ObjectRecord(0, 0, 0, -1, 1, 'A'),
            model.ObjectRecord(1, 1, 0, -1, 0, 'B'),
        ])
        with self.assertRaises(ValueError):
            t2.full_name(0)

    def test_full_name_class_short_name(self):
        # The class part uses short_name (strip_path), like the object part, not the raw name.
        t = model.ObjectTable([
            model.ObjectRecord(0, 0x10, 0, 1, -1, '/Script/Engine.Actor'),
            model.ObjectRecord(1, 0x20, 0, 0, -1, 'MyActor'),
        ])
        self.assertEqual(t.full_name(1), 'Engine.Actor MyActor')

    def test_package_rules(self):
        R = model.ObjectRecord
        t = model.ObjectTable([
            R(0, 0x10, 0, 3, -1, '/Script/CoreUObject'),
            R(2, 0x20, 0, -1, 0, 'Class'),
            R(1, 0x18, 0, 2, 9, 'Package'),  # decoy: lower index, not outered to CoreUObject
            R(3, 0x30, 0, 2, 0, 'Package'),
            R(4, 0x40, 0, 3, -1, '/Game/A'),
            R(5, 0x50, 0, 3, 4, 'Sub'),
            R(6, 0x60, 0, -1, 5, 'Leaf'),
            R(7, 0x70, 0, -1, -1, 'Loose'),
            R(8, 0x80, 0, -1, 7, 'Kid'),
            R(9, 0x90, 0, -1, 8, 'Grand'),
        ])
        self.assertEqual(t.path(6), '/Game/A.Sub.Leaf')
        self.assertEqual(t.path(8), 'Loose.Kid')
        self.assertEqual(t.path(9), 'Loose.Kid.Grand')
        self.assertFalse(t.is_package(7))
        self.assertTrue(t.is_package(5))

    def test_table_api(self):
        R = model.ObjectRecord
        t = model.ObjectTable([R(5, 0x10, 0, -1, -1, 'P'), R(3, 0x10, 0, -1, -1, 'P'), R(4, 0x20, 0, -1, -1, 'Q')])
        self.assertEqual(t.by_address(0x10).index, 3)
        self.assertIsNone(t.by_address(0x99))
        self.assertEqual([r.index for r in t], [3, 4, 5])
        self.assertEqual(len(t), 3)
        self.assertEqual(t.index_of_path('P'), 3)
        with self.assertRaises(TypeError):
            t.get('x')
        with self.assertRaises(KeyError) as cm:
            t.path(99)
        self.assertEqual(cm.exception.args, (99,))

    def test_chain_boundary(self):
        def make(hops):
            recs = [model.ObjectRecord(i, 0x9000 + i, 0, -1, i + 1, f'N{i}') for i in range(hops)]
            recs.append(model.ObjectRecord(hops, 0x9000 + hops, 0, -1, -1, 'Top'))
            return model.ObjectTable(recs)
        self.assertEqual(make(255).package_of(0), 255)
        self.assertEqual(make(256).package_of(0), 256)
        with self.assertRaises(ValueError):
            make(257).package_of(0)

    def test_negative_index(self):
        with self.assertRaises(ValueError):
            model.ObjectTable([model.ObjectRecord(-1, 0x10, 0, -1, -1, 'Neg')])

    def test_fallbacks(self):
        t = _make_main_table()
        self.assertEqual(t.package_of(7), 4)
        t2 = model.ObjectTable([
            model.ObjectRecord(0, 0x2000, 0, -1, -1, 'Root'),
            model.ObjectRecord(1, 0x2010, 0, -1, 0, 'Child'),
        ])
        self.assertTrue(t2.is_package(0))
        self.assertFalse(t2.is_package(1))

    def test_absent_index(self):
        t = _make_main_table()
        for method in (t.path, t.full_name, t.package_of, t.class_of):
            with self.assertRaises(KeyError, msg=method):
                method(999)
        self.assertIsNone(t.get(999))
        with self.assertRaises(TypeError):
            t.path('x')
        self.assertNotIn(999, t)
        self.assertNotIn('x', t)
        with self.assertRaises(TypeError):
            t.index_of_path(3)

    def test_cycles(self):
        chain_records = [model.ObjectRecord(200 + i, 0x3000 + i, 0, -1, 200 + i + 1, f'N{i}') for i in range(299)]
        chain_records.append(model.ObjectRecord(499, 0x3000 + 299, 0, -1, -1, 'N299'))
        records = [
            model.ObjectRecord(100, 0x4000, 0, -1, 101, 'A'),
            model.ObjectRecord(101, 0x4010, 0, -1, 100, 'B'),
            model.ObjectRecord(102, 0x4020, 0, -1, -1, 'Normal'),
            *chain_records,
        ]
        t = model.ObjectTable(records)
        with self.assertRaises(ValueError):
            t.path(100)
        with self.assertRaises(ValueError):
            t.package_of(200)
        self.assertEqual(t.index_of_path('Normal'), 102)
        self.assertIsNone(t.index_of_path('does-not-exist'))

    def test_rows(self):
        rec = model.ObjectRecord(1, 0x1000, 0x2A, 2, -1, 'Foo')
        row6 = rec.to_row()
        self.assertEqual(row6, [1, '0x1000', '0x0000002A', 2, -1, 'Foo'])
        self.assertEqual(model.ObjectRecord.from_row(row6), rec)

        rec2 = model.ObjectRecord(1, 0x1000, 0x2A, 2, -1, 'Foo', vtable_rva=0x50)
        row7 = rec2.to_row()
        self.assertEqual(row7, [1, '0x1000', '0x0000002A', 2, -1, 'Foo', '0x50'])
        self.assertEqual(model.ObjectRecord.from_row(row7), rec2)

        with self.assertRaises(ValueError):
            model.ObjectRecord.from_row([1, '0x1000', '0x0000002A', 2, -1])
        with self.assertRaises(ValueError):
            model.ObjectRecord.from_row([1, 'nothex', '0x0000002A', 2, -1, 'Foo'])
        with self.assertRaises(ValueError):
            model.ObjectRecord.from_row('not-a-list')
        with self.assertRaises(ValueError):
            model.ObjectTable([rec, rec])
        with self.assertRaises(TypeError):
            model.ObjectTable([rec, object()])


if __name__ == '__main__':
    unittest.main()
