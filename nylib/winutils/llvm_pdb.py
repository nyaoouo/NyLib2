import enum
import json
import logging
import subprocess

import pathlib
import pickle
from inspect import isclass
from ..utils import yaml2json


class SimpleType:
    kind = 'SIMPLE_TYPE'

    def __init__(self, name, size=0, signed=False, ctypes_type=None):
        self.name = name
        self.size = size
        self.signed = signed
        self.ctypes_type = ctypes_type

    def __repr__(self):
        return f"<{self.kind} name={self.name}>"


simple_type_map = {
    # https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/DebugInfo/CodeView/TypeIndex.h
    0x0003: SimpleType('void', ctypes_type='c_void_p'),
    0x0007: SimpleType('type not translated by cvpack'),
    0x0008: SimpleType('OLE/COM HRESULT', ctypes_type='c_int'),

    0x0010: SimpleType('8 bit signed', size=8, signed=True, ctypes_type='c_int8'),
    0x0020: SimpleType('8 bit unsigned', size=8, signed=False, ctypes_type='c_uint8'),
    0x0070: SimpleType('really a char', size=8, signed=True, ctypes_type='c_char'),
    0x0071: SimpleType('wide char', size=16, signed=False, ctypes_type='c_wchar'),
    0x007a: SimpleType('char16_t', size=16, signed=False, ctypes_type='c_uint16'),
    0x007b: SimpleType('char32_t', size=32, signed=False, ctypes_type='c_uint32'),
    0x007c: SimpleType('char8_t', size=8, signed=False, ctypes_type='c_char'),

    0x0068: SimpleType('8 bit signed int', size=8, signed=True, ctypes_type='c_int8'),
    0x0069: SimpleType('8 bit unsigned int', size=8, signed=False, ctypes_type='c_uint8'),
    0x0011: SimpleType('16 bit signed', size=16, signed=True, ctypes_type='c_int16'),
    0x0021: SimpleType('16 bit unsigned', size=16, signed=False, ctypes_type='c_uint16'),
    0x0072: SimpleType('16 bit signed int', size=16, signed=True, ctypes_type='c_int16'),
    0x0073: SimpleType('16 bit unsigned int', size=16, signed=False, ctypes_type='c_uint16'),
    0x0012: SimpleType('32 bit signed', size=32, signed=True, ctypes_type='c_int32'),
    0x0022: SimpleType('32 bit unsigned', size=32, signed=False, ctypes_type='c_uint32'),
    0x0074: SimpleType('32 bit signed int', size=32, signed=True, ctypes_type='c_int32'),
    0x0075: SimpleType('32 bit unsigned int', size=32, signed=False, ctypes_type='c_uint32'),
    0x0013: SimpleType('64 bit signed', size=64, signed=True, ctypes_type='c_int64'),
    0x0023: SimpleType('64 bit unsigned', size=64, signed=False, ctypes_type='c_uint64'),
    0x0076: SimpleType('64 bit signed int', size=64, signed=True, ctypes_type='c_int64'),
    0x0077: SimpleType('64 bit unsigned int', size=64, signed=False, ctypes_type='c_uint64'),
    0x0014: SimpleType('128 bit signed int', size=128, signed=True, ctypes_type='c_int64'),
    0x0024: SimpleType('128 bit unsigned int', size=128, signed=False, ctypes_type='c_uint64*2'),
    0x0078: SimpleType('128 bit signed int', size=128, signed=True, ctypes_type='c_uint64*2'),
    0x0079: SimpleType('128 bit unsigned int', size=128, signed=False, ctypes_type='c_uint64*2'),

    0x0046: SimpleType('16 bit float', size=16, signed=True, ctypes_type='c_int16'),
    0x0040: SimpleType('32 bit float', size=32, signed=True, ctypes_type='c_float'),
    0x0045: SimpleType('32 bit PP float', size=32, signed=True, ctypes_type='c_float'),
    0x0044: SimpleType('48 bit float', size=48, signed=True),
    0x0041: SimpleType('64 bit float', size=64, signed=True, ctypes_type='c_double'),
    0x0042: SimpleType('80 bit float', size=80, signed=True),
    0x0043: SimpleType('128 bit float', size=128, signed=True),

    0x0056: SimpleType('16 bit complex', size=16, signed=True),
    0x0050: SimpleType('32 bit complex', size=32, signed=True),
    0x0055: SimpleType('32 bit PP complex', size=32, signed=True),
    0x0054: SimpleType('48 bit complex', size=48, signed=True),
    0x0051: SimpleType('64 bit complex', size=64, signed=True),
    0x0052: SimpleType('80 bit complex', size=80, signed=True),
    0x0053: SimpleType('128 bit complex', size=128, signed=True),

    0x0030: SimpleType('8 bit boolean', size=8, signed=True, ctypes_type='c_int8'),
    0x0031: SimpleType('16 bit boolean', size=16, signed=True, ctypes_type='c_int16'),
    0x0032: SimpleType('32 bit boolean', size=32, signed=True, ctypes_type='c_int32'),
    0x0033: SimpleType('64 bit boolean', size=64, signed=True, ctypes_type='c_int64'),
    0x0034: SimpleType('128 bit boolean', size=128, signed=True, ctypes_type='c_int64*2'),
}


class DataKind:
    kind = 'unnamed'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        self.tpi_stream = tpi_stream

    def __repr__(self):
        return f'<{self.kind}>'


class FieldList(DataKind):
    kind = 'LF_FIELDLIST'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        _raw = raw['FieldList']
        self.fields = [self.tpi_stream.parse_data(_f) for _f in _raw]

    def __len__(self):
        return len(self.fields)

    def __getitem__(self, item):
        return self.fields[item]

    def __iter__(self):
        return iter(self.fields)

    def __repr__(self):
        return f'<{self.kind} size={len(self)}>'


class Enumerator(DataKind):
    kind = 'LF_ENUMERATE'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        _raw = raw['Enumerator']
        self.attrs = _raw['Attrs']
        self.value = _raw['Value']
        self.name = _raw['Name']

    def __repr__(self):
        return f'<{self.kind} name={self.name} value={self.value}>'


class Enum(DataKind):
    kind = 'LF_ENUM'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        _raw = raw['Enum']
        self.num_enumerators = _raw['NumEnumerators']
        self.options = _raw['Options']
        self._field_list = _raw['FieldList']
        self.name = _raw['Name']
        self.unique_name = _raw['UniqueName']
        self._underlying_type = _raw['UnderlyingType']

    field_list = property(lambda self: self.tpi_stream[self._field_list])
    underlying_type = property(lambda self: self.tpi_stream[self._underlying_type])

    def __repr__(self):
        return f'<{self.kind} name={self.name} underlying_type={self.underlying_type}>'


class ListContinuation(DataKind):
    kind = 'LF_INDEX'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        _raw = raw['ListContinuation']
        self.continuation_index = _raw['ContinuationIndex']

    def __repr__(self):
        return f'{self.kind}({self.continuation_index})'


class Modifier(DataKind):
    kind = 'LF_MODIFIER'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        _raw = raw['Modifier']
        self._modified_type = _raw['ModifiedType']
        self.modifiers = _raw['Modifiers']

    modified_type = property(lambda self: self.tpi_stream[self._modified_type])

    def __repr__(self):
        return f'<{self.kind} modifiers={self.modifiers} modified_type={self.modified_type}>'


class Array(DataKind):
    kind = 'LF_ARRAY'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        _raw = raw['Array']
        self._element_type = _raw['ElementType']
        self.index_type = _raw['IndexType']
        self.size = _raw['Size']
        self.name = _raw['Name']

    element_type = property(lambda self: self.tpi_stream[self._element_type])

    def __repr__(self):
        return f'<{self.kind} name={self.name} element_type={self.element_type} size={self.size}>'


class Structure(DataKind):
    kind = 'LF_STRUCTURE'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        _raw = raw['Class']
        self.member_count = _raw['MemberCount']
        self.options = _raw['Options']
        self._field_list = _raw['FieldList']
        self.name = _raw['Name']
        self.unique_name = _raw['UniqueName']
        self._derivation_list = _raw['DerivationList']
        self._vtable_shape = _raw['VTableShape']
        self.size = _raw['Size']

    field_list = property(lambda self: self.tpi_stream[self._field_list])
    derivation_list = property(lambda self: self.tpi_stream[self._derivation_list])
    vtable_shape = property(lambda self: self.tpi_stream[self._vtable_shape])

    def __repr__(self):
        return f'<{self.kind} name={self.name} size={self.size} member_count={self.member_count}>'


class Pointer(DataKind):
    # https://llvm.org/docs/PDB/CodeViewTypes.html#lf-pointer-0x1002
    kind = 'LF_POINTER'

    class Attribute:
        class Kind(enum.IntEnum):
            Near16 = 0x00
            Far16 = 0x01
            Huge16 = 0x02
            BasedOnSegment = 0x03
            BasedOnValue = 0x04
            BasedOnSegmentValue = 0x05
            BasedOnAddress = 0x06
            BasedOnSegmentAddress = 0x07
            BasedOnType = 0x08
            BasedOnSelf = 0x09
            Near32 = 0x0a
            Far32 = 0x0b
            Near64 = 0x0c

        class Mode(enum.IntEnum):
            Pointer = 0x00
            LValueReference = 0x01
            PointerToDataMember = 0x02
            PointerToMemberFunction = 0x03
            RValueReference = 0x04

        class Modifiers(enum.IntFlag):
            Flat32 = 0x01
            Volatile = 0x02
            Const = 0x04
            Unaligned = 0x08
            Restrict = 0x10

        class Flags(enum.IntFlag):
            WinRTSmartPointer = 0x01
            LValueRefThisPointer = 0x02
            RValueRefThisPointer = 0x04

        def __init__(self, val):
            self.val = val

        kind = property(lambda self: self.Kind(self.val & 0b11111))
        mode = property(lambda self: self.Mode((self.val >> 5) & 0b111))
        modifiers = property(lambda self: self.Modifiers((self.val >> 8) & 0b11111))
        flags = property(lambda self: self.Flags((self.val >> 13) & 0b111))

        def __repr__(self):
            return f'<Pointer.Attribute kind={self.kind} mode={self.mode} modifiers={self.modifiers} flags={self.flags}>'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        _raw = raw['Pointer']
        self._referent_type = _raw['ReferentType']
        self.attr = self.Attribute(_raw['Attrs'])

    referent_type = property(lambda self: self.tpi_stream[self._referent_type])

    def __repr__(self):
        return f'<{self.kind} referent_type={self.referent_type} attr={self.attr}>'


class DataMember(DataKind):
    kind = 'LF_MEMBER'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        _raw = raw['DataMember']
        self.attrs = _raw['Attrs']
        self._type = _raw['Type']
        self.field_offset = _raw['FieldOffset']
        self.name = _raw['Name']

    type = property(lambda self: self.tpi_stream[self._type])

    def __repr__(self):
        return f'<{self.kind} name={self.name} type={self.type} field_offset={self.field_offset}>'


class Class(Structure):
    kind = 'LF_CLASS'


class ArgList(DataKind):
    kind = 'LF_ARGLIST'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        _raw = raw['ArgList']
        self._arg_indices = [_raw['ArgIndices'][i] for i in range(len(_raw['ArgIndices']))]

    arg_indices = property(lambda self: map(self.tpi_stream.__getitem__, self._arg_indices))


class MemberFunction(DataKind):
    kind = 'LF_MFUNCTION'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        _raw = raw['MemberFunction']
        self._return_type = _raw['ReturnType']
        self._class_type = _raw['ClassType']
        self._this_type = _raw['ThisType']
        self.call_conv = _raw['CallConv']
        self.options = _raw['Options']
        self.parameter_count = _raw['ParameterCount']
        self._argument_list = _raw['ArgumentList']
        self.this_pointer_adjustment = _raw['ThisPointerAdjustment']

    return_type = property(lambda self: self.tpi_stream[self._return_type])
    class_type = property(lambda self: self.tpi_stream[self._class_type])
    this_type = property(lambda self: self.tpi_stream[self._this_type])
    argument_list = property(lambda self: self.tpi_stream[self._argument_list])


class _MethodOverload:
    def __init__(self, tpi_stream: 'TpiStream', raw):
        self.tpi_stream = tpi_stream
        self._type = raw['Type']
        self.attrs = raw['Attrs']
        self.vf_table_offset = raw['VFTableOffset']
        self.name = raw['Name']

    type = property(lambda self: self.tpi_stream[self._type])

    def __repr__(self):
        return f'<MethodOverload name={self.name} type={self.type}>'


class MethodList(DataKind):
    kind = 'LF_METHODLIST'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        self.methods = [
            _MethodOverload(tpi_stream, r) for r in raw['MethodOverloadList']['Methods']
        ]

    def __len__(self):
        return len(self.methods)

    def __getitem__(self, index):
        return self.methods[index]

    def __iter__(self):
        return iter(self.methods)

    def __repr__(self):
        return f'<{self.kind} size={len(self)}>'


class Method(DataKind):
    kind = 'LF_METHOD'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        _raw = raw['OverloadedMethod']
        self.num_overloads = _raw['NumOverloads']
        self._method_list = _raw['MethodList']
        self.name = _raw['Name']

    method_list = property(lambda self: self.tpi_stream[self._method_list])

    def __repr__(self):
        return f'<{self.kind} name={self.name} num_overloads={self.num_overloads}>'


class OneMethod(DataKind):
    kind = 'LF_ONEMETHOD'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        _raw = raw['OneMethod']
        self._type = _raw['Type']
        self.attrs = _raw['Attrs']
        self.vf_table_offset = _raw['VFTableOffset']
        self.name = _raw['Name']

    type = property(lambda self: self.tpi_stream[self._type])

    def __repr__(self):
        return f'<{self.kind} name={self.name} type={self.type} vf_table_offset={self.vf_table_offset}>'


class NestType(DataKind):
    kind = 'LF_NESTTYPE'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        _raw = raw['NestedType']
        self._type = _raw['Type']
        self.name = _raw['Name']

    type = property(lambda self: self.tpi_stream[self._type])

    def __repr__(self):
        return f'<{self.kind} name={self.name} type={self.type}>'


class StMember(DataKind):
    kind = 'LF_STMEMBER'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        _raw = raw['StaticDataMember']
        self._type = _raw['Type']
        self.name = _raw['Name']
        self.attrs = _raw['Attrs']

    type = property(lambda self: self.tpi_stream[self._type])

    def __repr__(self):
        return f'<{self.kind} name={self.name} type={self.type}>'


class Procedure(DataKind):
    kind = 'LF_PROCEDURE'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        _raw = raw['Procedure']
        self._return_type = _raw['ReturnType']
        self.call_conv = _raw['CallConv']
        self.options = _raw['Options']
        self.parameter_count = _raw['ParameterCount']
        self.argument_list = _raw['ArgumentList']

    return_type = property(lambda self: self.tpi_stream[self._return_type])


class BClass(DataKind):
    kind = 'LF_BCLASS'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        _raw = raw['BaseClass']
        self._type = _raw['Type']
        self.offset = _raw['Offset']
        self.attrs = _raw['Attrs']

    type = property(lambda self: self.tpi_stream[self._type])

    def __repr__(self):
        return f'<{self.kind} type={self.type} offset={self.offset}>'


class Union(DataKind):
    kind = 'LF_UNION'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        _raw = raw['Union']
        self.member_count = _raw['MemberCount']
        self.options = _raw['Options']
        self._field_list = _raw['FieldList']
        self.name = _raw['Name']
        self.unique_name = _raw['UniqueName']
        self.size = _raw['Size']

    field_list = property(lambda self: self.tpi_stream[self._field_list])

    def __repr__(self):
        return f'<{self.kind} name={self.name} size={self.size} member_count={self.member_count}>'


class VFTableShape(DataKind):
    kind = 'LF_VTSHAPE'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        _raw = raw['VFTableShape']
        self.slots = _raw['Slots']

    def __repr__(self):
        return f'<{self.kind} slots={self.slots}>'


class BitField(DataKind):
    kind = 'LF_BITFIELD'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        _raw = raw['BitField']
        self._type = _raw['Type']
        self.bit_size = _raw['BitSize']
        self.bit_offset = _raw['BitOffset']

    type = property(lambda self: self.tpi_stream[self._type])

    def __repr__(self):
        return f'<{self.kind} type={self.type} bit_size={self.bit_size} bit_offset={self.bit_offset}>'


class VFPointer(DataKind):
    kind = 'LF_VFUNCTAB'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        self._type = raw['VFPtr']['Type']

    type = property(lambda self: self.tpi_stream[self._type])

    def __repr__(self):
        return f'<{self.kind} type={self.type}>'


class VBClass(DataKind):
    kind = 'LF_VBCLASS'

    def __init__(self, tpi_stream: 'TpiStream', raw):
        super().__init__(tpi_stream, raw)
        _raw = raw['VirtualBaseClass']
        self.attrs = _raw['Attrs']
        self._base_type = _raw['BaseType']
        self._vb_ptr_type = _raw['VBPtrType']
        self.vb_ptr_offset = _raw['VBPtrOffset']
        self.v_table_index = _raw['VTableIndex']

    base_type = property(lambda self: self.tpi_stream[self._base_type])
    vb_ptr_type = property(lambda self: self.tpi_stream[self._vb_ptr_type])

    def __repr__(self):
        return f'<{self.kind} base_type={self.base_type} vb_ptr_type={self.vb_ptr_type} vb_ptr_offset={self.vb_ptr_offset} v_table_index={self.v_table_index}>'


class IVBClass(VBClass):
    kind = 'LF_IVBCLASS'


kind_map = {v.kind: v for k, v in globals().items() if isclass(v) and issubclass(v, DataKind) and v != DataKind}

unimplemented_kinds = set()


class SuperBlock:
    def __init__(self, raw):
        self.block_size = raw['BlockSize']
        self.free_block_map = raw['FreeBlockMap']
        self.num_blocks = raw['NumBlocks']
        self.num_directory_bytes = raw['NumDirectoryBytes']


class TpiStream:
    def __init__(self, pdb_data, raw):
        self.pdb_data = pdb_data
        self.super_block = pdb_data.super_block
        self.records = [self.parse_data(r) for r in raw['Records']]
        self.unique_name_map = {}
        self.name_map = {}

        self.build_unique_name_map()
        self.build_name_map()

    def build_unique_name_map(self):
        self.unique_name_map = {}
        for record in self.records:
            if not hasattr(record, 'options'): continue
            if 'HasUniqueName' in record.options and 'ForwardReference' not in record.options:
                self.unique_name_map[record.unique_name] = record

    def build_name_map(self):
        self.name_map = {}
        for record in self.records:
            if hasattr(record, 'name') and (not hasattr(record, 'options') or 'ForwardReference' not in record.options):
                self.name_map.setdefault(record.name, []).append(record)
        for k in self.name_map.keys():
            if len(self.name_map[k]) == 1:
                self.name_map[k] = self.name_map[k][0]

    def get_forward_record(self, record):
        if hasattr(record, 'options') and 'ForwardReference' in record.options:
            return self.unique_name_map.get(record.unique_name, record)
        return record

    def parse_data(self, raw):
        try:
            k = kind_map[raw['Kind']]
        except KeyError:
            if raw['Kind'] not in unimplemented_kinds:
                print('Unimplemented kind: {}'.format(raw['Kind']))
                unimplemented_kinds.add(raw['Kind'])
            return None
        return k(self, raw)

    def __getitem__(self, item):
        if isinstance(item, str):
            return self.name_map[item]
        elif isinstance(item, int):
            if not item:
                return None
            if item < self.super_block.block_size:
                if item & 0x600:
                    return Pointer(self, {
                        'Pointer': {
                            'ReferentType': item & 0xff,
                            'Attrs': 0,
                        }
                    })
                return simple_type_map.get(item, item)
            return self.get_forward_record(
                self.records[item - self.super_block.block_size]
            )

        return None


class PublicSymbol:
    def __init__(self, public_stream, raw):
        self.public_stream = public_stream
        assert raw['Kind'] == 'S_PUB32'
        _raw = raw['PublicSym32']
        self.name = _raw['Name']
        self.offset = _raw['Offset']
        self.segment = _raw['Segment']
        self.flags = _raw['Flags']


class PublicStream:
    def __init__(self, pdb_data, raw):
        self.pdb_data = pdb_data
        self.records = [PublicSymbol(self, r) for r in raw['Records']]
        self.name_map = {r.name: r for r in self.records if r.name}


class PdbData:
    def __init__(self, raw, cache_path=None):
        self.cache_path = cache_path
        self.super_block = SuperBlock(raw['MSF']['SuperBlock'])
        self.tpi_stream = TpiStream(self, raw['TpiStream'])
        self.public_stream = PublicStream(self, raw['PublicsStream'])

    def save(self, path):
        with open(path, 'wb') as f:
            pickle.dump(self, f)

    @classmethod
    def load(cls, path) -> 'TpiStream':
        with open(path, 'rb') as f:
            return pickle.load(f)


def get_pdb_data(
        cache_path: pathlib.Path, llvm_pdbutil_exe_path: pathlib.Path, pdb_path: pathlib.Path,
        new_pkl=False, new_json=False, new_yaml=False, log=False
):
    logger = logging.getLogger('get_pdb_data') if log else None
    # load pdb data
    pkl_file = cache_path / 'pdb_data.pkl'
    if logger: logger.debug(f'Loading {pkl_file}...')
    if not pkl_file.exists() or new_pkl:
        # load json data
        json_file = cache_path / 'pdb_data.json'
        if logger: logger.debug(f'creating pkl, loading json data from {json_file}...')
        if not json_file.exists() or new_json:
            # load yaml data
            yaml_file = cache_path / 'pdb_data.yaml'
            if logger: logger.debug(f'creating json, loading yaml data from {yaml_file}...')
            if not yaml_file.exists() or new_yaml:
                # create yaml data
                if logger: logger.debug(f'creating yaml data...')
                cache_path.mkdir(parents=True, exist_ok=True)
                with open(yaml_file, 'w') as f:
                    subprocess.run([
                        llvm_pdbutil_exe_path,
                        'pdb2yaml', '-tpi-stream', '-publics-stream',
                        pdb_path,
                    ], stdout=f)
            yaml2json.parse(yaml_file, json_file, log=log)
        if logger: logger.debug(f'loading json...')
        with open(json_file, 'r') as f:
            data = json.load(f)

        # create pdb data
        pdb_data = PdbData(data, cache_path)

        # save pdb data
        if logger: logger.debug(f'writing pkl...')
        with open(pkl_file, 'wb') as f:
            pickle.dump(pdb_data, f)
    else:
        if logger: logger.debug(f'loading pkl...')
        with open(pkl_file, 'rb') as f:
            pdb_data = pickle.load(f)
    return pdb_data
