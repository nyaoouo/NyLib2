import json
import os
import pathlib
import struct
import tempfile
import unittest

from nylib.ue.tests.oracle import (
    GObjectsDump,
    compare_gobjects, compare_idmap, compare_offsets,
    flatten_oracle_offsets,
    parse_basic_offsets, parse_gobjects_dump, parse_idmap,
    parse_offsets_info, parse_predefined_members,
)

R0_ORACLE = os.environ.get('NYLIB_UE_R0_ORACLE')


def _gobjects_text(line1, count, rows, *, stem=None, props=None):
    """Build a Dumper-7-shaped GObjects dump; stem=None -> 5-line header (Dumper-7's own)."""
    header = line1 + '\r\n\r\n'
    if stem is not None:
        header += stem + '\r\n\r\n'
    header += f'Count: {count}\r\n\r\n\r\n'
    body = []
    for index, address, name in rows:
        body.append(f'[{index:08X}] {{{address:#x}}} {name}')
        for offset, paddr, prop, pname in (props or {}).get(index, ()):
            body.append(f'[{offset:08X}] {{{paddr:#x}}}     {prop} {pname}')
    return (header + '\r\n'.join(body) + ('\r\n' if body else '')).encode('utf-8')


class ParserTests(unittest.TestCase):
    def test_gobjects_seven_line_header(self):
        rows = [(0, 0x1000, 'Package Core'), (1, 0x1008, 'Class Core.Object')]
        data = _gobjects_text('Object dump by nylib.ue (Dumper-7 format)', 2, rows, stem='TestStem')
        d = parse_gobjects_dump(data)
        self.assertEqual(d.line1, 'Object dump by nylib.ue (Dumper-7 format)')
        self.assertEqual(d.stem, 'TestStem')
        self.assertEqual(d.count, 2)
        self.assertEqual(d.rows, rows)
        self.assertEqual(d.props, {})

    def test_gobjects_dumper7_five_line_header(self):
        rows = [(0, 0x1000, 'Package Core')]
        data = _gobjects_text('Object dump by Dumper-7', 1, rows, stem=None)
        d = parse_gobjects_dump(data)
        self.assertEqual(d.stem, '')
        self.assertEqual(d.count, 1)
        self.assertEqual(d.rows, rows)

    def test_gobjects_any_nonempty_line1_accepted(self):
        rows = [(0, 0x1000, 'Package Core')]
        for line1 in ('Object dump by Dumper-7', 'Object dump by nylib.ue (Dumper-7 format)', 'x'):
            data = _gobjects_text(line1, 1, rows, stem=None)
            self.assertEqual(parse_gobjects_dump(data).line1, line1)

    def test_gobjects_with_properties(self):
        rows = [(0, 0x1000, 'Class Core.Object'), (1, 0x1008, 'Class Core.Actor')]
        props = {0: [(0x0, 0x2000, 'IntProperty', 'Count')], 1: [(0x8, 0x2010, 'StrProperty', 'Name Field')]}
        data = _gobjects_text('Object dump by nylib.ue (Dumper-7 format)', 2, rows, stem='S', props=props)
        d = parse_gobjects_dump(data, with_properties=True)
        self.assertEqual(d.rows, rows)
        self.assertEqual(d.props, props)

    def test_gobjects_bare_lf_rejected(self):
        data = _gobjects_text('L1', 1, [(0, 0x1000, 'Package Co\nre')], stem=None)
        with self.assertRaises(ValueError):
            parse_gobjects_dump(data)

    def test_gobjects_bare_lf_in_header_rejected(self):
        # a bare LF inside line1 itself is not caught by the object-row regex fallback,
        # so this isolates the dedicated bare-LF scan from that coincidental protection.
        data = _gobjects_text('L1\nmore', 1, [(0, 0x1000, 'Package Core')], stem=None)
        with self.assertRaises(ValueError):
            parse_gobjects_dump(data)

    def test_gobjects_object_row_requires_single_space(self):
        # a five-space property-formatted row, with an offset that collides with no real
        # object index, must never be accepted as an object row when with_properties=False.
        header = 'L1\r\n\r\nCount: 1\r\n\r\n\r\n'
        body = '[00000000] {0x1000} Class Core.Object\r\n[00000099] {0x2000}     IntProperty Count\r\n'
        with self.assertRaises(ValueError):
            parse_gobjects_dump((header + body).encode('utf-8'), with_properties=False)

    def test_gobjects_five_line_header_trailing_lines_must_be_blank(self):
        header = 'L1\r\n\r\nCount: 1\r\nnot blank\r\n\r\n'
        body = '[00000000] {0x1000} Class Core.Object\r\n'
        with self.assertRaises(ValueError):
            parse_gobjects_dump((header + body).encode('utf-8'))

    def test_gobjects_seven_line_header_trailing_lines_must_be_blank(self):
        header = 'L1\r\n\r\nStem\r\n\r\nCount: 1\r\nnot blank\r\n\r\n'
        body = '[00000000] {0x1000} Class Core.Object\r\n'
        with self.assertRaises(ValueError):
            parse_gobjects_dump((header + body).encode('utf-8'))

    def test_gobjects_missing_final_crlf_rejected(self):
        data = _gobjects_text('L1', 1, [(0, 0x1000, 'Package Core')], stem=None)
        with self.assertRaises(ValueError):
            parse_gobjects_dump(data[:-2])  # strip the trailing CRLF

    def test_gobjects_extra_trailing_blank_line_rejected(self):
        data = _gobjects_text('L1', 1, [(0, 0x1000, 'Package Core')], stem=None)
        with self.assertRaises(ValueError):
            parse_gobjects_dump(data + b'\r\n')

    def test_gobjects_unrecognized_line_names_line_number(self):
        data = _gobjects_text('L1', 1, [(0, 0x1000, 'Package Core')], stem=None)
        data += 'not a valid row\r\n'.encode('utf-8')
        with self.assertRaises(ValueError) as cm:
            parse_gobjects_dump(data)
        self.assertIn('line 7', str(cm.exception))

    def test_gobjects_property_row_without_with_properties_rejected(self):
        rows = [(0, 0x1000, 'Class Core.Object')]
        props = {0: [(0x0, 0x2000, 'IntProperty', 'Count')]}
        data = _gobjects_text('L1', 1, rows, stem=None, props=props)
        with self.assertRaises(ValueError):
            parse_gobjects_dump(data, with_properties=False)

    def test_gobjects_property_row_before_first_object_rejected(self):
        header = 'L1\r\n\r\nCount: 0\r\n\r\n\r\n'
        data = (header + '[00000000] {0x2000}     IntProperty Count\r\n').encode('utf-8')
        with self.assertRaises(ValueError):
            parse_gobjects_dump(data, with_properties=True)

    def test_gobjects_repeated_object_index_rejected(self):
        header = 'L1\r\n\r\nCount: 0\r\n\r\n\r\n'
        body = '[00000000] {0x1000} A\r\n[00000000] {0x1008} B\r\n'
        with self.assertRaises(ValueError):
            parse_gobjects_dump((header + body).encode('utf-8'))

    def test_gobjects_str_is_content_not_path(self):
        with self.assertRaises(ValueError):
            parse_gobjects_dump('C:/definitely/not/a/real/path.txt')

    def test_gobjects_pathlike_is_read(self):
        rows = [(0, 0x1000, 'Package Core')]
        data = _gobjects_text('L1', 1, rows, stem=None)
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / 'dump.txt'
            p.write_bytes(data)
            parsed = parse_gobjects_dump(p)
            self.assertEqual(parsed.rows, rows)

    def test_gobjects_int_raises_type_error(self):
        with self.assertRaises(TypeError):
            parse_gobjects_dump(42)

    def test_gobjects_lowercase_hex_index_rejected(self):
        header = 'L1\r\n\r\nCount: 1\r\n\r\n\r\n'
        body = '[0000001a] {0x1000} Package Core\r\n'  # object index must be uppercase hex
        with self.assertRaises(ValueError):
            parse_gobjects_dump((header + body).encode('utf-8'))

    def test_gobjects_invalid_utf8_rejected(self):
        header = 'L1\r\n\r\nCount: 1\r\n\r\n\r\n'.encode('utf-8')
        body = b'[00000000] {0x1000} Package Co\xffre\r\n'  # \xff is not valid UTF-8
        with self.assertRaises(ValueError):
            parse_gobjects_dump(header + body)

    def test_gobjects_bom_stays_in_line1(self):
        data = b'\xef\xbb\xbf' + _gobjects_text('Object dump by Dumper-7', 1, [(0, 0x1000, 'Package Core')], stem=None)
        d = parse_gobjects_dump(data)
        self.assertEqual(d.line1, '﻿Object dump by Dumper-7')

    def test_gobjects_count_line_trailing_garbage_rejected(self):
        header = 'L1\r\n\r\nStem\r\n\r\nCount: 5 extra\r\n\r\n\r\n'
        body = '[00000000] {0x1000} A\r\n'
        with self.assertRaises(ValueError):
            parse_gobjects_dump((header + body).encode('utf-8'))

    def test_gobjects_property_row_requires_space_between_prop_and_name(self):
        header = 'L1\r\n\r\nCount: 1\r\n\r\n\r\n'
        body = '[00000000] {0x1000} Class Core.Object\r\n[00000000] {0x2000}     IntPropertyNoSpace\r\n'
        with self.assertRaises(ValueError):
            parse_gobjects_dump((header + body).encode('utf-8'), with_properties=True)

    def test_property_rows_not_objects(self):
        rows = [(0, 0x1000, 'Class Core.Object'), (1, 0x1008, 'Class Core.Actor'), (2, 0x1010, 'Class Core.Widget')]
        props = {
            0: [(0x0, 0x2000, 'IntProperty', 'Some Field'), (0x4, 0x2004, 'StrProperty', 'Other Field')],
            2: [(0x0, 0x2010, 'BoolProperty', 'Flag')],
        }
        data = _gobjects_text('L1', 3, rows, stem=None, props=props)
        d = parse_gobjects_dump(data, with_properties=True)
        self.assertEqual(d.rows, rows)
        self.assertEqual(len(d.rows), 3)
        self.assertEqual(sum(len(v) for v in d.props.values()), 3)
        self.assertEqual(d.props, props)

    def test_idmap_roundtrip(self):
        records = [(0x1000, '_ZN7UObject4ExecEv'), (0x2000, 'UActorComponent_VFT'), (0x3000, 'x')]
        raw = b''.join(struct.pack('<IH', rva, len(name.encode())) + name.encode() for rva, name in records)
        self.assertEqual(parse_idmap(raw), records)

    def test_idmap_truncated_last_record_rejected(self):
        raw = struct.pack('<IH', 0x1000, 5) + b'abc'  # declares 5 bytes, only 3 present
        with self.assertRaises(ValueError):
            parse_idmap(raw)

    def test_idmap_truncated_header_rejected(self):
        with self.assertRaises(ValueError):
            parse_idmap(b'\x01\x02\x03')  # fewer than 6 bytes

    def test_idmap_str_raises_type_error(self):
        with self.assertRaises(TypeError):
            parse_idmap('not bytes')

    def test_idmap_invalid_utf8_name_rejected(self):
        raw = struct.pack('<IH', 0x1000, 3) + b'\xff\xfe\xfd'  # not valid UTF-8
        with self.assertRaises(ValueError):
            parse_idmap(raw)

    def test_idmap_pathlike_is_read(self):
        records = [(0x1000, 'name')]
        raw = struct.pack('<IH', 0x1000, 4) + b'name'
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / 'x.idmap'
            p.write_bytes(raw)
            self.assertEqual(parse_idmap(p), records)

    def test_offsets_info_parses_all_pairs(self):
        doc = {'data': [['Dumper', 7], ['OFFSET_GOBJECTS', 100], ['INDEX_PROCESSEVENT', 76]]}
        result = parse_offsets_info(json.dumps(doc))
        self.assertEqual(result, {'Dumper': 7, 'OFFSET_GOBJECTS': 100, 'INDEX_PROCESSEVENT': 76})

    def test_offsets_info_non_list_data_rejected(self):
        with self.assertRaises(ValueError):
            parse_offsets_info(json.dumps({'data': 'not a list'}))

    def test_offsets_info_empty_non_list_data_rejected(self):
        # a non-list 'data' that also happens to iterate to nothing (here: an empty object)
        # must still be rejected; it cannot slip through as an accidentally-empty result.
        with self.assertRaises(ValueError):
            parse_offsets_info(json.dumps({'data': {}}))

    def test_offsets_info_bad_pair_shape_rejected(self):
        with self.assertRaises(ValueError):
            parse_offsets_info(json.dumps({'data': [['A', 1, 2]]}))

    def test_offsets_info_bool_value_rejected(self):
        with self.assertRaises(ValueError):
            parse_offsets_info(json.dumps({'data': [['A', True]]}))

    def test_offsets_info_float_value_rejected(self):
        with self.assertRaises(ValueError):
            parse_offsets_info(json.dumps({'data': [['A', 1.5]]}))

    def test_offsets_info_repeated_name_rejected(self):
        with self.assertRaises(ValueError):
            parse_offsets_info(json.dumps({'data': [['A', 1], ['A', 2]]}))

    def test_basic_offsets_bom_and_crlf(self):
        # the caller decodes the file with utf-8-sig, so the BOM never reaches the parser;
        # this fixture exercises CRLF line endings, which the real Basic.hpp uses throughout.
        text = (
            '#pragma once\r\n'
            'namespace Offsets\r\n{\r\n'
            '\tconstexpr int32 GObjects = 0x094F8910;\r\n'
            '\tconstexpr int32 GNames   = 0x093FDE78;\r\n'
            '}\r\n'
        )
        result = parse_basic_offsets(text)
        self.assertEqual(result, {'GObjects': 0x094F8910, 'GNames': 0x093FDE78})

    def test_basic_offsets_no_block_rejected(self):
        with self.assertRaises(ValueError):
            parse_basic_offsets('no offsets namespace here\r\n')

    def test_basic_offsets_repeated_name_rejected(self):
        text = 'namespace Offsets\r\n{\r\n\tconstexpr int32 X = 0x1;\r\n\tconstexpr int32 X = 0x2;\r\n}\r\n'
        with self.assertRaises(ValueError):
            parse_basic_offsets(text)

    def test_basic_offsets_block_ends_at_unindented_brace_only(self):
        # the block runs to the next line that IS `}`, not one that merely strips to `}`;
        # an indented nested brace must not close the namespace early.
        text = (
            'namespace Offsets\r\n{\r\n'
            '\tconstexpr int32 A = 0x1;\r\n'
            '\t}\r\n'
            '\tconstexpr int32 B = 0x2;\r\n'
            '}\r\n'
        )
        self.assertEqual(parse_basic_offsets(text), {'A': 0x1, 'B': 0x2})

    def test_basic_offsets_block_does_not_scan_past_closing_brace(self):
        # content after the real closing brace (outside the namespace) must not be scanned.
        text = (
            'namespace Offsets\r\n{\r\n'
            '\tconstexpr int32 A = 0x1;\r\n'
            '}\r\n'
            '\tconstexpr int32 Bogus = 0x2;\r\n'
        )
        self.assertEqual(parse_basic_offsets(text), {'A': 0x1})

    def test_predefined_members_initializer_and_static_and_reflected(self):
        text = (
            'struct FName final\r\n'
            '{\r\n'
            'public:\r\n'
            '\tint32 ComparisonIndex = 0x0;                    // 0x0000(0x0004)(NOT AUTO-GENERATED PROPERTY)\r\n'
            '\tstatic constexpr int32 Foo = 1;                 // 0x0008(0x0004)(NOT AUTO-GENERATED PROPERTY)\r\n'
            '\tint32 Reflected;                                 // 0x000C(0x0004)\r\n'
            '};\r\n'
        )
        result = parse_predefined_members(text)
        self.assertEqual(result, {('FName', 'ComparisonIndex'): (0x0, 0x4)})

    def test_predefined_members_super_struct_and_type_dispatch(self):
        text = (
            'class UStruct\r\n'
            '{\r\n'
            'public:\r\n'
            '\tclass UStruct*  SuperStruct;                     // 0x0040(0x0008)(NOT AUTO-GENERATED PROPERTY)\r\n'
            '};\r\n'
            'struct FField final\r\n'
            '{\r\n'
            'public:\r\n'
            '\tclass FField*  Next;                              // 0x0020(0x0008)(NOT AUTO-GENERATED PROPERTY)\r\n'
            '};\r\n'
        )
        result = parse_predefined_members(text)
        self.assertEqual(result, {
            ('UStruct', 'SuperStruct'): (0x40, 0x8),
            ('FField', 'Next'): (0x20, 0x8),
        })

    def test_predefined_members_before_any_header_rejected(self):
        text = 'class FField*     Next;                            // 0x0020(0x0008)(NOT AUTO-GENERATED PROPERTY)\r\n'
        with self.assertRaises(ValueError):
            parse_predefined_members(text)

    def test_predefined_members_repeated_key_rejected(self):
        text = (
            'struct FName\r\n{\r\npublic:\r\n'
            '\tint32 X;  // 0x0000(0x0004)(NOT AUTO-GENERATED PROPERTY)\r\n'
            '\tint32 X;  // 0x0004(0x0004)(NOT AUTO-GENERATED PROPERTY)\r\n'
            '};\r\n'
        )
        with self.assertRaises(ValueError):
            parse_predefined_members(text)

    def test_predefined_members_str_type_required(self):
        with self.assertRaises(TypeError):
            parse_predefined_members(b'not str')

    def test_predefined_members_unparsable_taken_line_rejected(self):
        # ends in the marker, isn't static and isn't array/bitfield-shaped, but the member
        # regex still can't parse it: must raise, never be silently skipped.
        text = (
            'struct FName final\r\n{\r\npublic:\r\n'
            '\tint32 Something;  // not the expected shape (NOT AUTO-GENERATED PROPERTY)\r\n'
            '};\r\n'
        )
        with self.assertRaises(ValueError):
            parse_predefined_members(text)

    def test_predefined_members_gnames_fallback_shapes(self):
        # Dumper-7 emits these only in the GNames-fallback / outline-number Basic.hpp shape
        # (MakeMemberString); array and bitfield members have no single-offset layout and are
        # skipped like `static`, while a normal member alongside them still parses.
        text = (
            'union FStringData final\r\n{\r\npublic:\r\n'
            '\tchar    AnsiName[0x400];   // 0x0000(0x0400)(NOT AUTO-GENERATED PROPERTY)\r\n'
            '\twchar_t WideName[0x400];   // 0x0000(0x0800)(NOT AUTO-GENERATED PROPERTY)\r\n'
            '};\r\n'
            'struct FNameEntryHeader final\r\n{\r\npublic:\r\n'
            '\tuint16  bIsWide : 1;       // 0x0000(0x0002)(NOT AUTO-GENERATED PROPERTY)\r\n'
            '};\r\n'
            'class FNamePool final\r\n{\r\npublic:\r\n'
            '\tuint32  CurrentBlock;      // 0x0008(0x0004)(NOT AUTO-GENERATED PROPERTY)\r\n'
            '\tuint8*  Blocks[0x2000];    // 0x0010(0x10000)(NOT AUTO-GENERATED PROPERTY)\r\n'
            '};\r\n'
        )
        result = parse_predefined_members(text)
        self.assertEqual(result, {('FNamePool', 'CurrentBlock'): (0x8, 0x4)})

    def test_predefined_members_bracketed_marker_skipped(self):
        # "ends in" is literal: a comment that ends in `]` (the real Pal Engine_classes.hpp
        # ULevel.Actors line) or in a second `)` (the real MakeMemberString bitfield comment)
        # does not end in the exact marker, so both are skipped, not taken.
        text = (
            'class ULevel final : public UObject\r\n{\r\npublic:\r\n'
            "\tclass TArray<class AActor*>  Actors;  "
            "// 0x0098(0x0010)(THIS IS THE ARRAY YOU'RE LOOKING FOR! [NOT AUTO-GENERATED PROPERTY])\r\n"
            '};\r\n'
            'struct FNameEntryHeader final\r\n{\r\npublic:\r\n'
            '\tuint16 bIsWide : 1;  '
            '// 0x0000(0x0002)(BitIndex: 0x00, PropSize: 0x0002 (NOT AUTO-GENERATED PROPERTY))\r\n'
            '};\r\n'
        )
        self.assertEqual(parse_predefined_members(text), {})


class FlattenTests(unittest.TestCase):
    def test_flatten_keys_and_dumper_dropped(self):
        basic = {'GObjects': 0x100, 'GNames': 0x200}
        members = {('FName', 'ComparisonIndex'): (0x0, 0x4), ('UStruct', 'SuperStruct'): (0x40, 0x8)}
        offsets_info = {'Dumper': 7, 'OFFSET_GOBJECTS': 0x300}
        flat = flatten_oracle_offsets(basic, members, offsets_info)
        self.assertEqual(flat, {
            'Offsets.GObjects': 0x100, 'Offsets.GNames': 0x200,
            'FName.ComparisonIndex': 0x0, 'UStruct.SuperStruct': 0x40,
            'OffsetsInfo.OFFSET_GOBJECTS': 0x300,
        })
        self.assertNotIn('OffsetsInfo.Dumper', flat)

    def test_flatten_duplicate_key_rejected(self):
        basic = {'X': 1}
        members = {('Offsets', 'X'): (2, 4)}  # collides with 'Offsets.X'
        with self.assertRaises(ValueError):
            flatten_oracle_offsets(basic, members, {})

    def test_flatten_non_dict_raises_type_error(self):
        with self.assertRaises(TypeError):
            flatten_oracle_offsets([], {}, {})
        with self.assertRaises(TypeError):
            flatten_oracle_offsets({}, [], {})
        with self.assertRaises(TypeError):
            flatten_oracle_offsets({}, {}, [])


def _dump(rows, props=None):
    return GObjectsDump(line1='L', stem='', count=len(rows), rows=rows, props=props or {})


class CompareTests(unittest.TestCase):
    def test_gobjects_identical_ok(self):
        rows = [(i, 0x1000 + i, f'Class Foo.Bar{i}') for i in range(20000)]
        r = compare_gobjects(_dump(rows), _dump(rows))
        self.assertTrue(r.ok)
        self.assertEqual(r.matched, 20000)
        self.assertEqual(r.changed, 0)
        self.assertEqual(r.drift, 0.0)

    def test_gobjects_one_sided_half_percent_passes(self):
        oracle_rows = [(i, 0x1000 + i, f'Class Foo.Bar{i}') for i in range(20000)]
        ours_rows = oracle_rows[100:]  # 100 oracle-only rows = 0.5%
        r = compare_gobjects(_dump(ours_rows), _dump(oracle_rows))
        self.assertTrue(r.ok)
        self.assertEqual(r.drift, 100 / 20000)

    def test_gobjects_one_sided_two_percent_fails(self):
        oracle_rows = [(i, 0x1000 + i, f'Class Foo.Bar{i}') for i in range(20000)]
        ours_rows = oracle_rows[400:]  # 400 oracle-only rows = 2%
        r = compare_gobjects(_dump(ours_rows), _dump(oracle_rows))
        self.assertFalse(r.ok)
        self.assertEqual(r.drift, 400 / 20000)

    def test_gobjects_below_min_matched_fails(self):
        rows = [(i, 0x1000 + i, f'Class Foo.Bar{i}') for i in range(5)]
        r = compare_gobjects(_dump(rows), _dump(rows))
        self.assertFalse(r.ok)  # matched=5 < default min_matched=10000
        self.assertEqual(r.drift, 0.0)

    def test_gobjects_default_min_matched_10000(self):
        # boundary of the default (no override): 9,999 fails, 10,000 passes.
        rows_9999 = [(i, 0x1000 + i, f'Class Foo.Bar{i}') for i in range(9999)]
        self.assertFalse(compare_gobjects(_dump(rows_9999), _dump(rows_9999)).ok)
        rows_10000 = [(i, 0x1000 + i, f'Class Foo.Bar{i}') for i in range(10000)]
        self.assertTrue(compare_gobjects(_dump(rows_10000), _dump(rows_10000)).ok)

    def test_gobjects_drift_bound_inclusive_at_exactly_one_percent(self):
        oracle_rows = [(i, 0x1000 + i, f'Class Foo.Bar{i}') for i in range(20000)]
        ours_rows = oracle_rows[200:]  # 200 oracle-only rows = 1.0% exactly
        r = compare_gobjects(_dump(ours_rows), _dump(oracle_rows))
        self.assertTrue(r.ok)
        self.assertEqual(r.drift, 0.01)

    def test_gobjects_ours_only_rows_are_drift(self):
        oracle_rows = [(i, 0x1000 + i, f'Class Foo.Bar{i}') for i in range(20000)]
        extra_rows = [(20000 + i, 0x9000 + i, f'Class Foo.Extra{i}') for i in range(100)]  # ours-only, 0.5%
        r = compare_gobjects(_dump(oracle_rows + extra_rows), _dump(oracle_rows))
        self.assertTrue(r.ok)
        self.assertEqual(r.drift, 100 / 20000)

    def test_gobjects_empty_oracle_fails_with_full_drift(self):
        r = compare_gobjects(_dump([]), _dump([]))
        self.assertFalse(r.ok)
        self.assertEqual(r.drift, 1.0)

    def test_gobjects_changed_row_is_drift(self):
        oracle_rows = [(i, 0x1000 + i, f'Class Foo.Bar{i}') for i in range(20000)]
        ours_rows = [(i, 0x1000 + i, f'Class Foo.Changed{i}' if i < 100 else f'Class Foo.Bar{i}') for i in range(20000)]
        r = compare_gobjects(_dump(ours_rows), _dump(oracle_rows))
        self.assertTrue(r.ok)
        self.assertEqual(r.matched, 19900)
        self.assertEqual(r.changed, 100)
        self.assertAlmostEqual(r.drift, 0.005)
        self.assertIn('changed', r.samples[0])

    def test_gobjects_changed_row_never_matched_and_300_fails(self):
        oracle_rows = [(i, 0x1000 + i, f'Class Foo.Bar{i}') for i in range(20000)]
        ours_rows = [(i, 0x1000 + i, f'Class Foo.Changed{i}' if i < 300 else f'Class Foo.Bar{i}') for i in range(20000)]
        r = compare_gobjects(_dump(ours_rows), _dump(oracle_rows))
        self.assertFalse(r.ok)
        self.assertEqual(r.changed, 300)
        self.assertAlmostEqual(r.drift, 0.015)

    def test_gobjects_changed_property_row_with_compare_props(self):
        rows = [(0, 0x1000, 'Class Foo.Bar')]
        oracle = _dump(rows, props={0: [(0x0, 0x2000, 'IntProperty', 'Count')]})
        ours = _dump(rows, props={0: [(0x0, 0x2000, 'IntProperty', 'OtherName')]})
        r = compare_gobjects(ours, oracle, min_matched=0, compare_props=True)
        self.assertEqual(r.changed, 1)
        self.assertEqual(r.matched, 0)
        r_ignore = compare_gobjects(ours, oracle, min_matched=0, compare_props=False)
        self.assertEqual(r_ignore.matched, 1)
        self.assertEqual(r_ignore.changed, 0)

    def test_gobjects_changed_samples_appear_before_one_sided(self):
        oracle_rows = [(i, 0x1000 + i, f'Class Foo.Bar{i}') for i in range(10)]
        ours_rows = [(0, 0x1000, 'Class Foo.Changed0')] + [(i, 0x1000 + i, f'Class Foo.Bar{i}') for i in range(1, 9)]
        r = compare_gobjects(_dump(ours_rows), _dump(oracle_rows), min_matched=0)
        self.assertEqual(r.changed, 1)
        self.assertGreaterEqual(len(r.samples), 2)
        self.assertIn('changed', r.samples[0])
        self.assertIn('oracle-only', r.samples[1])

    def test_gobjects_missing_ours_props_is_changed(self):
        rows = [(0, 0x1000, 'Class Foo.Bar')]
        oracle = _dump(rows, props={0: [(0x0, 0x2000, 'IntProperty', 'Count')]})
        ours = _dump(rows)  # no props recorded for index 0 at all
        r = compare_gobjects(ours, oracle, min_matched=0, compare_props=True)
        self.assertEqual(r.changed, 1)
        self.assertEqual(r.matched, 0)

    def test_gobjects_negative_min_matched_rejected(self):
        with self.assertRaises(ValueError):
            compare_gobjects(_dump([]), _dump([]), min_matched=-1)

    def test_gobjects_drift_bound_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
            compare_gobjects(_dump([]), _dump([]), drift_bound=1.5)

    def test_gobjects_repeated_row_key_rejected(self):
        rows = [(0, 0x1000, 'A'), (0, 0x1000, 'B')]  # same (index, address) key twice
        with self.assertRaises(ValueError):
            compare_gobjects(_dump(rows), _dump(rows))

    def test_gobjects_wrong_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            compare_gobjects('not a dump', _dump([]))

    def test_idmap_identical_passes(self):
        records = [(0x1000, 'a'), (0x2000, 'b'), (0x3000, 'c')]
        r = compare_idmap(records, list(records))
        self.assertTrue(r.ok)
        self.assertEqual(r.matched, 3)
        self.assertEqual(r.drift, 0.0)

    def test_idmap_reordered_common_record_fails(self):
        records = [(0x1000, 'a'), (0x2000, 'b')]
        reordered = [(0x2000, 'b'), (0x1000, 'a')]
        r = compare_idmap(reordered, records)
        self.assertFalse(r.ok)

    def test_idmap_drift_is_symmetric_difference(self):
        # same multiset, only order differs: drift is the symmetric difference (here 0),
        # not derived from how much of the common prefix matched.
        oracle = [(0x1000, 'a'), (0x2000, 'b')]
        reordered = [(0x2000, 'b'), (0x1000, 'a')]
        r = compare_idmap(reordered, oracle)
        self.assertFalse(r.ok)
        self.assertEqual(r.drift, 0.0)

    def test_idmap_differing_multiset_drift(self):
        oracle = [(0x1000, 'a'), (0x2000, 'b'), (0x3000, 'c'), (0x4000, 'd')]
        ours = [(0x1000, 'a'), (0x2000, 'b'), (0x9000, 'z'), (0x4000, 'd')]
        r = compare_idmap(ours, oracle)
        self.assertFalse(r.ok)
        self.assertEqual(r.drift, 2 / 4)  # one missing from ours, one extra in ours
        self.assertEqual(r.matched, 2)  # the identical prefix: 'a', 'b'

    def test_idmap_bad_element_raises_type_error(self):
        with self.assertRaises(TypeError):
            compare_idmap([(1, 2)], [(1, 'x')])

    def test_idmap_bad_oracle_element_raises_type_error(self):
        # ours is valid; the oracle side must be validated too, not just ours.
        with self.assertRaises(TypeError):
            compare_idmap([(1, 'x')], [(1, 2)])

    def test_offsets_equal_values_pass(self):
        ours = {f'K{i}': i for i in range(30)}
        oracle = dict(ours)
        r = compare_offsets(ours, oracle)
        self.assertTrue(r.ok)
        self.assertEqual(r.changed, 0)

    def test_offsets_one_unequal_value_fails(self):
        ours = {f'K{i}': i for i in range(30)}
        oracle = dict(ours)
        oracle['K0'] = 999
        r = compare_offsets(ours, oracle)
        self.assertFalse(r.ok)
        self.assertEqual(r.changed, 1)

    def test_offsets_below_min_values_fails(self):
        ours = {'A': 1, 'B': 2}
        oracle = dict(ours)
        r = compare_offsets(ours, oracle)
        self.assertFalse(r.ok)

    def test_offsets_floor_is_25(self):
        # boundary of the default (no override): 24 fails, 25 passes.
        ours_24 = {f'K{i}': i for i in range(24)}
        self.assertFalse(compare_offsets(ours_24, dict(ours_24)).ok)
        ours_25 = {f'K{i}': i for i in range(25)}
        self.assertTrue(compare_offsets(ours_25, dict(ours_25)).ok)

    def test_offsets_missing_key_does_not_fail_but_raises_drift(self):
        ours = {f'K{i}': i for i in range(30)}
        oracle = dict(ours)
        oracle['EXTRA'] = 12345  # present in oracle only
        r = compare_offsets(ours, oracle)
        self.assertTrue(r.ok)
        self.assertEqual(r.drift, 1 / 31)  # missing / len(oracle), not / len(ours)

    def test_offsets_ours_only_keys_ignored(self):
        oracle = {f'K{i}': i for i in range(30)}
        ours = dict(oracle)
        ours['EXTRA'] = 999  # present in ours only, not a compared key
        r = compare_offsets(ours, oracle)
        self.assertTrue(r.ok)
        self.assertEqual(r.changed, 0)
        self.assertEqual(r.matched, 30)

    def test_offsets_non_dict_raises_type_error(self):
        with self.assertRaises(TypeError):
            compare_offsets([], {})

    def test_offsets_non_int_value_raises_type_error(self):
        with self.assertRaises(TypeError):
            compare_offsets({'A': 'not an int'}, {'A': 1})

    def test_offsets_min_values_type_checked(self):
        with self.assertRaises(TypeError):
            compare_offsets({}, {}, min_values=25.0)


@unittest.skipUnless(R0_ORACLE, 'set NYLIB_UE_R0_ORACLE to the stale Pal Dumper-7 output folder')
class R0FormatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = pathlib.Path(R0_ORACLE)
        if not cls.root.is_dir():
            raise AssertionError(f'NYLIB_UE_R0_ORACLE is set but not a directory: {cls.root}')

    def test_real(self):
        root = self.root
        dump_path = root / 'GObjects-Dump.txt'
        dump = parse_gobjects_dump(dump_path)
        self.assertEqual(len(dump.rows), 97032)
        self.assertEqual(dump.count, 97214)
        self.assertEqual(dump.line1, 'Object dump by Dumper-7')
        self.assertEqual(dump.stem, '5.1.1-0+++UE5+Release-5.1-Pal')
        self.assertEqual(sum(1 for _, _, name in dump.rows if '\n' in name), 0)
        nonascii = sum(1 for _, _, name in dump.rows if not name.isascii())
        self.assertEqual(nonascii, 98)
        # a bare-LF check on the raw bytes, not just the parsed object names: every '\n' in the
        # file is part of a '\r\n' pair.
        raw_text = dump_path.read_bytes().decode('utf-8')
        self.assertEqual(raw_text.replace('\r\n', '').count('\n'), 0)

        dump_props = parse_gobjects_dump(root / 'GObjects-Dump-WithProperties.txt', with_properties=True)
        self.assertEqual(len(dump_props.rows), 97032)
        self.assertEqual(dump_props.rows, dump.rows)  # same object rows, with_properties or not
        self.assertEqual(sum(len(v) for v in dump_props.props.values()), 143006)
        spaced_prop_names = sum(
            1 for plist in dump_props.props.values() for (_, _, _, name) in plist if ' ' in name)
        self.assertEqual(spaced_prop_names, 155)

        idmap = parse_idmap(root / 'IDAMappings' / '5.1.1-0+++UE5+Release-5.1-Pal.idmap')
        self.assertEqual(len(idmap), 23576)
        exec_records = [r for r in idmap if r[1].endswith('Ev') and r[1].startswith('_ZN')]
        vft_records = [r for r in idmap if r[1].endswith('_VFT')]
        self.assertEqual(len(exec_records), 17623)
        self.assertEqual(len(vft_records), 5953)
        exec_rvas = [r[0] for r in exec_records]
        self.assertEqual(len(exec_rvas), len(set(exec_rvas)))  # exec RVAs are unique
        vft_rvas = [r[0] for r in vft_records]
        self.assertEqual(len(vft_rvas) - len(set(vft_rvas)), 1348)
        idmap_path = root / 'IDAMappings' / '5.1.1-0+++UE5+Release-5.1-Pal.idmap'
        idmap_bytes = idmap_path.stat().st_size
        self.assertEqual(idmap_bytes, 1278129)
        self.assertEqual(sum(6 + len(name.encode('utf-8')) for _, name in idmap), idmap_bytes)

        offsets_info = parse_offsets_info(root / 'Dumpspace' / 'OffsetsInfo.json')
        self.assertEqual(len(offsets_info), 7)
        self.assertEqual(set(offsets_info), {
            'Dumper', 'OFFSET_GOBJECTS', 'OFFSET_APPENDSTRING', 'OFFSET_GNAMES',
            'OFFSET_GWORLD', 'OFFSET_PROCESSEVENT', 'INDEX_PROCESSEVENT',
        })
        self.assertEqual(offsets_info['Dumper'], 7)
        self.assertEqual(offsets_info['INDEX_PROCESSEVENT'], 76)

        basic_text = (root / 'CppSDK' / 'SDK' / 'Basic.hpp').read_text(encoding='utf-8-sig')
        basic = parse_basic_offsets(basic_text)
        self.assertEqual(len(basic), 6)
        self.assertEqual(set(basic), {'GObjects', 'AppendString', 'GNames', 'GWorld', 'ProcessEvent', 'ProcessEventIdx'})
        members_basic = parse_predefined_members(basic_text)
        self.assertEqual(len(members_basic), 64)
        self.assertEqual(members_basic[('FName', 'ComparisonIndex')], (0x0, 0x4))
        self.assertEqual(members_basic[('FField', 'Next')], (0x20, 0x8))
        self.assertEqual(members_basic[('FProperty', 'Offset')], (0x4C, 0x4))
        self.assertEqual(members_basic[('TUObjectArray', 'NumElements')], (0x14, 0x4))
        # the same GObjects/GNames/GWorld offsets, read from two independent sources.
        self.assertEqual(basic['GObjects'], offsets_info['OFFSET_GOBJECTS'])
        self.assertEqual(basic['GNames'], offsets_info['OFFSET_GNAMES'])
        self.assertEqual(basic['GWorld'], offsets_info['OFFSET_GWORLD'])

        classes_text = (root / 'CppSDK' / 'SDK' / 'CoreUObject_classes.hpp').read_text(encoding='utf-8-sig')
        members_classes = parse_predefined_members(classes_text)
        self.assertEqual(len(members_classes), 17)
        self.assertEqual(members_classes[('UStruct', 'SuperStruct')], (0x40, 0x8))
        self.assertEqual(members_classes[('UStruct', 'Children')], (0x48, 0x8))
        self.assertEqual(members_classes[('UStruct', 'ChildProperties')], (0x50, 0x8))
        self.assertEqual(members_classes[('UStruct', 'Size')], (0x58, 0x4))
        self.assertEqual(members_classes[('UStruct', 'MinAlignment')], (0x5C, 0x2))
        self.assertEqual(members_classes[('UClass', 'ClassDefaultObject')], (0x110, 0x8))

        members = dict(members_basic)
        members.update(members_classes)
        flat = flatten_oracle_offsets(basic, members, offsets_info)
        self.assertEqual(len(flat), 93)

        self.assertTrue(compare_gobjects(dump, dump).ok)
        self.assertTrue(compare_gobjects(dump_props, dump_props, compare_props=True).ok)
        self.assertTrue(compare_idmap(idmap, idmap).ok)
        self.assertTrue(compare_offsets(flat, flat).ok)

    def test_missing_oracle_path_raises_oserror(self):
        missing = self.root / 'does-not-exist-oracle-check'
        with self.assertRaises(OSError):
            parse_gobjects_dump(missing)


if __name__ == '__main__':
    unittest.main()
