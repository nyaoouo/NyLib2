import datetime
import os
import tempfile
import tomllib
import unittest

from nylib.ue.errors import ProfileError
from nylib.ue.profiles import (
    GLOBAL_PINS, HOOK_NAMES, LAYOUT_FIELDS, Pin, Profile,
    find_profiles, load_hook, load_profile, parse_profile, render_profile, toml_dumps, write_profile_file,
)

_VALID_1 = '''
[match]
exe = "LyraGame-Win64-Shipping.exe"

[globals]
# comment
gobjects = { rva = 0x8A2B3C0, build = 0x66F1A2B3 }
gnames = { rva = 0x89F1200, build = 0x66F1A2B3 }

[offsets]
"UStruct.MinAlignment" = 0x5C

[hooks]
'''

_VALID_2 = '''
[match]
exe = "ProtectedGame-Win64-Shipping.exe"

[globals]
gobjects = { rva = 0x7D90C80, build = 0x65A0C011 }
gnames = { sig = "48 8D 0D * * * * E8 * * * * 48 8B D8", note = "FNamePool ctor call site" }

[offsets]

[hooks]
# only needed when GObjects is encrypted
# decrypt_objects = "hooks.py:decrypt_objects"
'''


class ParseProfileConstantsTests(unittest.TestCase):
    def test_global_pins(self):
        self.assertEqual(GLOBAL_PINS, ('gobjects', 'gnames', 'process_event'))

    def test_hook_names(self):
        self.assertEqual(HOOK_NAMES, ('decrypt_objects',))

    def test_layout_fields(self):
        self.assertEqual(LAYOUT_FIELDS, ('ObjectsOffset', 'MaxElementsOffset', 'NumElementsOffset', 'MaxChunksOffset', 'NumChunksOffset'))


class ParseProfileValidTests(unittest.TestCase):
    def test_1b_example_1(self):
        p = parse_profile(_VALID_1, 'x.toml')
        self.assertEqual(p.exe, 'LyraGame-Win64-Shipping.exe')
        self.assertEqual(p.pins['gobjects'], Pin('gobjects', rva=0x8A2B3C0, build=0x66F1A2B3))
        self.assertEqual(p.pins['gnames'], Pin('gnames', rva=0x89F1200, build=0x66F1A2B3))
        self.assertEqual(p.offsets, {'UStruct.MinAlignment': 0x5C})
        self.assertEqual(p.hooks, {})
        self.assertEqual(p.path, os.path.abspath('x.toml'))

    def test_1b_example_2_sig_pin(self):
        p = parse_profile(_VALID_2, 'y.toml')
        self.assertEqual(p.pins['gnames'], Pin('gnames', sig='48 8D 0D * * * * E8 * * * * 48 8B D8', note='FNamePool ctor call site'))

    def test_text_without_path(self):
        p = parse_profile('[match]\nexe = "a.exe"\n')
        self.assertIsNone(p.path)

    def test_empty_doc(self):
        p = parse_profile('')
        self.assertIsNone(p.exe)
        self.assertEqual(p.pins, {})
        self.assertEqual(p.offsets, {})
        self.assertEqual(p.hooks, {})

    def test_match_without_exe(self):
        p = parse_profile('[match]\n')
        self.assertIsNone(p.exe)

    def test_offsets_nested_table_flattened(self):
        p = parse_profile('[offsets]\n[offsets.UStruct]\nMinAlignment = 0x5C\n')
        self.assertEqual(p.offsets, {'UStruct.MinAlignment': 0x5C})

    def test_offsets_dotted_key_flattened(self):
        p = parse_profile('[offsets]\nUStruct.MinAlignment = 0x5C\n')
        self.assertEqual(p.offsets, {'UStruct.MinAlignment': 0x5C})

    def test_gobjects_layout_and_elements_per_chunk(self):
        text = ('[globals]\ngobjects = { rva = 0x1000, build = 0x2000, elements_per_chunk = 0x100, '
                'layout = { ObjectsOffset = 0, MaxElementsOffset = 4, NumElementsOffset = 8, MaxChunksOffset = 12, NumChunksOffset = 16 } }\n')
        p = parse_profile(text)
        pin = p.pins['gobjects']
        self.assertEqual(pin.elements_per_chunk, 0x100)
        self.assertEqual(pin.layout, (0, 4, 8, 12, 16))

    def test_process_event_pin(self):
        p = parse_profile('[globals]\nprocess_event = { index = 5 }\n')
        self.assertEqual(p.pins['process_event'], Pin('process_event', index=5))

    def test_hooks_without_gobjects_pin_ok(self):
        p = parse_profile('[hooks]\ndecrypt_objects = "h.py:fn"\n')
        self.assertEqual(p.hooks, {'decrypt_objects': ('h.py', 'fn')})


class ParseProfileTypeErrorTests(unittest.TestCase):
    def test_text_not_str(self):
        with self.assertRaises(TypeError):
            parse_profile(b'[match]')

    def test_path_bad_type(self):
        with self.assertRaises(TypeError):
            parse_profile('', 5)


class ParseProfileBadCaseTests(unittest.TestCase):
    def _bad(self, text, path='bad.toml'):
        with self.assertRaises(ProfileError) as cm:
            parse_profile(text, path)
        return cm.exception

    def test_not_valid_toml(self):
        e = self._bad('not [ valid')
        self.assertIn('not valid TOML', e.reason)

    def test_message_format(self):
        e = self._bad('[bogus]\n')
        self.assertEqual(str(e), f'invalid profile {os.path.abspath("bad.toml")}: unknown table [bogus]')

    def test_unknown_table(self):
        e = self._bad('[bogus]\n')
        self.assertEqual(e.reason, 'unknown table [bogus]')

    def test_table_not_a_table(self):
        e = self._bad('match = 1\n')
        self.assertEqual(e.reason, '[match] must be a table')

    def test_unknown_match_key(self):
        e = self._bad('[match]\nfoo = 1\n')
        self.assertEqual(e.reason, 'unknown key [match] foo')

    def test_bad_exe_type(self):
        e = self._bad('[match]\nexe = 5\n')
        self.assertIn('[match] exe', e.reason)

    def test_empty_exe(self):
        e = self._bad('[match]\nexe = ""\n')
        self.assertIn('[match] exe', e.reason)

    def test_unknown_globals_key(self):
        e = self._bad('[globals]\nbogus = {}\n')
        self.assertEqual(e.reason, 'unknown key [globals] bogus')

    def test_unknown_globals_subkey(self):
        e = self._bad('[globals]\ngobjects = { bogus = 1 }\n')
        self.assertEqual(e.reason, 'unknown key [globals] gobjects.bogus')

    def test_rva_and_sig_together(self):
        e = self._bad('[globals]\ngobjects = { rva = 1, sig = "90", build = 1 }\n')
        self.assertEqual(e.reason, '[globals] gobjects needs exactly one of rva, sig')

    def test_neither_rva_nor_sig(self):
        e = self._bad('[globals]\ngobjects = { build = 1 }\n')
        self.assertEqual(e.reason, '[globals] gobjects needs exactly one of rva, sig')

    def test_rva_without_build(self):
        e = self._bad('[globals]\ngnames = { rva = 1 }\n')
        self.assertEqual(e.reason, '[globals] gnames rva needs build')

    def test_sig_with_build(self):
        e = self._bad('[globals]\ngnames = { sig = "90", build = 1 }\n')
        self.assertEqual(e.reason, '[globals] gnames sig takes no build')

    def test_sig_with_image_size(self):
        e = self._bad('[globals]\ngnames = { sig = "90", image_size = 1 }\n')
        self.assertEqual(e.reason, '[globals] gnames sig takes no build')

    def test_process_event_missing_index(self):
        e = self._bad('[globals]\nprocess_event = {}\n')
        self.assertEqual(e.reason, '[globals] process_event needs index')

    def test_rva_range_bool_rejected(self):
        e = self._bad('[globals]\ngnames = { rva = true, build = 1 }\n')
        self.assertIn('[globals] gnames.rva', e.reason)

    def test_rva_out_of_range(self):
        e = self._bad('[globals]\ngnames = { rva = 0, build = 1 }\n')
        self.assertIn('[globals] gnames.rva', e.reason)

    def test_layout_wrong_keys(self):
        e = self._bad('[globals]\ngobjects = { rva = 1, build = 1, layout = { ObjectsOffset = 0 } }\n')
        self.assertIn('[globals] gobjects.layout', e.reason)

    def test_bad_sig_pattern(self):
        e = self._bad('[globals]\ngnames = { sig = "zz" }\n')
        self.assertIn('is not a valid pattern', e.reason)

    def test_offsets_duplicate_nested_and_quoted(self):
        text = '[offsets]\nUStruct.MinAlignment = 1\n"UStruct.MinAlignment" = 2\n'
        e = self._bad(text)
        self.assertEqual(e.reason, '[offsets] UStruct.MinAlignment is given twice')

    def test_offsets_bad_key_no_dot(self):
        e = self._bad('[offsets]\nFoo = 1\n')
        self.assertIn('is not a valid key', e.reason)

    def test_offsets_bad_value_type(self):
        e = self._bad('[offsets]\n"A.B" = "x"\n')
        self.assertIn('[offsets] A.B', e.reason)

    def test_offsets_bool_rejected(self):
        e = self._bad('[offsets]\n"A.B" = true\n')
        self.assertIn('[offsets] A.B', e.reason)

    def test_hooks_unknown_name(self):
        e = self._bad('[hooks]\nbogus = "h.py:fn"\n')
        self.assertEqual(e.reason, 'unknown key [hooks] bogus')

    def test_hooks_no_colon(self):
        e = self._bad('[hooks]\ndecrypt_objects = "h.py"\n')
        self.assertIn('[hooks] decrypt_objects', e.reason)

    def test_hooks_func_not_identifier(self):
        e = self._bad('[hooks]\ndecrypt_objects = "h.py:1bad"\n')
        self.assertIn('FUNC must be an identifier', e.reason)

    def test_hooks_file_not_py(self):
        e = self._bad('[hooks]\ndecrypt_objects = "h.txt:fn"\n')
        self.assertIn('must end with .py', e.reason)

    def test_hooks_file_dotdot(self):
        e = self._bad('[hooks]\ndecrypt_objects = "../h.py:fn"\n')
        self.assertIn('..', e.reason)

    def test_hooks_file_absolute(self):
        e = self._bad('[hooks]\ndecrypt_objects = "/h.py:fn"\n')
        self.assertIn('absolute', e.reason)

    def test_hooks_file_drive(self):
        e = self._bad('[hooks]\ndecrypt_objects = "C:\\\\h.py:fn"\n')
        self.assertIn('drive', e.reason)

    def test_gobjects_pin_with_decrypt_hook(self):
        text = '[globals]\ngobjects = { rva = 1, build = 1 }\n\n[hooks]\ndecrypt_objects = "h.py:fn"\n'
        e = self._bad(text)
        self.assertEqual(
            e.reason,
            '[globals] gobjects cannot be combined with [hooks] decrypt_objects: '
            'a pinned GObjects is read without decryption',
        )

    def test_path_none_uses_string_marker(self):
        with self.assertRaises(ProfileError) as cm:
            parse_profile('[bogus]\n')
        self.assertEqual(str(cm.exception), 'invalid profile <string>: unknown table [bogus]')


class LoadProfileTests(unittest.TestCase):
    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'p.toml')
            with open(path, 'w', encoding='utf-8') as f:
                f.write(_VALID_1)
            p = load_profile(path)
            self.assertEqual(p.exe, 'LyraGame-Win64-Shipping.exe')
            self.assertEqual(p.path, os.path.abspath(path))

    def test_utf8_sig_bom(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'p.toml')
            with open(path, 'wb') as f:
                f.write(b'\xef\xbb\xbf' + _VALID_1.encode('utf-8'))
            p = load_profile(path)
            self.assertEqual(p.exe, 'LyraGame-Win64-Shipping.exe')

    def test_missing_file(self):
        with self.assertRaises(ProfileError) as cm:
            load_profile('does/not/exist.toml')
        self.assertIn('cannot read', cm.exception.reason)

    def test_not_utf8(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'p.toml')
            with open(path, 'wb') as f:
                f.write(b'\xff\xfe\x00\x01')
            with self.assertRaises(ProfileError) as cm:
                load_profile(path)
            self.assertEqual(cm.exception.reason, 'not UTF-8')

    def test_path_bad_type(self):
        with self.assertRaises(TypeError):
            load_profile(5)


class FindProfilesTests(unittest.TestCase):
    def test_missing_folder(self):
        self.assertEqual(find_profiles('does/not/exist', 'a.exe'), [])

    def test_bad_exe_type(self):
        with self.assertRaises(TypeError):
            find_profiles('x', 5)

    def test_empty_exe(self):
        with self.assertRaises(ValueError):
            find_profiles('x', '')

    def test_matches_case_insensitive_and_toml_new_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            profiles_dir = os.path.join(d, 'profiles')
            os.makedirs(profiles_dir)
            with open(os.path.join(profiles_dir, 'a.toml'), 'w', encoding='utf-8') as f:
                f.write('[match]\nexe = "Foo-Win64-Shipping.exe"\n')
            with open(os.path.join(profiles_dir, 'a.toml.new'), 'w', encoding='utf-8') as f:
                f.write('[match]\nexe = "Foo-Win64-Shipping.exe"\n')
            found = find_profiles(d, 'foo-win64-shipping.exe')
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0].exe, 'Foo-Win64-Shipping.exe')

    def test_skips_bad_profile_and_logs_warning(self):
        with tempfile.TemporaryDirectory() as d:
            profiles_dir = os.path.join(d, 'profiles')
            os.makedirs(profiles_dir)
            with open(os.path.join(profiles_dir, 'bad.toml'), 'w', encoding='utf-8') as f:
                f.write('[bogus]\n')
            with self.assertLogs('nylib.ue.profiles', level='WARNING') as cm:
                found = find_profiles(d, 'foo.exe')
            self.assertEqual(found, [])
            self.assertTrue(any('skipping profile' in m for m in cm.output))

    def test_no_match_filtered_out(self):
        with tempfile.TemporaryDirectory() as d:
            profiles_dir = os.path.join(d, 'profiles')
            os.makedirs(profiles_dir)
            with open(os.path.join(profiles_dir, 'a.toml'), 'w', encoding='utf-8') as f:
                f.write('[match]\nexe = "Other.exe"\n')
            self.assertEqual(find_profiles(d, 'foo.exe'), [])


class LoadHookTests(unittest.TestCase):
    def test_missing_name(self):
        prof = Profile(path='x.toml', exe=None, pins={}, offsets={}, hooks={})
        with self.assertRaises(KeyError):
            load_hook(prof, 'decrypt_objects')

    def test_no_profile_path(self):
        prof = Profile(path=None, exe=None, pins={}, offsets={}, hooks={'decrypt_objects': ('h.py', 'fn')})
        with self.assertRaises(ProfileError) as cm:
            load_hook(prof, 'decrypt_objects')
        self.assertEqual(cm.exception.reason, 'hooks need a profile file')

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as d:
            prof_path = os.path.join(d, 'p.toml')
            open(prof_path, 'w').close()
            prof = Profile(path=prof_path, exe=None, pins={}, offsets={}, hooks={'decrypt_objects': ('h.py', 'fn')})
            with self.assertRaises(ProfileError) as cm:
                load_hook(prof, 'decrypt_objects')
            self.assertIn('not found', cm.exception.reason)

    def test_loads_and_returns_callable(self):
        with tempfile.TemporaryDirectory() as d:
            prof_path = os.path.join(d, 'p.toml')
            open(prof_path, 'w').close()
            with open(os.path.join(d, 'h.py'), 'w', encoding='utf-8') as f:
                f.write('def fn(x):\n    return x + 1\n')
            prof = Profile(path=prof_path, exe=None, pins={}, offsets={}, hooks={'decrypt_objects': ('h.py', 'fn')})
            with self.assertLogs('nylib.ue.profiles', level='WARNING'):
                func = load_hook(prof, 'decrypt_objects')
            self.assertEqual(func(1), 2)
            import sys
            self.assertNotIn('_nylib_ue_hook', ','.join(sys.modules))

    def test_hook_file_raises_on_load(self):
        with tempfile.TemporaryDirectory() as d:
            prof_path = os.path.join(d, 'p.toml')
            open(prof_path, 'w').close()
            with open(os.path.join(d, 'h.py'), 'w', encoding='utf-8') as f:
                f.write('raise RuntimeError("boom")\n')
            prof = Profile(path=prof_path, exe=None, pins={}, offsets={}, hooks={'decrypt_objects': ('h.py', 'fn')})
            with self.assertRaises(ProfileError) as cm:
                load_hook(prof, 'decrypt_objects')
            self.assertIn('failed to load', cm.exception.reason)
            self.assertIsInstance(cm.exception.__cause__, RuntimeError)

    def test_hook_func_missing(self):
        with tempfile.TemporaryDirectory() as d:
            prof_path = os.path.join(d, 'p.toml')
            open(prof_path, 'w').close()
            with open(os.path.join(d, 'h.py'), 'w', encoding='utf-8') as f:
                f.write('x = 1\n')
            prof = Profile(path=prof_path, exe=None, pins={}, offsets={}, hooks={'decrypt_objects': ('h.py', 'fn')})
            with self.assertRaises(ProfileError) as cm:
                load_hook(prof, 'decrypt_objects')
            self.assertIn('is not a function', cm.exception.reason)

    def test_hook_func_not_callable(self):
        with tempfile.TemporaryDirectory() as d:
            prof_path = os.path.join(d, 'p.toml')
            open(prof_path, 'w').close()
            with open(os.path.join(d, 'h.py'), 'w', encoding='utf-8') as f:
                f.write('fn = 1\n')
            prof = Profile(path=prof_path, exe=None, pins={}, offsets={}, hooks={'decrypt_objects': ('h.py', 'fn')})
            with self.assertRaises(ProfileError) as cm:
                load_hook(prof, 'decrypt_objects')
            self.assertIn('is not a function', cm.exception.reason)


class TomlDumpsTests(unittest.TestCase):
    def test_round_trip_various_values(self):
        t = {
            'a': {'b': True, 'c': False, 'd': 0, 'e': 0x1F, 'f': -5, 'g': 'hi "there"\nnewline\\back', 'h': {}, 'i': {'x': 1}},
            'j': {},
        }
        dumped = toml_dumps(t, header=('line one', 'line two'), comments={'a': ('note one', 'note two')})
        self.assertTrue(dumped.endswith('\n'))
        self.assertNotIn('\r', dumped)
        self.assertEqual(tomllib.loads(dumped), t)

    def test_bare_vs_quoted_keys(self):
        dumped = toml_dumps({'a': {'bare-key_1': 1, 'has space': 2}})
        self.assertEqual(tomllib.loads(dumped), {'a': {'bare-key_1': 1, 'has space': 2}})

    def test_header_and_blank_lines_shape(self):
        dumped = toml_dumps({'a': {'x': 1}, 'b': {'y': 2}}, header=('h1',))
        lines = dumped.split('\n')
        self.assertEqual(lines[0], '# h1')
        self.assertEqual(lines[1], '')
        self.assertEqual(lines[2], '[a]')
        self.assertIn('', lines)  # blank line between tables

    def test_tables_not_a_mapping(self):
        with self.assertRaises(TypeError):
            toml_dumps([])

    def test_value_float_rejected(self):
        with self.assertRaises(TypeError):
            toml_dumps({'a': {'x': 1.5}})

    def test_value_list_rejected(self):
        with self.assertRaises(TypeError):
            toml_dumps({'a': {'x': [1, 2]}})

    def test_value_none_rejected(self):
        with self.assertRaises(TypeError):
            toml_dumps({'a': {'x': None}})

    def test_value_bytes_rejected(self):
        with self.assertRaises(TypeError):
            toml_dumps({'a': {'x': b'x'}})

    def test_non_str_key_rejected(self):
        with self.assertRaises(TypeError):
            toml_dumps({'a': {1: 'x'}})

    def test_header_newline_rejected(self):
        with self.assertRaises(ValueError):
            toml_dumps({}, header=('bad\nline',))

    def test_comment_newline_rejected(self):
        with self.assertRaises(ValueError):
            toml_dumps({'a': {}}, comments={'a': ('bad\rline',)})

    def test_surrogate_rejected(self):
        with self.assertRaises(ValueError):
            toml_dumps({'a': {'x': '\ud800'}})


class RenderProfileTests(unittest.TestCase):
    def test_round_trip_both_pins(self):
        pins = [Pin('gobjects', rva=0x1000, build=0x2000), Pin('gnames', rva=0x3000, build=0x2000)]
        when = datetime.datetime(2026, 9, 30, 14, 2)
        text = render_profile('Lyra-Win64-Shipping.exe', 'LyraStarterGame', pins, when=when)
        p = parse_profile(text)
        self.assertEqual(p.exe, 'Lyra-Win64-Shipping.exe')
        self.assertEqual(p.pins, {pin.name: pin for pin in pins})

    def test_round_trip_sig_pin_and_no_pins(self):
        pins = [Pin('gnames', sig='48 8D 0D * * * *', note='ctor')]
        text = render_profile('A.exe', 'A', pins, when=datetime.datetime(2026, 1, 1))
        p = parse_profile(text)
        self.assertEqual(p.pins, {'gnames': pins[0]})
        self.assertNotIn('gobjects', p.pins)

    def test_round_trip_no_pins(self):
        text = render_profile('A.exe', 'A', [], when=datetime.datetime(2026, 1, 1))
        p = parse_profile(text)
        self.assertEqual(p.exe, 'A.exe')
        self.assertEqual(p.pins, {})

    def test_header_lines(self):
        text = render_profile('A.exe', 'MyGame', [], when=datetime.datetime(2026, 9, 30, 14, 2))
        self.assertIn('# nylib.ue profile for MyGame', text)
        self.assertIn('Written by "nylib.ue probe --write-profile" on 2026-09-30 14:02; edit freely.', text)
        self.assertIn('A profile can never enable remote calls.', text)

    def test_duplicate_pin_name(self):
        with self.assertRaises(ValueError):
            render_profile('A.exe', 'A', [Pin('gobjects'), Pin('gobjects')], when=datetime.datetime(2026, 1, 1))

    def test_bad_exe_type(self):
        with self.assertRaises(TypeError):
            render_profile(5, 'A', [], when=datetime.datetime(2026, 1, 1))

    def test_bad_when_type(self):
        with self.assertRaises(TypeError):
            render_profile('A.exe', 'A', [], when='now')

    def test_bad_pin_type(self):
        with self.assertRaises(TypeError):
            render_profile('A.exe', 'A', [object()], when=datetime.datetime(2026, 1, 1))


class WriteProfileFileTests(unittest.TestCase):
    def test_f71_write_then_raise_on_second_write(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'profiles', 'a.toml')
            returned = write_profile_file(path, 'hello\n')
            self.assertEqual(returned, path)
            with open(path, encoding='utf-8', newline='') as f:
                self.assertEqual(f.read(), 'hello\n')
            with self.assertRaises(FileExistsError) as cm:
                write_profile_file(path, 'second write\n')
            self.assertEqual(cm.exception.args[0], path)
            with open(path, encoding='utf-8', newline='') as f:
                self.assertEqual(f.read(), 'hello\n')

    def test_bad_path_type(self):
        with self.assertRaises(TypeError):
            write_profile_file(5, 'x')

    def test_bad_text_type(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(TypeError):
                write_profile_file(os.path.join(d, 'a.toml'), 5)


if __name__ == '__main__':
    unittest.main()
