"""G7.5: write_image's round trip against a real x64 PE (I6), plus argument and skip-path coverage."""
import os
import stat
import struct
import sys
import tempfile
import unittest
import unittest.mock

from .. import image
from ..capture import ImageSource
from ..errors import MemoryReadError
from ..memory import MemorySource, Module
from . import pe_file

NEW_BASE = 0x7FF600000000


class _Mem(MemorySource):
    """Backs reads from a dict[base, bytes] of disjoint segments; bytes outside any segment are unreadable."""

    def __init__(self, data: dict):
        self._data = dict(data)

    def _read(self, address, size):
        for base, buf in self._data.items():
            if base <= address and address + size <= base + len(buf):
                return buf[address - base:address - base + size]
        raise MemoryReadError(address, size, 'unmapped')

    def _readable_ranges(self, address, size):
        out = []
        for base, buf in self._data.items():
            lo, hi = max(address, base), min(address + size, base + len(buf))
            if hi > lo:
                out.append((lo, hi - lo))
        return out

    def modules(self):
        return []


class _PagedMem(_Mem):
    """Like _Mem, but refuses any read above PAGE_SIZE: only the page-by-page retry can read it (M7)."""

    def _read(self, address, size):
        if size > image.PAGE_SIZE:
            raise MemoryReadError(address, size, 'only page-sized reads served')
        return super()._read(address, size)


def _minimal_pe64_header(size: int, *, file_alignment: int, num_sections: int = 0,
                         size_of_headers: int = 0x400, size_opt: int = 0xF0, e_lfanew: int = 0xC0) -> bytearray:
    """A buffer with just enough PE32+ AMD64 fields to reach write_image's layout check and pe_unmap (I1)."""
    buf = bytearray(size)
    opt = e_lfanew + 24
    buf[0:2] = b'MZ'
    struct.pack_into('<I', buf, 0x3C, e_lfanew)
    buf[e_lfanew:e_lfanew + 4] = b'PE\0\0'
    struct.pack_into('<H', buf, e_lfanew + 4, 0x8664)  # IMAGE_FILE_MACHINE_AMD64
    struct.pack_into('<H', buf, e_lfanew + 6, num_sections)
    struct.pack_into('<H', buf, e_lfanew + 0x14, size_opt)
    struct.pack_into('<H', buf, opt, 0x20B)
    struct.pack_into('<I', buf, opt + 0x24, file_alignment)
    struct.pack_into('<I', buf, opt + 0x3C, size_of_headers)
    return buf


def _mapped_image(path: str, new_base: int, *, hole: tuple | None = None) -> ImageSource:
    """Map `path` at its own preferred base (pe_file.map_pe_file), copy it into one zero-filled
    SizeOfImage buffer, and place that buffer at `new_base`; the header keeps the file's own ImageBase.
    `hole`, when given, is a (offset, size) byte range (relative to `new_base`) left out of the image."""
    mapped = pe_file.map_pe_file(path)
    main = mapped.main_module
    buf = bytearray(main.size)
    for addr, n in mapped.readable_ranges(main.base, main.size):
        buf[addr - main.base:addr - main.base + n] = mapped.read(addr, n)
    module = Module(main.name, new_base, main.size, main.path)
    if hole is None:
        return ImageSource([(new_base, bytes(buf))], [module])
    off, size = hole
    segments = []
    if off > 0:
        segments.append((new_base, bytes(buf[:off])))
    end = off + size
    if end < len(buf):
        segments.append((new_base + end, bytes(buf[end:])))
    return ImageSource(segments, [module])


def _first_exec_section_rva(path: str) -> int:
    mapped = pe_file.map_pe_file(path)
    base = mapped.main_module.base
    head = mapped.read(base, 0x400)
    e_lfanew = struct.unpack_from('<I', head, 0x3C)[0]
    opt = e_lfanew + 24
    num_sections = struct.unpack_from('<H', head, e_lfanew + 6)[0]
    size_opt = struct.unpack_from('<H', head, e_lfanew + 0x14)[0]
    sections_offset = opt + size_opt
    sec_table = mapped.read(base, sections_offset + num_sections * 40)
    for i in range(num_sections):
        sh = sections_offset + i * 40
        characteristics = struct.unpack_from('<I', sec_table, sh + 36)[0]
        virt_addr = struct.unpack_from('<I', sec_table, sh + 12)[0]
        if characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            return virt_addr
    raise AssertionError(f'{path}: no executable section found')


def _header_fields(buf) -> tuple:
    e_lfanew = struct.unpack_from('<I', buf, 0x3C)[0]
    opt = e_lfanew + 24
    num_sections = struct.unpack_from('<H', buf, e_lfanew + 6)[0]
    size_opt = struct.unpack_from('<H', buf, e_lfanew + 0x14)[0]
    size_of_headers = struct.unpack_from('<I', buf, opt + 0x3C)[0]
    return opt, num_sections, opt + size_opt, size_of_headers


def _blanked(buf: bytes, opt: int, num_sections: int, sections_offset: int) -> bytes:
    """`buf` with the fields write_image is allowed to change zeroed out, for an equality compare."""
    out = bytearray(buf)
    for i in range(num_sections):
        sh = sections_offset + i * 40
        struct.pack_into('<II', out, sh + 16, 0, 0)  # SizeOfRawData, PointerToRawData
    struct.pack_into('<Q', out, opt + 0x18, 0)  # ImageBase
    if struct.unpack_from('<I', out, opt + 0x6C)[0] > 4:
        out[opt + 0x90:opt + 0x98] = bytes(8)  # DataDirectory[4]
    return bytes(out)


def _file_image_base(path: str) -> int:
    with open(path, 'rb') as f:
        raw = f.read()
    e_lfanew = struct.unpack_from('<I', raw, 0x3C)[0]
    return struct.unpack_from('<Q', raw, e_lfanew + 24 + 0x18)[0]


class RoundTripTests(unittest.TestCase):
    """G7.5: write_image against sys._base_executable (an x64 PE every run has), relocated to NEW_BASE."""

    def test_part1_full_round_trip(self):
        py_exe = sys._base_executable
        mem = _mapped_image(py_exe, NEW_BASE)
        with tempfile.TemporaryDirectory() as d:
            result = image.write_image(mem, base=NEW_BASE, size_of_image=mem.main_module.size,
                                       exe='base.exe', folder=d, disk_exe=py_exe)
            self.assertIsNone(result.skipped)
            self.assertEqual(result.unreadable_pages, 0)
            self.assertIsNone(result.first_unreadable)
            self.assertEqual(result.warnings, ())
            self.assertEqual(result.image_base, NEW_BASE)
            self.assertEqual(result.original_image_base, _file_image_base(py_exe))
            self.assertTrue(result.path and result.path.startswith(d))

            written = pe_file.map_pe_file(result.path)
            self.assertEqual(written.main_module.base, NEW_BASE)

            mem_head_probe = mem.read(mem.main_module.base, 0x1000)
            opt, num_sections, sections_offset, size_of_headers = _header_fields(mem_head_probe)
            self.assertLessEqual(size_of_headers, 0x1000)
            mem_head = mem_head_probe[:size_of_headers]
            written_head = written.read(written.main_module.base, size_of_headers)

            self.assertEqual(struct.unpack_from('<Q', written_head, opt + 0x18)[0], NEW_BASE)
            if struct.unpack_from('<I', written_head, opt + 0x6C)[0] > 4:
                self.assertNotEqual(mem_head[opt + 0x90:opt + 0x98], bytes(8))  # M2: precondition, else this proves nothing
                self.assertEqual(written_head[opt + 0x90:opt + 0x98], bytes(8))
            self.assertEqual(_blanked(mem_head, opt, num_sections, sections_offset),
                             _blanked(written_head, opt, num_sections, sections_offset))

            for i in range(num_sections):
                sh = sections_offset + i * 40
                virt_size = struct.unpack_from('<I', mem_head, sh + 8)[0]
                virt_addr = struct.unpack_from('<I', mem_head, sh + 12)[0]
                if virt_size <= 0:
                    continue
                a = mem.read(mem.main_module.base + virt_addr, virt_size)
                b = written.read(written.main_module.base + virt_addr, virt_size)
                self.assertEqual(a, b, f'section at rva {virt_addr:#x}')

    def test_part2_one_missing_page_counts_and_zero_fills(self):
        py_exe = sys._base_executable
        hole_rva = _first_exec_section_rva(py_exe)
        self.assertEqual(hole_rva % image.PAGE_SIZE, 0)
        mem = _mapped_image(py_exe, NEW_BASE, hole=(hole_rva, image.PAGE_SIZE))
        with tempfile.TemporaryDirectory() as d:
            result = image.write_image(mem, base=NEW_BASE, size_of_image=mem.main_module.size,
                                       exe='base.exe', folder=d, disk_exe=py_exe)
            self.assertIsNone(result.skipped)
            self.assertEqual(result.unreadable_pages, 1)
            self.assertEqual(result.first_unreadable, NEW_BASE + hole_rva)
            self.assertEqual(len(result.warnings), 1)
            self.assertIn('1 unreadable pages', result.warnings[0])

            written = pe_file.map_pe_file(result.path)
            hole_bytes = written.read(written.main_module.base + hole_rva, image.PAGE_SIZE)
            self.assertEqual(hole_bytes, bytes(image.PAGE_SIZE))

    def test_part3_missing_first_page_skips(self):
        py_exe = sys._base_executable
        mem = _mapped_image(py_exe, NEW_BASE, hole=(0, image.PAGE_SIZE))
        with tempfile.TemporaryDirectory() as d:
            result = image.write_image(mem, base=NEW_BASE, size_of_image=mem.main_module.size,
                                       exe='base.exe', folder=d, disk_exe=py_exe)
            self.assertEqual(result.skipped, f'the PE headers at {NEW_BASE:#x} are unreadable')
            self.assertIsNone(result.path)
            self.assertEqual(result.warnings, (f'image skipped: {result.skipped}',))
            self.assertFalse(os.path.isdir(os.path.join(d, 'image')))

    def test_relative_folder_yields_absolute_path(self):
        """M3: ImageResult.path is absolute even when `folder` is given as a relative path."""
        py_exe = sys._base_executable
        mem = _mapped_image(py_exe, NEW_BASE)
        with tempfile.TemporaryDirectory() as d:
            old_cwd = os.getcwd()
            os.chdir(d)
            try:
                result = image.write_image(mem, base=NEW_BASE, size_of_image=mem.main_module.size,
                                           exe='base.exe', folder='out')
                self.assertIsNone(result.skipped)
                self.assertTrue(os.path.isabs(result.path))
            finally:
                os.chdir(old_cwd)


class RetryPathTests(unittest.TestCase):
    """M7: no committed test used to exercise the page-by-page retry of a failed READ_STEP piece."""

    def test_page_by_page_retry_covers_every_page(self):
        py_exe = sys._base_executable
        mapped = pe_file.map_pe_file(py_exe)
        main = mapped.main_module
        buf = bytearray(main.size)
        for addr, n in mapped.readable_ranges(main.base, main.size):
            buf[addr - main.base:addr - main.base + n] = mapped.read(addr, n)
        mem = _PagedMem({NEW_BASE: bytes(buf)})
        with tempfile.TemporaryDirectory() as d:
            result = image.write_image(mem, base=NEW_BASE, size_of_image=main.size, exe='x.exe', folder=d)
            self.assertIsNone(result.skipped)
            self.assertEqual(result.unreadable_pages, 0)


class ArgumentTypeTests(unittest.TestCase):
    def test_rejects_non_memorysource(self):
        with self.assertRaises(TypeError):
            image.write_image(object(), base=0x140000000, size_of_image=0x1000, exe='x.exe', folder='.')

    def test_rejects_bool_base(self):
        with self.assertRaises(TypeError):
            image.write_image(_Mem({}), base=True, size_of_image=0x1000, exe='x.exe', folder='.')

    def test_rejects_bool_size_of_image(self):
        with self.assertRaises(TypeError):
            image.write_image(_Mem({}), base=0x140000000, size_of_image=False, exe='x.exe', folder='.')

    def test_rejects_non_str_exe(self):
        with self.assertRaises(TypeError):
            image.write_image(_Mem({}), base=0x140000000, size_of_image=0x1000, exe=b'x', folder='.')

    def test_rejects_bad_folder(self):
        with self.assertRaises(TypeError):
            image.write_image(_Mem({}), base=0x140000000, size_of_image=0x1000, exe='x.exe', folder=123)

    def test_rejects_bad_disk_exe(self):
        with self.assertRaises(TypeError):
            image.write_image(_Mem({}), base=0x140000000, size_of_image=0x1000, exe='x.exe', folder='.', disk_exe=123)


class SkipPathTests(unittest.TestCase):
    def test_unaligned_base_is_skipped_before_any_read(self):
        result = image.write_image(_Mem({}), base=0x140000001, size_of_image=0x1000, exe='x.exe', folder='.')
        self.assertIsNotNone(result.skipped)
        self.assertEqual(result.unreadable_pages, 0)
        self.assertIsNone(result.first_unreadable)
        self.assertIsNone(result.path)

    def test_oversized_image_is_skipped(self):
        result = image.write_image(_Mem({}), base=0x140000000, size_of_image=image.IMAGE_MAX_BYTES + 1,
                                   exe='x.exe', folder='.')
        self.assertIn('exceeds', result.skipped)

    def test_non_pe_bytes_are_skipped(self):
        base, size = 0x140000000, 0x2000
        mem = _Mem({base: bytes(size)})
        with tempfile.TemporaryDirectory() as d:
            result = image.write_image(mem, base=base, size_of_image=size, exe='x.exe', folder=d)
        self.assertEqual(result.skipped, 'not a PE32+ AMD64 image')
        self.assertEqual(result.unreadable_pages, 0)

    def test_hostile_file_alignment_is_skipped(self):
        """I1: FileAlignment above 0x10000 is rejected before pe_unmap, however many sections."""
        base, size = 0x140000000, 0x10000
        buf = _minimal_pe64_header(size, file_alignment=0x01000000, num_sections=4)
        mem = _Mem({base: bytes(buf)})
        with tempfile.TemporaryDirectory() as d:
            result = image.write_image(mem, base=base, size_of_image=size, exe='x.exe', folder=d)
        self.assertEqual(result.skipped, 'not a PE32+ AMD64 image')
        self.assertIsNone(result.path)
        self.assertFalse(os.path.isdir(os.path.join(d, 'image')))

    def test_section_table_beyond_headers_is_skipped(self):
        """I1: a section table that would run past SizeOfHeaders is rejected before pe_unmap's struct.pack_into."""
        base, size = 0x140000000, 0x1000
        buf = _minimal_pe64_header(size, file_alignment=1, num_sections=1, size_of_headers=0x100)
        mem = _Mem({base: bytes(buf)})
        with tempfile.TemporaryDirectory() as d:
            result = image.write_image(mem, base=base, size_of_image=size, exe='x.exe', folder=d)
        self.assertEqual(result.skipped, 'not a PE32+ AMD64 image')
        self.assertIsNone(result.path)

    def test_memory_error_in_unmap_is_skipped(self):
        """I2: a MemoryError from pe_unmap (steps 3-6) is skipped, not raised."""
        py_exe = sys._base_executable
        mem = _mapped_image(py_exe, NEW_BASE)
        with tempfile.TemporaryDirectory() as d:
            with unittest.mock.patch('nylib.ue.image.pe_unmap', side_effect=MemoryError):
                result = image.write_image(mem, base=NEW_BASE, size_of_image=mem.main_module.size,
                                           exe='x.exe', folder=d)
        self.assertIsNotNone(result.skipped)
        self.assertIn('not enough memory', result.skipped)
        self.assertIsNone(result.path)


class WriteFailureTests(unittest.TestCase):
    """M4: the write-failure cleanup removes the file only when this call created it."""

    def test_preexisting_readonly_file_survives_skip(self):
        py_exe = sys._base_executable
        mem = _mapped_image(py_exe, NEW_BASE)
        with tempfile.TemporaryDirectory() as d:
            image_dir = os.path.join(d, 'image')
            os.makedirs(image_dir)
            dest = os.path.join(image_dir, 'x.exe')
            with open(dest, 'wb') as f:
                f.write(b'preexisting')
            os.chmod(dest, stat.S_IREAD)
            try:
                result = image.write_image(mem, base=NEW_BASE, size_of_image=mem.main_module.size,
                                           exe='x.exe', folder=d)
                self.assertIsNotNone(result.skipped)
                self.assertTrue(os.path.exists(dest))
                with open(dest, 'rb') as f:
                    self.assertEqual(f.read(), b'preexisting')
            finally:
                os.chmod(dest, stat.S_IWRITE | stat.S_IREAD)


class ImageResultMetaTests(unittest.TestCase):
    def test_to_meta_and_warnings_written(self):
        r = image.ImageResult(rel_path='image/x.exe', path='/tmp/x.exe', size=0x10, sha256='ab' * 32,
                              image_base=0x140000000, original_image_base=0x140000000, unreadable_pages=0,
                              first_unreadable=None, skipped=None, seconds=0.1)
        meta = r.to_meta()
        self.assertEqual(meta, {'file': 'image/x.exe', 'size': '0x10', 'sha256': 'ab' * 32,
                                'image_base': '0x140000000', 'original_image_base': '0x140000000',
                                'unreadable_pages': 0, 'skipped': None})
        self.assertEqual(r.warnings, ())

    def test_to_meta_and_warnings_skipped(self):
        r = image.ImageResult(rel_path='image/x.exe', path=None, size=0, sha256=None, image_base=0x140000000,
                              original_image_base=None, unreadable_pages=0, first_unreadable=None,
                              skipped='reason text', seconds=0.0)
        meta = r.to_meta()
        self.assertIsNone(meta['file'])
        self.assertIsNone(meta['size'])
        self.assertEqual(meta['skipped'], 'reason text')
        self.assertEqual(r.warnings, ('image skipped: reason text',))

    def test_warnings_unreadable_pages(self):
        r = image.ImageResult(rel_path='image/x.exe', path='/tmp/x.exe', size=4, sha256='00' * 32,
                              image_base=0x140000000, original_image_base=None, unreadable_pages=2,
                              first_unreadable=0x140001000, skipped=None, seconds=0.0)
        self.assertEqual(r.warnings,
                         ('image image/x.exe: 2 unreadable pages zero-filled, the first at 0x140001000',))


if __name__ == '__main__':
    unittest.main()
