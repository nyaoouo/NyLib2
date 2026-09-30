"""Stage-1 integration (V7): the PE parser and scanner over the three real shipping exe files of root plan §8a.

Skipped entirely when NYLIB_UE_EXES is unset. Once set, a listed path that does not exist fails
rather than skips: this suite exists to prove the real-image contract, not to be silently inert."""
import os
import struct
import time
import unittest

from nylib.ue.pe import PeImage
from nylib.ue.scan import Scanner

from .pe_file import align_up, map_pe_file

_SECTION_STRUCT = struct.Struct('<8sIIIIIIHHI')
_PREFETCH = (('ByteProperty', True), ('ForwardShadingQuality_', False), ('Accessed None', True))


def _exe_paths():
    raw = os.environ.get('NYLIB_UE_EXES')
    return raw.split(os.pathsep) if raw else None


def _file_header(data: bytes):
    """The file's own size/timestamp/section table/alignment, read independently of nylib.ue.pe for comparison."""
    nt = struct.unpack_from('<I', data, 0x3C)[0]
    num_sections, = struct.unpack_from('<H', data, nt + 6)
    timestamp, = struct.unpack_from('<I', data, nt + 8)
    size_opt, = struct.unpack_from('<H', data, nt + 20)
    opt = nt + 24
    image_base, = struct.unpack_from('<Q', data, opt + 0x18)
    section_alignment, = struct.unpack_from('<I', data, opt + 0x20)
    size_image, = struct.unpack_from('<I', data, opt + 0x38)
    sec_table = opt + size_opt
    sections = []
    for i in range(num_sections):
        entry = data[sec_table + i * _SECTION_STRUCT.size: sec_table + (i + 1) * _SECTION_STRUCT.size]
        name_raw, virt_size, virt_addr, *_rest = _SECTION_STRUCT.unpack(entry)
        sections.append((name_raw.split(b'\0', 1)[0].decode('latin-1'), virt_addr, virt_size))
    return image_base, size_image, timestamp, section_alignment, sections


class RealImagesTests(unittest.TestCase):
    @unittest.skipUnless(_exe_paths(), 'NYLIB_UE_EXES not set')
    def test_real_images(self):
        for path in _exe_paths():
            with self.subTest(exe=path):
                self._check_one(path)

    def _check_one(self, path):
        started = time.perf_counter()
        with open(path, 'rb') as f:
            data = f.read()
        image_base, size_image, timestamp, section_alignment, expected_sections = _file_header(data)

        source = map_pe_file(path)
        image = PeImage(source, image_base)
        self.assertEqual(image.size, size_image)
        self.assertEqual(image.timestamp, timestamp)
        self.assertEqual([(s.name, image.rva(s.address)) for s in image.sections],
                          [(name, addr) for name, addr, _ in expected_sections])

        modules = source.modules()
        self.assertEqual(len(modules), 1)
        self.assertEqual((modules[0].base, modules[0].size), (image_base, size_image))

        # the loader zero-fills each section up to align_up(VirtualSize, SectionAlignment): the padding
        # bytes just past a section's declared data are still committed and readable, not a hole (review-2 M2)
        padded = False
        for name, addr, virt_size in expected_sections:
            aligned = align_up(virt_size, section_alignment)
            if aligned > virt_size:
                self.assertTrue(source.readable(image_base + addr + virt_size, 1), name)
                self.assertEqual(source.read(image_base + addr + aligned - 1, 1), b'\0', name)
                padded = True
        self.assertTrue(padded)  # at least one real section exercises the padding path

        slots = image.import_slots('InitializeSRWLock')
        self.assertTrue(slots)
        self.assertTrue(all(s.dll == 'kernel32.dll' for s in slots), slots)

        scanner = Scanner(source, image)
        scanner.prefetch_string_refs(_PREFETCH)
        for text, wide in _PREFETCH:
            self.assertTrue(scanner.string_refs(text, wide=wide), (text, wide))

        wide_hits = scanner.find_bytes('+Release-'.encode('utf-16-le'))
        ascii_hits = scanner.find_bytes(b'+Release-')
        self.assertTrue(wide_hits)
        self.assertEqual(ascii_hits, [])

        elapsed = time.perf_counter() - started
        print(f'\n{os.path.basename(path)}: {elapsed:.1f}s', flush=True)
        self.assertLess(elapsed, 60)


if __name__ == '__main__':
    unittest.main()
