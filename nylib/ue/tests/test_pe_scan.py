import struct
import unittest

from nylib.ue.errors import CaptureError, MemoryReadError, PeFormatError
from nylib.ue.memory import MemorySource
from nylib.ue.pe import IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, PeImage, _read_cstring
from nylib.ue.scan import Scanner

BASE = 0x140000000
_CODE_EXEC_READ = 0x00000020 | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
_READ_ONLY = IMAGE_SCN_MEM_READ
_READ_WRITE = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE


class _Pages(MemorySource):
    """Backs reads from a dict[base, bytes] of disjoint mapped segments; bytes outside any segment are unreadable."""

    def __init__(self, segments):
        self._segments = dict(segments)

    def _segment_for(self, address, size):
        for seg_base, data in self._segments.items():
            if seg_base <= address and address + size <= seg_base + len(data):
                return seg_base, data
        return None

    def _read(self, address, size):
        found = self._segment_for(address, size)
        if found is None:
            raise MemoryReadError(address, size, 'unmapped')
        seg_base, data = found
        off = address - seg_base
        return data[off:off + size]

    def _readable_ranges(self, address, size):
        out = []
        for seg_base, data in self._segments.items():
            lo, hi = max(address, seg_base), min(address + size, seg_base + len(data))
            if hi > lo:
                out.append((lo, hi - lo))
        return out

    def regions(self):
        return []

    def modules(self):
        return []


class _CountingPages(_Pages):
    def __init__(self, segments):
        super().__init__(segments)
        self.reads = 0

    def _read(self, address, size):
        self.reads += 1
        return super()._read(address, size)


class _WithSibling(_Pages):
    """A source whose fresh is a separate counting sibling, so reads through fresh are distinguishable."""

    def __init__(self, segments):
        super().__init__(segments)
        self.direct_reads = 0
        self.sibling = _CountingPages(self._segments)

    def _read(self, address, size):
        self.direct_reads += 1
        return super()._read(address, size)

    @property
    def fresh(self):
        return self.sibling


class _RaisingPages(_Pages):
    """_read raises a fixed exception after `after` successful reads (simulates CaptureError / closed-capture pass-through)."""

    def __init__(self, segments, exc, after=0):
        super().__init__(segments)
        self.exc, self.after, self.n = exc, after, 0

    def _read(self, address, size):
        self.n += 1
        if self.n > self.after:
            raise self.exc
        return super()._read(address, size)


class _LyingReadableRange(_Pages):
    """_readable_ranges reports [bad_lo, bad_hi) as readable, but _read still fails there (stale map / race)."""

    def __init__(self, segments, bad_lo, bad_hi):
        super().__init__(segments)
        self.bad = (bad_lo, bad_hi)

    def _read(self, address, size):
        if address < self.bad[1] and address + size > self.bad[0]:
            raise MemoryReadError(address, size, 'winerror 299')
        return super()._read(address, size)


class _FlakyOnceFresh(_Pages):
    """Each distinct (address, size) read fails once, then succeeds (simulates a transient race healed on retry)."""

    def __init__(self, segments):
        super().__init__(segments)
        self._failed_once = set()

    def _read(self, address, size):
        key = (address, size)
        if key not in self._failed_once:
            self._failed_once.add(key)
            raise MemoryReadError(address, size, 'transient')
        return super()._read(address, size)


class _WithFlakyFresh(_Pages):
    """A source whose fresh is a sibling that fails each range once before succeeding."""

    def __init__(self, segments):
        super().__init__(segments)
        self.sibling = _FlakyOnceFresh(self._segments)

    @property
    def fresh(self):
        return self.sibling


def _cstr(text):
    return text.encode('ascii') + b'\0'


def _wstr(text):
    return text.encode('utf-16-le') + b'\0\0'


def _pack_header(buf, *, e_lfanew, machine, num_sections, timestamp, size_opt, magic, size_image, n_rva_sizes, import_rva):
    buf[0:2] = b'MZ'
    struct.pack_into('<I', buf, 0x3C, e_lfanew)
    nt = e_lfanew
    buf[nt:nt + 4] = b'PE\0\0'
    struct.pack_into('<H', buf, nt + 4, machine)
    struct.pack_into('<H', buf, nt + 6, num_sections)
    struct.pack_into('<I', buf, nt + 8, timestamp)
    struct.pack_into('<H', buf, nt + 20, size_opt)
    opt = nt + 24
    struct.pack_into('<H', buf, opt, magic)
    struct.pack_into('<I', buf, opt + 0x38, size_image)
    struct.pack_into('<I', buf, opt + 0x6C, n_rva_sizes)
    struct.pack_into('<I', buf, opt + 0x78, import_rva)
    return opt


def _pack_section(buf, off, name, virtual_size, virtual_addr, raw_size, characteristics):
    buf[off:off + 8] = name.encode('ascii').ljust(8, b'\0')[:8]
    struct.pack_into('<III', buf, off + 8, virtual_size, virtual_addr, raw_size)
    struct.pack_into('<I', buf, off + 36, characteristics)


_SIZE_OPT = 0xF0


def _build_header_only(*, machine=0x8664, magic=0x20B, num_sections=1, n_rva_sizes=0, import_rva=0,
                        virtual_size=0x1000, raw_size=0x1000, truncate_at_opt=False):
    header = bytearray(0x2000)
    opt = _pack_header(header, e_lfanew=0x80, machine=machine, num_sections=num_sections, timestamp=0,
                        size_opt=_SIZE_OPT, magic=magic, size_image=0x1000, n_rva_sizes=n_rva_sizes, import_rva=import_rva)
    if truncate_at_opt:
        return bytes(header[:opt + _SIZE_OPT])
    if num_sections == 1:
        _pack_section(header, opt + _SIZE_OPT, '.text', virtual_size, 0x1000, raw_size, _CODE_EXEC_READ)
    return bytes(header)


def _build_pe():
    """One synthetic PE32+ image at BASE: 3 sections, KERNEL32/ntdll imports, .text refs, an aligned .data qword."""
    facts = {'base': BASE, 'timestamp': 0x5F5E1000, 'size_image': 0x4000}

    header = bytearray(0x1000)
    opt = _pack_header(header, e_lfanew=0x80, machine=0x8664, num_sections=3, timestamp=facts['timestamp'],
                        size_opt=_SIZE_OPT, magic=0x20B, size_image=facts['size_image'], n_rva_sizes=16, import_rva=0x2050)
    sec_table = opt + _SIZE_OPT
    _pack_section(header, sec_table + 0 * 40, '.text', 0x1000, 0x1000, 0x1000, _CODE_EXEC_READ)
    _pack_section(header, sec_table + 1 * 40, '.rdata', 0x1000, 0x2000, 0x1000, _READ_ONLY)
    _pack_section(header, sec_table + 2 * 40, '.data', 0x1000, 0x3000, 0x1000, _READ_WRITE)

    # --- .rdata: strings, import descriptors, INT/IAT arrays, DLL and hint/name strings ---
    rdata_addr = BASE + 0x2000
    rdata = bytearray(0x109)

    def rrva(off):
        return 0x2000 + off

    wide_bp = _wstr('ByteProperty')
    rdata[0x00:0x00 + len(wide_bp)] = wide_bp
    ascii_fsq = _cstr('ForwardShadingQuality_')
    rdata[0x1A:0x1A + len(ascii_fsq)] = ascii_fsq
    wide_an = _wstr('Accessed None')
    rdata[0x32:0x32 + len(wide_an)] = wide_an  # even offset: wide strings need 2-byte alignment

    # descriptor 0: KERNEL32.dll (has an INT), descriptor 1: ntdll.dll (OriginalFirstThunk == 0), descriptor 2: terminator (zero)
    struct.pack_into('<IIIII', rdata, 0x50, rrva(0x8C), 0, 0, rrva(0xCC), rrva(0xA4))
    struct.pack_into('<IIIII', rdata, 0x64, 0, 0, 0, rrva(0xD9), rrva(0xBC))

    struct.pack_into('<QQQ', rdata, 0x8C, rrva(0xE3), rrva(0xF7), 0)  # KERNEL32 INT: InitializeSRWLock, Sleep, 0
    slot_islock, slot_islock_value = rdata_addr + 0xA4, 0x00007FF612340000
    slot_sleep, slot_sleep_value = rdata_addr + 0xAC, 0x00007FF612345678
    struct.pack_into('<QQQ', rdata, 0xA4, slot_islock_value, slot_sleep_value, 0)  # KERNEL32 IAT
    slot_ntdll, slot_ntdll_value = rdata_addr + 0xBC, 0x8000000000000005  # ordinal #5
    struct.pack_into('<QQ', rdata, 0xBC, slot_ntdll_value, 0)

    k32_name = _cstr('KERNEL32.dll')
    rdata[0xCC:0xCC + len(k32_name)] = k32_name
    ntdll_name = _cstr('ntdll.dll')
    rdata[0xD9:0xD9 + len(ntdll_name)] = ntdll_name
    islock_entry = struct.pack('<H', 0) + _cstr('InitializeSRWLock')
    rdata[0xE3:0xE3 + len(islock_entry)] = islock_entry
    sleep_entry = struct.pack('<H', 0) + _cstr('Sleep')
    rdata[0xF7:0xF7 + len(sleep_entry)] = sleep_entry
    assert len(rdata) == 0x109 and rdata[0xFE] == 0  # Sleep's name NUL, 10 bytes before the segment end

    # --- .data addresses computed early: .text leas below reference the terminator decoys placed there ---
    data_addr = BASE + 0x3000
    decoy_ascii_addr = data_addr + 0x100
    decoy_wide_addr = data_addr + 0x140
    decoy_s06_addr = data_addr + 0x180

    # --- .text: LEA/CALL refs, a find_bytes marker, filled with NOP elsewhere ---
    text_addr = BASE + 0x1000
    text = bytearray(b'\x90' * 0x200)

    def place_lea(off, rex, modrm, target):
        site = text_addr + off
        text[off:off + 3] = bytes((rex, 0x8D, modrm))
        struct.pack_into('<i', text, off + 3, target - (site + 7))

    wide_bp_addr, ascii_fsq_addr, wide_an_addr = rdata_addr + 0x00, rdata_addr + 0x1A, rdata_addr + 0x32
    place_lea(0x10, 0x48, 0x0D, wide_bp_addr)
    site_e8 = text_addr + 0x17
    text[0x17] = 0xE8
    struct.pack_into('<i', text, 0x18, text_addr - (site_e8 + 5))  # backward call: target == text_addr itself
    place_lea(0x30, 0x48, 0x0D, wide_bp_addr + 1)  # decoy: 1 byte past the real string start
    site_ff = text_addr + 0x40
    text[0x40:0x42] = bytes((0xFF, 0x15))
    struct.pack_into('<i', text, 0x42, slot_islock - (site_ff + 6))
    text[0x60:0x63] = bytes((0xAB, 0xAB, 0xAB))  # overlapping find_bytes marker
    text[0x70:0x78] = bytes((0x48, 0x8D, 0x04, 0x25, 0, 0, 0, 0))  # SIB LEA (mod=00,rm=100): not RIP-relative, must be ignored
    place_lea(0x80, 0x4C, 0x05, ascii_fsq_addr)
    backward_lea_site, backward_lea_target = text_addr + 0x90, text_addr + 0x05
    place_lea(0x90, 0x48, 0x0D, backward_lea_target)  # backward lea (review-2 I2): target precedes the site
    place_lea(0xA0, 0x48, 0x15, wide_an_addr)
    place_lea(0xB0, 0x48, 0x0D, decoy_ascii_addr)  # must never surface in string_refs('ForwardShadingQuality_')
    place_lea(0xC0, 0x48, 0x0D, decoy_wide_addr)  # must never surface in string_refs('ByteProperty', wide=True)
    place_lea(0xD0, 0x48, 0x0D, decoy_s06_addr)  # must never surface in string_refs('ByteProperty', wide=True)
    place_lea(0xE0, 0x40, 0x0D, wide_bp_addr)  # REX 0x40 (W=0): not a 64-bit RIP-relative lea, must be ignored
    struct.pack_into('<Q', text, 0x140, 0x1122334455667788)  # decoy aligned qword in an executable section

    # --- .data: an aligned qword, the same bytes 4-mod-8 elsewhere, last page unmapped ---
    data = bytearray(0xE00)
    qword = struct.pack('<Q', 0x1122334455667788)
    data[0x10:0x18] = qword
    data[0x24:0x2C] = qword

    # terminator decoys (review-2 I3): longer strings that share a prefix with the real ones but must
    # never satisfy a properly NUL-terminated needle. Referenced by .text leas above; string_refs must
    # never include those sites.
    decoy_ascii = _cstr('ForwardShadingQuality_X')
    data[0x100:0x100 + len(decoy_ascii)] = decoy_ascii
    decoy_wide = _wstr('BytePropertyX')
    data[0x140:0x140 + len(decoy_wide)] = decoy_wide
    # S06 decoy: 'ByteProperty' followed by a wide char whose low byte is 0x00 (U+4100), not a real
    # double-NUL terminator; a 1-null-byte terminator check would wrongly accept it.
    decoy_s06 = _wstr('ByteProperty')[:-2] + struct.pack('<H', 0x4100)
    data[0x180:0x180 + len(decoy_s06)] = decoy_s06

    segments = {BASE: bytes(header), rdata_addr: bytes(rdata), text_addr: bytes(text), data_addr: bytes(data)}
    facts.update(
        text_addr=text_addr, rdata_addr=rdata_addr, data_addr=data_addr,
        wide_bp_addr=wide_bp_addr, ascii_fsq_addr=ascii_fsq_addr, wide_an_addr=wide_an_addr,
        slot_islock=slot_islock, slot_islock_value=slot_islock_value,
        slot_sleep=slot_sleep, slot_sleep_value=slot_sleep_value,
        slot_ntdll=slot_ntdll, slot_ntdll_value=slot_ntdll_value,
        marker_addr=text_addr + 0x60,
        data_qword_aligned=data_addr + 0x10, data_qword_unaligned=data_addr + 0x24,
        backward_lea_site=backward_lea_site, backward_lea_target=backward_lea_target,
        decoy_ascii_addr=decoy_ascii_addr, decoy_wide_addr=decoy_wide_addr, decoy_s06_addr=decoy_s06_addr,
    )
    return segments, facts


class PeTests(unittest.TestCase):
    def setUp(self):
        self.segments, self.facts = _build_pe()
        self.source = _Pages(self.segments)
        self.image = PeImage(self.source, BASE)

    def test_headers(self):
        img, f = self.image, self.facts
        self.assertEqual(img.size, f['size_image'])
        self.assertEqual(img.timestamp, f['timestamp'])
        self.assertEqual(img.machine, 0x8664)
        self.assertEqual([s.name for s in img.sections], ['.text', '.rdata', '.data'])
        text, rdata, data = img.sections
        self.assertEqual((text.address, text.size), (f['text_addr'], 0x1000))
        self.assertTrue(text.executable)
        self.assertFalse(text.writable)
        self.assertEqual((rdata.address, rdata.size), (f['rdata_addr'], 0x1000))
        self.assertFalse(rdata.executable)
        self.assertFalse(rdata.writable)
        self.assertEqual((data.address, data.size), (f['data_addr'], 0x1000))
        self.assertFalse(data.executable)
        self.assertTrue(data.writable)
        self.assertIs(img.section('.data'), data)
        self.assertIsNone(img.section('.nope'))
        self.assertIsNone(img.section('.DATA'))  # exact, case-sensitive match only
        self.assertEqual(img.rva(f['text_addr']), 0x1000)

    def test_virtualsize_zero(self):
        blob = _build_header_only(virtual_size=0, raw_size=0x800)
        img = PeImage(_Pages({BASE: blob}), BASE)
        self.assertEqual(img.sections[0].size, 0x800)

    def test_imports(self):
        f = self.facts
        slots = self.image.import_slots('InitializeSRWLock')
        self.assertEqual(len(slots), 1)
        self.assertEqual((slots[0].dll, slots[0].slot, slots[0].value), ('kernel32.dll', f['slot_islock'], f['slot_islock_value']))
        ordinal = self.image.import_slots('#5')
        self.assertEqual(len(ordinal), 1)
        self.assertEqual((ordinal[0].dll, ordinal[0].slot, ordinal[0].value), ('ntdll.dll', f['slot_ntdll'], f['slot_ntdll_value']))
        self.assertEqual(self.image.import_slots('Lock'), [])  # exact match only, not a substring match
        self.assertEqual(len(self.image.imports()), 3)  # no spurious entries past the real 3

    def test_imports_cached(self):
        calls = []
        orig = PeImage._compute_imports

        def counting(self):
            calls.append(1)
            return orig(self)

        PeImage._compute_imports = counting
        try:
            self.image.imports()
            self.image.imports()
            self.image.import_slots('Sleep')
        finally:
            PeImage._compute_imports = orig
        self.assertEqual(len(calls), 1)

    def test_bad_images(self):
        good = bytearray(_build_header_only(num_sections=1))
        no_mz = bytearray(good)
        no_mz[0:2] = b'XX'
        no_pe = bytearray(good)
        no_pe[0x80:0x84] = b'XXXX'
        cases = {
            'no_mz': (bytes(no_mz), 'no MZ signature'),
            'no_pe_sig': (bytes(no_pe), 'no PE signature'),
            'machine': (_build_header_only(machine=0x14C), f'machine {0x14C:#x} is not AMD64'),
            'not_pe32_plus': (_build_header_only(magic=0x10B), 'not PE32+'),
            'too_many_sections': (_build_header_only(num_sections=97), 'too many sections'),
        }
        for label, (blob, reason) in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(PeFormatError) as cm:
                    PeImage(_Pages({BASE: blob}), BASE)
                self.assertEqual(cm.exception.reason, reason)

        with self.subTest(label='unreadable_section_table'):
            truncated = _build_header_only(num_sections=1, truncate_at_opt=True)
            with self.assertRaises(PeFormatError) as cm:
                PeImage(_Pages({BASE: truncated}), BASE)
            self.assertTrue(cm.exception.reason.startswith('unreadable header:'), cm.exception.reason)

        with self.subTest(label='negative_base'):
            with self.assertRaises(PeFormatError) as cm:
                PeImage(_Pages(self.segments), -1)
            self.assertEqual(cm.exception.reason, 'unreadable header: address out of range')

    def test_domain(self):
        with self.assertRaises(TypeError):
            PeImage(self.source, 1.0)
        with self.assertRaises(TypeError):
            self.image.section(1)
        with self.assertRaises(TypeError):
            self.image.rva('x')
        with self.assertRaises(TypeError):
            self.image.import_slots(None)

    def test_imports_resilient(self):
        broken = bytearray(self.segments[self.facts['rdata_addr']])
        struct.pack_into('<Q', broken, 0x8C, 0x2000 + 0x800)  # InitializeSRWLock's INT entry now points unmapped
        segments2 = dict(self.segments)
        segments2[self.facts['rdata_addr']] = bytes(broken)
        img = PeImage(_Pages(segments2), BASE)
        self.assertEqual(img.import_slots('InitializeSRWLock'), [])
        self.assertEqual(len(img.import_slots('Sleep')), 1)  # sibling entry in the same descriptor still resolves

        empty_dir = _build_header_only(n_rva_sizes=2, import_rva=0)
        self.assertEqual(PeImage(_Pages({BASE: empty_dir}), BASE).imports(), [])

        one_rva_size = _build_header_only(n_rva_sizes=1, import_rva=0x500)
        self.assertEqual(PeImage(_Pages({BASE: one_rva_size}), BASE).imports(), [])

        # NumberOfRvaAndSizes == 2 is not "< 2": the import table must still be parsed.
        header_two = bytearray(self.segments[BASE])
        struct.pack_into('<I', header_two, 0x104, 2)  # opt+0x6C for e_lfanew=0x80
        segments_two = dict(self.segments)
        segments_two[BASE] = bytes(header_two)
        self.assertEqual(len(PeImage(_Pages(segments_two), BASE).imports()), 3)

        # a name RVA landing in a gap just before mapped bytes must not read past the gap.
        gap_segments = dict(self.segments)
        gap_segments[self.facts['rdata_addr'] + 0x300] = b'FAKE.dll\0'
        broken_gap = bytearray(self.segments[self.facts['rdata_addr']])
        struct.pack_into('<I', broken_gap, 0x5C, 0x2000 + 0x2FA)  # descriptor0.Name -> 6 bytes before the fake segment
        gap_segments[self.facts['rdata_addr']] = bytes(broken_gap)
        img_gap = PeImage(_Pages(gap_segments), BASE)
        self.assertEqual(img_gap.import_slots('InitializeSRWLock'), [])
        self.assertEqual(len(img_gap.import_slots('#5')), 1)  # ntdll descriptor is untouched

        # a non-ASCII byte in a hint/name string makes that one entry (not the descriptor) unreadable.
        broken_ascii = bytearray(self.segments[self.facts['rdata_addr']])
        broken_ascii[0xF9] = 0xFF  # first byte of Sleep's name, was 'S'
        ascii_segments = dict(self.segments)
        ascii_segments[self.facts['rdata_addr']] = bytes(broken_ascii)
        img_ascii = PeImage(_Pages(ascii_segments), BASE)
        self.assertEqual(img_ascii.import_slots('Sleep'), [])
        self.assertEqual(len(img_ascii.imports()), 2)

        # the ordinal mask must keep all 16 bits, not just the low byte.
        broken_ord = bytearray(self.segments[self.facts['rdata_addr']])
        struct.pack_into('<Q', broken_ord, 0xBC, 0x8000000000000105)  # ordinal 0x105, not representable in 8 bits
        ord_segments = dict(self.segments)
        ord_segments[self.facts['rdata_addr']] = bytes(broken_ord)
        self.assertEqual(len(PeImage(_Pages(ord_segments), BASE).import_slots('#261')), 1)

    def test_descriptor_zero_terminator_stops_loop(self):
        # an all-zero descriptor must end enumeration, even when a resolvable descriptor follows it.
        header = bytearray(0x1000)
        opt = _pack_header(header, e_lfanew=0x80, machine=0x8664, num_sections=1, timestamp=0,
                            size_opt=_SIZE_OPT, magic=0x20B, size_image=0x1000, n_rva_sizes=2, import_rva=0x300)
        _pack_section(header, opt + _SIZE_OPT, '.text', 0x1000, 0x1000, 0x1000, _CODE_EXEC_READ)
        # descriptor0 @ 0x300 stays all-zero (20 bytes); descriptor1 @ 0x314 would resolve if ever reached.
        struct.pack_into('<IIIII', header, 0x314, 0, 0, 0, 0x340, 0x330)
        struct.pack_into('<QQ', header, 0x330, 0x8000000000000007, 0)
        header[0x340:0x344] = b'x\0\0\0'
        img = PeImage(_Pages({BASE: bytes(header)}), BASE)
        self.assertEqual(img.imports(), [])

    def test_import_name_at_segment_end(self):
        f = self.facts
        slots = self.image.import_slots('Sleep')
        self.assertEqual(len(slots), 1)
        self.assertEqual((slots[0].dll, slots[0].slot, slots[0].value), ('kernel32.dll', f['slot_sleep'], f['slot_sleep_value']))

    def test_imports_resilient_dll_name_read_fails(self):
        # review-2 I1: readable_ranges says the KERNEL32 name is readable, but _read fails there anyway
        # (stale map / race). imports() must not raise; only the untouched ntdll descriptor resolves.
        k32_name_addr = self.facts['rdata_addr'] + 0xCC
        lying = _LyingReadableRange(self.segments, k32_name_addr, k32_name_addr + 1)
        img = PeImage(lying, BASE)
        self.assertEqual(img.import_slots('InitializeSRWLock'), [])
        self.assertEqual(img.import_slots('Sleep'), [])
        self.assertEqual(len(img.import_slots('#5')), 1)
        self.assertEqual(len(img.imports()), 1)

    def test_rva_sizes_one_with_real_descriptor_present(self):
        # review-2 R07: NumberOfRvaAndSizes == 1 must short-circuit to [] even when import_rva points at
        # a real, resolvable descriptor table (not just an empty/garbage one).
        header_one = bytearray(self.segments[BASE])
        struct.pack_into('<I', header_one, 0x104, 1)  # opt+0x6C for e_lfanew=0x80
        segments_one = dict(self.segments)
        segments_one[BASE] = bytes(header_one)
        self.assertEqual(PeImage(_Pages(segments_one), BASE).imports(), [])

    def test_import_rva_zero_short_circuits_even_when_rva0_parses(self):
        # review-2 R08: import_rva == 0 must short-circuit to [] even though the mandatory 'MZ' bytes at
        # rva 0 happen to decode into a real, resolvable descriptor if that check is skipped.
        header = bytearray(0x8000)
        _pack_header(header, e_lfanew=0x80, machine=0x8664, num_sections=1, timestamp=0,
                      size_opt=_SIZE_OPT, magic=0x20B, size_image=0x8000, n_rva_sizes=2, import_rva=0)
        thunk_rva = int.from_bytes(header[0:4], 'little')  # b'MZ\x00\x00' -> 0x5A4D, forced by the MZ signature
        struct.pack_into('<H', header, thunk_rva + 0x10, 0)  # hint
        name = b'FakeImport\0'
        header[thunk_rva + 0x12:thunk_rva + 0x12 + len(name)] = name
        struct.pack_into('<Q', header, thunk_rva, thunk_rva + 0x10)  # thunk[0] -> name rva (bit63 clear)
        struct.pack_into('<Q', header, thunk_rva + 8, 0)  # terminator
        struct.pack_into('<I', header, 16, thunk_rva)  # descriptor0.FirstThunk == OriginalFirstThunk
        img = PeImage(_Pages({BASE: bytes(header)}), BASE)
        self.assertEqual(img.imports(), [])

    def test_capture_errors_propagate(self):
        # review-2 R03/R04: a lazily loaded capture's CaptureError, and a closed capture's
        # ValueError('capture is closed'), must pass through unchanged, both at construction and from imports().
        with self.assertRaises(CaptureError):
            PeImage(_RaisingPages(self.segments, CaptureError('x.cap', 'corrupt')), BASE)
        with self.assertRaises(ValueError) as cm:
            PeImage(_RaisingPages(self.segments, ValueError('capture is closed')), BASE)
        self.assertEqual(str(cm.exception), 'capture is closed')

        src = _RaisingPages(self.segments, CaptureError('x.cap', 'corrupt'), after=10 ** 9)
        img = PeImage(src, BASE)
        src.after = src.n
        with self.assertRaises(CaptureError):
            img.imports()

        src2 = _RaisingPages(self.segments, ValueError('capture is closed'), after=10 ** 9)
        img2 = PeImage(src2, BASE)
        src2.after = src2.n
        with self.assertRaises(ValueError) as cm2:
            img2.imports()
        self.assertEqual(str(cm2.exception), 'capture is closed')

    def test_imports_returns_copy(self):
        # review-2 R09: imports() must return a fresh list each time, not the cache's own list.
        result = self.image.imports()
        result.append('bogus')
        self.assertEqual(len(self.image.imports()), 3)

    def test_cstring_window_and_no_nul(self):
        # review-2 R05/R06: no NUL within the 512-byte window -> None; a NUL past a too-small window
        # (e.g. 32 bytes) must still be found within the real 512-byte window.
        addr = BASE + 0x9000
        long_ident = b'A' * 40 + b'\0'
        self.assertEqual(_read_cstring(_Pages({addr: long_ident + b'B' * 600}), addr), 'A' * 40)
        self.assertIsNone(_read_cstring(_Pages({addr: b'C' * 600}), addr))

    def test_section_contains_bounds(self):
        # review-2 R12/R13: end is exclusive, and a non-int address must raise TypeError even when it
        # would otherwise compare fine (a float is orderable against int without the explicit check).
        text = self.image.sections[0]
        self.assertTrue(text.contains(text.address))
        self.assertTrue(text.contains(text.end - 1))
        self.assertFalse(text.contains(text.end))
        with self.assertRaises(TypeError):
            text.contains(1.0)

    def test_section_size_uses_virtual_size_not_max(self):
        # review-2 R02: a nonzero VirtualSize smaller than SizeOfRawData must win outright, not max(vs, rs).
        blob = _build_header_only(virtual_size=0x500, raw_size=0x1000)
        img = PeImage(_Pages({BASE: blob}), BASE)
        self.assertEqual(img.sections[0].size, 0x500)

    def test_section_table_uses_size_of_optional_header(self):
        # review-2 R01: the section table must sit at opt + SizeOfOptionalHeader, not a hardcoded 0xF0.
        size_opt = 0x140
        header = bytearray(0x1000)
        opt = _pack_header(header, e_lfanew=0x80, machine=0x8664, num_sections=1, timestamp=0,
                            size_opt=size_opt, magic=0x20B, size_image=0x1000, n_rva_sizes=0, import_rva=0)
        _pack_section(header, opt + size_opt, '.text', 0x100, 0x1000, 0x100, _CODE_EXEC_READ)
        img = PeImage(_Pages({BASE: bytes(header)}), BASE)
        self.assertEqual(img.sections[0].address, BASE + 0x1000)

    def test_section_first_match_with_duplicate_names(self):
        # review-2 R14: section(name) returns the first exact match, not the last.
        header = bytearray(0x1000)
        opt = _pack_header(header, e_lfanew=0x80, machine=0x8664, num_sections=2, timestamp=0,
                            size_opt=_SIZE_OPT, magic=0x20B, size_image=0x3000, n_rva_sizes=0, import_rva=0)
        sec_table = opt + _SIZE_OPT
        _pack_section(header, sec_table + 0 * 40, '.data', 0x100, 0x1000, 0x100, _READ_ONLY)
        _pack_section(header, sec_table + 1 * 40, '.data', 0x100, 0x2000, 0x100, _READ_WRITE)
        img = PeImage(_Pages({BASE: bytes(header)}), BASE)
        first, second = img.sections
        self.assertIsNot(first, second)
        self.assertIs(img.section('.data'), first)


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.segments, self.facts = _build_pe()
        self.source = _Pages(self.segments)
        self.image = PeImage(self.source, BASE)
        self.scanner = Scanner(self.source, self.image)

    def test_chunks(self):
        data_chunks = self.scanner.chunks(self.image.section('.data'))
        self.assertEqual(len(data_chunks), 1)
        self.assertEqual(data_chunks[0], (self.facts['data_addr'], self.segments[self.facts['data_addr']]))

        text_chunks = self.scanner.chunks(self.image.section('.text'))
        self.assertEqual(len(text_chunks), 1)
        self.assertEqual(text_chunks[0][0], self.facts['text_addr'])

        src2 = _WithSibling(self.segments)
        img2 = PeImage(src2, BASE)
        scanner2 = Scanner(src2, img2)
        src2.direct_reads = 0
        src2.sibling.reads = 0
        scanner2.chunks(img2.section('.data'))
        self.assertGreater(src2.sibling.reads, 0)
        self.assertEqual(src2.direct_reads, 0)

    def test_chunks_cached(self):
        calls = []
        orig = MemorySource.readable_ranges

        def counting(self, address, size):
            calls.append(1)
            return orig(self, address, size)

        MemorySource.readable_ranges = counting
        try:
            section = self.image.section('.data')
            self.scanner.chunks(section)
            self.scanner.chunks(section)
            self.scanner.chunks(section)
        finally:
            MemorySource.readable_ranges = orig
        self.assertEqual(len(calls), 1)

    def test_pattern(self):
        matches = self.scanner.find_pattern('48 8D 0D * * * * E8', executable=True)
        self.assertEqual(matches, [(self.facts['text_addr'] + 0x10, [self.facts['wide_bp_addr']])])
        with self.assertRaises(TypeError):
            self.scanner.find_pattern(5)
        with self.assertRaises(TypeError):
            self.scanner.find_pattern('48', executable=1)

    def test_pattern_value_capture_not_rebased(self):
        # review-2 S19: a non-ref (`?`) capture must stay the raw matched value, never rebased by + base_addr.
        f = self.facts
        matches = self.scanner.find_pattern('48 8D 0D <? ? ? ?> E8', executable=True)
        self.assertEqual(len(matches), 1)
        addr, vals = matches[0]
        self.assertEqual(addr, f['text_addr'] + 0x10)
        raw_disp = f['wide_bp_addr'] - (f['text_addr'] + 0x10 + 7)
        self.assertEqual(vals, [raw_disp])

    def test_pattern_malformed(self):
        # review-2 M1: nylib.pattern raises AssertionError/IndexError/ValueError for the first three, and
        # OverflowError (not one of those three) for the repeat-count case; all must surface as ValueError.
        for bad in ('4', '48 [', '(48', '48{4294967296}', '48 [48', '[48|zz]'):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError) as cm:
                    self.scanner.find_pattern(bad)
                self.assertIn(bad, str(cm.exception))

    def test_string_refs(self):
        self.assertEqual(self.scanner.string_refs('ByteProperty', wide=True), [self.facts['text_addr'] + 0x10])
        self.assertEqual(self.scanner.string_refs('ForwardShadingQuality_', wide=False), [self.facts['text_addr'] + 0x80])
        self.assertEqual(self.scanner.string_refs('NoSuchString', wide=True), [])
        with self.assertRaises(ValueError):
            self.scanner.string_refs('', wide=True)

    def test_string_refs_cache_key_includes_wide(self):
        wide_refs = self.scanner.string_refs('ByteProperty', wide=True)
        narrow_refs = self.scanner.string_refs('ByteProperty', wide=False)  # distinct cache entry from the wide one
        self.assertEqual(wide_refs, [self.facts['text_addr'] + 0x10])
        self.assertEqual(narrow_refs, [])  # the ASCII encoding of "ByteProperty" occurs nowhere in the image

    def test_string_refs_returns_copy(self):
        # review-2 M2: string_refs must return a fresh list each time, not the cache's own list.
        result = self.scanner.string_refs('ByteProperty', wide=True)
        result.append(0xBAD)
        self.assertEqual(self.scanner.string_refs('ByteProperty', wide=True), [self.facts['text_addr'] + 0x10])

    def test_prefetch_string_refs_domain(self):
        # review-2 M3 (amended F5): items must be real 2-tuples (str, bool); wide must be an actual bool.
        for bad in (['ab'], ('x', None), ('x', 1)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    self.scanner.prefetch_string_refs([bad])
        with self.assertRaises(ValueError):
            self.scanner.prefetch_string_refs([('', True)])  # review-2 S13: empty text still checked

    def test_find_string_wide_alignment(self):
        wide = 'Hi'.encode('utf-16-le') + b'\0\0'
        buf = bytearray(0x40)
        buf[0x10:0x10 + len(wide)] = wide  # even offset: a genuine occurrence
        buf[0x21:0x21 + len(wide)] = wide  # odd offset: must be filtered out by align=2
        blob = _build_header_only(virtual_size=len(buf), raw_size=len(buf))[:0x200]  # truncated so it doesn't cover RVA 0x1000
        segments = {BASE: blob, BASE + 0x1000: bytes(buf)}
        src = _Pages(segments)
        img = PeImage(src, BASE)
        scanner = Scanner(src, img)
        self.assertEqual(scanner.find_string('Hi', wide=True), [BASE + 0x1000 + 0x10])

    def test_string_refs_batched(self):
        calls = []
        orig = Scanner.lea_refs

        def counting(self, targets):
            calls.append(1)
            return orig(self, targets)

        Scanner.lea_refs = counting
        try:
            self.scanner.prefetch_string_refs([
                ('ByteProperty', True), ('ForwardShadingQuality_', False), ('Accessed None', True),
            ])
            self.assertEqual(len(calls), 1)
            r1 = self.scanner.string_refs('ByteProperty', wide=True)
            r2 = self.scanner.string_refs('ForwardShadingQuality_', wide=False)
            r3 = self.scanner.string_refs('Accessed None', wide=True)
            self.assertEqual(len(calls), 1)
            self.scanner.prefetch_string_refs([('ByteProperty', True)])
            self.assertEqual(len(calls), 1)
        finally:
            Scanner.lea_refs = orig
        self.assertEqual(r1, [self.facts['text_addr'] + 0x10])
        self.assertEqual(r2, [self.facts['text_addr'] + 0x80])
        self.assertEqual(r3, [self.facts['text_addr'] + 0xA0])

    def test_lea_refs(self):
        self.assertEqual(self.scanner.lea_refs([]), {})
        result = self.scanner.lea_refs([self.facts['wide_bp_addr'], 0xDEADBEEF])
        # only the real REX 0x48 site resolves; the REX 0x40 decoy at text+0xE0 must be excluded (review-2 S20).
        self.assertEqual(result[self.facts['wide_bp_addr']], [self.facts['text_addr'] + 0x10])
        self.assertEqual(result[0xDEADBEEF], [])
        with self.assertRaises(TypeError):
            self.scanner.lea_refs(['x'])

    def test_lea_refs_empty_does_not_scan(self):
        # review-2 S11: an empty targets iterable must return {} without scanning any chunk.
        orig = Scanner._all_chunks

        def spy(self, executable):
            raise AssertionError('lea_refs([]) must not scan chunks')

        Scanner._all_chunks = spy
        try:
            self.assertEqual(self.scanner.lea_refs([]), {})
        finally:
            Scanner._all_chunks = orig

    def test_lea_refs_backward_displacement(self):
        # review-2 I2/S09: a negative rel32 (target before the site) must be decoded as signed, not unsigned.
        f = self.facts
        result = self.scanner.lea_refs([f['backward_lea_target']])
        self.assertEqual(result[f['backward_lea_target']], [f['backward_lea_site']])

    def test_lea_refs_requires_rip_relative_modrm(self):
        # a SIB-addressed LEA (mod=00, rm=100) at text+0x70 must never be treated as RIP-relative.
        # (a mod-only modrm check would misread the SIB byte 0x25 as the low disp32 byte, landing on +7+0x25.)
        sib_target = self.facts['text_addr'] + 0x70 + 7 + 0x25
        self.assertEqual(self.scanner.lea_refs([sib_target]), {sib_target: []})

    def test_aligned_values(self):
        f = self.facts
        # the default (executable=False) must exclude the decoy qword placed in the executable .text section
        # (review-2 S14: a mutant defaulting executable to None would pull it in too).
        self.assertEqual(self.scanner.aligned_values(0x1122334455667788), [f['data_qword_aligned']])
        self.assertEqual(self.scanner.aligned_values(0x1122334455667788, executable=True), [f['text_addr'] + 0x140])
        with self.assertRaises(ValueError):
            self.scanner.aligned_values(0x1122334455667788, size=3)
        with self.assertRaises(ValueError):
            self.scanner.aligned_values(-1)
        with self.assertRaises(ValueError):
            self.scanner.aligned_values(2 ** 64, size=8)  # upper bound (review-2 S18)

    def test_find_bytes(self):
        needle = bytes((0xAB, 0xAB))
        base = self.facts['marker_addr']
        self.assertEqual(self.scanner.find_bytes(needle, executable=True), [base, base + 1])
        self.assertEqual(self.scanner.find_bytes(needle, align=2, executable=True), [a for a in (base, base + 1) if a % 2 == 0])
        with self.assertRaises(ValueError):
            self.scanner.find_bytes(b'')
        with self.assertRaises(TypeError):
            self.scanner.find_bytes('ab')
        with self.assertRaises(ValueError):
            self.scanner.find_bytes(needle, align=0)
        with self.assertRaises(TypeError):
            self.scanner.find_bytes(needle, align=1.0)  # review-2 S04
        with self.assertRaises(TypeError):
            self.scanner.find_bytes(needle, executable=1)  # review-2 S16

    def test_rip_target(self):
        site = self.facts['text_addr'] + 0x40
        self.assertEqual(self.scanner.rip_target(site, 2, 6), self.facts['slot_islock'])
        with self.assertRaises(MemoryReadError):
            self.scanner.rip_target(BASE + 0x9000, 0, 4)
        # review-2 I2/S10: a negative rel32 (backward call) must be decoded as signed, not unsigned.
        f = self.facts
        self.assertEqual(self.scanner.rip_target(f['text_addr'] + 0x17, 1, 5), f['text_addr'])

    def test_chunks_retries_once_after_transient_failure(self):
        # review-2 M6 (amended F5): a read that fails is retried once after re-querying fresh.readable_ranges;
        # a transient failure anywhere in the range must not drop the whole section.
        src = _WithFlakyFresh(self.segments)
        img = PeImage(src, BASE)
        scanner = Scanner(src, img)
        data_chunks = scanner.chunks(img.section('.data'))
        self.assertEqual(data_chunks, [(self.facts['data_addr'], self.segments[self.facts['data_addr']])])

    def test_chunks_cache_keyed_by_name_and_address(self):
        # review-2 S02: two sections sharing a name but different addresses must not collide in the cache.
        header = bytearray(0x1000)
        opt = _pack_header(header, e_lfanew=0x80, machine=0x8664, num_sections=2, timestamp=0,
                            size_opt=_SIZE_OPT, magic=0x20B, size_image=0x3000, n_rva_sizes=0, import_rva=0)
        sec_table = opt + _SIZE_OPT
        _pack_section(header, sec_table + 0 * 40, '.data', 0x100, 0x1000, 0x100, _READ_ONLY)
        _pack_section(header, sec_table + 1 * 40, '.data', 0x100, 0x2000, 0x100, _READ_WRITE)
        segments = {BASE: bytes(header), BASE + 0x1000: b'A' * 0x100, BASE + 0x2000: b'B' * 0x100}
        src = _Pages(segments)
        img = PeImage(src, BASE)
        scanner = Scanner(src, img)
        first, second = img.sections
        self.assertEqual(scanner.chunks(first), [(BASE + 0x1000, b'A' * 0x100)])
        self.assertEqual(scanner.chunks(second), [(BASE + 0x2000, b'B' * 0x100)])


if __name__ == '__main__':
    unittest.main()
