"""MSF 7.0 container: writer, seek-based reader, and the DBI section-header stream."""
import struct

from .pe_info import SectionHeader

BLOCK_SIZE = 4096
MSF_MAGIC = b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00'
_FPM_BLOCK = 1


def _is_fpm(b: int, bs: int) -> bool:
    return b % bs in (1, 2)


def write_msf(streams, *, block_size: int = BLOCK_SIZE) -> bytes:
    """Serialize ``streams`` (each ``bytes`` or ``None``) into an MSF 7.0 file.

    Stream 0 (the previous directory) is written but its pages stay free in the
    FPM, matching link.exe: a reader replaces stream 0's page list with the live
    directory's own pages at open.
    Never allocates a block ``k*block_size+1``/``+2`` (FPM intervals).
    ``ValueError`` when the stream directory needs more than one block.
    """
    bs = block_size
    if bs < 64 or bs & (bs - 1):
        raise ValueError(f'block_size must be a power of two >= 64, got {bs}')
    nxt = [3]

    def alloc(n):
        out = []
        while len(out) < n:
            b = nxt[0]
            nxt[0] += 1
            if not _is_fpm(b, bs):
                out.append(b)
        return out

    data = {}
    lists = []
    for s in streams:
        s = s or b''
        bl = alloc((len(s) + bs - 1) // bs)
        lists.append(bl)
        for i, b in enumerate(bl):
            data[b] = s[i * bs:(i + 1) * bs]

    d = struct.pack('<I', len(streams)) + b''.join(struct.pack('<I', len(s or b'')) for s in streams)
    d += b''.join(struct.pack('<I', b) for bl in lists for b in bl)
    dir_blocks = alloc((len(d) + bs - 1) // bs)
    for i, b in enumerate(dir_blocks):
        data[b] = d[i * bs:(i + 1) * bs]
    bm = b''.join(struct.pack('<I', b) for b in dir_blocks)
    if len(bm) > bs:
        raise ValueError('MSF directory block list needs more than one block')
    bm_block = alloc(1)[0]
    data[bm_block] = bm

    num_blocks = nxt[0]
    used = (set(data) - set(lists[0] if lists else ())) | {0} | {b for b in range(num_blocks) if _is_fpm(b, bs)}
    nbytes = (num_blocks + 7) // 8
    fpm = bytearray(b'\xff' * (((nbytes + bs - 1) // bs) * bs))
    for b in used:
        fpm[b // 8] &= ~(1 << (b % 8)) & 0xFF
    # every reserved FPM slot pair defaults to 0xFF (LLVM layout), even beyond the active bitmap
    for k in range((num_blocks + bs - 1) // bs):
        for off in (1, 2):
            b = k * bs + off
            if b < num_blocks:
                data.setdefault(b, b'\xff' * bs)
    for k in range(len(fpm) // bs):
        data[k * bs + _FPM_BLOCK] = bytes(fpm[k * bs:(k + 1) * bs])

    sb = MSF_MAGIC + struct.pack('<IIIIII', bs, _FPM_BLOCK, num_blocks, len(d), 0, bm_block)
    data[0] = sb
    out = bytearray(num_blocks * bs)
    for b, chunk in data.items():
        out[b * bs:b * bs + len(chunk)] = chunk
    return bytes(out)


class MsfReader:
    """Seek-based MSF 7.0 reader; never reads the whole file eagerly."""

    def __init__(self, path):
        self._f = open(path, 'rb')
        try:
            self._open()
        except Exception:
            self._f.close()
            raise

    def _open(self):
        magic = self._f.read(len(MSF_MAGIC))
        if magic != MSF_MAGIC:
            raise ValueError(f'bad MSF magic: {magic!r}')
        sb = self._f.read(24)
        if len(sb) < 24:
            raise ValueError('truncated MSF superblock')
        bs, fpm_block, num_blocks, num_dir_bytes, _unk, bm_block = struct.unpack('<IIIIII', sb)
        if bs < 64 or bs & (bs - 1):
            raise ValueError(f'bad MSF block size: {bs}')
        if not 0 <= bm_block < num_blocks:
            raise ValueError(f'bad MSF block-map block: {bm_block}')
        self._bs = bs
        self._num_blocks = num_blocks
        n_dir_blocks = (num_dir_bytes + bs - 1) // bs
        if n_dir_blocks * 4 > bs:
            raise ValueError('MSF directory block list needs more than one block')
        dir_block_nums = struct.unpack(f'<{n_dir_blocks}I', self._read_block(bm_block)[:n_dir_blocks * 4])
        d = b''.join(self._read_block(b) for b in dir_block_nums)[:num_dir_bytes]
        if len(d) < 4:
            raise ValueError('truncated MSF directory')
        (n,) = struct.unpack_from('<I', d, 0)
        if 4 + 4 * n > len(d):
            raise ValueError('truncated MSF directory')
        sizes = struct.unpack_from(f'<{n}I', d, 4)
        pos = 4 + 4 * n
        self._streams = []
        for sz in sizes:
            cnt = 0 if sz in (0, 0xFFFFFFFF) else (sz + bs - 1) // bs
            if pos + 4 * cnt > len(d):
                raise ValueError('truncated MSF directory')
            blocks = struct.unpack_from(f'<{cnt}I', d, pos)
            pos += 4 * cnt
            self._streams.append((0 if sz == 0xFFFFFFFF else sz, blocks))

    def _read_block(self, b: int) -> bytes:
        if not 0 <= b < self._num_blocks:
            raise ValueError(f'truncated MSF: block {b} out of range')
        self._f.seek(b * self._bs)
        data = self._f.read(self._bs)
        if len(data) < self._bs:
            raise ValueError(f'truncated MSF: short read at block {b}')
        return data

    @property
    def num_streams(self) -> int:
        return len(self._streams)

    @property
    def block_size(self) -> int:
        return self._bs

    def stream_size(self, i: int) -> int:
        return self._streams[i][0]

    def stream_blocks(self, i: int) -> tuple:
        return self._streams[i][1]

    def read_stream(self, i: int) -> bytes:
        size, blocks = self._streams[i]
        return b''.join(self._read_block(b) for b in blocks)[:size]

    def close(self):
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def read_section_headers(pdb_path) -> list[SectionHeader]:
    """Read the PE section headers recorded in a PDB's DBI optional debug header.

    ``[]`` when the DBI optional debug header has no slot 5, or it is 0xFFFF.
    """
    with MsfReader(pdb_path) as msf:
        dbi = msf.read_stream(3)
        if len(dbi) < 64:
            return []
        hdr = struct.unpack_from('<iIIHHHHHHiiiiiIiiHHI', dbi)
        (_vsig, _ver, _age, _gsi, _build, _psi, _dllver, _symrec, _rbld,
         modi_sz, sc_sz, secmap_sz, fileinfo_sz, tsm_sz, _mfc, dbghdr_sz, ec_sz, _flags, _machine, _res) = hdr
        off = 64 + modi_sz + sc_sz + secmap_sz + fileinfo_sz + tsm_sz + ec_sz
        dbg_hdr = dbi[off:off + dbghdr_sz]
        if len(dbg_hdr) < 6 * 2:
            return []
        slots = struct.unpack_from(f'<{len(dbg_hdr) // 2}H', dbg_hdr)
        if len(slots) <= 5 or slots[5] == 0xFFFF:
            return []
        raw = msf.read_stream(slots[5])
        sections = []
        for i in range(len(raw) // 40):
            name, vs, va, raw_sz, raw_ptr, _a, _b, _c, _d, chars = struct.unpack_from('<8sIIIIIIHHI', raw, 40 * i)
            sections.append(SectionHeader(
                name=name.split(b'\0', 1)[0].decode('latin-1'),
                virtual_address=va, virtual_size=vs, characteristics=chars,
                raw_size=raw_sz, raw_pointer=raw_ptr))
        return sections
