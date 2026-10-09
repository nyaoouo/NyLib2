"""PDB hash/table algorithms: TPI/IPI hash, GSI/PSI hash, named-stream map, /names."""
import functools
import struct
import zlib
from collections.abc import Mapping

from . import _codeview

IPHR_HASH = 4096


def hash_v1(data: bytes) -> int:
    """hashStringV1 / LHashPbCb without the final modulo."""
    r = 0
    n4 = len(data) // 4
    for (w,) in struct.iter_unpack('<I', data[:n4 * 4]):
        r ^= w
    rem = data[n4 * 4:]
    if len(rem) >= 2:
        r ^= struct.unpack_from('<H', rem)[0]
        rem = rem[2:]
    if rem:
        r ^= rem[0]
    r |= 0x20202020
    r ^= r >> 11
    return (r ^ (r >> 16)) & 0xFFFFFFFF


def crc_v8(data: bytes) -> int:
    """hashBufferV8: JamCRC (CRC-32 table, init 0, no final xor)."""
    return zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF


def _read_name_pair(record: bytes, off: int, props: int):
    """``(name, uniqueName)`` as raw bytes (never decoded: a foreign name may not be UTF-8)."""
    end = record.index(b'\0', off)
    name = record[off:end]
    off = end + 1
    unique = None
    if props & _codeview.CO_HASUNIQUENAME:
        end2 = record.index(b'\0', off)
        unique = record[off:end2]
    return name, unique


def _udt_name_info(record: bytes, leaf: int):
    """``(props, name, uniqueName)`` (name/uniqueName as bytes) for a UDT-defining leaf, else ``None``."""
    if leaf in (_codeview.LF_CLASS, _codeview.LF_STRUCTURE, _codeview.LF_INTERFACE):
        props = struct.unpack_from('<H', record, 6)[0]
        off = 20 + _codeview.numeric_len(record, 20)
        return (props,) + _read_name_pair(record, off, props)
    if leaf == _codeview.LF_UNION:
        props = struct.unpack_from('<H', record, 6)[0]
        off = 12 + _codeview.numeric_len(record, 12)
        return (props,) + _read_name_pair(record, off, props)
    if leaf == _codeview.LF_ENUM:
        props = struct.unpack_from('<H', record, 6)[0]
        return (props,) + _read_name_pair(record, 16, props)
    return None


def _is_anon_name(name: bytes) -> bool:
    return name in (b'<unnamed-tag>', b'__unnamed') or name.endswith((b'::<unnamed-tag>', b'::__unnamed'))


def tpi_hash(record: bytes) -> int:
    """TPI/IPI hash value of a full record (length prefix incl.), unreduced (no modulo)."""
    leaf = struct.unpack_from('<H', record, 2)[0]
    info = _udt_name_info(record, leaf)
    if info is not None:
        props, name, unique = info
        fwd = bool(props & _codeview.CO_FWDREF)
        scoped = bool(props & _codeview.CO_SCOPED)
        uniq = bool(props & _codeview.CO_HASUNIQUENAME)
        anon = uniq and _is_anon_name(name)
        if not fwd and not scoped and not anon:
            return hash_v1(name)
        if not fwd and uniq and not anon:
            return hash_v1(unique)
        return crc_v8(record)
    if leaf in (_codeview.LF_UDT_SRC_LINE, _codeview.LF_UDT_MOD_SRC_LINE):
        return hash_v1(record[4:8])
    return crc_v8(record)


def _gsi_cmp(a, b):
    (na, oa), (nb, ob) = a, b
    if len(na) != len(nb):
        return -1 if len(na) < len(nb) else 1
    if all(c < 0x80 for c in na) and all(c < 0x80 for c in nb):
        la, lb = na.lower(), nb.lower()
    else:
        la, lb = na, nb
    if la != lb:
        return -1 if la < lb else 1
    return (oa > ob) - (oa < ob)


def gsi_hash_stream(entries) -> bytes:
    """GSIHash stream: header, hash records (CRef fixed at 1), bitmap, buckets."""
    buckets = [[] for _ in range(IPHR_HASH)]
    for name, off in entries:
        buckets[hash_v1(name) % IPHR_HASH].append((name, off))
    recs, starts = [], []
    bitmap = [0] * ((IPHR_HASH + 32) // 32)
    for i, b in enumerate(buckets):
        if not b:
            continue
        b.sort(key=functools.cmp_to_key(_gsi_cmp))
        bitmap[i // 32] |= 1 << (i % 32)
        starts.append(len(recs) * 12)
        recs.extend(b)
    hr = b''.join(struct.pack('<II', off + 1, 1) for _, off in recs)
    bm = b''.join(struct.pack('<I', w) for w in bitmap)
    bk = b''.join(struct.pack('<I', s) for s in starts)
    return struct.pack('<IIII', 0xFFFFFFFF, 0xF12F091A, len(hr), len(bm) + len(bk)) + hr + bm + bk


def psi_address_map(entries) -> bytes:
    """PSI address map: symbol-record offsets, sorted by (segment, offset, name)."""
    ordered = sorted(entries, key=lambda e: (e[0], e[1], e[2]))
    return b''.join(struct.pack('<I', e[3]) for e in ordered)


def named_stream_map(names: Mapping[str, int]) -> bytes:
    """Named-stream map substring of the PDB info stream (LLVM HashTable layout)."""
    buf = bytearray()
    offs = {}
    for name in names:
        offs[name] = len(buf)
        buf += _codeview.cstr(name)
    cap = 1
    while len(names) >= cap * 2 // 3 + 1:  # LLVM HashTable growth: maxLoad = cap*2/3+1
        cap = (cap * 2 // 3 + 1) * 2
    table = [None] * cap
    for name, sn in names.items():
        h = (hash_v1(name.encode('utf-8')) & 0xFFFF) % cap
        while table[h] is not None:
            h = (h + 1) % cap
        table[h] = (offs[name], sn)
    present = sum(1 << i for i, e in enumerate(table) if e is not None)
    out = struct.pack('<I', len(buf)) + bytes(buf) + struct.pack('<II', len(names), cap)
    out += _bitvec(present) + _bitvec(0)
    for e in table:
        if e is not None:
            out += struct.pack('<II', *e)
    return out + struct.pack('<I', 0)  # niMac


def _bitvec(v: int) -> bytes:
    words = []
    while v:
        words.append(v & 0xFFFFFFFF)
        v >>= 32
    return struct.pack('<I', len(words)) + b''.join(struct.pack('<I', w) for w in words)


def string_table() -> bytes:
    """The empty ``/names`` table (no strings written, per OQ1-A)."""
    return struct.pack('<III', 0xEFFEEFFE, 1, 1) + b'\0' + struct.pack('<II', 1, 0) + struct.pack('<I', 0)
