"""Texture2D native data (FTexturePlatformData, FVirtualTextureBuiltData), tile location and bounded region assembly.

Only the UE 5.0+ non-legacy VT tile layout is read; only a single PF_DXT1 layer is decoded. Ordinary textures are
decoded in PF_B8G8R8A8 only, from inline or default-.ubulk mips.
"""
import bisect
import io
import math
import operator
import struct
import time
from array import array
from itertools import chain, islice

from ..errors import CorruptAssetError, InvalidMappingError, MissingTileError, UnsupportedAssetError, UnsupportedPixelFormatError
from . import _bc1
from ._records import MipInfo, TextureInfo, VirtualTextureInfo
from ._zen import PropertySkipper, Reader

_VT_CODEC_NAMES = ('Black', 'OpaqueBlack', 'White', 'Flat', 'RawGPU', 'ZippedGPU_DEPRECATED', 'Crunch_DEPRECATED')
EXPORT_BUNDLE_DATA, BULK_DATA = 1, 2  # the IoStore chunk types an ordinary mip's payload lives in
_ORDINARY_BYTES_PER_PIXEL = {'PF_B8G8R8A8': 4}  # the ordinary pixel formats this version decodes
_BULK_COMPRESSED = (1 << 1) | (1 << 4) | (1 << 9)  # SerializeCompressedZLIB, CompressedLZO, SerializeCompressedBitWindow
_BULK_UNUSED = 1 << 5
_BULK_FORCE_INLINE_PAYLOAD = 1 << 6
_BULK_PAYLOAD_IN_SEPARATE_FILE = 1 << 8
_BULK_OPTIONAL_PAYLOAD = 1 << 11
_BULK_MEMORY_MAPPED_PAYLOAD = 1 << 12
_BULK_LAZY_LOADABLE = 1 << 18
_BULK_DISQUALIFYING = _BULK_OPTIONAL_PAYLOAD | _BULK_MEMORY_MAPPED_PAYLOAD | _BULK_FORCE_INLINE_PAYLOAD
_PACKED_CUBEMAP = 1 << 31
_PACKED_HAS_OPT_DATA = 1 << 30
_PACKED_HAS_CPU_COPY = 1 << 29
_STRAIGHT_ALPHA_FORMATS = frozenset({
    'PF_B8G8R8A8', 'PF_R8G8B8A8', 'PF_A8R8G8B8', 'PF_DXT3', 'PF_DXT5', 'PF_BC7', 'PF_FloatRGBA',
    'PF_A32B32G32R32F', 'PF_A16B16G16R16'})
_INVALID = 0xFFFFFFFF
_MAX_ARRAY = 1 << 24  # every u32 array
_MAX_MIPS = 64  # the platform-data mip count
_MAX_TILE_OFFSET_DATA = 64
_MAX_VT_CHUNKS = 1 << 16
_MAX_TOTAL_ADDRESSES = 1 << 20  # the Addresses entries of all mips together
_MIN_TILE_SIZE = 8
_MAX_TILE_SIZE = 1024
_MAX_TILE_BORDER = 16
_MAX_GRID_SIDE = 1 << 16
_PRINTABLE = bytes(range(0x20, 0x7F))
_U8 = struct.Struct('<B')
_I32 = struct.Struct('<i')
_U32 = struct.Struct('<I')
_I64 = struct.Struct('<q')
_FNAME = struct.Struct('<ii')
_3I32 = struct.Struct('<iii')
_3U32 = struct.Struct('<III')
_5U32 = struct.Struct('<IIIII')
_SIZE_PACKED = struct.Struct('<iiI')
_LINEAR_COLOR = struct.Struct('<4f')


class _Misfit(Exception):
    """Internal: the native data does not fit the mapping; `pos` is where the failing field begins."""

    def __init__(self, pos: int):
        self.pos = pos


def _unpack(reader: Reader, s: struct.Struct) -> tuple:
    pos = reader.pos
    if s.size > len(reader.data) - pos:
        raise _Misfit(pos)
    reader.pos = pos + s.size
    return s.unpack_from(reader.data, pos)


def _skip(reader: Reader, n: int) -> None:
    if not 0 <= n <= len(reader.data) - reader.pos:
        raise _Misfit(reader.pos)
    reader.pos += n


def _count(reader: Reader, cap: int, unit: int) -> int:
    """An i32 element count, each element at least `unit` bytes."""
    pos = reader.pos
    (n,) = _unpack(reader, _I32)
    if n < 0 or n > cap or n * unit > len(reader.data) - reader.pos:
        raise _Misfit(pos)
    return n


def _u32_array(reader: Reader) -> array:
    n = _count(reader, _MAX_ARRAY, 4)
    a = array('I')
    a.frombytes(memoryview(reader.data)[reader.pos:reader.pos + 4 * n])
    reader.pos += 4 * n
    return a


def _skip_u32_array(reader: Reader) -> int:
    n = _count(reader, _MAX_ARRAY, 4)
    reader.pos += 4 * n
    return n


def _u32_array_checked(reader: Reader, remaining: int) -> array:
    """Like _u32_array, but raises _Misfit at the count field when the array would exceed `remaining`."""
    pos = reader.pos
    n = _count(reader, _MAX_ARRAY, 4)
    if n > remaining:
        raise _Misfit(pos)
    a = array('I')
    a.frombytes(memoryview(reader.data)[reader.pos:reader.pos + 4 * n])
    reader.pos += 4 * n
    return a


def _native_string(reader: Reader) -> str:
    """A native FString (pixel format, layer type): NUL-terminated, printable ASCII before the NUL."""
    pos = reader.pos
    (n,) = _unpack(reader, _I32)
    left = len(reader.data) - reader.pos
    if 0 < n <= left:
        raw = reader.data[reader.pos:reader.pos + n]
        reader.pos += n
    elif n < 0 and -2 * n <= left:
        wide = reader.data[reader.pos:reader.pos - 2 * n]
        reader.pos -= 2 * n
        if wide[1::2].count(0) != -n:
            raise _Misfit(pos)
        raw = wide[0::2]
    else:
        raise _Misfit(pos)
    if raw[-1] != 0 or raw[:-1].translate(None, _PRINTABLE):
        raise _Misfit(pos)
    return raw[:-1].decode('ascii')


def _bulk_entry(bulk_data_map: tuple, index: int):
    return bulk_data_map[index] if 0 <= index < len(bulk_data_map) else None


def _skip_inline_payload(reader: Reader, entry) -> None:
    """Skip a bulk payload that is serialized right after its bulk-data index."""
    if entry is None or not entry.serial_size or entry.flags & _BULK_UNUSED:
        return
    if entry.flags & _BULK_FORCE_INLINE_PAYLOAD or entry.flags in (0, _BULK_LAZY_LOADABLE):
        _skip(reader, entry.serial_size)


def _in_ubulk(entry) -> bool:
    """Whether a VT chunk's payload sits in the package's default-cooked-index .ubulk."""
    if not entry.flags & _BULK_PAYLOAD_IN_SEPARATE_FILE or entry.flags & _BULK_DISQUALIFYING or entry.cooked_index != 0:
        return False
    return True


def _ceil_div(a: int, b: int) -> int:
    return -(-a // b)


def _srgb_u8(v: float) -> int:
    if not math.isfinite(v):
        v = 0.0
    v = min(1.0, max(0.0, v))
    v = 12.92 * v if v <= 0.0031308 else 1.055 * v ** (1 / 2.4) - 0.055
    return int(v * 255 + 0.5)


def _alpha_u8(a: float) -> int:
    if not math.isfinite(a):
        a = 0.0
    return int(min(1.0, max(0.0, a)) * 255 + 0.5)


def _read_vt(reader: Reader, bulk_data_map: tuple) -> dict:
    """FVirtualTextureBuiltData, non-legacy UE 5.0+ layout; raises _Misfit at the first field out of shape."""
    _skip(reader, 4)  # bCooked
    pos = reader.pos
    num_layers, wib, hib, tile_size, border = _unpack(reader, _5U32)
    if not 1 <= num_layers <= 8:
        raise _Misfit(pos)
    tile_data_offset_per_layer = _u32_array(reader)
    pos = reader.pos
    num_mips, width, height = _unpack(reader, _3U32)
    if num_mips > _MAX_ARRAY:
        raise _Misfit(pos)
    chunk_index_per_mip = _u32_array(reader)
    base_offset_per_mip = _u32_array(reader)
    tile_offset_data = []
    addr_total = 0
    for _ in range(_count(reader, _MAX_TILE_OFFSET_DATA, 20)):
        w, h, _max_address = _unpack(reader, _3U32)
        addrs = _u32_array_checked(reader, _MAX_TOTAL_ADDRESSES - addr_total)
        addr_total += len(addrs)
        tile_offset_data.append((w, h, addrs, _u32_array(reader)))
    _skip_u32_array(reader)  # TileIndexPerChunk
    _skip_u32_array(reader)  # TileIndexPerMip
    legacy = _skip_u32_array(reader) > 0  # TileOffsetInChunk
    layer_types = tuple(_native_string(reader) for _ in range(num_layers))
    fallback = tuple(_unpack(reader, _LINEAR_COLOR) for _ in range(num_layers))
    chunk_struct = struct.Struct('<20xII' + 'BI' * num_layers + 'i')  # FSHAHash, sizes, per-layer codec, bulk index
    chunks = []
    for _ in range(_count(reader, _MAX_VT_CHUNKS, chunk_struct.size)):
        fields = _unpack(reader, chunk_struct)
        entry = _bulk_entry(bulk_data_map, fields[-1])
        _skip_inline_payload(reader, entry)
        codecs = tuple(_VT_CODEC_NAMES[c] if c < len(_VT_CODEC_NAMES) else f'Unknown{c}' for c in fields[2:-1:2])
        chunks.append((fields[0], codecs, entry))
    return dict(num_layers=num_layers, wib=wib, hib=hib, tile_size=tile_size, border=border,
                tile_data_offset_per_layer=tile_data_offset_per_layer, num_mips=num_mips, width=width, height=height,
                chunk_index_per_mip=chunk_index_per_mip, base_offset_per_mip=base_offset_per_mip,
                tile_offset_data=tuple(tile_offset_data), legacy=legacy, layer_types=layer_types, fallback=fallback,
                chunks=tuple(chunks))


def _unsupported(pkg: str, reason: str, feature: str) -> UnsupportedAssetError:
    return UnsupportedAssetError(f'{pkg}: {reason}', package=pkg, feature=feature)


def _read_platform_data(reader: Reader, bulk_data_map: tuple, serialize_mips: bool, pkg: str) -> dict:
    """FTexturePlatformData (UE 5.2+ cooked); raises _Misfit, or UnsupportedAssetError when no metadata can be produced."""
    pos = reader.pos
    (using_derived_data,) = _unpack(reader, _U8)
    if using_derived_data not in (0, 1):
        raise _Misfit(pos)
    if using_derived_data:
        raise _unsupported(pkg, 'cooked texture platform data using derived data is not supported by this nylib version',
                           'texture platform data derived-data flag')
    _skip(reader, 15)  # the rest of the 16-byte derived-data placeholder
    size_x, size_y, packed = _unpack(reader, _SIZE_PACKED)
    pixel_format = _native_string(reader)
    if packed & _PACKED_HAS_CPU_COPY:
        raise _unsupported(pkg, 'cooked texture platform data with a CPU copy is not supported by this nylib version',
                           'texture platform data CPU copy')
    if packed & _PACKED_CUBEMAP:
        raise _unsupported(pkg, 'a cubemap texture is not supported by this nylib version', 'cubemap texture')
    if packed & _PACKED_HAS_OPT_DATA:
        _skip(reader, 8)  # FOptTexturePlatformData
    _skip(reader, 4)  # FirstMipToSerialize
    mips = []
    sources = []  # per serialized mip: (bulk-data entry or None, export offset right after its index)
    for _ in range(_count(reader, _MAX_MIPS, 16 if serialize_mips else 12)):
        if serialize_mips:
            entry = _bulk_entry(bulk_data_map, _unpack(reader, _I32)[0])
            sources.append((entry, reader.pos))
            _skip_inline_payload(reader, entry)
        mx, my, _mz = _unpack(reader, _3I32)
        mips.append(MipInfo(mx, my))
    pos = reader.pos
    (is_virtual,) = _unpack(reader, _U32)
    if is_virtual not in (0, 1):
        raise _Misfit(pos)
    vt = _read_vt(reader, bulk_data_map) if is_virtual else None
    return dict(size_x=size_x, size_y=size_y, pixel_format=pixel_format, mips=tuple(mips), sources=tuple(sources), vt=vt)


def _native_start(reader: Reader, names: tuple) -> tuple:
    """The fields before the first platform data: (bSerializeMipData, where the first skip offset lands)."""
    (has_guid,) = _unpack(reader, _U32)
    if has_guid not in (0, 1):
        raise _Misfit(0)
    _skip(reader, 16 * has_guid + 4)  # object GUID, UTexture and UTexture2D FStripDataFlags
    (cooked,) = _unpack(reader, _U32)
    if cooked != 1:
        raise _Misfit(0)
    (serialize_mips,) = _unpack(reader, _U32)
    if serialize_mips not in (0, 1):
        raise _Misfit(0)
    idx, num = _unpack(reader, _FNAME)
    if not 0 <= idx < len(names) or num < 0 or not names[idx].startswith('PF_'):
        raise _Misfit(0)
    skip_pos = reader.pos
    (skip,) = _unpack(reader, _I64)
    if skip <= 0 or skip_pos + skip + 8 > len(reader.data):
        raise _Misfit(0)
    return bool(serialize_mips), skip_pos + skip


def _skip_later_platform_data(reader: Reader, names: tuple) -> None:
    """Jump through the later platform-data entries to the terminating None, which must end the export."""
    while True:
        pos = reader.pos
        idx, num = _unpack(reader, _FNAME)
        if not 0 <= idx < len(names) or num < 0:
            raise _Misfit(pos)
        if num == 0 and names[idx] == 'None':
            break
        pos = reader.pos
        (skip,) = _unpack(reader, _I64)
        if skip < 8 or pos + skip + 8 > len(reader.data):
            raise _Misfit(pos)
        reader.pos = pos + skip
    if reader.pos != len(reader.data):
        raise _Misfit(reader.pos)


def _fail_misfit(usmap: str, pkg: str, class_name: str, pos: int, size: int) -> InvalidMappingError:
    message = (f'{usmap} does not fit {pkg}: the {class_name} properties end at {pos:#x} but the native texture data '
               f'does not start there (export is {size} bytes)')
    return InvalidMappingError(message, usmap=usmap, class_name=class_name, reason='native start')


def _fail_skip(usmap: str, pkg: str, pos: int, expected: int, size: int) -> InvalidMappingError:
    message = f'{usmap} does not fit {pkg}: the platform data ends at {pos:#x} but its skip offset gives {expected:#x} (export is {size} bytes)'
    return InvalidMappingError(message, usmap=usmap, reason='skip offset')


def _fail_export_end(usmap: str, pkg: str, pos: int, size: int) -> InvalidMappingError:
    message = f'{usmap} does not fit {pkg}: parsing ends at {pos:#x}, not at the export end (export is {size} bytes)'
    return InvalidMappingError(message, usmap=usmap, reason='export end')


def _corrupt(pkg: str, detail: str) -> CorruptAssetError:
    return CorruptAssetError(f'{pkg}: {detail}', package=pkg, detail=detail)


def _covering_grid(vt: dict, m: int) -> tuple:
    """(cw, ch, W_m, H_m): the tiles that cover mip `m`, and its pixel size."""
    pw, ph = max(1, vt['width'] >> m), max(1, vt['height'] >> m)
    return _ceil_div(pw, vt['tile_size']), _ceil_div(ph, vt['tile_size']), pw, ph


def _run_ends(addrs, end: int):
    """Each run's end address: the next run's address, the last `end`, all clipped to `end`."""
    return (min(e, end) for e in chain(islice(addrs, 1, None), (end,)))


def _check_vt_structure(vt: dict, pkg: str, bulk_chunk_length: int) -> None:
    """The virtual-texture self-consistency checks, in order; the first that fails raises CorruptAssetError.

    A legacy layout (TileOffsetInChunk non-empty) leaves the UE5 per-mip arrays empty: only the tile-size and
    chunk checks run for it, and the texture is reported unreadable instead.
    """
    tile, border = vt['tile_size'], vt['border']
    if tile == 0:
        raise _corrupt(pkg, 'the virtual texture tile size is 0')
    if tile < _MIN_TILE_SIZE:
        raise _corrupt(pkg, f'the virtual texture tile size {tile} is below {_MIN_TILE_SIZE}')
    if tile > _MAX_TILE_SIZE:
        raise _corrupt(pkg, f'the virtual texture tile size {tile} is above {_MAX_TILE_SIZE}')
    if border > _MAX_TILE_BORDER:
        raise _corrupt(pkg, f'the virtual texture tile border {border} is above {_MAX_TILE_BORDER}')
    legacy = vt['legacy']
    num_mips = vt['num_mips']
    if not legacy:
        if len(vt['chunk_index_per_mip']) != num_mips or len(vt['base_offset_per_mip']) != num_mips or len(vt['tile_offset_data']) != num_mips:
            raise _corrupt(pkg, 'a virtual texture array length disagrees with NumMips')
        if len(vt['tile_data_offset_per_layer']) != vt['num_layers']:
            raise _corrupt(pkg, 'a virtual texture array length disagrees with NumLayers')
        for m, (w, h, addrs, offs) in enumerate(vt['tile_offset_data']):
            if len(addrs) != len(offs):
                raise _corrupt(pkg, f"mip {m}'s Addresses and Offsets differ in length")
            if not all(map(operator.lt, addrs, islice(addrs, 1, None))):
                raise _corrupt(pkg, f"mip {m}'s tile addresses are not strictly increasing")
            cw, ch, pw, ph = _covering_grid(vt, m)
            if w < cw or h < ch:
                raise _corrupt(pkg, f"mip {m}'s tile grid is {w}x{h}, smaller than the {cw}x{ch} its {pw}x{ph} pixels need")
            if w > _MAX_GRID_SIDE:
                raise _corrupt(pkg, f"mip {m}'s tile grid is {w}x{h}, more than {_MAX_GRID_SIDE} tiles across")
            if h > _MAX_GRID_SIDE:
                raise _corrupt(pkg, f"mip {m}'s tile grid is {w}x{h}, more than {_MAX_GRID_SIDE} tiles down")
    for ci, (size_in_bytes, _codecs, bulk) in enumerate(vt['chunks']):
        if bulk is None:
            raise _corrupt(pkg, f'virtual texture chunk {ci} has no bulk-data entry')
        if bulk.serial_size != size_in_bytes:
            raise _corrupt(pkg, f"virtual texture chunk {ci}'s SizeInBytes {size_in_bytes} differs "
                                f"from its bulk data serial size {bulk.serial_size}")
        if _in_ubulk(bulk) and bulk.serial_offset + bulk.serial_size > bulk_chunk_length:
            raise _corrupt(pkg, f"virtual texture chunk {ci}'s bulk range falls outside the .ubulk chunk")
    if legacy:
        return
    layer_offsets = tuple(vt['tile_data_offset_per_layer'])
    if vt['num_layers'] == 1 and vt['layer_types'][0] == 'PF_DXT1':
        phys = tile + 2 * border
        if phys % 4 == 0:
            want = ((phys // 4) ** 2 * 8,)
            if layer_offsets != want:
                raise _corrupt(pkg, f'TileDataOffsetPerLayer {layer_offsets} does not match {want}')
    tile_data_size = layer_offsets[-1]
    for m, (w, h, addrs, offs) in enumerate(vt['tile_offset_data']):
        base = vt['base_offset_per_mip'][m]
        if base == _INVALID:
            continue
        chunk_i = vt['chunk_index_per_mip'][m]
        if chunk_i >= len(vt['chunks']):
            raise _corrupt(pkg, f"mip {m}'s chunk index {chunk_i} is out of range for {len(vt['chunks'])} chunks")
        chunk_size = vt['chunks'][chunk_i][0]
        end = _morton2(w - 1, h - 1) + 1
        for a, off, e in zip(addrs, offs, _run_ends(addrs, end)):
            if off == _INVALID or a >= end:
                continue
            if base + (off + e - a) * tile_data_size > chunk_size:
                raise _corrupt(pkg, f"mip {m}'s tile data falls outside chunk {chunk_i} ({chunk_size} bytes)")


def _tiles_below(e: int, w: int, h: int) -> int:
    """The number of tiles (x, y) with x < w, y < h and a Morton address below e; w, h <= 65536."""
    if e >= 1 << 32:
        return w * h
    count, ox, oy = 0, 0, 0
    for level in range(15, -1, -1):
        if ox >= w or oy >= h:
            return count
        s = 1 << level
        if ox + 2 * s <= w and oy + 2 * s <= h:
            return count + (e & ((4 << 2 * level) - 1))  # the block holding e lies inside the grid
        q = (e >> 2 * level) & 3
        if q:
            cx0, cy0 = min(w - ox, s), min(h - oy, s)
            count += cx0 * cy0
            if q > 1:
                count += min(max(w - ox - s, 0), s) * cy0
                if q > 2:
                    count += cx0 * min(max(h - oy - s, 0), s)
        ox += (q & 1) << level
        oy += (q >> 1) << level
    return count


def _missing_tiles(vt: dict) -> int:
    """Absent tiles among each mip's covering tiles, over all mips."""
    missing = 0
    for m, (w, h, addrs, offs) in enumerate(vt['tile_offset_data']):
        cw, ch, _pw, _ph = _covering_grid(vt, m)
        total = cw * ch
        if vt['base_offset_per_mip'][m] == _INVALID:
            missing += total
            continue
        end = _morton2(w - 1, h - 1) + 1
        present = 0
        start = stop = None  # the address range of the current stretch of consecutive stored runs
        for a, off, e in zip(addrs, offs, _run_ends(addrs, end)):
            if off != _INVALID and a < end:
                if start is None:
                    start = a
                stop = e
            elif start is not None:
                present += _tiles_below(stop, cw, ch) - _tiles_below(start, cw, ch)
                start = None
        if start is not None:
            present += _tiles_below(stop, cw, ch) - _tiles_below(start, cw, ch)
        missing += total - present
    return missing


def _fallback_rgba(color: tuple, alpha_mode: str) -> tuple:
    r, g, b, a = color
    rgba = (_srgb_u8(r), _srgb_u8(g), _srgb_u8(b))
    return rgba + (255 if alpha_mode == 'none' else _alpha_u8(a),)


def _vt_codecs(vt: dict) -> tuple:
    codecs = []
    for _size, chunk_codecs, _bulk in vt['chunks']:
        for cname in chunk_codecs:
            if cname not in codecs:
                codecs.append(cname)
    return tuple(codecs)


def _unreadable_vt(vt: dict, codecs: tuple):
    """(reason, error class, details) of the first rule that makes a virtual texture unreadable, or None."""
    if vt['wib'] != 1 or vt['hib'] != 1:
        return 'UDIM virtual textures are not supported by this nylib version', UnsupportedAssetError, {'feature': 'UDIM virtual texture'}
    if vt['num_layers'] != 1:
        return (f"virtual textures with {vt['num_layers']} layers are not supported by this nylib version", UnsupportedAssetError,
                {'feature': 'multi-layer virtual texture'})
    if vt['legacy']:
        return ('the legacy virtual texture tile layout is not supported by this nylib version', UnsupportedAssetError,
                {'feature': 'legacy virtual texture tile layout'})
    bad = [c for c in codecs if c != 'RawGPU']
    if bad:
        return (f'virtual texture codec {bad[0]} is not supported by this nylib version', UnsupportedAssetError,
                {'feature': f'virtual texture codec {bad[0]}'})
    fmt = vt['layer_types'][0]
    if fmt != 'PF_DXT1':
        return (f'pixel format {fmt} has no decoder in this nylib version', UnsupportedPixelFormatError,
                {'feature': f'pixel format {fmt}', 'pixel_format': fmt})
    phys = vt['tile_size'] + 2 * vt['border']
    if phys % 4:
        return (f'virtual texture tiles of {phys} pixels are not block-aligned', UnsupportedAssetError,
                {'feature': 'unaligned virtual texture tiles'})
    for _size, _codecs, bulk in vt['chunks']:
        if not _in_ubulk(bulk):
            return ('virtual texture data stored outside the .ubulk is not supported by this nylib version', UnsupportedAssetError,
                    {'feature': 'virtual texture data outside the .ubulk'})
    return None


def _mip_placement(entry) -> tuple:
    """The ordinary mip table: (chunk type, None) for a readable bulk-data entry, else (None, the placement not read)."""
    if entry is None:
        return None, 'no bulk-data entry'
    flags = entry.flags
    if flags & _BULK_UNUSED or not entry.serial_size:
        return None, 'an unused bulk-data entry'
    if flags & _BULK_COMPRESSED:
        return None, 'compressed bulk data'
    if flags & _BULK_OPTIONAL_PAYLOAD:
        return None, 'optional bulk data (.uptnl)'
    if flags & _BULK_MEMORY_MAPPED_PAYLOAD:
        return None, 'memory-mapped bulk data (.m.ubulk)'
    if flags & _BULK_FORCE_INLINE_PAYLOAD or flags in (0, _BULK_LAZY_LOADABLE):
        return EXPORT_BUNDLE_DATA, None
    if flags & _BULK_PAYLOAD_IN_SEPARATE_FILE:
        if entry.cooked_index:
            return None, f'bulk data with cooked index {entry.cooked_index}'
        return BULK_DATA, None
    return None, f'bulk data with flags {flags:#x}'


def _unreadable_ordinary(pd: dict, serialize_mips: bool):
    """(reason, error class, details) of the first rule that makes an ordinary texture unreadable, or None."""
    fmt = pd['pixel_format']
    if fmt not in _ORDINARY_BYTES_PER_PIXEL:
        return (f'pixel format {fmt} has no decoder in this nylib version', UnsupportedPixelFormatError,
                {'feature': f'pixel format {fmt}', 'pixel_format': fmt})
    if not pd['mips']:
        return ('an ordinary Texture2D without serialized mips is not readable by this nylib version', UnsupportedAssetError,
                {'feature': 'ordinary texture without mips'})
    if not serialize_mips:
        return ('mip data that is not serialized with the texture is not supported by this nylib version', UnsupportedAssetError,
                {'feature': 'mip data not serialized'})
    for m, (entry, _pos) in enumerate(pd['sources']):
        if (placement := _mip_placement(entry)[1]) is not None:
            return (f'mip {m} is stored as {placement}, which this nylib version does not read', UnsupportedAssetError,
                    {'feature': f'bulk data: {placement}'})
    return None


def _ordinary_sources(pd: dict, pkg: str, export_start: int, bulk_chunk_length: int) -> tuple:
    """(chunk type, payload offset in that chunk, length) per mip of a readable ordinary texture; raises CorruptAssetError."""
    fmt = pd['pixel_format']
    sources = []
    for m, ((w, h), (entry, pos)) in enumerate(zip(pd['mips'], pd['sources'])):
        if w < 1 or h < 1:
            raise _corrupt(pkg, f'mip {m} has size {w}x{h}')
        kind = _mip_placement(entry)[0]
        if kind == BULK_DATA and entry.serial_offset + entry.serial_size > bulk_chunk_length:
            raise _corrupt(pkg, f"mip {m}'s bulk range falls outside the .ubulk chunk")
        need = w * h * _ORDINARY_BYTES_PER_PIXEL[fmt]
        if entry.serial_size != need:
            raise _corrupt(pkg, f'mip {m} holds {entry.serial_size} bytes, but {w}x{h} {fmt} needs {need}')
        sources.append((kind, entry.serial_offset if kind == BULK_DATA else export_start + pos, need))
    return tuple(sources)


class OrdinaryLayout:
    """A readable ordinary texture's mips: each one's size and the (chunk type, offset, length) of its payload."""

    def __init__(self, *, package: str, mips: tuple, sources: tuple):
        self.package = package
        self.mips = mips
        self.sources = sources


class VtLayout:
    """A readable virtual texture's resolved tile layout: per-mip tile grids and chunk-relative bulk ranges."""

    def __init__(self, *, package: str, tile_size: int, border: int, tile_data_size: int,
                 base_offset_per_mip, chunk_index_per_mip, tile_offset_data: tuple,
                 chunk_bulk: tuple, fallback_rgba: tuple):
        self.package = package
        self.tile_size = tile_size
        self.border = border
        self.physical = tile_size + 2 * border
        self.tile_data_size = tile_data_size
        self._base_offset_per_mip = base_offset_per_mip
        self._chunk_index_per_mip = chunk_index_per_mip
        self._tile_offset_data = tile_offset_data
        self._chunk_bulk = chunk_bulk  # (offset within the .ubulk chunk, length) per VT chunk
        self.fallback_rgba = fallback_rgba

    def locate(self, mip: int, tx: int, ty: int):
        """(offset, length) of tile (tx, ty) of `mip` within the .ubulk chunk, or None when absent or outside the grid."""
        width, height, addrs, offs = self._tile_offset_data[mip]
        if tx < 0 or ty < 0 or tx >= width or ty >= height:
            return None
        base = self._base_offset_per_mip[mip]
        if base == _INVALID:
            return None
        addr = _morton2(tx, ty)
        k = bisect.bisect_right(addrs, addr) - 1
        if k < 0 or offs[k] == _INVALID:
            return None
        tile_offset = offs[k] + (addr - addrs[k])
        chunk_off, _chunk_len = self._chunk_bulk[self._chunk_index_per_mip[mip]]
        return chunk_off + base + tile_offset * self.tile_data_size, self.tile_data_size


def _morton2(x: int, y: int) -> int:
    """MathUtils.MortonCode2: interleave the low bits of x and y, x in the even bits."""
    def part(v):
        v &= 0xFFFF
        v = (v | (v << 8)) & 0x00FF00FF
        v = (v | (v << 4)) & 0x0F0F0F0F
        v = (v | (v << 2)) & 0x33333333
        v = (v | (v << 1)) & 0x55555555
        return v
    return part(x) | (part(y) << 1)


def parse_texture2d(header, export: int, mappings, bulk_chunk_length: int) -> tuple:
    """Parse export `export` of zen `header` as a Texture2D: (TextureInfo, VtLayout | OrdinaryLayout | None, unreadable).

    `bulk_chunk_length` is the length of the package's (id, 0, BulkData) chunk, or 0. `unreadable` is None for a
    readable texture, else (error class, details) of the reason it is not.
    """
    pkg = header.name
    usmap = mappings._usmap
    e = header.exports[export]
    start, end = header.export_range(export)
    export_bytes = header.data[start:end]
    size = len(export_bytes)
    r = Reader(export_bytes)
    PropertySkipper(mappings, header.names, usmap).skip(r, 'Texture2D', package=pkg, size=size)
    props_end = r.pos

    try:
        serialize_mips, skip_to = _native_start(r, header.names)
    except _Misfit:
        raise _fail_misfit(usmap, pkg, 'Texture2D', props_end, size) from None
    try:
        pd0 = _read_platform_data(r, header.bulk_data_map, serialize_mips, pkg)
        if r.pos != skip_to:
            raise _Misfit(r.pos)
    except _Misfit as m:
        raise _fail_skip(usmap, pkg, m.pos, skip_to, size) from None
    try:
        _skip_later_platform_data(r, header.names)
    except _Misfit as m:
        raise _fail_export_end(usmap, pkg, m.pos, size) from None

    pixel_format = pd0['pixel_format']
    alpha = 'straight' if pixel_format in _STRAIGHT_ALPHA_FORMATS else 'none'
    vt = pd0['vt']
    if vt is None:
        if pd0['mips']:
            width, height = pd0['mips'][0]
        else:
            width, height = pd0['size_x'], pd0['size_y']
        rule = _unreadable_ordinary(pd0, serialize_mips)
        layout = unreadable = None
        if rule is None:
            layout = OrdinaryLayout(package=pkg, mips=pd0['mips'], sources=_ordinary_sources(pd0, pkg, start, bulk_chunk_length))
        else:
            unreadable = rule[1:]
        info = TextureInfo(package=pkg, name=e.name, class_name='Texture2D', width=width, height=height,
                           pixel_format=pixel_format, mips=pd0['mips'], alpha=alpha, virtual=None,
                           readable=rule is None, unsupported=None if rule is None else rule[0])
        return info, layout, unreadable

    _check_vt_structure(vt, pkg, bulk_chunk_length)
    width, height = vt['width'], vt['height']
    mips = tuple(MipInfo(max(1, width >> m), max(1, height >> m)) for m in range(vt['num_mips']))
    codecs = _vt_codecs(vt)
    fallback_rgba = tuple(_fallback_rgba(c, alpha) for c in vt['fallback'])
    virtual_info = VirtualTextureInfo(tile_size=vt['tile_size'], border=vt['border'], layers=vt['layer_types'],
                                      fallback=fallback_rgba, codecs=codecs, chunks=len(vt['chunks']),
                                      missing_tiles=_missing_tiles(vt))
    rule = _unreadable_vt(vt, codecs)
    layout = unreadable = None
    if rule is None:
        layout = VtLayout(package=pkg, tile_size=vt['tile_size'], border=vt['border'],
                          tile_data_size=vt['tile_data_offset_per_layer'][-1],
                          base_offset_per_mip=vt['base_offset_per_mip'], chunk_index_per_mip=vt['chunk_index_per_mip'],
                          tile_offset_data=vt['tile_offset_data'],
                          chunk_bulk=tuple((bulk.serial_offset, bulk.serial_size) for _s, _c, bulk in vt['chunks']),
                          fallback_rgba=fallback_rgba)
    else:
        unreadable = rule[1:]
    info = TextureInfo(package=pkg, name=e.name, class_name='Texture2D', width=width, height=height,
                       pixel_format=pixel_format, mips=mips, alpha=alpha, virtual=virtual_info,
                       readable=rule is None, unsupported=None if rule is None else rule[0])
    return info, layout, unreadable


def _missing_tile_error(layout: VtLayout, mip: int, absent: list) -> MissingTileError:
    ordered = tuple(absent)
    shown = ordered[:8]
    text = ', '.join(f'({tx}, {ty})' for tx, ty in shown) + (', ...' if len(ordered) > 8 else '')
    message = f'{layout.package}: {len(ordered)} tiles of mip {mip} are not stored: {text}'
    return MissingTileError(message, package=layout.package, mip=mip, tiles=ordered)


def assemble(layout: VtLayout, mip: int, rect: tuple, *, missing: str, out, fetch, checkpoint, counters) -> tuple:
    """Assemble the RGBA8 pixels of `rect` at `mip` from `layout`; returns (pixels, missing_rects).

    Calls checkpoint(k, n) before each of the n touched tiles, then fetch(offset, length) for a present one;
    present tiles go first, by offset, then absent ones row-major.
    """
    x0, y0, width, height = rect
    n = width * height * 4
    view = None
    if out is not None:
        view = memoryview(out).cast('B')
        if (have := len(view)) < n:
            view.release()
            raise ValueError(f'out holds {have} bytes, the region needs {n}')
    ts = layout.tile_size
    border = layout.border
    phys = layout.physical

    tx0, tx1 = x0 // ts, (x0 + width - 1) // ts
    ty0, ty1 = y0 // ts, (y0 + height - 1) // ts
    present = []
    absent = []
    for ty in range(ty0, ty1 + 1):
        for tx in range(tx0, tx1 + 1):
            loc = layout.locate(mip, tx, ty)
            if loc is None:
                absent.append((tx, ty))
            else:
                present.append((loc[0], loc[1], tx, ty))

    present.sort(key=operator.itemgetter(0))
    total = len(present) + len(absent)
    done = 0
    buf = bio = None
    missing_rects = []
    try:
        if missing == 'raise' and absent:
            raise _missing_tile_error(layout, mip, absent)
        for off, length, tx, ty in present:
            checkpoint(done, total)
            if buf is None:
                buf, bio = _output(view, n)
            raw = fetch(off, length)
            t0 = time.perf_counter()
            _decode_tile(buf, raw, tx, ty, ts, border, phys, x0, y0, width, height)
            raw = None
            if counters is not None:
                counters.seconds_decode += time.perf_counter() - t0
                counters.tiles_decoded += 1
                counters.pixels_decoded += phys * phys
            done += 1
        if absent:
            color = (0, 0, 0, 0) if missing == 'transparent' else layout.fallback_rgba[0]
            for tx, ty in absent:
                checkpoint(done, total)
                if buf is None:
                    buf, bio = _output(view, n)
                t0 = time.perf_counter()
                r = _fill_tile(buf, color, tx, ty, ts, x0, y0, width, height)
                if counters is not None:
                    counters.seconds_decode += time.perf_counter() - t0
                if r is not None:
                    missing_rects.append(r)
                done += 1
    except BaseException:
        for v in (buf, view):
            if v is not None:
                v.release()
        raise
    if bio is None:
        return buf[:n], tuple(missing_rects)
    buf.release()
    return bio.getvalue(), tuple(missing_rects)


def _output(view, n: int) -> tuple:
    """(writable byte view, BytesIO or None): `out`'s view, or one zero-filled buffer that getvalue() hands over uncopied."""
    if view is not None:
        return view, None
    bio = io.BytesIO()
    bio.seek(n - 1)
    bio.write(b'\0')
    return bio.getbuffer(), bio


def _decode_tile(buf, raw, tx, ty, ts, border, phys, x0, y0, width, height) -> None:
    _copy_tile(buf, _bc1.decode(raw, phys, phys), tx, ty, ts, border, phys, x0, y0, width, height)


def _copy_tile(buf, px, tx, ty, ts, border, phys, x0, y0, width, height) -> None:
    gx0, gy0 = tx * ts, ty * ts
    ix0, iy0 = max(x0, gx0), max(y0, gy0)
    ix1, iy1 = min(x0 + width, gx0 + ts), min(y0 + height, gy0 + ts)
    if ix0 >= ix1 or iy0 >= iy1:
        return
    row_len = 4 * (ix1 - ix0)
    for y in range(iy0, iy1):
        sy = y - gy0 + border
        sx = ix0 - gx0 + border
        so = 4 * (sy * phys + sx)
        do = 4 * ((y - y0) * width + (ix0 - x0))
        buf[do:do + row_len] = px[so:so + row_len]


def _fill_tile(buf, color, tx, ty, ts, x0, y0, width, height):
    gx0, gy0 = tx * ts, ty * ts
    ix0, iy0 = max(x0, gx0), max(y0, gy0)
    ix1, iy1 = min(x0 + width, gx0 + ts), min(y0 + height, gy0 + ts)
    if ix0 >= ix1 or iy0 >= iy1:
        return None
    pixel = bytes(color)
    row = pixel * (ix1 - ix0)
    for y in range(iy0, iy1):
        do = 4 * ((y - y0) * width + (ix0 - x0))
        buf[do:do + len(row)] = row
    return ix0, iy0, ix1 - ix0, iy1 - iy0


def assemble_rows(layout: OrdinaryLayout, mip: int, rect: tuple, *, out, chunk_start: int, block_size: int, fetch,
                  checkpoint, counters) -> tuple:
    """Assemble the RGBA8 pixels of `rect` at `mip` from only the rows it covers; returns (pixels, ()).

    `chunk_start` is the logical offset of the mip's chunk. Calls checkpoint(k, n) before each of the n compression
    blocks the rows' bytes touch, then fetch(offset, length) for that block's part of those bytes.
    """
    x0, y0, width, height = rect
    n = width * height * 4
    view = None
    if out is not None:
        view = memoryview(out).cast('B')
        if (have := len(view)) < n:
            view.release()
            raise ValueError(f'out holds {have} bytes, the region needs {n}')
    _kind, base, _length = layout.sources[mip]
    row = 4 * layout.mips[mip][0]
    start, stop = base + row * y0, base + row * (y0 + height)
    first = (chunk_start + start) // block_size
    total = (chunk_start + stop - 1) // block_size - first + 1
    buf = bio = None
    try:
        for k in range(total):
            checkpoint(k, total)
            if buf is None:
                buf, bio = _output(view, n)
            b = first + k
            lo, hi = max(start, b * block_size - chunk_start), min(stop, (b + 1) * block_size - chunk_start)
            raw = fetch(lo, hi - lo)
            t0 = time.perf_counter()
            _copy_rows(buf, raw, lo - start, row, 4 * x0, 4 * width)
            raw = None
            if counters is not None:
                counters.seconds_decode += time.perf_counter() - t0
    except BaseException:
        for v in (buf, view):
            if v is not None:
                v.release()
        raise
    if counters is not None:
        counters.pixels_decoded += width * height
    if bio is None:
        return buf[:n], ()
    buf.release()
    return bio.getvalue(), ()


def _copy_rows(buf, raw, at: int, row: int, col: int, span: int) -> None:
    """Copy the rectangle's bytes of `raw`, which starts `at` bytes into the rows, to `buf`; swizzle BGRA to RGBA per finished row."""
    with memoryview(raw) as src:
        end = at + len(src)
        for r in range(at // row, (end - 1) // row + 1):
            cs = r * row + col
            a, e = max(cs, at), min(cs + span, end)
            if a >= e:
                continue
            do = r * span + a - cs
            buf[do:do + e - a] = src[a - at:e - at]
            if e == cs + span:
                with buf[r * span:(r + 1) * span] as line:
                    blue = bytes(line[0::4])
                    line[0::4] = line[2::4]
                    line[2::4] = blue
