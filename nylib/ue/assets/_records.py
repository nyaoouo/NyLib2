"""The 8 result records of nylib.ue.assets, plus the private per-operation counter _Counters."""
from dataclasses import dataclass, field, fields
from typing import NamedTuple


@dataclass(frozen=True)
class ContainerInfo:
    file: str
    kind: str
    mounted: bool
    version: int
    compression: tuple[str, ...]
    encrypted: bool
    chunks: int | None
    reason: str | None


@dataclass(frozen=True)
class BuildInfo:
    exe: str
    stamp: int
    version: str | None
    path: str = field(repr=False)

    def __repr__(self) -> str:
        return f'BuildInfo(exe={self.exe!r}, stamp={self.stamp:#010x}, version={self.version!r})'


@dataclass(frozen=True)
class PackageInfo:
    name: str
    container: str
    size: int
    bulk_size: int
    package_id: int

    def __repr__(self) -> str:
        return (f'PackageInfo(name={self.name!r}, container={self.container!r}, size={self.size!r}, '
                f'bulk_size={self.bulk_size!r}, package_id={self.package_id:#018x})')


class MipInfo(NamedTuple):
    width: int
    height: int


@dataclass(frozen=True)
class VirtualTextureInfo:
    tile_size: int
    border: int
    layers: tuple[str, ...]
    fallback: tuple[tuple[int, int, int, int], ...]
    codecs: tuple[str, ...]
    chunks: int
    missing_tiles: int


@dataclass(frozen=True)
class TextureInfo:
    package: str
    name: str
    class_name: str
    width: int
    height: int
    pixel_format: str
    mips: tuple[MipInfo, ...]
    alpha: str
    virtual: VirtualTextureInfo | None
    readable: bool
    unsupported: str | None


@dataclass(frozen=True)
class ReadStats:
    reads: int
    bytes_read: int
    blocks_read: int
    blocks_decompressed: int
    cache_hits: int
    bytes_decompressed: int
    tiles_decoded: int
    pixels_decoded: int
    seconds: float
    seconds_io: float
    seconds_aes: float
    seconds_oodle: float
    seconds_decode: float

    def __sub__(self, other):
        if not isinstance(other, ReadStats):
            return NotImplemented
        return ReadStats(**{f.name: getattr(self, f.name) - getattr(other, f.name) for f in fields(self)})

    def __str__(self) -> str:
        return (
            f"{self.blocks_read} block{'' if self.blocks_read == 1 else 's'} read ({self.bytes_read} B), "
            f"{self.blocks_decompressed} decompressed ({self.bytes_decompressed} B), {self.cache_hits} from cache, "
            f"{self.tiles_decoded} tile{'' if self.tiles_decoded == 1 else 's'} / {self.pixels_decoded} px decoded, "
            f"{self.seconds * 1e3:.1f} ms "
            f"(io {self.seconds_io * 1e3:.1f}, aes {self.seconds_aes * 1e3:.1f}, "
            f"oodle {self.seconds_oodle * 1e3:.1f}, decode {self.seconds_decode * 1e3:.1f})"
        )


@dataclass(frozen=True)
class Region:
    pixels: bytes | memoryview = field(repr=False)
    mip: int
    x: int
    y: int
    width: int
    height: int
    format: str = 'rgba8'
    missing: tuple[tuple[int, int, int, int], ...] = ()
    stats: ReadStats = field(repr=False, default=None)

    @property
    def stride(self) -> int:
        return self.width * 4


_INT_FIELDS = ('reads', 'bytes_read', 'blocks_read', 'blocks_decompressed', 'cache_hits', 'bytes_decompressed', 'tiles_decoded', 'pixels_decoded')
_FLOAT_FIELDS = ('seconds', 'seconds_io', 'seconds_aes', 'seconds_oodle', 'seconds_decode')


class _Counters:
    """Mutable per-operation accumulator with one slot per ReadStats field; never shared between threads."""
    __slots__ = _INT_FIELDS + _FLOAT_FIELDS

    def __init__(self):
        for name in _INT_FIELDS:
            setattr(self, name, 0)
        for name in _FLOAT_FIELDS:
            setattr(self, name, 0.0)

    def add(self, other) -> None:
        for name in self.__slots__:
            setattr(self, name, getattr(self, name) + getattr(other, name))

    def snapshot(self) -> ReadStats:
        return ReadStats(**{name: getattr(self, name) for name in self.__slots__})
