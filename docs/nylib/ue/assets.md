# nylib.ue.assets

Read-only reader for a UE 5.7 game's IoStore (`.utoc`/`.ucas`) containers: enumerate packages, read `Texture2D` metadata, and decode bounded regions of virtual-texture BC1 tiles to RGBA8. Python, with Windows BCrypt for AES and the bundled Oodle DLL for decompression; no FModel, CUE4Parse or Unreal dependency.

Keywords: IoStore, utoc, ucas, AesKey, open_installation, Installation, Texture, virtual texture, VT, BC1, DXT1, read_region, usmap, mapping, zen package, PackageInfo, TextureInfo, Region, ScriptObjects, Oodle

## Quick start

```python
# needs: an installed UE 5.7 game, its AES key file and a matching .usmap
from nylib.ue.assets import open_installation, AesKey

key = AesKey.from_file('path/to/game-aes.txt')
with open_installation('path/to/MyGame/Content/Paks', engine='5.7',
                        usmap='path/to/MyGame.usmap', build=None, aes_key=key) as assets:
    print(assets)                                           # <Installation engine=5.7 build=unknown ...>
    tex = assets.texture('/Game/UI/Icons/T_Something')
    print(tex.info.width, tex.info.height, tex.info.readable)
    region = tex.read_region(0, 0, 0, 128, 128)               # mip 0, top-left 128x128, RGBA8
    print(region.width, region.height, len(region.pixels))
```

## Opening

```python
from nylib.ue.assets import AesKey

key = AesKey.from_hex('00' * 32)
print(repr(key))
```

- `aes_key=` takes an `AesKey`, raw `bytes`/`bytearray` (wrapped with the zero GUID), a list of `AesKey` (one per container GUID), or `None` for an install with no encrypted container. `AesKey` also reads a key file (`AesKey.from_file(path)`) or raw/hex bytes (`AesKey(key_bytes)`); a `str` passed as `aes_key=` is rejected, pointing at `from_hex()` / `from_file()`, so a key is never typed into a log or a repr by accident.
- `usmap=` is the game's `.usmap` mapping file (v0-v4; compression None, Oodle, or ZStd on Python 3.14+). It is parsed once, at open.
- `build=` pins the exe's PE `TimeDateStamp`: pass the int you verified a `.usmap` against, and a mismatched or missing exe raises `BuildMismatchError`. Pass `None` to skip the check; `Installation.build` still reports the exe found, if any.
- `cache_bytes=` caps the shared decompressed-block cache; default 4 MiB (approximate measured timings are under Notes).
- `Installation` is a context manager; `close()` is idempotent and thread-safe, and an unclosed instance that is garbage-collected closes itself and emits a `ResourceWarning`.

## Finding packages

- `assets.has_package(name) -> bool` checks without reading any container data.
- `assets.package(name) -> PackageInfo` reads the package header's summary block. `name` accepts a package path (`/Game/UI/Icon`), an object path (`/Game/UI/Icon.Icon`), or a `.uasset`/`.umap` file path.
- `assets.list_packages(prefix='/', *, match=None) -> list[PackageInfo]` walks the directory index of every mounted container (built once, cached until `close()`); `match` is an `fnmatch`-style pattern over the whole name, ASCII-case-insensitive like `prefix`.
- Name case: `list_packages()` reports the case the container's directory index recorded for the path; `package()` and `texture()` report the case the package header itself recorded. The two can differ -- measured on one game: 3 of 212 sampled names, e.g. `.../APC/Wavs/...` against `.../APC/WAVs/...` -- but always name the same package: the same `PackageInfo.package_id`, and name matching throughout is ASCII-case-insensitive.

## Metadata

- `assets.texture(name) -> Texture` resolves the `Texture2D` export and parses its header into `Texture.info` (a `TextureInfo`): `width`, `height`, `pixel_format`, `mips` (a `MipInfo` per level), `alpha` (`'none'` or `'straight'`), `virtual` (a `VirtualTextureInfo`, or `None` for an ordinary texture -- not readable in this stage), `readable`, and `unsupported` (the reason, matching the error `read_region` would raise). The first `texture()` call on an installation is slower; see Notes.
- `assets.stats() -> ReadStats` returns the running totals since open (`reads`, `bytes_read`, `blocks_decompressed`, `tiles_decoded`, `seconds`, ...). Subtracting two snapshots measures one span; `str(stats)` is a one-line summary.

## Reading regions

`tex.read_region(mip, x, y, width, height, *, clip=False, missing='raise', out=None, cancel=None) -> Region` decodes virtual-texture BC1 tiles to RGBA8 (ordinary textures are not readable in this stage; check `info.readable` first).

- Coordinates are pixel coordinates of mip `mip`, origin top-left, rows returned top to bottom; sizes come from `info.mips[mip]` and are never rescaled.
- Output is tightly packed RGBA8: `len(region.pixels) == width * height * 4`, no sRGB conversion. Alpha is 255 whenever `info.alpha == 'none'`.
- `clip=True` shrinks the rectangle to the mip's bounds instead of raising; `clip=False` (default) raises `RegionOutOfBoundsError` outside the bounds.
- `missing='raise'` (default) raises `MissingTileError` if any touched tile is unstored; `'transparent'` fills it with `(0, 0, 0, 0)`; `'fallback'` fills it with `info.virtual.fallback[0]`. `region.missing` lists the filled rectangles either way.
- Only the tiles the rectangle touches are decoded, and each compression block is fetched and decompressed at most once per call. The result is the same regardless of cache state, thread count, or the `missing` policy outside the filled areas.
- `out=` writes into a caller-supplied writable buffer instead of allocating a new `bytes`; `cancel=` is a zero-argument callable polled between tiles, raising `ReadCancelledError` when it returns true.

## Threads and cancellation

- Any number of threads may call `Installation` and `Texture` methods at once; they wait on each other only briefly, around each container block read and the shared block cache. Records and `AesKey` are immutable.
- The GIL is released during file I/O, AES decrypt and Oodle decompress, and held during parsing and the BC1 decode, which is pure Python.
- `close()` waits for reads running on other threads, except one it is called from itself; once it returns with no in-flight read of its own, the installation holds no file handle, lock object or cache.
- `Installation`, `Texture` and `AesKey` refuse pickling and `copy`/`deepcopy`; records and the error classes do pickle.

## Errors

```text
UeError
└── AssetError                      every nylib.ue.assets failure but argument-type errors; .package, .container
    ├── InvalidKeyError             no/wrong AES key, GUID mismatch, bad key file; .key_guid, .reason, .path
    ├── InvalidMappingError         .usmap missing, invalid, or does not fit the data; .usmap, .class_name, .property_index, .property_name, .reason, .path
    │   └── BuildMismatchError      build= differs from the exe's own stamp; .expected, .found, .exe, .path
    ├── MissingAssetError           package or export not in a mounted container (a LookupError); .export
    │   └── MissingTileError        missing='raise' hit an unstored VT tile; .mip, .tiles
    ├── UnsupportedError             outside the supported profile; .feature
    │   ├── UnsupportedContainerError    TOC version, AES mode, compression method, or no usable Oodle
    │   ├── UnsupportedAssetError         asset class or native layout; .exports
    │   └── UnsupportedPixelFormatError   no decoder for this pixel format; .pixel_format
    ├── CorruptAssetError            structure or codec check failed; .detail (a block decode's __cause__ is an OodleError)
    ├── RegionOutOfBoundsError       rectangle or mip out of range (a ValueError); .mip, .rect, .size
    ├── ReadCancelledError           cancel() returned true
    └── InstallationClosedError      the installation is already closed (a ValueError)
```

- Wrong argument types raise `TypeError`, wrong values raise `ValueError` -- never one of the classes above, except `RegionOutOfBoundsError`, which is both an `AssetError` and a `ValueError`.
- `AmbiguousNameError` (re-exported from `nylib.ue`, not under `AssetError`) is raised by `texture()` when a short name matches more than one export.
- Messages are one line of English; never a path beyond a basename, key material, decrypted/decoded bytes, mapping-file content, or a property name.

## Supported profile

| Layer | Supported in this version | Beyond it |
|---|---|---|
| Container | IoStore TOC v8; AES-256-ECB; Oodle (Kraken) and stored blocks; compression blocks a power of two from 4 KiB to 16 MiB | `UnsupportedContainerError`; a `.pak` is listed in `containers` but never mounted |
| Mapping | `.usmap` v0-v4; compression None, Oodle, ZStd (needs Python 3.14+) | `InvalidMappingError` |
| Package | zen packages, unversioned properties | `InvalidMappingError`, `CorruptAssetError` |
| Texture metadata | every `Texture2D` export, virtual and ordinary | another class: `UnsupportedAssetError` |
| Region reads | virtual textures only: `RawGPU` codec, one layer, `PF_DXT1`, non-legacy tile layout | `UnsupportedAssetError` / `UnsupportedPixelFormatError`; `info.readable` is False and names the reason |

## Notes

- No resampling: a mip's pixels come back at that mip's own size; scaling is the caller's job.
- The BC1 decode is pure Python: it holds the GIL and costs CPU per pixel, so a large region read is single-core bound during that part.
- The first `texture()` call on an installation also loads the global ScriptObjects table once (about 4.66 MB on the measured game) and costs about 0.42 s total on one measured machine, almost all of it that load; later `texture()` calls reuse the table.
- A BC1 three-colour block's index-3 texel decodes here as `(0, 0, 0, 255)` (CUE4Parse's own fill is alpha 0). Neither measured map's blocks used that index (0 of 1,560,299 sampled three-colour blocks), so this never showed a difference there.
- Approximate, one machine: `open_installation` took about 0.22 s (about 0.15 s of that parsing the `.usmap`); region reads were about 30 ms p50 whether `cache_bytes` was 0, the 4 MiB default, or 16 MiB -- decode-bound, so a bigger cache mainly helps repeated reads of the same tiles.
- Windows x64 only (BCrypt for AES; the exe's PE and the `.ucas`/`.utoc` layout). Treat an AES key file and its contents as a secret: never log, print or commit one; pass it by path.
