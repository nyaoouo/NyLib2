# nylib.ue.assets

Read-only reader for a UE 5.7 game's IoStore (`.utoc`/`.ucas`) containers: enumerate packages, including those under plugin mount roots, read `Texture2D` metadata, read typed export properties and cross-package references, and decode bounded regions of virtual-texture BC1 tiles and ordinary `PF_B8G8R8A8` textures to RGBA8. Python, with Windows BCrypt for AES and the bundled Oodle DLL for decompression; no FModel, CUE4Parse or Unreal dependency.

Keywords: IoStore, utoc, ucas, AesKey, open_installation, Installation, Texture, virtual texture, VT, BC1, DXT1, B8G8R8A8, ordinary texture, plugin, read_region, usmap, mapping, zen package, PackageInfo, TextureInfo, Region, ScriptObjects, Oodle, Exports, StructValue, DataTable, CurveTable, native struct, ObjectRef

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
- `exe=` names the game exe whose PE stamp `build=` checks. By default it is the unique `*-Win64-Shipping.exe` in `<paks>/../../Binaries/Win64`; none, or more than one, counts as missing. A game that ships its exe elsewhere needs `exe=`.
- `cache_bytes=` caps the shared decompressed-block cache; default 4 MiB (approximate measured timings are under Notes).
- `Installation` is a context manager; `close()` is idempotent and thread-safe, and an unclosed instance that is garbage-collected closes itself and emits a `ResourceWarning`.

## Finding packages

- `assets.has_package(name) -> bool` checks without reading any container data.
- `assets.package(name) -> PackageInfo` reads the package header's summary block. `name` accepts a package path (`/Game/UI/Icon`), an object path (`/Game/UI/Icon.Icon`), or a `.uasset`/`.umap` file path (`Engine/Content/...` or `<Project>/Content/...`); a name may now end in a sub-object path, `/Pkg.Top:Sub.Sub`, naming a nested export by its outer chain, in every method that takes a name (`has_package()`, `package()` and `exports()` ignore the export part). It is also how `texture()` picks one of several `Texture2D` exports that share a name: `texture('<pkg>.<outer>:<name>')` selects one when `AmbiguousNameError` lists more than one.
- `assets.list_packages(prefix='/', *, match=None) -> list[PackageInfo]` walks the directory index of every mounted container (built once, cached until `close()`); `match` is an `fnmatch`-style pattern over the whole name, ASCII-case-insensitive like `prefix`.
- Name case: `list_packages()` reports the case the container's directory index recorded for the path; `package()` and `texture()` report the case the package header itself recorded. The two can differ -- measured on one game: 3 of 212 sampled names, e.g. `.../APC/Wavs/...` against `.../APC/WAVs/...` -- but always name the same package: the same `PackageInfo.package_id`, and name matching throughout is ASCII-case-insensitive.
- Plugin mount roots: `list_packages()` also lists packages under an `Engine/Plugins/.../Content/...` or `<Project>/Plugins/.../Content/...` directory, named `/<mount>/<rest>`. `<mount>` is the plugin folder name when that already matches the entries' recorded chunk ids; otherwise the directory spends one summary read on its first non-matching entry to learn `<mount>` from that entry's recorded package name, then reuses it for the rest of the directory (measured on one game: 106 of 22,313 plugin-root files needed a learned mount, from 2 learning reads). A learned `<mount>` keeps the recorded name's case; `<rest>` always keeps the directory index's case.
- The `.uasset`/`.umap` file-path form does not extend to plugin roots: a file path under a `Plugins/` directory still raises `ValueError`. Address a plugin-root package by the package-path or object-path form (`/<mount>/...`), or by the name `list_packages()` returns.

## Metadata

- `assets.texture(name) -> Texture` resolves the `Texture2D` export and parses its header into `Texture.info` (a `TextureInfo`): `width`, `height`, `pixel_format`, `mips` (a `MipInfo` per level), `alpha` (`'none'` or `'straight'`), `virtual` (a `VirtualTextureInfo`, or `None` for an ordinary texture), `readable`, and `unsupported` (the reason, matching the error `read_region` would raise). The first `texture()` call on an installation is slower; see Notes.
- `assets.stats() -> ReadStats` returns the running totals since open (`reads`, `bytes_read`, `blocks_decompressed`, `tiles_decoded`, `seconds`, ...); `reads` now also counts `read()`, `Exports.read()`, `raw()` and `Exports.raw()` calls, not only region reads. Subtracting two snapshots measures one span; `str(stats)` is a one-line summary.

## Reading regions

`tex.read_region(mip, x, y, width, height, *, clip=False, missing='raise', out=None, cancel=None) -> Region` decodes pixel data to RGBA8: virtual-texture BC1 tiles, or an ordinary `PF_B8G8R8A8` texture's mip rows. Check `info.readable` first; `info.unsupported` names the reason when it is False.

- Coordinates are pixel coordinates of mip `mip`, origin top-left, rows returned top to bottom; sizes come from `info.mips[mip]` and are never rescaled.
- Output is tightly packed RGBA8: `len(region.pixels) == width * height * 4`, no sRGB conversion. Alpha is 255 whenever `info.alpha == 'none'`.
- `clip=True` shrinks the rectangle to the mip's bounds instead of raising; `clip=False` (default) raises `RegionOutOfBoundsError` outside the bounds.
- Virtual texture: `missing='raise'` (default) raises `MissingTileError` if any touched tile is unstored; `'transparent'` fills it with `(0, 0, 0, 0)`; `'fallback'` fills it with `info.virtual.fallback[0]`. `region.missing` lists the filled rectangles either way, and only the tiles the rectangle touches are decoded.
- Ordinary texture: the stored byte order is B, G, R, A; the output is R, G, B, A with the values as stored, still no sRGB conversion. There are no tiles, so `missing` is validated but has no other effect, and `region.missing` is always `()`. Only the rows `y .. y + height - 1` of the mip are read.
- Either way, each compression block is fetched and decompressed at most once per call, and the result is the same regardless of cache state, thread count, or (for a virtual texture) the `missing` policy outside the filled areas.
- `out=` writes into a caller-supplied writable buffer instead of allocating a new `bytes`; `cancel=` is a zero-argument callable polled between tiles (virtual texture) or compression blocks (ordinary texture), raising `ReadCancelledError` when it returns true.

Compatibility: in an earlier version, every ordinary (non-virtual) texture raised `UnsupportedAssetError(feature='non-virtual texture')` from `read_region`, unconditionally. Now a readable ordinary texture decodes, and an ordinary texture in a pixel format with no decoder raises `UnsupportedPixelFormatError` instead -- as an unsupported virtual-texture layer format already did. Both error classes derive from `UnsupportedError`; a caller that catches only `UnsupportedAssetError` around `read_region` misses the new one. `texture()` on an ordinary texture can now also raise `CorruptAssetError`, for a mip whose size, `.ubulk` range or serial size is inconsistent. And a plugin content directory whose learning read fails lists only the entries that already match their folder name; the rest are dropped, visible only in the DEBUG log.

## Exports and properties

```python
# needs: an installed UE 5.7 game, its AES key file and a matching .usmap
from nylib.ue.assets import (
    open_installation, AesKey, Exports, ExportInfo, Export, StructValue, Slot,
    MapValue, EnumValue, TextValue, ObjectRef, SoftObjectRef, DataTable, CurveTable,
    AbsentPropertyError, AmbiguousNameError,
)

key = AesKey.from_file('path/to/game-aes.txt')
with open_installation('path/to/MyGame/Content/Paks', engine='5.7',
                        usmap='path/to/MyGame.usmap', build=None, aes_key=key) as assets:
    exp = assets.exports('/Game/Some/DataAsset')             # Exports: the cooked header only, no export data
    print(exp.package.name, len(exp))                        # a package name and its export count
    export = exp.read(0)                                     # Export: typed properties of export 0
    print(export.info.class_name, export.complete, export.exact, export.native_size)   # class_name can be None, see ExportInfo below
    props = export.properties                                # StructValue, the export's top-level slots
    print(props.struct, len(props.slots), props.state(0))     # struct name, slot count, slot 0's state
    try:
        props.at(0)
    except AbsentPropertyError as e:
        print(str(e))                                        # not serialized: the archetype's value is unknown here
```

- `assets.exports(name, *, cancel=None) -> Exports` reads a package's cooked header only (no export data) and returns an `Exports` handle: a `Sequence[ExportInfo]` with `package` (a `PackageInfo`), `stats` (a `ReadStats` for this call), `find(name) -> ExportInfo` (no I/O), `read(which, *, partial=False, cancel=None) -> Export` and `raw(which, *, offset=0, limit, cancel=None) -> bytes`. `which` takes an index, a name or sub-object path, or an `ExportInfo` from this handle. Calling `Exports(...)` directly raises `TypeError`; an `Exports` keeps its `Installation` alive and refuses pickling. After `close()`, its `read()` and `raw()` raise `InstallationClosedError`; `len`, indexing, iteration and `find()` keep working.
- `assets.read(target, *, partial=False, cancel=None) -> Export` reads one export directly: `target` is a package or object path (`str`, sub-object paths included), an `ExportInfo`, an `ObjectRef` or a `SoftObjectRef` (see References, below). `Export` holds `info` (`ExportInfo`), `properties` (a `StructValue`), `native` (a `DataTable`, `CurveTable` or `None`), `native_size` (the bytes after the object trailer, or after any table rows), `exact` (`complete` and `native_size == 0`), `guid`, `complete` and `problem` (an `AssetError`, set only on a partial result; see Partial reads, below).
- `ExportInfo` (from `Exports`, `find()` or `resolve()`) holds `package`, `name`, `path`, `index`, `class_name`, `class_ref`, `super_ref`, `template_ref` (the last three `ObjectRef`s), `outer` (an export index or `None`), `flags`, `size` and `container`. `class_name` is set only when `class_ref.kind` is `'script'` (an engine class) or `'export'` (a class in the same package); for a class imported from another package, which is how a Blueprint `..._C` class usually appears, it is `None`, and `assets.resolve(info.class_ref).name` gives the class name.
- Each property reads to a plain Python value for the simple kinds (`bool`, `int`, `float`, `str`), or to one of the records above: `ObjectRef` / `SoftObjectRef` for a reference, `EnumValue` for an enum, `TextValue` for an `FText`, a `tuple` (or `bytes`, for a byte array) for an array or set, `MapValue` for a map, the value itself or `None` for an optional, and a nested `StructValue` for a struct -- reflected (decoded through the `.usmap` mapping) or native (one of the built-in layouts below).
- `StructValue` is a read-only `Mapping[str, object]` with `struct` (its class or struct name), `native` (`bool`) and `slots` (a tuple of `Slot`); `sv[name]`, `sv.at(index)` and `sv.state(key)` read by name or by schema index. A slot's state is `'serialized'` (its bytes were stored), `'zero'` (the header marked it unset; it reads as its type's zero value), `'absent'` (the header never listed it -- the real value is the class archetype's, which this data does not hold, so `sv[name]` raises `AbsentPropertyError`), or `'unread'` (only inside a partial result). A name shared by more than one property in the class chain raises `AmbiguousNameError` from `sv[name]`; use `sv.at(index)` instead.
- `StructValue.to_python()` returns a plain `dict` built only from lists, dicts and `str`/`int`/`float`/`bool`/`None` -- safe for `json.dumps(..., allow_nan=False)`; a float inside may be NaN or infinite, which plain `json.dumps` then writes as non-standard JSON. It raises `problem` if any slot of the value is `'unread'`. The shape is frozen:

  | value | plain form |
  | --- | --- |
  | a property whose name is not shared, all its slots serialized or zero | one key: its value |
  | a name shared by several properties | one key per property sharing it, `name#index` (`index` the base schema index) |
  | a static array, no absent elements | a `list` |
  | a static array with some absent elements | one key per present element, `name[element]` (`name#index[element]` when the name is also shared) |
  | `MapValue` | a list of `[key, value]` pairs, repeated keys included |
  | a native struct | its fields, by the same rules |
  | `ObjectRef` | a dict of `kind`, `package`, `name`, `path`; an `'import'` ref gives `name` and `path` as `None`, so it does not identify its target on its own -- call `resolve()` first when the target matters |
  | `SoftObjectRef` | a dict of `package`, `asset`, `subpath`, `path` |
  | `EnumValue` | a dict of `enum`, `name`, `value` |
  | `TextValue` | a dict of `history`, `string`, `namespace`, `key`, `table`, `data` |

  Absent properties are left out. See Notes, below, for what a read like this can cost in memory, and for the risk of an untrusted `.usmap` mapping.
- Beyond the reflected shapes the mapping describes, 121 built-in ("native") struct layouts are recognized directly: simple fixed-size math types (`Vector`, `Color`, `Guid`, `Matrix`, `Quat`, and similar), and a smaller set of variable-length engine types (`GameplayTagContainer`, `InstancedStruct` and its container/array forms, the property-bag types, `Spline`, the `MovieScene*` channel and evaluation-tree types, the `Niagara*` variable types, `PCGPointArray`, and a few more). Each decodes to a `StructValue` with `native=True`, one `Slot` per field, named and typed the same way any other property is; `slots` and `to_python()` list them for a given value. Four exceptions read differently: `InstancedStruct` decodes to its payload value directly (`None` for a null type), not a `StructValue`; `InstancedStructContainer` and `InstancedStructArray` decode to a `tuple` of payloads; the soft-path family (`SoftObjectPath`, `SoftClassPath`, `StringAssetReference`, `StringClassReference`) decodes to a `SoftObjectRef`; and `InstancedPropertyBag` and `RigVMPropertyBag` decode to a `StructValue` with `native=False`, whose slots can be serialized, zero or absent like any reflected struct's. A struct name outside the native set still reads through the `.usmap` mapping like any reflected struct -- see Supported natives, below.

## References

- A reference inside a property value is an `ObjectRef` (for `Object`, `WeakObject` and `Interface` properties; a lazy pointer reads as a plain GUID string instead) or a `SoftObjectRef` (a soft/asset path property). `ObjectRef.kind` is `'null'`, `'export'` (points inside the same package), `'import'` (points at another package, named by `package` and resolved lazily by its hash) or `'script'` (an engine class or package with no cooked export of its own, for example `/Script/Engine.StaticMesh`); `bool(ref)` is `False` only for `'null'`. Two `ObjectRef`s compare equal only when they point at the exact same object, so two different exports imported from one package never compare equal even though both have `kind == 'import'` and the same `package`. An export ref and an import ref to the same object compare unequal too, because the two kinds never carry the same hidden identity; compare `resolve()` results by `path` when it is the target, not the reference's own kind, that must match.
- `SoftObjectRef` holds `package`, `asset`, `subpath` and the combined `path`; `bool(ref)` is `False` only for an empty `path`.
- `assets.resolve(ref, *, cancel=None) -> ExportInfo` follows an `ObjectRef` or `SoftObjectRef` to the `ExportInfo` it points at, reading only the target package's cooked header -- never the export's own data, and nothing is cached across calls. `assets.read(ref)` and `assets.raw(ref)` accept a reference directly and read the target's data in one call. Resolving `ObjectRef('null', ...)`, or a reference to a `'script'` object, raises `ValueError`: neither has a cooked export to read.

## Tables and curves

- A `DataTable` export's `Export.native` is a `DataTable` record: `row_struct` (the row struct's name, or `None` when it came from another package -- the rows still decode through the resolved struct), `row_struct_ref` (an `ObjectRef`) and `rows`, a `MapValue` from row name to that row's `StructValue`, in file order.
- A `CurveTable` export's `Export.native` is a `CurveTable` record: `mode` (`'Empty'`, `'SimpleCurves'` or `'RichCurves'`), `rows` (as above, each row a `SimpleCurve` or `RichCurve` `StructValue`), and `keys(row) -> tuple[StructValue, ...]`, the row's key array -- `SimpleCurveKey` or `RichCurveKey` values, in order; `keys()` raises `KeyError` for an unknown row name.
- `Export.native` is `None` for every other class; a class is read as a table only when its class chain includes `DataTable` or `CurveTable`.

## Partial reads and `raw()`

- `read(target, *, partial=True)` returns a best-effort `Export` instead of raising when a property, the object trailer, or a table row fails to decode: `complete` is `False`, `native` is `None`, and `problem` holds the `AssetError` that a non-partial call would have raised. `properties` keeps every top-level slot that was read completely before the failure; the slot that failed, and every slot after it that the header listed, are `'unread'` (reading one re-raises `problem`); slots the header never listed are `'absent'`, as usual. A partially read value is never exposed through a slot. Two failures make every top-level slot `'unread'` instead of mixing in `'absent'`: the header itself failed to parse, and a class block whose own slots would exceed the decode budget -- marking the unlisted ones absent would itself build the slots the budget refuses.
- `assets.raw(target, *, offset=0, limit, cancel=None) -> bytes` and `Exports.raw(which, ...)` return the export's raw bytes `[offset, offset + limit)`, cut at the export's end, without decoding anything; `limit` has no default and must be at most 64 MiB, like `read()`'s own export-size cap. Only the compression blocks that range touches are read.

## Supported natives

- Beyond the hundred-plus built-in layouts under Exports and properties, above, every other struct name encountered reads through the `.usmap` mapping, the same way any reflected struct does -- including several engine-looking names (for example `BodyInstance`, `ScalarParameterValue`, `VectorParameterValue`, `TextureParameterValue`) whose only native implementation elsewhere belongs to another UE game; for this game, those names are ordinary unversioned data, and the mapping's own record decides how each reads.
- A struct name that is not read at all raises `UnsupportedAssetError` with `feature='native struct <name>'`, `struct_name` set to that name, and `position` where its bytes begin. These fall into two groups: 29 engine-independent natives that sit outside the built-in set and were never seen in the measured install -- `ColorMaterialInput`, `CompressedRichCurve`, `ExpressionInput`, `ScalarMaterialInput`, `VectorMaterialInput`, `Vector2MaterialInput`, `MaterialAttributesInput`, `SkeletalMeshSamplingRegionBuiltData`, `PannerDetails`, `LevelSequenceObjectReferenceMap`, `MaterialLayersFunctionsTree`, `MidiEvent`, `RawAnimSequenceTrack`, `SectionEvaluationDataTree`, `Transform3f`, `TypedParameter`, `UniqueNetIdRepl`, `ClothLODDataCommon`, `ClothLODData`, `ClothTetherData`, `AnimationAttributeIdentifier`, `AttributeCurve`, `PCGPoint`, `CacheEventTrack`, `DataCacheDuplicatedObjectData`, `EdGraphPinType`, `ControlRigOverrideContainer`, `UInt32Property`, `ZeroSizeProperty` -- and 74 natives whose one known layout was written for a different game entirely (for example `FixedPoint`, `GameplayEffectFloatMapping`, `NiagaraUserParameterModifier`). Reading either raises rather than guessing at a layout this game's own data may not share.

## Threads and cancellation

- Any number of threads may call `Installation`, `Exports` and `Texture` methods at once; they wait on each other only briefly, around each container block read and the shared block cache. Records and `AesKey` are immutable.
- The GIL is released during file I/O, AES decrypt and Oodle decompress, and held during parsing and the BC1 decode, which is pure Python.
- `close()` waits for reads running on other threads, except one it is called from itself; once it returns with no in-flight read of its own, the installation holds no file handle, lock object or cache.
- `Installation`, `Exports`, `Texture` and `AesKey` refuse pickling and `copy`/`deepcopy`; records, values (`StructValue` and `MapValue` included) and the error classes pickle and `deepcopy` round-trip.
- `cancel=` on `exports()`, `read()`, `raw()` and `resolve()` is checked before every compression block an operation touches, every few thousand export-map entries while listing a package's exports, and every few thousand decoded values while decoding properties or table rows. The one gap is the cooked-header parse itself after its last block, which has no checkpoint and grows linearly with the header: on one measured install, worst-case cancel latency there was about 0.2 s for a main map's `exports()` and about 0.45-0.48 s for the largest cooked header in the whole install.

## Errors

```text
UeError
└── AssetError                      every nylib.ue.assets failure but argument-type errors; .package, .container, .export
    ├── InvalidKeyError             no/wrong AES key, GUID mismatch, bad key file; .key_guid, .reason, .path
    ├── InvalidMappingError         .usmap missing, invalid, or does not fit the data; .usmap, .class_name, .property_index,
    │                               .property_name, .reason, .path, .property_path, .property_type, .position, .struct_name, .row
    │   └── BuildMismatchError      build= differs from the exe's own stamp; .expected, .found, .exe, .path
    ├── MissingAssetError           package or export not in a mounted container (a LookupError)
    │   └── MissingTileError        missing='raise' hit an unstored VT tile; .mip, .tiles
    ├── UnsupportedError             outside the supported profile; .feature
    │   ├── UnsupportedContainerError    TOC version, AES mode, compression method, or no usable Oodle
    │   ├── UnsupportedAssetError         asset class or native layout; .exports, .class_name, .property_index,
    │   │                                 .property_name, .property_path, .property_type, .position, .struct_name, .row
    │   └── UnsupportedPixelFormatError   no decoder for this pixel format; .pixel_format
    ├── CorruptAssetError            structure or codec check failed; .detail (a block decode's __cause__ is an OodleError)
    ├── RegionOutOfBoundsError       rectangle or mip out of range (a ValueError); .mip, .rect, .size
    ├── ReadCancelledError           cancel() returned true
    ├── InstallationClosedError      the installation is already closed (a ValueError)
    └── AbsentPropertyError          a property slot was not serialized, so its value is the archetype's one nylib does not
                                      hold (also a KeyError); .class_name, .property_index, .property_name
```

- Wrong argument types raise `TypeError`, wrong values raise `ValueError` -- never one of the classes above, except `RegionOutOfBoundsError`, which is both an `AssetError` and a `ValueError`. An out-of-range `Exports` index, or an out-of-range index to `StructValue.at()` or `StructValue.state()`, raises `IndexError`; an unknown name to `sv[name]` or `CurveTable.keys()` raises `KeyError`.
- `AmbiguousNameError` (re-exported from `nylib.ue`, not under `AssetError`) is raised by `texture()` when a package name, or an object path's export name, matches more than one Texture2D export, and by `read()`, `raw()` and `Exports.find()` when a name matches more than one export; it is not an `AssetError`.
- `AbsentPropertyError` is also a `KeyError`, but overrides `__str__` so `str(err)` is the plain message despite `KeyError`'s quoting; `StructValue.get()` and `in` treat it as missing, the way a real `KeyError` would. A `problem` carried by a partial `Export` (below) is never a `KeyError`, so `get()` never turns an unread property into a default silently.
- A failure found while reading one export's properties -- `InvalidMappingError` or `UnsupportedAssetError` raised from inside a property block, the object trailer, a table row, or a native struct -- carries `property_path`: the steps from the export's class down to the failure, for example `WDWeaponStatsData#1.WDWeaponStats#36`, an array index as `[3]`, a map key or value as `[key 0]` / `[value 0]`, a table row as `[row 2]`. `class_name`, `property_index`, `property_name` and `property_type` describe that last step; `position` is where the failing read began; `struct_name` names the native struct involved, when there is one; `row` names the table row, when the failure is inside one. The message itself still never repeats a property or row name -- those live only in the attributes.
- Messages are one line of English; never a path beyond a basename, key material, decrypted/decoded bytes, mapping-file content, or a property name.

## Supported profile

| Layer | Supported in this version | Beyond it |
|---|---|---|
| Container | IoStore TOC v8, one partition per container; AES-256-ECB; Oodle (Kraken) and stored blocks; compression blocks a power of two from 4 KiB to 16 MiB | `UnsupportedContainerError` (more than one partition: `feature='multiple partitions'`); a `.pak` is listed in `containers` but never mounted |
| Mapping | `.usmap` v0-v4; compression None, Oodle, ZStd (needs Python 3.14+) | `InvalidMappingError` |
| Package | zen packages, unversioned properties | `InvalidMappingError`, `CorruptAssetError` |
| Exports and typed properties | every property kind and reference (`exports()`, `read()`, `raw()`, `resolve()`); 121 built-in native struct layouts; any other struct name through the `.usmap` mapping | a native struct this version does not read (named under Supported natives, above): `UnsupportedAssetError` |
| Texture metadata | every `Texture2D` export, virtual and ordinary | another class: `UnsupportedAssetError` |
| Virtual-texture region reads | `RawGPU` codec, one layer, `PF_DXT1`, non-legacy tile layout | `UnsupportedAssetError` / `UnsupportedPixelFormatError`; `info.readable` is False and names the reason |
| Ordinary-texture region reads | `PF_B8G8R8A8` mips that are inline in the export, or in the package's default `.ubulk` (cooked index 0) | `UnsupportedPixelFormatError` for another pixel format; `UnsupportedAssetError` for no serialized mips, mip data not serialized with the texture, compressed bulk data, optional bulk data (`.uptnl`), memory-mapped bulk data (`.m.ubulk`), bulk data under another cooked index, or any other placement; `info.readable` is False and names the reason |

## Notes

- No resampling: a mip's pixels come back at that mip's own size; scaling is the caller's job.
- The BC1 decode is pure Python: it holds the GIL and costs CPU per pixel, so a large region read is single-core bound during that part.
- The first call to `texture()`, `exports()`, `read()`, `raw()` or `resolve()` on an installation loads the global ScriptObjects table once (about 4.66 MB on the measured game) and costs about 0.42 s total on one measured machine, almost all of it that load; later calls reuse the table.
- A BC1 three-colour block's index-3 texel decodes here as `(0, 0, 0, 255)` (CUE4Parse's own fill is alpha 0). Neither measured map's blocks used that index (0 of 1,560,299 sampled three-colour blocks), so this never showed a difference there.
- Approximate, one machine: `open_installation` took about 0.22 s (about 0.15 s of that parsing the `.usmap`); region reads were about 30 ms p50 whether `cache_bytes` was 0, the 4 MiB default, or 16 MiB -- decode-bound, so a bigger cache mainly helps repeated reads of the same tiles.
- Approximate, one machine, an ordinary-texture terrain tile (`PF_B8G8R8A8`, `.ubulk` mips): a 2x2 sample took about 0.1 ms on 1 compression block; a mip 0 read was about 2.5 ms p50, with `cancel=` polled once per compression block, about every 0.3 ms on the measured tile -- it does not add that much latency itself. `list_packages()`'s first call, which also learns plugin mount roots, took 4.25-5.0 s.
- Approximate, one machine, exports and typed reads: `exports()` of a main map's cooked header took about 0.28-0.30 s and retained about 35-38 MiB; `read()` of a small export was well under 1 ms p50; a 64-byte `raw()` through an `Exports` handle read 1 compression block (2 when the range crosses a block boundary); through `assets.raw()` it read 3, because that call also reads the target's cooked header. Over a one-in-sixty sample of the install's packages (1,787 packages, 21,141 exports), the sweep itself took a few seconds, and the export with the most decoded values in that sample (394,305, an `AudioImpulseResponse`) read in about 0.13 s with peak working-set growth of about 17 MiB over the baseline. Cancelling during a main map's `exports()` had a latency of about 93 ms p50 (198 ms worst case, from the gap noted under Threads and cancellation, above); cancelling mid-decode was about 1 ms.
- Limits of one `read()`: a cooked header or an export's data over 64 MiB raises `CorruptAssetError`; a value more than 16 struct levels deep raises `InvalidMappingError` with reason `struct nesting`, and one more than 64 levels deep counting containers raises `value nesting`; a read whose decoded values and built slots exceed the export's size in bytes plus 65,536 raises `decode budget`. On one measured install no export reached the last two, and the largest read used 0.375 units per byte above the 65,536.
- Memory follows the decoded values, which are Python objects: an export made mostly of small native structs keeps up to about 190 bytes per input byte while its result is alive, so a 64 MiB export of `Color` values would take about 12 GiB. Read large exports one at a time, or use `raw()`.
- The `.usmap` is trusted input: with a hand-crafted mapping, `==` between values from two reads and `to_python()` can take seconds on a few bytes of data, because they expand zero-masked structs that one read shares.
- Windows x64 only (BCrypt for AES; the exe's PE and the `.ucas`/`.utoc` layout). Treat an AES key file and its contents as a secret: never log, print or commit one; pass it by path.
