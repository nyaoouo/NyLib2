# nylib.ue.assets

Read-only reader for a UE 5.7 game's IoStore (`.utoc`/`.ucas`) containers: enumerate packages, including those under plugin mount roots, read `Texture2D` metadata, read typed export properties and cross-package references, and decode bounded regions of virtual-texture BC1 tiles and ordinary `PF_B8G8R8A8`, `PF_DXT1`, `PF_DXT5` and `PF_BC7` textures to RGBA8, including ordinary mips stored as optional bulk data (`.uptnl`). Windows BCrypt handles AES and the bundled Oodle DLL handles decompression. BC1 decodes through `nylib.utils.bcn`'s bundled DLL when it loads, otherwise in pure Python, with identical pixels; no FModel, CUE4Parse or Unreal dependency.

Keywords: is_stale, usmap=None, nylib.utils.bcn, IoStore, utoc, ucas, AesKey, open_installation, Installation, Texture, virtual texture, VT, BC1, DXT1, DXT5, BC7, B8G8R8A8, .uptnl, ordinary texture, plugin, read_region, usmap, mapping, zen package, PackageInfo, TextureInfo, Region, ScriptObjects, Oodle, Exports, StructValue, DataTable, CurveTable, native struct, ObjectRef, pak, read_file, FileInfo, locres, locmeta, localization, InstanceData, instanced mesh

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
- `usmap=` is the game's `.usmap` mapping file (v0-v4; compression None, Oodle, or ZStd on Python 3.14+), a `Usmap` from `load_usmap()`, or explicitly `None` for reads [without a mapping](#without-a-mapping). A path is parsed once, at open; a `Usmap` is reused without reading the mapping file again.
- `build=` pins the exe's PE `TimeDateStamp`: pass the int you verified a `.usmap` against, and a mismatched or missing exe raises `BuildMismatchError`. Pass `None` to skip the check; `Installation.build` still reports the exe found, if any.
- `exe=` names the game exe whose PE stamp `build=` checks. By default it is the unique `*-Win64-Shipping.exe` in `<paks>/../../Binaries/Win64`; none, or more than one, counts as missing. A game that ships its exe elsewhere needs `exe=`.
- `cache_bytes=` caps only the shared decompressed-block cache; default 4 MiB (approximate measured timings are under Notes). A separate 96 MiB accounted-byte LRU retains validated cooked headers, even with `cache_bytes=0`. First loads also account for retained header fields and strings; this budget excludes transient parsing memory and caller-owned handles.
- `Installation` is a context manager; `close()` is idempotent and thread-safe, and an unclosed instance that is garbage-collected closes itself and emits a `ResourceWarning`.

## Long-lived installations

Keep an installation open and reuse its `Texture` handles between reads. Call `assets.is_stale()` periodically from a worker, for example every 10 seconds, rather than on every frame. It compares the top-level `.utoc` and `.pak` names and the recorded `.utoc`, partition `.ucas` and `.pak` identities: volume serial, file index, size and last-write time. A directory-listing failure or a file that can no longer be identified counts as a change; an already unidentified `.pak` that remains unidentified does not.

The check reads no container data, keeps no handle, takes no installation lock and adds nothing to `stats()`. It reports the present state: renaming a file back unchanged can make it return False again. It does not cover the exe, mapping or key file, deeper directories, or changes preserving all four identity fields. Mapping and key data are read into memory once. After close it raises `InstallationClosedError`.

Container files open with `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`. An updater can rename, delete or write them while the installation is open. Measured on Windows 11 build 26200 with NTFS: rename away and back, deletion, recreation under a deleted name and an in-place append succeeded; `os.replace()` onto the name of a held-open file failed with `winerror=5`. Delete and replacement behavior depends on Windows and the filesystem; sharing does not guarantee every updater operation succeeds.

An already open handle keeps reading the file it opened after a rename or deletion. An installation is not a snapshot: in-place writes can affect later payload reads while validated cooked headers remain cached until eviction or close, including with `cache_bytes=0`. A read can combine old header offsets with new export bytes, causing `CorruptAssetError`, `InvalidMappingError` or incorrect decoded values. `is_stale()` detects recorded identity changes but does not invalidate cached headers. Stop reads, close the installation, discard its handles and reopen after a change. A data handle opened later is compared with the identity recorded at installation open; a mismatch raises `CorruptAssetError` with `container file {f} has changed since the installation was opened`. A missing or unreadable file keeps its existing error instead.

On a change, stop submitting reads, close the installation, discard its `Texture` and `Exports` handles, reopen and request the visible tiles again. For `CorruptAssetError`, show a status and check `is_stale()` before treating it as an update; other corruption needs investigation. Reopening during an update can raise a transient `AssetError`: retry after a delay. Old identity-keyed tile results must not be displayed as tiles of the new installation.

Compatibility: container renames and deletes can now succeed while an installation is open. OS failures retain their container-file messages but expose Win32 `errno` and `winerror`; a locked byte range, for example, gives `errno=13`, `winerror=33`, where the earlier C-runtime read gave `winerror=None`. The changed-file error is a consistency check, with both attributes `None`.

## Without a mapping

Pass `usmap=None` explicitly when a matching mapping is unavailable, for example after an update. The keyword remains required; omitting it raises Python's `TypeError`. `assets.usmap` is then `None`, including after close, and the installation identity differs from an open with a mapping.

`texture()` and `read_region()` work without reflected properties, as do package lookup and listing, `exports()` and its header inspection, `find()`, `resolve()`, `raw()`, `Exports.raw()` and all loose-file methods. `Texture.mapping_changes` is `()`. Typed `read()` and `Exports.read()` raise `InvalidMappingError(reason='no mapping')` even with `partial=True` or `instances=True`, after argument and closed checks but before cancellation or I/O.

Without a mapping, `texture()` reads the unversioned property header and accepts a native-data start only when it is the unique candidate across the remaining export whose native checks and platform-data skip chain fit through the export's end. It then parses the native data normally. An unreadable property header, no candidate or several candidates raises `InvalidMappingError`; it never chooses the first match. A mapping supplied by the caller still uses the mapped property walk, with no automatic fallback.

On one measured build, all 16,208 Texture2D calls agreed with the mapping path: 16,094 ordinary and 104 virtual textures, 8 `UnsupportedAssetError` and 2 `CorruptAssetError` outcomes, with no differences. The 161 sampled regions, including four world maps, were byte-identical. This is evidence for that build, not a guarantee after another update. Keep the returned `Texture`: the scan runs on each `texture()` call, has no cache or cancellation checkpoint, and can be slow for a large inline export. Measured product costs are under Notes.

## Mappings

`load_usmap(path, *, meta=None, custom_serialization=()) -> Usmap` parses a mapping once for inspection, checks and optional in-memory changes. It never writes a `.usmap`. Pass the resulting `Usmap` to `open_installation(usmap=u)` to read through its effective records.

```python
# needs: an installed UE 5.7 game, its AES key file and a matching .usmap
from nylib.ue.assets import AesKey, MappingChange, Requirement, load_usmap, open_installation

u = load_usmap('path/to/MyGame.usmap')
u = u.with_changes([
    MappingChange.retype('Texture2D', 4, 'Struct<IntPoint>', before='Struct<None>'),
])
report = u.check({'textures': [Requirement('Texture2D', index=4, type='Struct<IntPoint>')]})
print(report)
key = AesKey.from_file('path/to/game-aes.txt')
with open_installation('path/to/MyGame/Content/Paks', engine='5.7',
                        usmap=u, build=None, aes_key=key) as assets:
    print(assets.usmap.digest, assets.identity)
```

The example's retype is skipped when that slot already has `Struct<IntPoint>`; it is a repair only for a mapping whose own index 4 needs that type. Check the mapping against your game's layout before applying changes.

- `Usmap` is immutable, made only by `load_usmap()` and `with_changes()`. `file` is the basename; `sha256` hashes the original file bytes; `digest` identifies the file plus its applied changes, and equals `sha256` without changes. `version`, `structs` and `enums` describe the effective mapping, and `changes` lists applied changes in order. `repr(u)` includes the basename, SHA-256 prefix, version and counts.
- `u.record(name) -> RecordInfo | None` looks up a record ASCII-case-insensitively; it holds `name`, `super`, `count` and `properties` (one entry per declared property, static arrays unexpanded). `u.records()` iterates effective records in file order, followed by added records. `u.properties(struct) -> tuple[PropertyInfo, ...] | None` expands every slot of the whole super chain, in chain-index order; a missing record or a cycle gives `None`. Each `PropertyInfo` holds `index`, `element`, `owner`, `own_index`, `name`, `type` and `array_dim`: `index` is chain-wide, while `own_index` is the property's first index within its declaring record.
- `meta=` explicitly names a nylib dump's `meta.json` (UTF-8 JSON, at most 64 MiB). `u.meta` is a `DumpInfo` with `created`, `exe`, `pe_timestamp`, `quality` and `reasons`, or `None` without a file. No sidecar is discovered automatically, and file locations or record counts never prove a pairing. `u.check(..., build=stamp).paired` compares only that stamp with `meta.pe_timestamp`, returning `None` when either is unavailable. Opening an installation does not compare `build` with the meta; pass `build=u.meta.pe_timestamp` to pin the exe when that stamp is available.
- `custom_serialization=` is the caller's iterable of non-empty class names, kept in order; nylib supplies no built-in class list and this declaration adds no decoder. `u.declared_custom(class_name_or_export_info)` returns the matching entry for the class or its first matching super, ASCII-case-insensitively, or `None`.

Changes are `MappingChange` records, applied in order by `u.with_changes(iterable)`, which returns a new `Usmap` and leaves `u` unchanged. The constructors are `add(struct, own_index, name, type, *, array_dim=1, note=None)`, `retype(struct, own_index, type, *, before=None, note=None)`, `rename(struct, own_index, name, *, before=None, type=None, note=None)`, `set_count(struct, count, *, before=None, note=None)` and `record(struct, *, super=None, count, properties=(), note=None)`. A record's properties are `(own_index, name, type[, array_dim])` entries. `add` needs a free range within the record's count; `set_count` cannot strand entries outside it. An existing record with the same super and count is treated as already in place, without comparing its property list.

`before` guards the previous type, name or count; a rename's optional `type` is another guard. Changes already in place are skipped and not listed (a rename's type guard is still checked). A change that does not fit raises `InvalidMappingError(reason='change does not apply')`; no partially changed mapping is returned. Applied changes record the previous value where available and use `by='patch'` for the constructors above. When building a change from a check result, use `found.owner` and `found.own_index`, never `found.index`: inherited properties have different chain indexes. Type labels include `Float`, `Struct<IntPoint>`, `Array<Struct<Vector>>`, `Map<Name,Int>` and `Enum<MyEnum:Byte>`; `Struct<None>` means an absent struct name. `Object<C>` is refused because a `.usmap` stores no object property's class.

`u.check(requirements, *, fallback=None, by=None, build=None) -> MappingReport` never changes `u`. Pass a mapping of family names to non-empty iterables of `Requirement(struct, name=None, index=None, type=None)`, or one non-empty iterable for a family named `''`. `index` is chain-wide. A struct-only requirement checks its chain; a type-only requirement needs one matching property. Names match exactly, including case. Results have six statuses:

| status | meaning |
| --- | --- |
| `ok` | the original file satisfies the requirement with the same slot |
| `resolved` | an applied change satisfies it, or a fallback proposes a rename |
| `missing` | a record or slot is missing, or the super chain cycles |
| `type mismatch` | the candidate has another type |
| `index mismatch` | the name is at another index, or the requested index has another name |
| `ambiguous` | several candidates or conflicting name claims prevent a match |

`report.families` holds `FamilyResult(name, verdict, items)` records. A verdict is `'usable'` when every requirement is satisfied by the effective mapping, `'usable after apply'` when applying the proposals and checking again without a fallback satisfies the family, or `'not usable'`. `family.usable` is true only for `'usable'`. `report.family(name)` selects one family; `covered` lists only usable families, `items` flattens their results, and `counts` is a tuple of `(status, count)` pairs in the table's order. Each result holds `family`, `requirement`, `status`, `found`, `change`, `by` and `detail`; `found` is a `PropertyInfo` or `None`. `str(report)` is an ASCII summary of counts, proposals, changes and dump pairing, with no property names.

A fallback runs only for a named requirement whose chain resolves but has no exact name match. Pass `fallback=callable, by='your-rule'`; `by` must be non-empty, contain no control characters and differ from `'patch'` (without a fallback, leave it `None`). It receives `(requirement, chain)` on the checking thread and returns a slot from that chain, `None`, or a tuple of distinct candidate slots. Several candidates give `ambiguous`; exceptions propagate. An answer must still satisfy the requirement's type and index, and conflicting claims across families are refused. Two opt-in functions are provided:

- `index_and_type_fallback` requires both `index` and `type`, returning the slot at that chain index only when its label matches; it ignores names.
- `unique_prefix_fallback` matches `_aaa` names by prefix in either direction within the chain, using element-0 slots and honoring a required type. The shorter prefix must be at least **6 characters**; a candidate's name is cut at its first NUL before comparing. Several matches return several candidates.

Fallback answers are proposals to review: even a unique prefix can select the wrong property when the intended one is missing. `report.proposed` contains guarded rename changes; inspect them, then explicitly apply the accepted changes with `u.with_changes(...)` and check again. No read runs a fallback or applies a proposal. `report.changes` holds changes already applied to `u`, separately from proposals.

Applying `report.proposed` can make another family ambiguous. Re-run `check()` on the changed mapping before serving reads.

Mapping records are immutable, hashable and pickle/deepcopy round-trip. Except for `RecordInfo`, each has `to_python()` and `from_python()` for a JSON-compatible dict; tuples become lists, and `None` becomes JSON `null`. The compact schemas are:

| record | dict keys |
| --- | --- |
| `PropertyInfo` | `index`, `element`, `owner`, `own_index`, `name`, `type`, `array_dim` |
| `Requirement` | `struct`, `name`, `index`, `type` |
| `MappingChange` | `kind`, `struct`, `own_index`, `name`, `type`, `array_dim`, `count`, `super`, `properties`, `before`, `by`, `note`; all 12 keys are emitted, and properties are four-item lists |
| `DumpInfo` | `created`, `exe`, `pe_timestamp`, `quality`, `reasons` |
| `RequirementResult` | `family`, nested `requirement`, `status`, nested `found` or `None`, nested `change` or `None`, `by`, `detail` |
| `FamilyResult` | `name`, `verdict`, nested `items` |
| `MappingReport` | `format='nylib.ue.assets.MappingReport'`, `format_version=1`, `file`, `sha256`, `digest`, `version`, `structs`, `enums`, `meta`, `build`, `paired`, `families`, `covered`, `counts` (a dict), `proposed`, `changes`, `custom_serialization`, `summary` |

To archive applied changes, use `json.dumps([c.to_python() for c in u.changes])`; replay with `load_usmap(path).with_changes(MappingChange.from_python(d) for d in json.loads(text))`. Preserve the original file hash and any meta/custom-serialization arguments alongside the archive. JSON's default `ensure_ascii=True` preserves NULs and undecodable name bytes. `MappingReport.from_python()` round-trips a report archive and validates its format version and derived pairing/counts/coverage; `summary` is display text. Readers reject missing or unknown keys and wrong types; `MappingChange.from_python()` accepts omitted optional keys, but uses `own_index`, not `index`. `Usmap` itself refuses pickle and copy/deepcopy: load the file and replay changes in the receiving process.

`Export.mapping_changes` and `Texture.mapping_changes` list applied changes to records that call looked up, in application order, or `()`. A typed read resolves whole chains, while the texture property walk is lazy, so the two tuples need not match. A partial export lists changes encountered before failure; its `problem` keeps error attribution. `Export.mapping_changes` is outside equality, hash and repr. Property-walk failures (`InvalidMappingError` and `UnsupportedAssetError`) carry `mapping_changes` for records looked up before failure and `custom_serialization` for the first declared match: the export class/supers, then property-path structs in order, then the error's class and struct names. Unrelated instances, including mapping-load/change errors, keep both attributes `None`.

| failure attribution | caller action |
| --- | --- |
| `custom_serialization` set | the declared custom layout can fail with any mapping |
| non-empty `mapping_changes` | inspect those changes first; add/retype/count/record can move layout, rename cannot |
| neither, `InvalidMappingError` | inspect `reason` for how the file does not fit |
| neither, `UnsupportedAssetError` | nylib lacks the native layout or variant |
| another error class | investigate beyond the mapping |

Compatibility: names, types and slots now follow the effective mapping; an opt-in rename changes `Slot.name` and `to_python()` keys. `Installation.identity` follows `usmap.digest`, and is unchanged without applied changes. `Installation.usmap` stays readable after `close()`, retaining parsed records until the installation and any other mapping references are released (about 26 MiB for one measured mapping). An invalid `usmap=` type now raises `TypeError` with `usmap must be a str, os.PathLike[str], Usmap or None, got <type>`; a bytes-returning `PathLike` keeps its previous bytes-path error. Existing path opens keep their read outcomes, messages and reprs. The 12 added public names are `load_usmap`, `Usmap`, `RecordInfo`, `PropertyInfo`, `MappingChange`, `Requirement`, `RequirementResult`, `FamilyResult`, `MappingReport`, `DumpInfo`, `index_and_type_fallback` and `unique_prefix_fallback`; existing exports remain available.

## Finding packages

- `assets.has_package(name) -> bool` checks without reading any container data.
- `assets.package(name) -> PackageInfo` reads the package header's summary block. `name` accepts a package path (`/Game/UI/Icon`), an object path (`/Game/UI/Icon.Icon`), or a `.uasset`/`.umap` file path (`Engine/Content/...` or `<Project>/Content/...`); a name may now end in a sub-object path, `/Pkg.Top:Sub.Sub`, naming a nested export by its outer chain, in every method that takes a name (`has_package()`, `package()` and `exports()` ignore the export part). It is also how `texture()` picks one of several `Texture2D` exports that share a name: `texture('<pkg>.<outer>:<name>')` selects one when `AmbiguousNameError` lists more than one.
- `assets.list_packages(prefix='/', *, match=None) -> list[PackageInfo]` walks the directory index of every mounted container (built once, cached until `close()`); `match` is an `fnmatch`-style pattern over the whole name, ASCII-case-insensitive like `prefix`.
- Name case: `list_packages()` reports the case the container's directory index recorded for the path; `package()` and `texture()` report the case the package header itself recorded. The two can differ -- measured on one game: 3 of 212 sampled names, e.g. `.../APC/Wavs/...` against `.../APC/WAVs/...` -- but always name the same package: the same `PackageInfo.package_id`, and name matching throughout is ASCII-case-insensitive.
- Plugin mount roots: `list_packages()` also lists packages under an `Engine/Plugins/.../Content/...` or `<Project>/Plugins/.../Content/...` directory, named `/<mount>/<rest>`. `<mount>` is the plugin folder name when that already matches the entries' recorded chunk ids; otherwise the directory spends one summary read on its first non-matching entry to learn `<mount>` from that entry's recorded package name, then reuses it for the rest of the directory (measured on one game: 106 of 22,313 plugin-root files needed a learned mount, from 2 learning reads). A learned `<mount>` keeps the recorded name's case; `<rest>` always keeps the directory index's case.
- The `.uasset`/`.umap` file-path form does not extend to plugin roots: a file path under a `Plugins/` directory still raises `ValueError`. Address a plugin-root package by the package-path or object-path form (`/<mount>/...`), or by the name `list_packages()` returns.

## Loose files

The same installation reads loose files from legacy `.pak` versions 11 and 12, including encrypted entries. Opening still needs an IoStore installation; `usmap=None` is accepted and loose-file reads need no mapping; there is no standalone `.pak` opener. Packages inside a `.pak` stay unmounted: use the package APIs for mounted IoStore packages.

```python
# needs: an open Installation named assets with the listed loose file
path = 'Wardogs/Content/Localization/Game/en/Game.locres'
info = assets.file(path)
data = assets.read_file(info)
sample = assets.read_file(path, offset=100000, limit=70000)
print(info.size, len(data), len(sample))
```

- `assets.has_file(path: str) -> bool` checks for a listed path; `assets.file(path: str) -> FileInfo` returns its record or raises `MissingAssetError`.
- `assets.list_files(prefix='', *, match=None) -> list[FileInfo]` returns a new list, filtered by a path prefix and an optional `fnmatch` pattern over the whole path. Both match ASCII-case-insensitively; any string is allowed for either filter. Results sort by `(ASCII-lower(path), path, container)`.
- `FileInfo` is immutable: `path` keeps the index's case, `container` is the `.pak` basename, `size` is uncompressed bytes, `stored_size` is stored bytes, `compression` is `'None'`, a method name or `'#k'` for an unnamed method index, and `encrypted` describes the entry itself. Passing a `FileInfo` to `read_file()` uses only its `path`, looking it up in that installation.
- Lookup paths are non-empty relative paths with `/` separators, such as the example above. Backslashes, a leading or trailing `/`, empty segments (`//`), and `.` or `..` segments raise `ValueError`; lookup is ASCII-case-insensitive. Entry paths join the mount point (without its leading `../../../`), directory and filename, collapse repeated `/` and remove a leading `/`. Invalid entry paths, paths over 1,024 characters, control characters, Unicode line/paragraph separators, lone surrogates and undecodable filenames are skipped, as are delete records.
- Duplicate paths, including case variants within one `.pak`, are not resolved by patch order: `has_file()` returns True and `list_files()` lists both, but `file()` and `read_file()` raise `UnsupportedContainerError(feature='patch containers')`.
- The first of these four calls loads all recognized `.pak` indexes, checks both indexes' SHA-1 hashes and keeps the result until `close()`. An encrypted index uses the `aes_key=` supplied at open whose GUID matches the footer; no key file is read again. Missing/wrong keys raise `InvalidKeyError`, damaged indexes raise `CorruptAssetError`, another version raises `UnsupportedContainerError(feature='pak version <v>')`, and no full directory index raises `UnsupportedContainerError(feature='pak without a full directory index')`. Any failure discards the whole load; the next call retries it. Opening itself still reads only footers, so these failures occur on first loose-file use.
- `assets.read_file(path, *, offset=0, limit=None, cancel=None) -> bytes` reads only the range's compression blocks, or 64 KiB pieces for stored entries. `offset` must be a non-negative integer no greater than `size`; `limit` is an integer from 0 to 67,108,864 (64 MiB), or `None` to read from `offset` to the end, subject to the same cap. Booleans are not integers here. An explicit limit is clipped at EOF; an empty range returns `b''`. Invalid arguments fail before I/O. A file larger than the cap can be read in bounded ranges.
- Only `'None'` and `'Oodle'` compression are read; another method raises `UnsupportedContainerError(feature='compression <method>')`. Encrypted entries use the `.pak` footer GUID's key too; missing keys raise `InvalidKeyError`. AES windows are aligned to 16 bytes before decrypting and cutting the result to the requested range. Reads use a call-local handle and bypass the shared block cache. `read_file()` returns the bytes UE stores; encryption a game adds to those bytes is the caller's to handle.

One key-validation limit: if an entry is encrypted but its index is plain, and nothing else validates that GUID's key, a wrong key returns wrong bytes for a stored entry; a compressed entry raises `CorruptAssetError`. The measured installation had encrypted indexes throughout, so this case was not exercised there.

Compatibility: `.pak` rows still have `mounted=False`. A supported 221-byte footer's `reason` is now `'legacy .pak: loose files only, through read_file()'`. Other versions keep `'legacy .pak is not read by this nylib version'`; recognized 222-, 225- and 262-byte footers now report their version and index-encryption flag, with `compression=()`, but are not read further. Unrecognized or unreadable footers keep their existing reasons and are skipped by the index load. `Installation.identity` and its repr are unchanged and do not identify `.pak` contents; key localization caches by `Locres.sha256`. The seven added lazy public names in `nylib.ue.assets.__all__` (now 59) are `FileInfo`, `parse_locres`, `parse_locmeta`, `Locres`, `LocresEntry`, `Locmeta` and `InstanceData`; `nylib.ue.__all__` is unchanged.

## Localization

`parse_locres(data, *, file=None) -> Locres` reads version 3; `parse_locmeta(data, *, file=None) -> Locmeta` reads version 2. Both accept `bytes`, `bytearray` or `memoryview`, keep no mutable input reference, and use the optional string `file=` for error context. Other versions raise `UnsupportedAssetError` with `feature='locres version <v>'` or `'locmeta version <v>'`; absent `.locres` magic is treated as legacy version 0. Missing `.locmeta` magic and malformed supported data raise `CorruptAssetError`. On one measured installation only 38 of 82 `.locres` and 2 of 8 `.locmeta` had supported versions; the older files are refused.

```python
# needs: an open Installation named assets and a Base TextValue named tv
from nylib.ue.assets import Locres, parse_locres, parse_locmeta

root = 'Wardogs/Content/Localization/Game/'
meta_path = root + 'Game.locmeta'
meta = parse_locmeta(assets.read_file(meta_path), file=meta_path)
loc_path = root + meta.native_locres
loc = parse_locres(assets.read_file(loc_path), file=loc_path)
translated = tv.string
if tv.history == 'Base':
    try:
        entry = loc.entry(tv.namespace, tv.key)
    except KeyError:
        pass
    else:
        if Locres.source_hash(tv.string) == entry.source_hash:
            translated = entry.string
```

- `Locres` is immutable and made only by `parse_locres()`: `version`, `sha256` (the full input's SHA-256), `namespaces` and `entries` (tuples in file order). Empty namespaces are preserved. `len(loc)` counts entries; `loc.get(namespace, key, default=None)` returns the localized string or the default; `loc.entry(namespace, key)` returns a `LocresEntry` or raises `KeyError`. Both lookup arguments must be strings. Each entry holds `namespace`, `key`, `string` and the stored unsigned 32-bit `source_hash`. Equality and hashing compare version, namespaces and entries, excluding `sha256`.
- `Locres.source_hash(text)` implements UE's `FCrc::StrCrc32`: text before the first NUL, UTF-16 code units (including surrogate pairs as two units), each fed to CRC-32 as four little-endian bytes. Empty text hashes to 0. Compare it with the entry's source hash before replacing a `Base` text, as above; the parser itself supplies no staleness policy.
- `Locmeta` holds `version`, `native_culture`, `native_locres` (relative to the metadata file's folder), `cultures` (a tuple of compiled cultures in file order) and `ugc` (`bool`). A listed culture need not have a `.locres` in the installation.
- There is no automatic culture fallback, target merge or `TextValue.localize()`. `StringTableEntry` text needs a namespace from the `StringTable` native tail, which this reader does not decode.
- Both parsers hold the GIL and take no `cancel=`. Their records remain usable after the installation closes and support pickling and `deepcopy`.

## Metadata

- `assets.texture(name) -> Texture` resolves the `Texture2D` export and parses its header into `Texture.info` (a `TextureInfo`): `width`, `height`, `pixel_format`, `mips` (a `MipInfo` per level), `alpha` (`'none'` or `'straight'`), `virtual` (a `VirtualTextureInfo`, or `None` for an ordinary texture), `readable`, and `unsupported` (the reason, matching the error `read_region` would raise). The first `texture()` call on an installation is slower; see Notes.
- `assets.stats() -> ReadStats` returns the running totals since open (`reads`, `bytes_read`, `blocks_decompressed`, `tiles_decoded`, `seconds`, ...); `reads` also counts `read()`, `Exports.read()`, `raw()`, `Exports.raw()` and `read_file()` calls. Subtracting two snapshots measures one span; `str(stats)` is a one-line summary.
- A parsed-header hit adds no header I/O or decompression counters and no `cache_hits`: that field counts only decompressed-block cache hits. Payload reads and import processing still count their actual work. `Exports.stats` describes that particular call; `resolve()` and `exports()` do not increment `reads`.
- `has_file()`, `file()` and `list_files()` do not increment `reads`. The call loading the loose-file index counts two `blocks_read` per `.pak` (primary and directory indexes), their stored bytes in `bytes_read`, and I/O/AES time. `read_file()` counts each compressed block or stored piece read, including encrypted alignment bytes, with the Oodle/AES counters as applicable and no cache hits. Localization parsers add nothing; instance-tail parsing contributes to the export read's `seconds_decode`.

## Reading regions

`tex.read_region(mip, x, y, width, height, *, clip=False, missing='raise', out=None, cancel=None) -> Region` decodes pixel data to RGBA8: virtual-texture BC1 tiles, or ordinary `PF_B8G8R8A8`, `PF_DXT1` (BC1), `PF_DXT5` (BC3) and `PF_BC7` mips. Check `info.readable` first; `info.unsupported` names the reason when it is False. A readable texture can still have an optional mip whose container is not installed; reading that mip raises `MissingAssetError` (also a `LookupError`), while its other mips remain readable.

- Coordinates are pixel coordinates of mip `mip`, origin top-left, rows returned top to bottom; sizes come from `info.mips[mip]` and are never rescaled.
- Output is tightly packed RGBA8: `len(region.pixels) == width * height * 4`, no sRGB conversion. Alpha is 255 whenever `info.alpha == 'none'`.
- `clip=True` shrinks the rectangle to the mip's bounds instead of raising; `clip=False` (default) raises `RegionOutOfBoundsError` outside the bounds.
- Virtual texture: `missing='raise'` (default) raises `MissingTileError` if any touched tile is unstored; `'transparent'` fills it with `(0, 0, 0, 0)`; `'fallback'` fills it with `info.virtual.fallback[0]`. `region.missing` lists the filled rectangles either way, and only the tiles the rectangle touches are decoded.
- Ordinary texture: `PF_B8G8R8A8` converts stored B, G, R, A bytes to R, G, B, A, reading only the touched pixel rows. Block formats read whole touched block rows and decode only the 4x4 blocks the rectangle touches; padded edge texels are cropped to the mip's own size, including 2x2 and 1x1 tail mips. `PF_DXT1` has `alpha='none'` (A = 255); `PF_B8G8R8A8`, `PF_DXT5` and `PF_BC7` have `alpha='straight'` (unpremultiplied). There is still no sRGB conversion. There are no tiles, so `missing` is validated but has no other effect, and `region.missing` is always `()`.
- Ordinary mips may be inline, in the package's default `.ubulk`, or in its optional `.uptnl` chunk in any mounted container (cooked index 0). A missing optional chunk fails only that mip's read, before I/O or the first `cancel` poll; `missing='transparent'` or `'fallback'` does not fill it.
- Either way, each compression block is fetched and decompressed at most once per call, and the result is the same regardless of cache state, thread count, or (for a virtual texture) the `missing` policy outside the filled areas.
- `out=` writes into a caller-supplied writable buffer instead of allocating a new `bytes`; `cancel=` is a zero-argument callable polled between tiles (virtual texture) or compression blocks (ordinary texture), raising `ReadCancelledError` when it returns true.

Compatibility: in an earlier version, every ordinary (non-virtual) texture raised `UnsupportedAssetError(feature='non-virtual texture')` from `read_region`, unconditionally. Now a readable ordinary texture decodes, and an ordinary texture in a pixel format with no decoder raises `UnsupportedPixelFormatError` instead -- as an unsupported virtual-texture layer format already did. Both error classes derive from `UnsupportedError`; a caller that catches only `UnsupportedAssetError` around `read_region` misses the new one. `texture()` on an ordinary texture can now also raise `CorruptAssetError`, for a mip whose size, `.ubulk` or mounted `.uptnl` range, or serial size is inconsistent. And a plugin content directory whose learning read fails lists only the entries that already match their folder name; the rest are dropped, visible only in the DEBUG log.

Ordinary `PF_DXT1`, `PF_DXT5` and `PF_BC7` textures that previously raised `UnsupportedPixelFormatError` now decode (3,814 more textures on one measured install). `Installation.identity` is unchanged for the same inputs: clear cached "unreadable" verdicts when upgrading; an identity-keyed cache alone will keep them. `info.readable=True` no longer guarantees every mip can be read when optional content is missing.

## On-demand map tiles

Read only the visible area and a small prefetch margin. This consumer example keeps one installation and one `Texture` per map on a worker thread. Its bounded priority queue puts visible tiles before prefetch; view generations cancel obsolete work. The render thread calls `set_view()` and `drain(upload, budget)` and uploads RGBA8 itself, with no asset reads on that thread. Use `fallback[map_name]`, populated when the worker opens that texture, for placeholders.

The example assumes virtual world maps whose mip 0 is 16384x16384: display zoom `z` uses mip `5 - z` and 512x512 pixel tiles. Supply valid tile coordinates for that mip. Cache results by the returned `(assets.identity, map_name, z, x, y, 'rgba8')` key. A full request queue returns False from `want()`; `set_view()` returns the number accepted, so the consumer can request missing tiles later. Only the render thread changes the view generation. On a changed-container error the worker reopens and requeues that tile; other errors are counted for the consumer to display or log.

```python
# needs: an installed UE 5.7 game, its AES key file and virtual world-map textures
"""Read visible map tiles on one worker thread."""
import itertools
import queue
import threading
import time

from nylib.ue.assets import AesKey, CorruptAssetError, ReadCancelledError, open_installation


class MapTiles:
    def __init__(self, paks, key_file, maps, *, engine='5.7', build=None, exe=None, capacity=64, retry_delay=1.0):
        self.options = dict(engine=engine, usmap=None, build=build, exe=exe, cache_bytes=4 << 20)
        self.paks, self.key_file, self.maps = paks, key_file, dict(maps)
        self.requests = queue.PriorityQueue(capacity)
        self.results = queue.Queue(capacity)
        self.sequence = itertools.count()
        self.generation = 0
        self.fallback = {}
        self.errors = self.reads = self.cancelled = 0
        self.retry_delay = retry_delay
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def want(self, map_name, z, x, y, *, prefetch=False):
        try:
            self.requests.put_nowait((int(prefetch), next(self.sequence), self.generation, (map_name, z, x, y)))
            return True
        except queue.Full:
            return False

    def set_view(self, visible, prefetch=()):
        self.generation += 1
        while True:
            try:
                self.requests.get_nowait()
            except queue.Empty:
                break
        while True:
            try:
                self.results.get_nowait()
            except queue.Empty:
                break
        accepted = sum(self.want(*tile) for tile in visible)
        accepted += sum(self.want(*tile, prefetch=True) for tile in prefetch)
        return accepted

    def drain(self, upload, budget):
        for _ in range(budget):
            try:
                generation, key, region = self.results.get_nowait()
            except queue.Empty:
                break
            if generation == self.generation:
                upload(key, region)

    def close(self):
        self.stopped.set()
        self.generation += 1
        self.thread.join()

    def _run(self):
        assets = None
        textures = {}
        next_poll = 0.0
        retry = None
        try:
            while not self.stopped.is_set():
                if assets is None:
                    try:
                        assets = open_installation(self.paks, aes_key=AesKey.from_file(self.key_file), **self.options)
                        textures = {}
                        next_poll = time.monotonic() + 10.0
                    except Exception:
                        self.errors += 1
                        self.stopped.wait(self.retry_delay)
                        continue
                if time.monotonic() >= next_poll:
                    next_poll = time.monotonic() + 10.0
                    if assets.is_stale():
                        assets.close()
                        assets = None
                        continue
                if retry is not None:
                    request, retry = retry, None
                else:
                    try:
                        request = self.requests.get(timeout=0.05)
                    except queue.Empty:
                        continue
                _, _, generation, tile = request
                if generation != self.generation:
                    self.cancelled += 1
                    continue
                map_name, z, x, y = tile
                try:
                    if map_name not in textures:
                        textures[map_name] = assets.texture(self.maps[map_name])
                        if (virtual := textures[map_name].info.virtual) is not None:
                            self.fallback[map_name] = virtual.fallback[0]
                    region = textures[map_name].read_region(5 - z, 512 * x, 512 * y, 512, 512,
                                                          cancel=lambda: generation != self.generation or self.stopped.is_set())
                    self.reads += 1
                    key = (assets.identity, map_name, z, x, y, 'rgba8')
                    while generation == self.generation and not self.stopped.is_set():
                        try:
                            self.results.put((generation, key, region), timeout=0.05)
                            break
                        except queue.Full:
                            pass
                except ReadCancelledError:
                    self.cancelled += 1
                except CorruptAssetError:
                    self.errors += 1
                    if assets.is_stale():  # a container changed: reopen, then read this tile again
                        assets.close()
                        assets = None
                        retry = request
                        self.stopped.wait(self.retry_delay)
                except Exception:
                    self.errors += 1
        finally:
            if assets is not None:
                assets.close()
```

Call `close()` when the consumer shuts down. The example polls for changes every 10 seconds on the worker, retries failed opens after a delay, and leaves scheduling, cache eviction and status presentation to the application. `drain()` bounds uploads by count per frame; choose its budget for the renderer's cost.

A child process is another placement for the worker: open the installation there and pass requests and pixel results over a pipe. `Installation` and `Texture` cannot be pickled. The measured child-process variant kept render impact near baseline; a thread also worked with the native BC1 decoder. See Notes for the workload and timings. These are consumer patterns, not a scheduler supplied by nylib.

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

- `assets.exports(name, *, cancel=None) -> Exports` reads or reuses a package's validated cooked header only (no export data) and returns an `Exports` handle: a `Sequence[ExportInfo]` with `package` (a `PackageInfo`), `stats` (a `ReadStats` for this call), `find(name) -> ExportInfo` (no I/O), `read(which, *, partial=False, cancel=None, instances=False) -> Export` and `raw(which, *, offset=0, limit, cancel=None) -> bytes`. `which` takes an index, a name or sub-object path, or an `ExportInfo` from this handle. Calling `Exports(...)` directly raises `TypeError`; an `Exports` keeps its `Installation` alive and refuses pickling. It retains its header independently of cache eviction and close. After `close()`, its `read()` and `raw()` raise `InstallationClosedError`; `len`, indexing, iteration and `find()` keep working.
- `assets.read(target, *, partial=False, cancel=None, instances=False) -> Export` reads one export directly: `target` is a package or object path (`str`, sub-object paths included), an `ExportInfo`, an `ObjectRef` or a `SoftObjectRef` (see References, below). `Export` holds `info` (`ExportInfo`), `properties` (a `StructValue`), `native` (a `DataTable`, `CurveTable`, `InstanceData` or `None`), `native_size` (the unconsumed bytes after the trailer and any decoded native tail), `exact` (`complete` and `native_size == 0`), `guid`, `complete` and `problem` (an `AssetError`, set only on a partial result; see Partial reads, below).
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
- `assets.resolve(ref, *, cancel=None) -> ExportInfo` follows an `ObjectRef` or `SoftObjectRef` to the `ExportInfo` it points at, reading only the target package's cooked header -- never the export's own data. Validated cooked headers are reused across resolve, raw, read, import-header reads and exports on the same installation. Export payloads still require their own reads; the whole-chunk texture path is unchanged. `assets.read(ref)` and `assets.raw(ref)` accept a reference directly and read the target's data in one call. Resolving `ObjectRef('null', ...)`, or a reference to a `'script'` object, raises `ValueError`: neither has a cooked export to read.

## Tables and curves

- A `DataTable` export's `Export.native` is a `DataTable` record: `row_struct` (the row struct's name, or `None` when it came from another package -- the rows still decode through the resolved struct), `row_struct_ref` (an `ObjectRef`) and `rows`, a `MapValue` from row name to that row's `StructValue`, in file order.
- A `CurveTable` export's `Export.native` is a `CurveTable` record: `mode` (`'Empty'`, `'SimpleCurves'` or `'RichCurves'`), `rows` (as above, each row a `SimpleCurve` or `RichCurve` `StructValue`), and `keys(row) -> tuple[StructValue, ...]`, the row's key array -- `SimpleCurveKey` or `RichCurveKey` values, in order; `keys()` raises `KeyError` for an unknown row name.
- A class is read as a table only when its class chain includes `DataTable` or `CurveTable`; these take precedence over instanced meshes. Other classes have `native=None` unless instance decoding is requested below.

## Instanced meshes

`assets.read(target, *, partial=False, cancel=None, instances=False)` and `Exports.read(which, *, partial=False, cancel=None, instances=False)` accept an opt-in boolean `instances`. With True, a non-CDO export whose mapped class chain includes `InstancedStaticMeshComponent` returns its native tail as `InstanceData`. Other exports read as before; the default remains False. `raw()`, `resolve()` and `texture()` have no such keyword.

```python
# needs: an open Installation named assets and an instanced component object path
from nylib.ue.assets import InstanceData

export = assets.read('/Game/Maps/MyMap.MyMap:PersistentLevel.Actor.InstancedComponent',
                     instances=True)
if isinstance(export.native, InstanceData):
    print(len(export.native.matrices), len(export.native.custom_data))
```

- `InstanceData.matrices` is a tuple of per-instance tuples: each is the exact 16 doubles of an `FMatrix`, row-major, element `(r, c)` at `4 * r + c`. No transform decomposition or float32 rounding is applied. `custom_data` is a flat tuple of float32 values widened exactly to Python floats, in instance order; its length is a multiple of the instance count, or zero when there are no instances. The immutable record pickles and `deepcopy` round-trips; its compact repr reports instance and custom-float counts.
- The reader skips actor-component bookkeeping and static-mesh LOD payloads, reads the instance arrays, then skips any hierarchical cluster-node array. Bounds, LOD payloads and the HISM cluster tree are not exposed. A scene-bounds block is read only when the export's own `SceneComponent.bComputeBoundsOnceForGame` slot is serialized as True; an absent or zero-masked slot reads no block. This also supports HLOD tails: all 120,022 measured HLOD exports followed that rule. Across the measured installation, 565,893 family tails contained 9,587,851 instances, with at most 23,340 in one export.
- A successful tail read has `native_size=0`, `exact=True` and `complete=True`; missing instance arrays give `InstanceData((), ())`. An unknown tail layout raises `UnsupportedAssetError(feature='<class> tail')`, and cooked instance render data raises it with `feature='instanced mesh cooked data'`. Both carry the class, failing `position` and an empty `property_path`, plus mapping-change/custom-serialization attribution under the usual rules.
- With `partial=True`, a tail failure keeps the decoded properties and trailer GUID, sets `complete=False`, `native=None`, `native_size=0`, `exact=False`, and puts the error in `problem`; no successfully decoded slot becomes unread. Each matrix, custom float and LOD entry counts toward the decode budget and the checkpoint every 4,096 values.
- Compatibility: `Export.native` can now be `InstanceData` as well as `DataTable`, `CurveTable` or `None`. For a family export, opting in changes `native`, `native_size`, `exact` and therefore equality; without the keyword existing results are unchanged. Retained memory is about 570 bytes per instance plus 32 bytes per custom float while the export lives; release large results between reads.

## Partial reads and `raw()`

- `read(target, *, partial=True)` returns a best-effort `Export` instead of raising when a property, the object trailer, or a table row fails to decode: `complete` is `False`, `native` is `None`, and `problem` holds the `AssetError` that a non-partial call would have raised. `properties` keeps every top-level slot that was read completely before the failure; the slot that failed, and every slot after it that the header listed, are `'unread'` (reading one re-raises `problem`); slots the header never listed are `'absent'`, as usual. A partially read value is never exposed through a slot. Two failures make every top-level slot `'unread'` instead of mixing in `'absent'`: the header itself failed to parse, and a class block whose own slots would exceed the decode budget -- marking the unlisted ones absent would itself build the slots the budget refuses.
- `assets.raw(target, *, offset=0, limit, cancel=None) -> bytes` and `Exports.raw(which, ...)` return the export's raw bytes `[offset, offset + limit)`, cut at the export's end, without decoding anything; `limit` has no default and must be at most 64 MiB, like `read()`'s own export-size cap. Only the compression blocks that range touches are read.

## Supported natives

- Beyond the hundred-plus built-in layouts under Exports and properties, above, every other struct name encountered reads through the `.usmap` mapping, the same way any reflected struct does -- including several engine-looking names (for example `BodyInstance`, `ScalarParameterValue`, `VectorParameterValue`, `TextureParameterValue`) whose only native implementation elsewhere belongs to another UE game; for this game, those names are ordinary unversioned data, and the mapping's own record decides how each reads.
- A struct name that is not read at all raises `UnsupportedAssetError` with `feature='native struct <name>'`, `struct_name` set to that name, and `position` where its bytes begin. These fall into two groups: 29 engine-independent natives that sit outside the built-in set and were never seen in the measured install -- `ColorMaterialInput`, `CompressedRichCurve`, `ExpressionInput`, `ScalarMaterialInput`, `VectorMaterialInput`, `Vector2MaterialInput`, `MaterialAttributesInput`, `SkeletalMeshSamplingRegionBuiltData`, `PannerDetails`, `LevelSequenceObjectReferenceMap`, `MaterialLayersFunctionsTree`, `MidiEvent`, `RawAnimSequenceTrack`, `SectionEvaluationDataTree`, `Transform3f`, `TypedParameter`, `UniqueNetIdRepl`, `ClothLODDataCommon`, `ClothLODData`, `ClothTetherData`, `AnimationAttributeIdentifier`, `AttributeCurve`, `PCGPoint`, `CacheEventTrack`, `DataCacheDuplicatedObjectData`, `EdGraphPinType`, `ControlRigOverrideContainer`, `UInt32Property`, `ZeroSizeProperty` -- and 74 natives whose one known layout was written for a different game entirely (for example `FixedPoint`, `GameplayEffectFloatMapping`, `NiagaraUserParameterModifier`). Reading either raises rather than guessing at a layout this game's own data may not share.

## Threads and cancellation

- Any number of threads may call `Installation`, `Exports` and `Texture` methods at once; container partitions are read by offset with no container lock around the read; the shared block and cooked-header caches use short locks. Concurrent misses may parse and validate the same header independently; parsing, validation and accounting run outside the cache lock. Loose-file index loading has its own lock and publishes one immutable index; other callers wait for it. Records and `AesKey` are immutable.
- The GIL is released during file I/O, AES decrypt, Oodle decompress and native BC1 decode when the bundled DLL loads. Parsing, DXT5 and BC7 decode hold it; BC1 also holds it when using the pure-Python fallback. Native BC1 argument checks and output allocation still hold it. `is_stale()` may run concurrently with reads and close; a check already past its closed check completes normally.
- `close()` waits for reads running on other threads, except one it is called from itself; once it returns with no in-flight read of its own, the installation holds no file handle, lock object or cache.
- `Installation`, `Exports`, `Texture`, `AesKey` and `Usmap` refuse pickling and `copy`/`deepcopy`; records, values (`StructValue` and `MapValue` included) and the error classes pickle and `deepcopy` round-trip. A `Usmap` may be shared by any number of threads and installations, including concurrent `check()` calls; `load_usmap()` has no `cancel=`.
- `cancel=` on `exports()`, `read()`, `raw()` and `resolve()` is checked initially, before every compression block an operation touches, every few thousand export-map entries while listing a package's exports, and every few thousand decoded values while decoding properties or table rows. A warm header skips block work and its callbacks; a fresh warm resolve or exports starts with 0/0 header blocks. Imported hits leave the operation's current progress untouched. A hit still checks for close. On a miss, parsing, ScriptObjects membership validation and retained-byte accounting after the last header block have no checkpoint and grow with the header. Pre-cache measurements on one install found worst-case cancel latency of about 0.2 s for a main map's `exports()` and about 0.45-0.48 s for the largest cooked header; accounting adds about 15 ms for the measured 120,472-export Kavkazi header. A validated header may remain cached when later work is cancelled.
- `read_file()` checks cancellation before any read, before each `.pak`'s index reads, about every 50 ms while waiting for another call's index load, and before every compressed block or stored piece. Cancellation raises `ReadCancelledError` and returns no bytes. The four loose-file methods raise `InstallationClosedError` after close; an in-flight read notices close at its next checkpoint. `close()` releases the index, retained keys and decryptors; no `.pak` handle survives a call. Returned file, localization and instance records outlive the installation.

## Errors

```text
UeError
└── AssetError                      every nylib.ue.assets failure but argument-type errors; .package, .container, .export, .file
    ├── InvalidKeyError             no/wrong AES key, GUID mismatch, bad key file; .key_guid, .reason, .path
    ├── InvalidMappingError         .usmap missing, invalid, or does not fit the data; .usmap, .class_name, .property_index,
    │                               .property_name, .reason, .path, .property_path, .property_type, .position, .struct_name, .row,
    │                               .mapping_changes, .custom_serialization
    │   └── BuildMismatchError      build= differs from the exe's own stamp; .expected, .found, .exe, .path
    ├── MissingAssetError           package, export or optional mip not in a mounted container (a LookupError)
    │   └── MissingTileError        missing='raise' hit an unstored VT tile; .mip, .tiles
    ├── UnsupportedError             outside the supported profile; .feature
    │   ├── UnsupportedContainerError    TOC version, AES mode, compression method, or no usable Oodle
    │   ├── UnsupportedAssetError         asset class or native layout; .exports, .class_name, .property_index,
    │   │                                 .property_name, .property_path, .property_type, .position, .struct_name, .row,
    │   │                                 .mapping_changes, .custom_serialization
    │   └── UnsupportedPixelFormatError   no decoder for this pixel format; .pixel_format
    ├── CorruptAssetError            structure or codec check failed; .detail (a block decode's __cause__ is an OodleError)
    ├── RegionOutOfBoundsError       rectangle or mip out of range (a ValueError); .mip, .rect, .size
    ├── ReadCancelledError           cancel() returned true
    ├── InstallationClosedError      the installation is already closed (a ValueError)
    └── AbsentPropertyError          a property slot was not serialized, so its value is the archetype's one nylib does not
                                      hold (also a KeyError); .class_name, .property_index, .property_name
```

- A container identity mismatch raises `CorruptAssetError` with `detail='has changed since the installation was opened'` and message `container file {f} has changed since the installation was opened`. `container` is the `.utoc` basename for a partition or the `.pak` basename; `read_file()` also sets `file` to the in-pak path. `errno` and `winerror` are `None`. Check `is_stale()`, then close and reopen as described under Long-lived installations.
- Without a mapping, typed reads raise `InvalidMappingError(reason='no mapping')` with a message ending `needs a .usmap: the installation was opened with usmap=None`. Texture location failures use reasons `'bad property header'`, `'native start not found'` or `'native start ambiguous'`, with message details `the property header cannot be read`, `no position fits` or `more than one position fits`. Their messages include the package and export size; `class_name='Texture2D'`, `usmap=None`, and neither mapping-change nor custom-serialization attribution is set. Supply a matching mapping rather than guessing a native start.
- Wrong argument types raise `TypeError`, wrong values raise `ValueError` -- never one of the classes above, except `RegionOutOfBoundsError`, which is both an `AssetError` and a `ValueError`. An out-of-range `Exports` index, or an out-of-range index to `StructValue.at()` or `StructValue.state()`, raises `IndexError`; an unknown name to `sv[name]` or `CurveTable.keys()` raises `KeyError`.
- Every `AssetError` has `file`, defaulting to `None`: loose-file failures concerning one path set it to that path, and localization parser failures use the supplied `file=`. These failures have no mapping-change or custom-serialization attribution. `Locres.entry()` raises `KeyError` for a missing namespace/key pair.
- `AmbiguousNameError` (re-exported from `nylib.ue`, not under `AssetError`) is raised by `texture()` when a package name, or an object path's export name, matches more than one Texture2D export, and by `read()`, `raw()` and `Exports.find()` when a name matches more than one export; it is not an `AssetError`.
- `AbsentPropertyError` is also a `KeyError`, but overrides `__str__` so `str(err)` is the plain message despite `KeyError`'s quoting; `StructValue.get()` and `in` treat it as missing, the way a real `KeyError` would. A `problem` carried by a partial `Export` (below) is never a `KeyError`, so `get()` never turns an unread property into a default silently.
- A failure found while reading one export's properties -- `InvalidMappingError` or `UnsupportedAssetError` raised from inside a property block, the object trailer, a table row, or a native struct -- carries `property_path`: the steps from the export's class down to the failure, for example `WDWeaponStatsData#1.WDWeaponStats#36`, an array index as `[3]`, a map key or value as `[key 0]` / `[value 0]`, a table row as `[row 2]`. `class_name`, `property_index`, `property_name` and `property_type` describe that last step; `position` is where the failing read began; `struct_name` names the native struct involved, when there is one; `row` names the table row, when the failure is inside one. The message itself still never repeats a property or row name -- those live only in the attributes.
- Messages are one line of English; paths use basenames except for quoted in-pak paths and object paths. They never include key material, decrypted/decoded bytes, localized text, mapping-file content or a property name. `load_usmap()` reports mapping/meta failures as `InvalidMappingError`; a missing meta file has `reason='meta.json not found'`, invalid UTF-8/JSON has `'meta.json not JSON'`, and a wrong dump schema has `'meta.json schema'`. `with_changes()` refusals have `reason='change does not apply'`; inspect attributes and change records for names. Report summaries and requirement details omit property names too.

## Supported profile

| Layer | Supported in this version | Beyond it |
|---|---|---|
| Container | IoStore TOC v8, one or more partitions (partition `p >= 1` read from `<base>_s<p>.ucas`); AES-256-ECB; Oodle (Kraken) and stored blocks; compression blocks a power of two from 4 KiB to 16 MiB. Legacy `.pak` v11/v12 loose files with a full directory index, stored or Oodle, encrypted indexes and entries included | `UnsupportedContainerError` (a count of 0 IoStore partitions: `feature='zero partitions'`; one such container makes `open_installation` fail for the whole install); a missing partition or a block crossing its end: `CorruptAssetError`. Other `.pak` versions, no full directory index or another entry codec are unsupported; `.pak` packages stay unmounted |
| Mapping | `.usmap` v0-v4; compression None, Oodle, ZStd (needs Python 3.14+); reusable `Usmap`, in-memory changes and requirement checks | `InvalidMappingError`; no `.usmap` writer or automatic name repair |
| Package | zen packages, unversioned properties | `InvalidMappingError`, `CorruptAssetError` |
| Exports and typed properties | every property kind and reference (`exports()`, `read()`, `raw()`, `resolve()`); 121 built-in native struct layouts; any other struct name through the `.usmap` mapping | a native struct this version does not read (named under Supported natives, above): `UnsupportedAssetError` |
| Localization | `.locres` v3 and `.locmeta` v2 over bytes; namespace/key lookup and source hashes | other versions: `UnsupportedAssetError`; malformed supported data: `CorruptAssetError`; no culture fallback, target merge or StringTable tail |
| Instanced meshes | opt-in `instances=True` for the mapped instanced-static-mesh family, HISM and HLOD included; exact matrices and custom floats | cooked instance render data or another tail layout: `UnsupportedAssetError`; cluster tree and matrix decomposition are not exposed |
| Texture metadata | every `Texture2D` export, virtual and ordinary | another class: `UnsupportedAssetError` |
| Virtual-texture region reads | `RawGPU` codec, one layer, `PF_DXT1`, non-legacy tile layout | `UnsupportedAssetError` / `UnsupportedPixelFormatError`; `info.readable` is False and names the reason. Any other VT layer format, including `PF_DXT5` and `PF_BC7`, still reports `has no decoder in this nylib version`, although those formats decode on ordinary textures |
| Ordinary-texture region reads | `PF_B8G8R8A8`, `PF_DXT1`, `PF_DXT5`, `PF_BC7`; inline mips, default `.ubulk` or optional `.uptnl` (cooked index 0, in any mounted container) | `UnsupportedPixelFormatError` for another pixel format; `UnsupportedAssetError` for no serialized mips, mip data not serialized with the texture, compressed or memory-mapped bulk data (`.m.ubulk`), another cooked index, an optional chunk in multiple containers, optional data also flagged inline, or any other placement; `info.readable` is False and names the reason. An unmounted optional chunk keeps `info.readable=True` but that mip's read raises `MissingAssetError` |

## Notes

- Measured on one shared machine, Python 3.14/3.12, best of three runs: warm `is_stale()` p95 was about 2.7/3.0 ms. Against the previous version as a same-session baseline with the same native decoder, the shared-handle positional reads gave region p50 ratios of 1.008/1.016 and four-thread throughput ratios 1.059/1.020. These are warm-cache observations, not cold-cache measurements or guarantees.
- The on-demand bench paced a render loop at 120 FPS with 1 ms of Python work and at most four counted uploads per frame, a 3x3 visible view plus 16 prefetch tiles, and a pan every 2 seconds. Best-of-three extra p95 frame time on Python 3.14/3.12 was about 0.12/0.50 ms for a worker thread, 0.11/0.55 ms with a 1 ms thread switch interval, and -0.02/-0.01 ms for a child process. Near-zero negative differences are measurement noise. Across all runs and placements the first view, including open, took about 0.86-0.94 s on 3.14 and 1.20-1.36 s on 3.12. Uploads counted bytes rather than exercising a GPU, so this does not establish the application's render cost. The pure-Python comparison took about 31-32 ms p50 per region, around 31 regions/s.
- In the product's mapping/no-mapping comparison on that same build, extra `texture()` time without a mapping was about 0.18-0.19 ms p50, 3.0-3.2 ms p95 and 0.99-1.00 s worst case on Python 3.12/3.14. The earlier locator study's full scan reached 2.0 s on an 8 MB inline export. These are different measurements; neither establishes a latency bound for other builds.

- Measured on one shared machine with other work running, Python 3.12/3.14: the product's first loose-file index load over 16 `.pak` files and 5,976 entries took about 60-94 ms, retaining 6.1-6.3 MiB (6.1-6.4 MiB peak); later index lookups took about 5 microseconds. Loose-file reads took about 0.53-0.54 ms p50 and 0.63-0.68 ms p95; reading all 219 encrypted entries took about 24 ms. Earlier range probes read 70,000 bytes across 2 blocks in each Game `.locres`, and a 70,000-byte movie tail across 2 stored pieces. These are approximate observations, with no cold-cache claim or throughput guarantee.
- On that shared machine, the product parsed Game `en` (525,364 bytes, 5,948 entries, 169 namespaces) in about 13-15 ms, retaining about 2.1 MiB; the largest `.locres` (6,892,728 bytes) took about 145-183 ms and retained 19.1-19.6 MiB. Earlier prototype probes of the two Game cultures took about 12-14 ms and retained 2.2 MiB each. Parser memory and time grow with the strings and entries; parsing has no cancellation checkpoint.
- On the same shared machine, reading 43,117 exports of a main map took about 9.0-10.6 s without instances and 10.1-13.1 s with them; a 23,340-instance export took about 12-14 ms with 15.5-15.7 MiB peak traced allocation. Earlier whole-install probes found about 8% extra tail work; this is a different workload from that map. Measured cancellation latency was about 1.7-2.1 ms during instance parsing and 0.10-0.14 ms during a stored loose-file read.
- `read_file()` keeps the returned bytes plus working buffers: measured traced allocation peaked near 128 MiB for a 64 MiB stored range and 67.5 MiB for a 33.8 MiB Oodle file, within `2 * returned_bytes + 4 MiB` on those inputs. Use smaller ranges to reduce peak memory.
- No resampling: a mip's pixels come back at that mip's own size; scaling is the caller's job.
- BC1 automatically selects the bundled native decoder on its first decode. If loading raises `BcnError`, one WARNING, `BC1 decode falls back to pure Python: ...`, names the cause, and the process uses pure Python thereafter with identical pixels. `nylib.utils.bcn.load()` checks native availability directly. See [nylib.utils.bcn](../utils/bcn.md#threads-and-the-gil) for measured native speed and GIL behavior. DXT5 and BC7 are unchanged and hold the GIL; prototype whole-mip measurements on one machine were about 2.6-2.9 Mpx/s for DXT5 and 0.6-1.0 Mpx/s for BC7, depending on the blocks. A whole 4096x4096 BC7 mip takes about 17-27 s at those rates; use bounded regions for interactive reads.
- Earlier measurements with the pure-Python BC1 decoder, on one machine with other work running: ordinary 512x512 region reads took about 27 ms p50 for DXT1, 97 ms for DXT5 and 239 ms for BC7 (16, 32 and 32 compression blocks respectively). A 2x2 sample took about 0.07-0.13 ms p50 on 1 block, including about 0.09 ms for an optional `.uptnl` mip. Measured cancellation latency was about 13 ms, 24 ms and 60 ms for those formats respectively; polls are between compression blocks, so latency includes decode work between polls. These figures do not establish cold-cache performance.
- The first call to `texture()`, `exports()`, `read()`, `raw()` or `resolve()` on an installation loads the global ScriptObjects table once (about 4.66 MB on the measured game) and costs about 0.42 s total on one measured machine, almost all of it that load; later calls reuse the table.
- Compared with CUE4Parse: DXT1's three-colour index-3 texel is opaque black `(0, 0, 0, 255)` here, where CUE4Parse gives alpha 0. DXT5 follows its BCDecoder arithmetic exactly, including alpha interpolation rounding and the forced four-colour block. BC7 follows the BPTC specification, matching CUE4Parse's AssetRipper path; its Windows Detex path can differ by 1 in a channel in mode 6. Mips off the 4-pixel grid decode as padded blocks cropped to their declared size; CUE4Parse's BC1/BC3 decoder cannot decode those sizes, and its BC7 paths return the padded image.
- Approximate, one machine: `open_installation` took about 0.22 s (about 0.15 s of that parsing one `.usmap`; a larger, 3.3 MB mapping's prototype parse took about 0.26 s and retained about 26 MiB); earlier pure-Python BC1 region reads were about 30 ms p50 whether `cache_bytes` was 0, the 4 MiB default, or 16 MiB. With native BC1, the later 16-region map workload took about 1.3-1.6 ms p50 at the 4 MiB default on Python 3.12/3.14. A larger cache can help repeated reads of the same blocks; these runs do not compare native decode across cache sizes.
- Measured on one machine with other work running, Python 3.12/3.14: `load_usmap()` took about 0.15-0.30 s over three mapping files, with about 17-31 MiB peak working-set growth. Checking 100 requirements took about 2.6-4.1 ms without a fallback, or 6.4-7.5 ms with the prefix fallback and its apply/recheck pass (6 proposals). Applying 3,167 synthetic renames took about 35-47 ms, plus about 7-12 ms for the digest. Opening with an already loaded mapping took about 68-94 ms, against 387-437 ms with its path; mapping-change attribution cost about 5-6 microseconds p50 over 1,598 reads. These are approximate observations, not cold-cache measurements or throughput guarantees.
- Approximate, one machine, an ordinary-texture terrain tile (`PF_B8G8R8A8`, `.ubulk` mips): a 2x2 sample took about 0.1 ms on 1 compression block; a mip 0 read was about 2.5 ms p50, with `cancel=` polled once per compression block, about every 0.3 ms on the measured tile -- it does not add that much latency itself. `list_packages()`'s first call, which also learns plugin mount roots, took 4.25-5.0 s.
- Approximate pre-cache measurements, one machine, exports and typed reads: `exports()` of a main map's cooked header took about 0.28-0.30 s and retained about 35-38 MiB. Validated header memory can now remain installation-owned after its `Exports` handle is dropped, until eviction or close. `read()` of a small export was well under 1 ms p50; a 64-byte `raw()` through an `Exports` handle read 1 compression block (2 when the range crosses a block boundary); through `assets.raw()` with a cold header it read 3, including the target's cooked header. With a resident header it skips those header blocks and reads only the payload range. Over a one-in-sixty sample of the install's packages (1,787 packages, 21,141 exports), the sweep itself took a few seconds, and the export with the most decoded values in that sample (394,305, an `AudioImpulseResponse`) read in about 0.13 s with peak working-set growth of about 17 MiB over the baseline. Cancelling during a main map's `exports()` had a latency of about 93 ms p50 (198 ms worst case, from the pre-cache gap noted under Threads and cancellation, above); cancelling mid-decode was about 1 ms.
- Cooked headers are admitted by accounted retained size, including parsed records and exact string sizes, rather than serialized header size. A valid header above the 96 MiB entry cap is returned without retention or eviction of useful headers; repeated calls pay the existing parse and validation cost. A cheap lower-bound check skips the string-accounting walk for clearly oversized headers; other oversized headers pay one walk on every call. The budget excludes ScriptObjects already owned by the installation, in-flight parses and headers retained independently by `Exports` handles; it is not a process-memory limit.
- Limits of one `read()`: a cooked header or an export's data over 64 MiB raises `CorruptAssetError`; a value more than 16 struct levels deep raises `InvalidMappingError` with reason `struct nesting`, and one more than 64 levels deep counting containers raises `value nesting`; a read whose decoded values and built slots exceed the export's size in bytes plus 65,536 raises `decode budget`. On one measured install no export reached the last two, and the largest read used 0.375 units per byte above the 65,536.
- Memory follows the decoded values, which are Python objects: an export made mostly of small native structs keeps up to about 190 bytes per input byte while its result is alive, so a 64 MiB export of `Color` values would take about 12 GiB. Read large exports one at a time, or use `raw()`.
- The `.usmap` is trusted input: with a hand-crafted mapping, `==` between values from two reads and `to_python()` can take seconds on a few bytes of data, because they expand zero-masked structs that one read shares.
- Windows x64 only (BCrypt for AES; the exe's PE and the `.ucas`/`.utoc` layout). Treat an AES key file and its contents as a secret: never log, print or commit one; pass it by path.
