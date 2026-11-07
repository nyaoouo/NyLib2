# Provenance: bundled BC1 decoder DLL

`bcn_win64.dll` is nylib's own C BC1-to-RGBA8 decoder, built from
`scripts/bcn/bcn.c`. It contains no third-party code and is covered by
nylib's GPL v3 licence. Alpha is always 255, including three-colour index 3.

## Source

The source, build script, DLL and this file are maintained together in the
same commit. Byte-identical rebuilding is the source-to-binary check; a source
hash is omitted because checkout line endings can vary.

| DLL | exports | DLL size | DLL SHA-256 |
| --- | --- | --- | --- |
| `bcn_win64.dll` | 1 (`bcn_decode_bc1`) | 10752 bytes | `8a7596cb6292e9c55cb6a91deff7e16f99e31ee889aa07e88a5abec1fd242dec` |

Imports: `KERNEL32.dll`, `VCRUNTIME140.dll`,
`api-ms-win-crt-runtime-l1-1-0.dll`. There are no delay imports.

## Toolchain

MSVC 14.51.36231, Windows SDK 10.0.28000.0, UCRT 10.0.28000.0.
Selected with `x64 10.0.28000.0 -vcvars_ver=14.51`.

Compiler: `cl /nologo /LD /MD /O2 /DNDEBUG /utf-8 /Brepro /W3`.
Linker: `/link /Brepro /MANIFEST:NO /INCREMENTAL:NO /OUT:<work>/bcn_win64.dll`.
No `/Zi`, `/Z7` or `/DEBUG`.

## Embedded strings

No local paths, usernames, `.pdb` strings or CodeView debug records are embedded.
The build verifies the AMD64 machine, the single export, the import allowlist,
the debug directory and the ASCII/UTF-16LE path scan before installing.

## Rebuild

```
python scripts/bcn/build.py --check
python scripts/bcn/build.py --scan nylib/utils/bcn/bcn_win64.dll
```

Exit 0 from `--check` means the rebuild is byte-identical to the committed DLL
on the pinned toolchain, the DLL hash appears here, and the known-answer checks
passed. Those checks cover four literal pixel cases and the -1/-2/-3 returns,
including unchanged output buffers on errors.

## Refresh

Edit the source, run `python scripts/bcn/build.py --install`, update the table
and toolchain facts here, then commit the source, build script, DLL and this
file together. Run `--check` before committing.
