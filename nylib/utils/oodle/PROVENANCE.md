# Provenance: bundled Oodle DLLs

`oo2core_9_win64.dll` and `oo2net_9_win64.dll` are Oodle Data and Oodle Network 1,
version 2.9.14, linked unmodified from Unreal Engine's static libraries. Each DLL
re-exports exactly the functions its public header declares; no Oodle code is
written, patched, or reimplemented by this project.

## Source

- Tag `5.7.4-release`, commit `260bb2e1c5610b31c63a36206eedd289409c5f11`.
- Manifest: `Engine/Build/Commit.gitdeps.xml` (blob `96c8af04742328d58637ca452658f32dbe645982`).

| DLL | manifest File | lib SHA-1 | exports | DLL size | DLL SHA-256 |
| --- | --- | --- | --- | --- | --- |
| `oo2core_9_win64.dll` | `Engine/Source/Runtime/OodleDataCompression/Sdks/2.9.14/lib/Win64/oo2core_win64.lib` | `bf36d7973361b14ac64fdce2e2cef7eb37af152b` | 49 | 642048 bytes | `9603066fea25ed4f706e1188efdf6423d345d7efc789328a58ded6a00057fba4` |
| `oo2net_9_win64.dll` | `Engine/Plugins/Compression/OodleNetwork/Sdks/2.9.14/lib/Win64/oo2net_win64.lib` | `2348c041f6fe3ec9598796b16ae1a93a0b9cf10b` | 33 | 99840 bytes | `2b6c2564b0bc84335429089a658bba3c9aff8f991ee00fefc1be5656d658fbca` |

## Toolchain

MSVC 14.51.36231 (VS 18), Windows SDK 10.0.28000.0, UCRT 10.0.28000.0.

Compiler: `cl /nologo /LD /MD /O2 /Brepro`.
Linker: `/link /DEF:<exports.def> /Brepro /MANIFEST:NO` (no `/DEBUG`, no `/Z7`/`/Zi`).

## Embedded strings

Epic's original `__FILE__` strings from the static-library build (e.g. under
`v:\devel\projects\oodle2\`) remain inside the compiled code, exactly as they do
in the official Oodle DLLs shipped with games. Nothing from the machine that
linked these DLLs is embedded: no local path, no username, no `.pdb`/CodeView
debug record.

## Rebuild

```
python scripts/oodle/build.py --manifest <Commit.gitdeps.xml from a 5.7.4-release checkout> --check
```

Exit 0 means the rebuild is byte-identical to the committed DLLs (same toolchain
and SDK as recorded above).

## Licence

Oodle Data and Oodle Network are proprietary software of Epic Games Tools LLC,
distributed with Unreal Engine 5.7.4 under the Unreal Engine EULA. nylib's
GPL v3 does not apply to these two files.
