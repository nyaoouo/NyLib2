# Dump

[Index](index.md) · Code: `nylib/ue/pipeline.py`, `nylib/ue/snapshot.py`, `nylib/ue/cli.py`

## Probe and dump

```python
# needs a running game
from nylib.ue import probe, dump

report = probe('TRIANGLE_STRATEGY-Win64-Shipping.exe')   # finds globals and offsets, writes nothing
print(report.ok, report.stem)
for v in report.values:
    print(v.name, v.value, v.how, 'UNVERIFIED' if v.unverified else '')

result = dump('TRIANGLE_STRATEGY-Win64-Shipping.exe', out=r'D:\ue_dumps')
print(result.path)            # D:\ue_dumps\TRIANGLE_STRATEGY\20261002-024137
print(result.counts, result.unverified, result.warnings, result.export_paths)
```

- Target: an exe name (`.exe` may be left out), a PID (`int`), or `None` for the current process (inside the game). Two processes with the same name raise `AmbiguousTargetError`; pass the PID.
- `probe()` and `dump()` take `cache_bytes=`: `None` uses the default page-cache cap (1 GiB outside the game, 128 MiB inside), `0` reads uncached, or an integer of at least `0x10000` sets the cap in bytes. A `bool` or other non-`int` raises `TypeError`; a negative value or `1..0xFFFF` raises `ValueError`. Uncached reads are slower and see objects the game creates meanwhile; one downstream attach measured 23.4 s uncached against 5.83 s cached.
- `nylib.ue.pipeline.list_targets()` lists the running processes that look like UE games.
- Output: `<out>/<GameName>/<YYYYmmdd-HHMMSS>/`. The root is `out=`, else the environment variable `NYLIB_UE_OUT`, else `.\ue_dumps` under the current directory. Inside the game there is no default: pass `out=` or set `NYLIB_UE_OUT`.
- Profiles: a TOML file in `<out>/profiles/` whose `[match] exe` is the target is used automatically (two files matching the exe and build constraints raise `ProfileError`; pass `profile=` to choose); `nylib.ue.pipeline.write_profile(report)` writes one that pins GObjects and GNames for this build. A profile can never enable calls.
- `write_profile` also notes the probe's ProcessEvent index and GWorld rva when the probe detected them itself (a `how` starting `auto:`, not `profile:` or `fallback:`), but only as commented lines under "found by this probe; check it before pinning". Uncommenting one makes it a pin; add `[match] build` to restrict it to that build (see below). `probe --write-profile` then prints `wrote <path> (pins: gobjects, gnames; rva pins hold for build 0x...; hints are commented out)`.
- Writing a profile never overwrites one. If the file exists, `write_profile` raises `FileExistsError` (`e.args[0]` is the path) with the text it would have written in `e.profile_text`. `probe --write-profile` then prints that text, says to merge it by hand and exits 1; with `--json`, the error document carries `path` and `profile_text`. If `<out>/profiles` is a file, `write_profile` raises `NotADirectoryError` naming it instead.
- `[match] build` (the PE TimeDateStamp, an integer in `0..0xFFFFFFFF`) restricts the whole profile to that build. Optional `[match] image_size` (SizeOfImage, `1..0xFFFFFFFF`) also checks image size and requires `build`; booleans are rejected. Automatic pickup skips a mismatch with a WARNING; an explicit `profile=` raises `ProfileError` before probing target memory. When the target's SizeOfImage reads 0, pickup can still match by build alone but skips a profile requiring `image_size` as uncheckable; an explicit profile compares against 0 and raises on that mismatch. Without `[match] build`, only `[globals]` rva pins (`gobjects`, `gnames`) are checked against the build: `process_event` and `[offsets]` pins, including `Off.InSDK.World.GWorld`, still apply to every build of that exe and count as verified. `write_profile` does not write `[match] build`; add it by hand.
- `[offsets]` keys are checked when the profile is parsed: each must be spelled as in `nylib.ue.engine.offsets.PINNABLE_KEYS` (`Off.UStruct.Size`, not `UStruct.Size`), else `ProfileError: [offsets] unknown key ...`. The automatic pickup skips any profile that fails to parse, with a WARNING; only this error, in a profile whose `[match] exe` is the target, fails the probe, dump or attach instead.
- In code, `nylib.ue.profiles.parse_profile(text)` and `load_profile(path)` build a `Profile` (`path`, `exe`, `pins`, `offsets`, `hooks`, `build`, `image_size`), which `profile=` accepts like a path. An in-memory profile shows as `<string>` in messages and cannot use `[hooks]` (`ProfileError`: hooks need a profile file).
- Quality: `result.quality` (and `meta.json`'s `quality`) reports a `verdict` of `complete` or `degraded` with the `reasons`, the per-kind issue `counts`, and the `thresholds` applied. It degrades on any `unreadable_type`, `unreadable_fields`, `unreadable_name` or `unreadable_interfaces`, or when `index_mismatch` over type-relevant rows (classes, structs, functions, enums, packages) exceeds 0.1% of them; other issue kinds are reported but never gate it (an `EnumProperty` whose enum does not resolve is an `unresolved_reference`). A null enum (sample `enum is null in the game`) is a game-side gap, for example a cooked Blueprint importing a native enum from a module absent from the shipping build; no dumper can name it, and the usmap names it `None`. `unresolved_reference` also counts function parameters and locals, which the usmap does not encode, so its count can exceed the usmap warning's. Samples from a class's listed functions name the function. `meta.json`'s `issues` keeps the count and first and last sample per kind, each cut at 200 characters. Every sample is logged whole at DEBUG on `nylib.ue.reflect`, so an ending such as `enum is null in the game` cut from a long function sample remains in a log that keeps DEBUG records, such as the CLI's `<out>/_logs/dump.log` or the file `dump(log_file=...)` names. If the usmap export finds a property that names a missing enum or struct, `result.warnings` gets a `usmap: N properties referenced a missing enum or struct (first: ...)` entry. `strict=True` (CLI: `--strict`) turns a degraded verdict into a raised error before anything is published, leaving only the `.partial` folder on disk; the default (`strict=False`) only reports it.

### Profile file

```toml
[match]
exe = "TRIANGLE_STRATEGY-Win64-Shipping.exe"
build = 0x67890ABC
image_size = 0x6F00000   # optional; needs build

[globals]
gobjects = { rva = 0x4A2B3C0, build = 0x67890ABC, image_size = 0x6F00000 }   # an rva needs build
gnames = { sig = "48 8D 0D ? ? ? ? E8" }                                     # a sig takes no build; it must match one site
process_event = { index = 76 }

[offsets]
"Off.InSDK.World.GWorld" = 0x4C7D1A8
```

Start from `probe --write-profile`, which writes `[match]` and the `gobjects` / `gnames` rva pins, plus commented hints (above). By hand you can add `note` (a string) to any `[globals]` pin, `elements_per_chunk` and `layout` to `gobjects`, and `[hooks] decrypt_objects = "hooks.py:decrypt_objects"` (a file beside the profile; it runs as Python in the dumping process, so use only profiles you trust; not with a `gobjects` pin, which is read without decryption). A `gobjects` / `gnames` pin needs exactly one of `rva` and `sig`.

## Exports

`dump(exports=...)` defaults to all five; `exports=()` writes the snapshot only.

- `gobjects`: `GObjects-Dump.txt`, Dumper-7's object list.
- `gobjects-props`: `GObjects-Dump-WithProperties.txt`, the same with properties.
- `idmap`: `IDAMappings/<stem>.idmap`, Dumper-7's IDA mappings (V1).
- `image`: `image/<exe>`, the game's main module as a PE file whose ImageBase is the runtime base. It holds the game's code: do not share a snapshot folder that contains it.
- `usmap`: `Mappings/<stem>.usmap`, Dumper-7's type mappings for `.usmap` readers (FModel, CUE4Parse), uncompressed.

## Calls during a dump (`allow_calls`)

```python
# needs a running game; each call can crash the game
from nylib.ue import probe, dump

result = dump('TRIANGLE_STRATEGY-Win64-Shipping.exe', allow_calls=('text', 'game-info', 'append-string'))
for r in result.remote_calls:
    print(r.feature, r.ran, r.ok, r.detail)
```

- `text`: finds the FText layout with one `Conv_StringToText` call, so FText values can be read later.
- `game-info`: reads the game name and engine version through `GetGameName` / `GetEngineVersion`; they make the stem that names the exports.
- `append-string`: checks the name decoder against `FName::AppendString` on a sample of names.
- Calls run on a new thread in the game (inside it: the calling thread), not the game thread, and can crash the game. None is made while the probe left an offset unverified (the two FText keys, the two game-name keys, and `Off.FFieldClass.Id`, `Off.FFieldClass.ClassFlags`, `Off.FFieldClass.SuperClass` excepted). A feature that fails becomes a warning; the dump goes on. What ran is listed in `meta.json` (`remote_calls`).

## Load a snapshot

```python
from nylib.ue import load_snapshot

with load_snapshot(r'ue_dumps\TRIANGLE_STRATEGY\20261002-024137') as snap:
    print(snap.stem, len(snap.objects), snap.meta['counts'])
    actor = snap.type('/Script/Engine.Actor')                      # ClassRecord
    print(actor.cpp_name, actor.super, hex(actor.size))
    for p in actor.properties[:3]:
        print(p.name, hex(p.offset), p.type.kind)
    fn = snap.type('/Script/Engine.Actor:K2_SetActorLocation')     # FunctionRecord
    print([p.name for p in fn.params])
    i = snap.objects.index_of_path('/Script/Engine.Default__KismetSystemLibrary')
    print(snap.objects[i], snap.objects.full_name(i))
```

The folder holds `meta.json`, `offsets.json`, `objects.jsonl`, `fields.jsonl`, `types.jsonl` and `types.idx.json`, plus the exports. Types load on first use. A snapshot holds types, layouts and the object list, but no property values, not even class defaults; read values from a live session (`ue.cdo(...)`, `ue.find(...)`).

## Command line

```text
python -m nylib.ue list
python -m nylib.ue probe TRIANGLE_STRATEGY-Win64-Shipping.exe [--write-profile] [--explain]
python -m nylib.ue dump TRIANGLE_STRATEGY-Win64-Shipping.exe [--out DIR] [--exports idmap,gobjects] [--allow-calls [text,game-info,append-string]] [--strict]
python -m nylib.ue export <snapshot> --format idmap
python -m nylib.ue info <snapshot>
```

`list`, `probe` and `dump` need a running game. `list` prints each process's matching profile and its status: `build matches`, `build differs`, `no rva pins`, `ambiguous (N profiles)` or `invalid` (an unknown `[offsets]` key; the log names it). `[match] build` and `image_size` filter the profiles for `list`: one match reports `build matches`, several report `ambiguous (N profiles)`, and only mismatches report `build differs`; without `[match] build`, status still follows the rva pins. `--explain` lists the GWorld candidate rvas when three or more image slots point at one UWorld. If no candidate is unique, the unverified GWorld label and a WARNING list up to eight distinct rvas to help choose a profile pin; they do not verify one. `--allow-calls` without a value means all three. `--json` (all but `export`) prints machine-readable output. Logs go to `<out>/_logs/<command>.log` unless `--log-file` is given. Exit codes: 0 ok, 1 error, 2 usage, 3 detection failed, 4 cannot open the target or it exited, 130 interrupted.

## Own memory backend

A private `_open_target=` factory lets `probe`, `dump` and `Unreal.attach` use your own `nylib.process.Process`-like object (`read`, `write`, `iter_memory_region`, `virtual_query`, `enum_ldr_data`, `process_id`, `still_alive`) instead of opening the target themselves:

```python
# needs a running game
from nylib.process import Process
from nylib.ue import memory, pipeline, probe

proc = Process.from_name('TRIANGLE_STRATEGY-Win64-Shipping.exe')   # your own handle

def factory(target, *, write, remote_calls, cache_bytes):
    source = (memory.ProcessSource(proc, cache=False) if cache_bytes == 0 else
              memory.ProcessSource(proc, max_cache_bytes=pipeline.CACHE_CAP_EXTERNAL if cache_bytes is None else cache_bytes))
    return pipeline.OpenedTarget(source, pipeline.target_info(source, mode='external', pid=proc.process_id),
                                 process=proc, check_alive=proc.still_alive)

report = probe(proc.process_id, _open_target=factory)
```

The factory receives `cache_bytes` as given, including `None` and `0`; it chooses how to honour that value. No `closer=`, so you keep your handle; `OpenedTarget.close()` closes it only if you pass one. A `nylib.ctype` accessor becomes a `memory.MemorySource` subclass instead (`_read`, `_readable_ranges`, `regions`, `modules`); the keyword is private and may change.

`_readable_ranges` must report only memory your backend can actually read; when unsure, leave it out. The dumper trusts it to choose which pointers to dereference and which ranges to read, so an over-report fails a probe or silently drops a scanned section. `_read` raises `nylib.ue.errors.MemoryReadError` for bytes it cannot read.

When each read of your source is a slow call, such as a driver, wrap it in the factory: `source = memory.PagedSource(my_source)`. The wrapper reads your source in 64 KiB pages. Where a page read fails, it reads that page in 4 KiB pieces, and where a piece fails too, it calls your `_read` with the original address and size. A read therefore returns the bytes or raises the error your source would, provided your source can read any part of a span it can read whole. Pages keep the bytes of their first read until `refresh()`, which `dump` calls once before the walk. `fresh` reads your source uncached, and a write drops the pages it touches. `page_size=` takes a power of two from 0x1000 to 0x100000, and `max_cache_bytes=` is the LRU cap: 1 GiB by default, `None` for none. `ProcessSource` already caches its reads and a capture reads a local file, so wrapping either gains nothing.
