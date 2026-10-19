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
- `nylib.ue.pipeline.list_targets()` lists the running processes that look like UE games.
- Output: `<out>/<GameName>/<YYYYmmdd-HHMMSS>/`. The root is `out=`, else the environment variable `NYLIB_UE_OUT`, else `.\ue_dumps` under the current directory. Inside the game there is no default: pass `out=` or set `NYLIB_UE_OUT`.
- Profiles: a TOML file in `<out>/profiles/` whose `[match] exe` is the target is used automatically (or pass `profile=`); `nylib.ue.pipeline.write_profile(report)` writes one that pins GObjects and GNames for this build. A profile can never enable calls.
- Quality: `result.quality` (and `meta.json`'s `quality`) reports a `verdict` of `complete` or `degraded` with the `reasons`, the per-kind issue `counts`, and the `thresholds` applied. It degrades on any `unreadable_type` or `unreadable_fields`, or when `index_mismatch` over type-relevant rows (classes, structs, functions, enums, packages) exceeds 0.1% of them; other issue kinds are reported but never gate it. `strict=True` (CLI: `--strict`) turns a degraded verdict into a raised error before anything is published, leaving only the `.partial` folder on disk; the default (`strict=False`) only reports it.

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
- Calls run on a new thread in the game (inside it: the calling thread), not the game thread, and can crash the game. None is made while the probe left an offset unverified (the FText and game-name ones excepted). A feature that fails becomes a warning; the dump goes on. What ran is listed in `meta.json` (`remote_calls`).

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

The folder holds `meta.json`, `offsets.json`, `objects.jsonl`, `fields.jsonl`, `types.jsonl` and `types.idx.json`, plus the exports. Types load on first use.

## Command line

```text
python -m nylib.ue list
python -m nylib.ue probe TRIANGLE_STRATEGY-Win64-Shipping.exe [--write-profile] [--explain]
python -m nylib.ue dump TRIANGLE_STRATEGY-Win64-Shipping.exe [--out DIR] [--exports idmap,gobjects] [--allow-calls [text,game-info,append-string]] [--strict]
python -m nylib.ue export <snapshot> --format idmap
python -m nylib.ue info <snapshot>
```

`list`, `probe` and `dump` need a running game. `--allow-calls` without a value means all three. `--json` (all but `export`) prints machine-readable output. Logs go to `<out>/_logs/<command>.log` unless `--log-file` is given. Exit codes: 0 ok, 1 error, 2 usage, 3 detection failed, 4 cannot open the target or it exited, 130 interrupted.

## Own memory backend

A private `_open_target=` factory lets `probe`, `dump` and `Unreal.attach` use your own `nylib.process.Process`-like object (`read`, `write`, `iter_memory_region`, `virtual_query`, `enum_ldr_data`, `process_id`, `still_alive`) instead of opening the target themselves:

```python
# needs a running game
from nylib.process import Process
from nylib.ue import memory, pipeline, probe

proc = Process.from_name('TRIANGLE_STRATEGY-Win64-Shipping.exe')   # your own handle

def factory(target, *, write, remote_calls, cache_bytes):
    source = memory.ProcessSource(proc, max_cache_bytes=cache_bytes or pipeline.CACHE_CAP_EXTERNAL)
    return pipeline.OpenedTarget(source, pipeline.target_info(source, mode='external', pid=proc.process_id),
                                 process=proc, check_alive=proc.still_alive)

report = probe(proc.process_id, _open_target=factory)
```

No `closer=`, so you keep your handle; `OpenedTarget.close()` closes it only if you pass one. A `nylib.ctype` accessor becomes a `memory.MemorySource` subclass instead (`_read`, `_readable_ranges`, `regions`, `modules`); the keyword is private and may change.

`_readable_ranges` must report only memory your backend can actually read; when unsure, leave it out. The dumper trusts it to choose which pointers to dereference and which ranges to read, so an over-report fails a probe or silently drops a scanned section. `_read` raises `nylib.ue.errors.MemoryReadError` for bytes it cannot read.

When each read of your source is a slow call, such as a driver, wrap it in the factory: `source = memory.PagedSource(my_source)`. The wrapper reads your source in 64 KiB pages. Where a page read fails, it reads that page in 4 KiB pieces, and where a piece fails too, it calls your `_read` with the original address and size. A read therefore returns the bytes or raises the error your source would, provided your source can read any part of a span it can read whole. Pages keep the bytes of their first read until `refresh()`, which `dump` calls once before the walk. `fresh` reads your source uncached, and a write drops the pages it touches. `page_size=` takes a power of two from 0x1000 to 0x100000, and `max_cache_bytes=` is the LRU cap: 1 GiB by default, `None` for none. `ProcessSource` already caches its reads and a capture reads a local file, so wrapping either gains nothing.
