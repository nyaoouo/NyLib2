# Dump

[Index](index.md) · Code: `nylib/ue/pipeline.py`, `nylib/ue/snapshot.py`, `nylib/ue/cli.py`

## Probe and dump

```python
# needs a running game
from nylib.ue import pipeline

report = pipeline.probe('TRIANGLE_STRATEGY-Win64-Shipping.exe')   # finds globals and offsets, writes nothing
print(report.ok, report.stem)
for v in report.values:
    print(v.name, v.value, v.how, 'UNVERIFIED' if v.unverified else '')

result = pipeline.dump('TRIANGLE_STRATEGY-Win64-Shipping.exe', out=r'D:\ue_dumps')
print(result.path)            # D:\ue_dumps\TRIANGLE_STRATEGY\20261002-024137
print(result.counts, result.unverified, result.warnings, result.export_paths)
```

- Target: an exe name (`.exe` may be left out), a PID (`int`), or `None` for the current process (inside the game). Two processes with the same name raise `AmbiguousTargetError`; pass the PID.
- `pipeline.list_targets()` lists the running processes that look like UE games.
- Output: `<out>/<GameName>/<YYYYmmdd-HHMMSS>/`. The root is `out=`, else the environment variable `NYLIB_UE_OUT`, else `.\ue_dumps` under the current directory. Inside the game there is no default: pass `out=` or set `NYLIB_UE_OUT`.
- Profiles: a TOML file in `<out>/profiles/` whose `[match] exe` is the target is used automatically (or pass `profile=`); `pipeline.write_profile(report)` writes one that pins GObjects and GNames for this build. A profile can never enable calls.

## Exports

`dump(exports=...)` defaults to all four; `exports=()` writes the snapshot only.

- `gobjects`: `GObjects-Dump.txt`, Dumper-7's object list.
- `gobjects-props`: `GObjects-Dump-WithProperties.txt`, the same with properties.
- `idmap`: `IDAMappings/<stem>.idmap`, Dumper-7's IDA mappings (V1).
- `image`: `image/<exe>`, the game's main module as a PE file whose ImageBase is the runtime base. It holds the game's code: do not share a snapshot folder that contains it.

## Calls during a dump (`allow_calls`)

```python
# needs a running game; each call can crash the game
result = pipeline.dump('TRIANGLE_STRATEGY-Win64-Shipping.exe', allow_calls=('text', 'game-info', 'append-string'))
for r in result.remote_calls:
    print(r.feature, r.ran, r.ok, r.detail)
```

- `text`: finds the FText layout with one `Conv_StringToText` call, so FText values can be read later.
- `game-info`: reads the game name and engine version through `GetGameName` / `GetEngineVersion`; they make the stem that names the exports.
- `append-string`: checks the name decoder against `FName::AppendString` on a sample of names.
- Calls run on a new thread in the game (inside it: the calling thread), not the game thread, and can crash the game. None is made while the probe left an offset unverified (the FText and game-name ones excepted). A feature that fails becomes a warning; the dump goes on. What ran is listed in `meta.json` (`remote_calls`).

## Load a snapshot

```python
from nylib.ue.snapshot import Snapshot

with Snapshot.load(r'ue_dumps\TRIANGLE_STRATEGY\20261002-024137') as snap:
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
python -m nylib.ue dump TRIANGLE_STRATEGY-Win64-Shipping.exe [--out DIR] [--exports idmap,gobjects] [--allow-calls [text,game-info,append-string]]
python -m nylib.ue export <snapshot> --format idmap
python -m nylib.ue info <snapshot>
```

`list`, `probe` and `dump` need a running game. `--allow-calls` without a value means all three. `--json` (all but `export`) prints machine-readable output. Logs go to `<out>/_logs/<command>.log` unless `--log-file` is given. Exit codes: 0 ok, 1 error, 2 usage, 3 detection failed, 4 cannot open the target or it exited, 130 interrupted.
