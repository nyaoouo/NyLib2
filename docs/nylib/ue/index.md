# nylib.ue

`nylib.ue` reads the reflection data of Unreal Engine games (UE 4.25+ and UE5, Windows x64).

- [Dump](dump.md): find the engine globals and offsets, walk every class, struct, enum and function, and write a versioned snapshot folder plus Dumper-7-format exports (the GObjects dumps, an `.idmap`, the game's main module as a PE file).
- [Runtime](runtime.md): attach to the running game and use its objects from Python: read members, write them (opt-in), call UFunctions (opt-in).
- [IDA](ida.md): import a snapshot's names, types and comments into IDA 9.x.
- [Stubs](stubs.md): write `.pyi` stubs of a snapshot's types for editor completion.

It works from outside the game (another process) by default, and from inside it (injected Python).
The details are in the code and its docstrings; these pages only show how to use it.

## Prerequisites

- Windows x64 and a 64-bit UE 4.25+ or UE5 game.
- Python 3.11 or newer (`pyproject.toml`); nylib.ue is tested with 3.12 and 3.14. It needs no third-party package.
- nylib installed from this repository: `pip install -e .` (see the readme).

## Quick start

```python
# needs a running game
from nylib.ue import dump, Unreal

exe = 'TRIANGLE_STRATEGY-Win64-Shipping.exe'
result = dump(exe)                               # writes .\ue_dumps\<game>\<timestamp>\
print(result.path, result.counts)

with Unreal.attach(exe, dump=result.path) as ue:  # read-only session, types from the snapshot
    world = ue.world()
    print(world, world.PersistentLevel)
    print(ue.local_player_controller().Pawn)
```

The snapshot stays usable without the game: [load it](dump.md#load-a-snapshot), import it into [IDA](ida.md), or make [stubs](stubs.md) from it.

## Safety

- Reads are the default. The dumper and a default session open the game with read rights only and never run code in it.
- Writes need `write=True` on `Unreal.attach`. They go straight into the game's memory.
- UFunction calls need `calls=` on `Unreal.attach` (`'remote-thread'` outside the game, `'any-thread'` inside it). The dumper's own calls need `allow_calls=` (CLI: `--allow-calls`).
- A call runs `ProcessEvent` on a thread that is not the game thread. It races the game thread and its garbage collector and can crash the game or corrupt its state.
- Latent functions (those taking an `FLatentActionInfo`) are refused.
- Offsets the dumper could not verify block writes and calls; the error lists them and how to fix them.
- A profile's hooks are Python code that the dumper runs (inside the game in internal mode): use only profiles you trust.
- A call can leave memory in the game: what the engine allocates for out parameters, and the call's own memory when it times out or is interrupted.
- Ctrl+C during a remote-thread call can crash the game.
- Injecting Python into a game that already loaded the same `python3XY.dll` crashes it. A missing `python_loader.dll` is built on first use, which needs MSVC and, when it is missing, downloads and installs Visual Studio Build Tools; build it once beforehand with `python -m nylib.winutils.python_loader build`.

## Tested with

- PalServer (UE 5.1, build 25247047), TRIANGLE STRATEGY (UE 4.27, build 11410614) and FrostBound (UE 5.4, build 24486464).
- Dumps: verified on captures of all three, and live against Dumper-7 on all three; the internal (injected) dump live on PalServer.
- The IDA importer, runtime reads, call parameter layouts, `--allow-calls` targets and stubs: checked on captures of all three; the importer applied in IDA 9.3.
- Live on FrostBound (main menu): runtime reads through both type sources, one property write (restored), one remote-thread UFunction call, and `dump --allow-calls` with all three features, checked against Dumper-7's output for the same build.
- Not yet verified on a real game: `attach_current` and `calls='any-thread'`; runtime sessions and `--allow-calls` on PalServer and TRIANGLE STRATEGY; calls with inputs or with string, array or FText outputs.
