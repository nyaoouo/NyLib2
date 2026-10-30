# Runtime

[Index](index.md) · Code: `nylib/ue/runtime/session.py` (`Unreal`), `nylib/ue/runtime/types.py`, `nylib/ue/runtime/invoke.py`

Every snippet on this page needs a running game.

## Attach

```python
from nylib.ue import Unreal

ue = Unreal.attach('TRIANGLE_STRATEGY-Win64-Shipping.exe', dump='latest')
print(ue)          # <Unreal external pid 1234 TRIANGLE_STRATEGY-Win64-Shipping.exe types=snapshot read-only>
ue.close()         # or: with Unreal.attach(...) as ue:
```

- `dump=None` (default): probe the game now and read types from it on first use.
- `dump='latest'`: the newest snapshot under the output root (see [Dump](dump.md)) made from this build; `DumpMismatchError` if there is none.
- `dump='auto'`: the same, but dumps first when no snapshot matches. That is a full dump with the default exports, including `image` (the game's main module, which holds its code: [Dump](dump.md#exports)).
- `dump=r'<snapshot folder>'`: that snapshot; it must match the running build.
- `profile=` (a path, or `nylib.ue.profiles.parse_profile(text)`) pins values for a probe (`dump=None`) and for the dump that `dump='auto'` makes. A snapshot session ignores `profile=`, because the snapshot's offsets were fixed when it was dumped: pin in a profile, then dump again. Without `profile=`, a probe uses the one profile in `<out>/profiles/` whose `[match] exe` is the target, and the `probe:` log line names the profile it used; pass `profile=` to avoid picking one up by accident. Profiles: [Dump](dump.md#probe-and-dump).
- `out=` is the output root for snapshots and profiles; it defaults to `NYLIB_UE_OUT`, else `.\ue_dumps` under the current directory.
- Inside the game (a script injected with `python -m nylib.winutils.python_loader inject --process <exe> --script <file>`): `Unreal.attach_current(...)` with the same arguments; `dump='latest'` and `'auto'` need `out=` or `NYLIB_UE_OUT`.
- Your own memory backend instead of a process handle: [Own memory backend](dump.md#own-memory-backend).

## Find objects

```python
world = ue.world()                                     # GWorld
pc = ue.local_player_controller()                      # world -> game instance -> first local player
ue.find('/Script/Engine.Default__KismetSystemLibrary')   # by full path, or None
ue.find_class('GameEngine')                            # short name or path; AmbiguousNameError lists matches
ue.objects_of('/Script/Engine.GameEngine')             # instances of a class and its subclasses, no default objects
ue.search('*PlayerController*')                        # glob over object names; class_= narrows it
ue.cdo('/Script/Engine.KismetSystemLibrary')           # the class default object
ue.component(pc.Pawn, '/Script/Engine.SceneComponent')   # first component of that class owned by an actor
ue.enum('/Script/Engine.ENetRole').ROLE_Authority      # an IntEnum
ue.refresh()                                           # re-read the object list after objects came and went
```

The first name or class lookup (`find`, `find_class`, `objects_of`, `search`, `component`, `cdo` by name) builds a table of all objects, kept until `refresh()`; that took about 8 s for 302,170 objects on one UE 5.7 game.

With type checking on, the checker does not know a found object's members (the lookups return the base object type); generate stubs and use `typing.cast`, see [stubs.md](stubs.md).

## Read

```python
pawn = pc.Pawn                       # objects come typed by their runtime class; None for a null pointer
pawn._path_, pawn._full_name_, pawn._address_
pawn.CustomTimeDilation              # members by their UE name (case-sensitive)
pawn.RootComponent.RelativeLocation  # a struct view into the game's memory
for actor in world.PersistentLevel.Actors:   # TArray: len(), [i], iteration, .to_list()
    print(actor)
pawn._get_('CustomTimeDilation')     # by name, for names that are not valid Python
pawn.cast('/Script/Engine.Actor')    # view the same object as another class
```

Strings come back as `str`, names as a `str` subclass, maps with `.items()` / `.get()`. An `FText` reads with `str(value)` once its layout is known: from a calls session, a snapshot dumped with `allow_calls=('text',)`, or a profile (a snapshot session needs a new dump made with it).

## Write

```python
ue = Unreal.attach('TRIANGLE_STRATEGY-Win64-Shipping.exe', dump='latest', write=True)
pawn = ue.local_player_controller().Pawn
pawn.CustomTimeDilation = 2.0
pawn.RootComponent.RelativeLocation.Z += 100.0   # struct fields are written in place
```

A session without `write=True` raises `ReadOnlySessionError`. Writes change values in place: a new string must fit the old one's buffer, containers cannot change size, and an `FText` cannot be written. `write=True` refuses to attach while offsets are unverified (`UnverifiedOffsetsError` lists them): pin them in a profile (a snapshot session needs a new dump made with it), pass `allow_unverified=True`, use a snapshot dumped with `allow_calls=('text',)`, or attach with `calls=` (the session then resolves the two FText offsets with one call). The two game-name keys (`Settings.Generator.GameName`, `GameVersion`) do not block writes; they stay in `ue.unverified`.

## Call UFunctions

```python
ue = Unreal.attach('TRIANGLE_STRATEGY-Win64-Shipping.exe', dump='latest', calls='remote-thread')
ksl = ue.cdo('/Script/Engine.KismetSystemLibrary')   # static functions are called on the CDO
print(ksl.GetEngineVersion())                       # one output: the value itself
pawn = ue.local_player_controller().Pawn
r = pawn.K2_SetActorLocation((0.0, 0.0, 500.0), False, True)   # NewLocation, bSweep, bTeleport
print(r.ReturnValue, r.SweepHitResult)              # several outputs: a named tuple, return value first
ue.call_timeout = 5.0                               # seconds; default 10, None waits forever
```

- `calls='game-thread'` queues calls for the next natural `ProcessEvent` entry on the game thread, inside or outside the game. It needs `keystone-engine` and `capstone`: `nylib.utils.pip` installs them on first use unless `PYTHON_PIP_ALL_REQ_INSTALLED` is set or the app is frozen, so run `pip install ".[asm]"` beforehand. If they still cannot be imported, the attach fails with `CallError(refused='dependencies')` before the target is opened. In a frozen app the message names the bundle and nylib's PyInstaller hooks (`hook-keystone.py`, `hook-capstone.py`), not pip.
- A game-thread session patches `ProcessEvent` during `Unreal.attach` when the session must resolve the FText layout (usually a probe, or a snapshot dumped without `allow_calls=('text',)`), otherwise on the first call. The attach then waits up to 10 s for that entry. If that call fails or times out, the attach still succeeds (with `write=True` it raises `UnverifiedOffsetsError`): check the log, or `ue.unverified` for the two FText keys.
- `CallError.refused` is the label a program can test; it is `None` for a failure that has none. Labels: `'dependencies'` (above); `'prologue'`, the trigger's first instructions cannot be relocated into the hook (a jump, call, return or RIP-relative operand, which is how a leftover hook shows, or a prologue crossing a page boundary), raised by a call; `'vtable'`, the `ProcessEvent` vtable entry is not executable code, so nothing was called. A session also labels calls it refuses before they start: `'delegate'`, `'latent'`, `'destroyed'`, `'not found'`, `'not a class function'`, `'no default object'`, `'class'`. Any other hook install failure reads "the hook could not install" with no label.
- A call can time out if the game thread stops entering that function; calling from that same thread is refused. While a timed-out call is still pending, `close()` raises `PendingCallsError` (a `SessionError` and a `RuntimeError`; `.pending` counts the calls). The session stays open and usable: retry `close()` once the call has run.
- The hook stays in the game until `close()` or a game restart (also when an attach fails while its own call is still pending: there is then no `ue` to close); every call of a later game-thread session over a leftover hook raises `CallError(refused='prologue')`. Use `with Unreal.attach(...) as ue:` or `try ... finally: ue.close()`.
- `calls='remote-thread'` runs each call on a new thread in the game; inside the game `attach_current(calls='any-thread')` runs it on the calling thread. These can race the game thread and its garbage collector. `call_timeout` applies to `game-thread` and `remote-thread`; `any-thread` ignores it.
- `ue.game_thread()` opens the detected game thread: the one thread named `GameThread`, else the earliest-created thread. It raises `DetectionError` when no thread qualifies or the thread scan fails. Close the returned `Thread` handle, or use it with `with`.
- For an APC, pass `calls=calls.ApcCaller(thread)` (`from nylib.ue import calls`) instead of a string. `thread` is a TID, a `Thread`, or `None` for the detected game thread. The thread must enter an alertable wait; a timed-out APC may run later and retains its call memory.
- To choose the thread or the hooked function, pass `calls=calls.HookCaller(thread_id=None, trigger=None, capacity=16)`. `thread_id` overrides the detected game thread. `trigger` is the address of another function whose entry drains the queue on that thread (default: `ProcessEvent`); a trigger not in committed executable memory raises `ValueError` at attach; the calls themselves still go through `ProcessEvent`, so its index must be verified. `capacity` is the queue size, a power of two from 1 to 64.
- Inputs go in reflection order or by keyword. Omitted inputs are zero; an `FText` input cannot be omitted. A struct input takes the struct, a tuple or a dict. Out parameters are never passed; they come back in the result.
- Results are copies. A call with no outputs returns `None`. UE skips some calls without a sign, so zero outputs can mean "not run".
- `calls=` refuses to attach while offsets are unverified (`UnverifiedOffsetsError`), except the two FText and the two game-name keys. In a probe session, a profile's `[globals] process_event = { index = ... }` pin verifies the ProcessEvent index.
- Without `calls=`, a call raises `CallsDisabledError`. Latent functions are refused. Bad arguments raise `MarshalError`; a failed or timed-out call raises `CallError`.

To use an existing game-thread pump, pass a `Caller` instance. Its `call` must return the target's integer `rax` and raise `CallError` for failed or uncertain execution:

```python
from nylib.ue import calls

class MyQueueCaller(calls.Caller):
    policy = 'game-thread'

    def __init__(self, queue):
        super().__init__()
        self.queue = queue

    def arena(self):
        return calls.CallArena(self.process)

    def call(self, function, *args, timeout):
        return self.queue.run_on_game_thread(function, args, timeout)

ue = Unreal.attach(target, calls=MyQueueCaller(my_queue))
```

The session calls `bind(site)` once; the base implementation stores `site.process` for `arena()`. `site` also supplies the ProcessEvent index and address, a game-thread opener, and the default timeout. The caller owns any hook it installs and should release it in `close()`.
