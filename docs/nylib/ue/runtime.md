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
- `dump='auto'`: the same, but dumps first when no snapshot matches.
- `dump=r'<snapshot folder>'`: that snapshot; it must match the running build.
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

Strings come back as `str`, names as a `str` subclass, maps with `.items()` / `.get()`. An `FText` reads with `str(value)` once its layout is known: from a calls session, a snapshot dumped with `allow_calls=('text',)`, or a profile.

## Write

```python
ue = Unreal.attach('TRIANGLE_STRATEGY-Win64-Shipping.exe', dump='latest', write=True)
pawn = ue.local_player_controller().Pawn
pawn.CustomTimeDilation = 2.0
pawn.RootComponent.RelativeLocation.Z += 100.0   # struct fields are written in place
```

A session without `write=True` raises `ReadOnlySessionError`. Writes change values in place: a new string must fit the old one's buffer, containers cannot change size, and an `FText` cannot be written. `write=True` refuses to attach while offsets are unverified (`UnverifiedOffsetsError` lists them): pin them in a profile, pass `allow_unverified=True`, use a snapshot dumped with `allow_calls=('text',)`, or attach with `calls=` (the session then resolves the two FText offsets with one call).

## Call UFunctions

```python
ue = Unreal.attach('TRIANGLE_STRATEGY-Win64-Shipping.exe', dump='latest', calls='remote-thread')
ksl = ue.cdo('/Script/Engine.KismetSystemLibrary')   # static functions are called on the CDO
print(ksl.GetEngineVersion())                       # one output: the value itself
pawn = ue.local_player_controller().Pawn
r = pawn.K2_SetActorLocation((0.0, 0.0, 500.0), False, True)   # NewLocation, bSweep, bTeleport
print(r.ReturnValue, r.SweepHitResult)              # several outputs: a named tuple, return value first
ue.call_timeout = 5.0                               # remote-thread only; seconds, default 10, None waits forever
```

- `calls='remote-thread'` runs each call on a new thread in the game; inside the game use `attach_current(calls='any-thread')`, which runs it on the calling thread. Neither is the game thread: a call can crash the game or corrupt its state.
- Inputs go in reflection order or by keyword. Omitted inputs are zero; an `FText` input cannot be omitted. A struct input takes the struct, a tuple or a dict. Out parameters are never passed; they come back in the result.
- Results are copies. A call with no outputs returns `None`. UE skips some calls without a sign, so zero outputs can mean "not run".
- Without `calls=`, a call raises `CallsDisabledError`. Latent functions are refused. Bad arguments raise `MarshalError`; a failed or timed-out call raises `CallError`.
