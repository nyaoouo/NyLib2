# Loading and installation tiers

## Process loaders

`load(payload)` uses `Process.current`. Supply `process=` for a caller-owned AMD64 target whose imports are already loaded:

```python
from nylib.process import Process
from nylib.winutils.pe_map.process import InstallTier, load

target = Process(child_pid)
try:
    with load(payload, process=target, tier=InstallTier.RUNTIME) as image:
        result = target.call(image.get_export('add'), 3, 4)
finally:
    target.close()
```

`host=` accepts an explicit `LocalProcessHost` or `RemoteProcessHost`; pass either `process=` or `host=`, not both. Keep the target handle open through `unload()`. For a remote image, pass remote addresses or use `Process.call` byte arguments. Do not cast a remote address to a local `ctypes` callable.

## Installation tiers

| Tier | Behavior | Rejected requirements |
| --- | --- | --- |
| `MINIMAL` | Copy headers and sections, apply base relocations, resolve ordinary imports, protect pages, call the DLL entry, cache exports, and detach/free on unload. | TLS, x64 exception table, delay imports, and load configuration. |
| `RUNTIME` | Add local TLS process callbacks, x64 function-table registration, eager delay imports, dependency bookkeeping, and rollback. | Static TLS templates and zero-fill, CFG, and unsupported image features; the remote host also rejects every TLS directory. |
| `STRICT` | Apply RUNTIME behavior while requiring a complete TLS thread lifecycle. | Any TLS directory with either shipped Process host, plus all RUNTIME rejections. |

All tiers require a page-aligned AMD64 DLL. The remote host rejects WOW64 targets. The loader rejects CLR, executable/writable sections, CFG, unsupported relocations, and rebasing without relocations. `STRICT` is a stricter feature gate, not native-loader equivalence. See [limitations](limitations.md) for the common host restrictions.

The local RUNTIME host invokes TLS process callbacks but does not install static TLS or issue thread attach/detach notifications. The remote host rejects TLS before allocation because `Process.call` uses a separate target thread for each invocation. Delay imports are resolved during mapping rather than on first use.

## Exports and lifetime

`get_export` accepts a name or ordinal and returns a cached absolute address, including resolved forwarders. `call_export` uses the selected host's `Process.call` and suits simple integer and pointer arguments. In the current process, callers needing a precise C signature can use the returned address with `ctypes`.

`LoadedImage` retains its base, size, entry address, resolved exports, TLS callback addresses, dependency tokens, unwind and CRT state, and any [discarded blocks](retention.md). `unload()` uses this state without reopening source bytes or parsing mapped headers. Calling an export after unload raises `RuntimeError`. The caller must keep code and data needed by active functions and detach callbacks intact, and ensure no thread is executing in the image when unloading.
