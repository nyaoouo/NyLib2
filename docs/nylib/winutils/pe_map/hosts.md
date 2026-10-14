# Core and host contracts

## Architecture

| Module | Responsibility |
| --- | --- |
| `pe_map.core` | Validate PE bytes and produce immutable layout, relocation, import, TLS, export, and unwind metadata without `Process` or Win32 calls. |
| `pe_map.contracts` | Define memory, module resolution, runtime, optional discard, and CRT roles. `MapHost` composes roles for one address space. |
| `pe_map.loader` | Apply an `ImagePlan`, invoke callbacks, and own the image lifecycle without direct `Process` or Win32 calls. |
| `pe_map.process` | Adapt `Process.current` or a remote `Process` to the host roles. |

The public loader accepts bytes rather than a path. It creates no temporary DLL file. Delivery, caching, logging, and payload authentication belong to the caller.

## Pure planning and alternate hosts

```python
from nylib.winutils.pe_map import build_plan, parse_image

parsed = parse_image(payload)
plan = build_plan(parsed, target_base=0x180000000)
```

`parse_image` returns metadata and a SHA-256 fingerprint without retaining the payload bytes. `build_plan` computes relocation deltas after a target base is known. Neither touches a process. `PEFormatError` reports malformed input; `UnsupportedImageError` reports a feature the implementation cannot handle.

Implement the protocols in `pe_map.contracts` for another address space:

```python
from nylib.winutils.pe_map.contracts import MapHost
from nylib.winutils.pe_map.loader import InstallTier, load

host = MapHost(memory=my_memory, modules=my_modules, runtime=my_runtime, machine=0x8664)
loaded = load(payload, host=host, tier=InstallTier.RUNTIME)
```

The memory, resolver, and runtime roles must target the same address space. `IImageMemory.alloc` returns a zero-filled writable region; it owns read/write, protection, and instruction-cache operations. `IModuleResolver.acquire` returns a dependency token used by `resolve`, `base`, and `release`. `IImageRuntime` owns calls, TLS, and unwind registration. Its capability flags gate unsupported TLS before allocation.

For opt-in [block discard](retention.md), supply an `IImageDiscard` as the fifth `MapHost` argument or as `discarder=`. It decommits whole pages after attach. Hosts that omit it continue to work when no block is requested. The shipped Process hosts use `Process.free(address, size)`.

## CRT extension

The default `NoopCrtGlue` performs no extra work. A normal MSVC `_DllMainCRTStartup` handles its own CRT initialization. A custom-entry DLL can supply `ICrtGlue`:

```python
class MyCrtGlue:
    def prepare(self, plan):
        return initialize_compiler_state(plan.target_base)

    def cleanup(self, plan, token):
        finalize_compiler_state(plan.target_base, token)

loaded = load(payload, crt_glue=MyCrtGlue())
```

`prepare` runs after layout, fixups, imports, protection, and unwind registration, but before TLS callbacks and the DLL entry. `cleanup` runs during unload or rollback after a completed `prepare`. The mapper does not infer compiler internals. For remote images, the custom helper must explicitly use the target `Process`; Python callbacks run in the caller's process.
