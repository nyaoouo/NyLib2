# nylib.winutils.pe_map

Map an AMD64 DLL from PE file bytes and call its exports in the current process.

Keywords: PE, manual mapping, DLL, memory loading, Process.current, relocations, imports, TLS, x64 unwind, delay imports, exports

## Quick start

```python
from nylib.winutils.pe_map.process import InstallTier, load

# needs: verified AMD64 DLL bytes supplied by the caller
payload = obtain_and_verify_dll_bytes()
with load(payload, tier=InstallTier.RUNTIME) as image:
    address = image.get_export('add')
    result = image.call_export('add', 3, 4)
```

`get_export` accepts a name or ordinal and returns a cached absolute address, including resolved export forwarders. `call_export` uses `Process.current.call` and is suitable for simple integer and pointer arguments; callers needing a precise C signature can use the returned address with `ctypes`. Calling an export after `unload()` raises `RuntimeError`.

`LoadedImage` retains `base`, `size`, `entry_point`, resolved export addresses, TLS callback addresses, host references, dependency tokens, TLS state, unwind registration token, and CRT cleanup state. `unload()` uses this state without reopening the source bytes or parsing the mapped headers. The caller must keep code and data needed by active functions, TLS callbacks, and the DLL entry intact, and must ensure no thread is executing in the image when unloading. The loader does not modify an image after installation.

## Architecture

PE parsing, host operations, and installation are separate:

| Module | Responsibility |
| --- | --- |
| `pe_map.core` | Validate PE bytes and produce immutable layout, relocation, import, TLS, export, and unwind metadata. It does not use `Process` or Win32 APIs. |
| `pe_map.contracts` | Define memory, module resolution, runtime, and CRT contracts. `MapHost` composes these roles for one address space. |
| `pe_map.loader` | Apply an `ImagePlan` through a `MapHost` and own the loaded image's lifecycle. It has no direct `Process` or Win32 calls. |
| `pe_map.process` | Provide the implemented `Process.current` host and a convenient `load` entry point. |

The public loader accepts bytes, not a path. It does not create a temporary DLL file. Any network cache, logging, or payload authentication belongs to the caller. Code running on a client remains inspectable in memory, including through a full process dump.

## Installation tiers

| Tier | Behavior | Rejected requirements |
| --- | --- | --- |
| `MINIMAL` | Copy headers and sections, apply base relocations, resolve ordinary imports, set page protections, call the DLL entry, cache exports, and detach/free on unload. | TLS, exception table, delay imports, and load configuration. |
| `RUNTIME` | Add TLS callback invocation for process attach/detach, x64 function-table registration, eager delay-import resolution, dependency lifetime hooks, and rollback. | Static TLS templates and zero-fill, CFG, and unsupported image features. |
| `STRICT` | Apply RUNTIME behavior with an additional requirement for a complete TLS thread lifecycle. | Any TLS directory with the shipped local host, plus all RUNTIME rejections. |

All tiers require an AMD64 DLL with page-aligned sections. The loader rejects CLR images, writable/executable sections, CFG images, unsupported relocations, and a rebase without relocations. The local resolver uses `Process.get_proc_address` and requires imported modules to be loaded already. It does not add the mapped image to the Windows loader's module registry; APIs that depend on that registration, such as normal module enumeration and some resource lookups, may not work. `STRICT` is a stricter known-feature gate, not equivalence to `LdrLoadDll`.

The local `RUNTIME` host invokes TLS process callbacks but does not install PE static TLS data or send thread attach/detach notifications. `TlsAlloc` slots are a separate mechanism from the loader's static TLS array; a DLL using `__declspec(thread)` or `thread_local` needs a different runtime host. `IImageRuntime.prepare_tls` and its capability flags reserve that integration point. Delay imports are resolved eagerly, rather than using the compiler's lazy helper.

## Pure planning and other hosts

```python
from nylib.winutils.pe_map import build_plan, parse_image

parsed = parse_image(payload)
plan = build_plan(parsed, target_base=0x180000000)
```

`parse_image` returns metadata and a SHA-256 fingerprint, without retaining the payload bytes. `build_plan` computes relocation deltas after a target base is known. Both calls have no process side effects and can be used independently of the current-process adapter. `PEFormatError` reports malformed input; `UnsupportedImageError` reports a feature the implementation cannot handle.

An alternative target can implement the protocols in `pe_map.contracts` and pass a `MapHost` to `pe_map.loader.load`:

```python
from nylib.winutils.pe_map.contracts import MapHost
from nylib.winutils.pe_map.loader import InstallTier, load

host = MapHost(memory=my_memory, modules=my_modules, runtime=my_runtime, machine=0x8664)
loaded = load(payload, host=host, tier=InstallTier.RUNTIME)
```

The memory, resolver, and runtime components must address the same target. `IImageMemory.alloc` must return a zero-filled writable region; it also owns read/write, protection, and instruction-cache operations. `IModuleResolver.acquire` returns a token for a dependency; `resolve` and `base` use that token, and `release` runs during rollback or unload. `IImageRuntime` owns function invocation, TLS preparation/release, and unwind-table registration. Its `supports_static_tls` and `supports_tls_thread_lifecycle` flags gate images before allocation. No other host implementation ships in this package yet.

## CRT extension

The default `NoopCrtGlue` performs no extra work. A normal MSVC DLL entry (`_DllMainCRTStartup`) handles its own CRT initialization. A DLL linked with a custom entry or other compiler/runtime requirements can supply `ICrtGlue`:

```python
class MyCrtGlue:
    def __init__(self, initialize, finalize):
        self.initialize = initialize
        self.finalize = finalize

    def prepare(self, plan):
        return self.initialize(plan.target_base)

    def cleanup(self, plan, token):
        self.finalize(plan.target_base, token)

loaded = load(payload, crt_glue=MyCrtGlue(my_compiler_init, my_compiler_fini))
```

`prepare` runs after layout, relocations, imports, protections, and unwind registration; `cleanup` runs during unload or rollback after a completed `prepare`. The caller must know the DLL's actual compiler and entry-point contract. The loader does not infer or call CRT internals from PE metadata.

## Local validation

The ignored `.ignore/pe_map/` directory holds the C fixture sources, fixture builder, and `unittest` script. With MSVC available, run from the repository root:

```powershell
cd .ignore\pe_map
..\..\.venv\Scripts\python.exe -m unittest -v test_pe_map
```

The tests build the DLLs, map them using `Process.current`, verify attach/export/detach, TLS callbacks and unwind registration, eager delay imports, static TLS rejection, and a simulated host at a nonpreferred base. The generated DLLs remain in `.ignore/pe_map/` and are not package artifacts.
