# nylib.winutils.pe_map

Map an AMD64 DLL from PE file bytes into the current process or a selected remote `Process`.

Keywords: PE, manual mapping, DLL, memory loading, Process.current, remote Process, relocations, imports, TLS, x64 unwind, delay imports, exports

## Quick start

Load into the current process:

```python
from nylib.winutils.pe_map.process import InstallTier, load

# needs: verified AMD64 DLL bytes supplied by the caller
payload = obtain_and_verify_dll_bytes()
with load(payload, tier=InstallTier.RUNTIME) as image:
    address = image.get_export('add')
    result = image.call_export('add', 3, 4)
```

Load into a caller-owned AMD64 process whose imports are already available:

```python
from nylib.process import Process
from nylib.winutils.pe_map.process import InstallTier, load

# needs: an initialized target process and verified AMD64 DLL bytes
target = Process(child_pid)
try:
    with load(payload, process=target, tier=InstallTier.RUNTIME) as image:
        address = image.get_export('add')
        result = target.call(address, 3, 4)
finally:
    target.close()
```

`load(payload)` uses `Process.current`; `load(payload, process=target)` constructs a `RemoteProcessHost`. You can also construct `LocalProcessHost` or `RemoteProcessHost` explicitly and pass it as `host=`. Pass either `process=` or `host=`, not both. The caller owns the target process handle and keeps it open through `unload()`.

`get_export` accepts a name or ordinal and returns a cached absolute address, including resolved export forwarders. `call_export` delegates to the selected host's `Process.call` and is suitable for simple integer and pointer arguments. For a remote image, pass remote addresses or use the byte-argument support in `Process.call`; a remote address must not be cast to a local `ctypes` callable. For an image in the current process, callers needing a precise C signature can use the returned address with `ctypes`. Calling an export after `unload()` raises `RuntimeError`.

`LoadedImage` retains `base`, `size`, `entry_point`, resolved export addresses, TLS callback addresses, host references, dependency tokens, TLS state, unwind registration token, and CRT cleanup state. `unload()` uses this state without reopening the source bytes or parsing the mapped headers. The caller must keep code and data needed by active functions, TLS callbacks, and the DLL entry intact, and must ensure no thread is executing in the image when unloading. The loader does not modify an image after installation.

## Architecture

PE parsing, host operations, and installation are separate:

| Module | Responsibility |
| --- | --- |
| `pe_map.core` | Validate PE bytes and produce immutable layout, relocation, import, TLS, export, and unwind metadata. It does not use `Process` or Win32 APIs. |
| `pe_map.contracts` | Define memory, module resolution, runtime, and CRT contracts. `MapHost` composes these roles for one address space. |
| `pe_map.loader` | Apply an `ImagePlan` through a `MapHost` and own the loaded image's lifecycle. It has no direct `Process` or Win32 calls. |
| `pe_map.process` | Provide local and remote `Process` hosts and a convenient `load` entry point. |

The public loader accepts bytes, not a path. It does not create a temporary DLL file. Any network cache, logging, or payload authentication belongs to the caller. Code running on a client remains inspectable in memory, including through a full process dump.

## Installation tiers

| Tier | Behavior | Rejected requirements |
| --- | --- | --- |
| `MINIMAL` | Copy headers and sections, apply base relocations, resolve ordinary imports, set page protections, call the DLL entry, cache exports, and detach/free on unload. | TLS, exception table, delay imports, and load configuration. |
| `RUNTIME` | Add local TLS callback invocation for process attach/detach, x64 function-table registration, eager delay-import resolution, dependency bookkeeping, and rollback. | Static TLS templates and zero-fill, CFG, and unsupported image features; the remote host also rejects every TLS directory. |
| `STRICT` | Apply RUNTIME behavior with an additional requirement for a complete TLS thread lifecycle. | Any TLS directory with either Process host, plus all RUNTIME rejections. |

All tiers require an AMD64 DLL with page-aligned sections; the remote adapter also rejects a WOW64 target before mapping. The loader rejects CLR images, writable/executable sections, CFG images, unsupported relocations, and a rebase without relocations. Both Process hosts use `Process.get_proc_address` and require imported modules to be loaded already. They do not add the mapped image to the Windows loader's module registry; APIs that depend on that registration, such as normal module enumeration and some resource lookups, may not work. `STRICT` is a stricter known-feature gate, not equivalence to `LdrLoadDll`.

The local `RUNTIME` host invokes TLS process callbacks but does not install PE static TLS data or send thread attach/detach notifications. `TlsAlloc` slots are a separate mechanism from the loader's static TLS array; a DLL using `__declspec(thread)` or `thread_local` needs a different runtime host. The remote host rejects the entire TLS directory before allocation because `Process.call` runs calls on separate remote threads. `IImageRuntime.prepare_tls` and its capability flags reserve the integration point for a fuller host. Delay imports are resolved eagerly, rather than using the compiler's lazy helper.

## Pure planning and other hosts

```python
from nylib.winutils.pe_map import build_plan, parse_image

parsed = parse_image(payload)
plan = build_plan(parsed, target_base=0x180000000)
```

`parse_image` returns metadata and a SHA-256 fingerprint, without retaining the payload bytes. `build_plan` computes relocation deltas after a target base is known. Both calls have no process side effects and can be used independently of either Process host. `PEFormatError` reports malformed input; `UnsupportedImageError` reports a feature the implementation cannot handle.

An alternative target can implement the protocols in `pe_map.contracts` and pass a `MapHost` to `pe_map.loader.load`:

```python
from nylib.winutils.pe_map.contracts import MapHost
from nylib.winutils.pe_map.loader import InstallTier, load

host = MapHost(memory=my_memory, modules=my_modules, runtime=my_runtime, machine=0x8664)
loaded = load(payload, host=host, tier=InstallTier.RUNTIME)
```

The memory, resolver, and runtime components must address the same target. `IImageMemory.alloc` must return a zero-filled writable region; it also owns read/write, protection, and instruction-cache operations. `IModuleResolver.acquire` returns a token for a dependency; `resolve` and `base` use that token, and `release` runs during rollback or unload. `IImageRuntime` owns function invocation, TLS preparation/release, and unwind-table registration. Its `supports_tls_process_callbacks`, `supports_static_tls`, and `supports_tls_thread_lifecycle` flags gate images before allocation. The package ships local and remote Process hosts; other targets can implement the same contracts.

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

## Known limitations and unverified behavior

| Area | Current behavior and impact |
| --- | --- |
| Dependency loading | Both Process hosts resolve imports only from modules already loaded in the target. They do not call `LoadLibrary` or own dependency reference counts; a missing import module fails mapping. |
| Loader integration | The image is absent from the Windows loader's module list. Module lookup, resources, loader notifications, and code that assumes a native `HMODULE` may fail. |
| TLS | Local mapping supports process attach/detach callbacks only, without static TLS or thread callbacks. Remote mapping rejects every TLS directory because each `Process.call` uses a separate remote thread. |
| Runtime features | CLR and CFG images, executable/writable sections, subpage section alignment, EXEs, non-AMD64 execution, and unsupported relocation forms are rejected. `STRICT` is not native-loader equivalence. |
| Load configuration | The parser records the security-cookie address and GuardFlags, but does not implement the remaining loader-managed load-configuration features. A non-CFG image with such requirements may pass the current gate and still fail at runtime. |
| Image gaps | Allocation starts writable. Final protections cover headers and section ranges; any whole pages in alignment gaps that neither range covers retain writable protection. |
| Custom CRT | `ICrtGlue.prepare` and `cleanup` run in the calling Python process. A remote CRT helper must explicitly use the target `Process`; the mapper cannot infer a nonstandard compiler's initialization. |
| Calls and unloading | Remote `Process.call` creates a new target thread for each call; image attach does not run under the Windows loader lock. Attach, export calls, and detach can block if target code hangs. The caller must keep the target alive and ensure no thread executes mapped code when unloading; the loader cannot quiesce target threads or recover a crashed process. |
| Partial cleanup | A failure during detach, unwind unregister, dependency release, or free is reported after the remaining cleanup steps, but it can leave target state behind. There is no retryable unload transaction. |
| Mutable input | The loader checks a source-buffer fingerprint before copying, but cannot prevent another thread from changing a `bytearray` or writable `memoryview` during the copy. Supply stable immutable `bytes`. |
| Payload secrecy | No DLL file is created by this API, but mapped code and data can still be read from process memory or a full dump. Payload authentication and dump policy belong to the caller. |

Remote tests prove import resolution, process attach, export calls, x64 function-table registration return values, relocation at a nonpreferred base, and unload on one child Notepad. A separate 32-bit `cmd.exe` test proves the WOW64 gate. Remote exception unwinding, TLS-capable hosts, alternate compilers, and target termination during mapping or unload are unverified.

## Validation

The ignored `.ignore/pe_map/` directory holds the C fixture sources, fixture builder, and `unittest` script. With MSVC available, run from the repository root:

```powershell
cd .ignore\pe_map
..\..\.venv\Scripts\python.exe -m unittest -v test_pe_map
```

The tests build the DLLs, map them using `Process.current`, verify attach/export/detach, TLS callbacks and unwind registration, eager delay imports, static TLS rejection, and a simulated host at a nonpreferred base. The generated DLLs remain in `.ignore/pe_map/` and are not package artifacts.

The ignored remote smoke script launches and terminates its own Notepad child, uses the library's `RemoteProcessHost` through `load(payload, process=target)`, forces a nonpreferred base, changes the window title through `Process.call`, returns the old title, restores it, and checks unload:

```powershell
cd .ignore\pe_map
..\..\.venv\Scripts\python.exe test_remote_notepad.py
..\..\.venv\Scripts\python.exe test_wow64_gate.py
```
