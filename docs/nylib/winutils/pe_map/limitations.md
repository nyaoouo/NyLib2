# Limitations and validation

## Known limitations

| Area | Current behavior and impact |
| --- | --- |
| Dependency loading | Both Process hosts resolve imports only from modules already loaded in the target. They do not call `LoadLibrary` or own dependency reference counts. |
| Loader integration | The image is absent from the Windows loader module list. Module lookup, resource access, loader notifications, and code assuming a native `HMODULE` may fail. |
| TLS | Local mapping supports process callbacks only, without static TLS or thread callbacks. Remote mapping rejects every TLS directory. |
| Runtime features | CLR, CFG, executable/writable sections, subpage section alignment, EXEs, non-AMD64 execution, and unsupported relocation forms are rejected. `STRICT` is not native-loader equivalence. |
| Load configuration | Core records the security-cookie address and GuardFlags, but does not handle all loader-managed load-configuration fields. An image may pass this gate and still fail at runtime. |
| Image gaps | Whole pages in alignment gaps outside protected header/section ranges retain the allocation's initial writable protection. |
| Custom CRT | `ICrtGlue` methods run in the caller's Python process. Remote helpers must explicitly address the target. |
| Calls and unloading | Remote `Process.call` creates a new target thread per call. Attach does not hold the Windows loader lock; calls may hang. The caller must keep the target alive and ensure no thread executes mapped code during unload. |
| Partial cleanup | Detach, unwind unregister, dependency release, or free can fail after other cleanup steps. Unload is not a retryable transaction. A [block discard failure](retention.md) separately leaves an active image in its exception. |
| Mutable input | A fingerprint is checked before copying, but another thread can mutate a `bytearray` or writable `memoryview` during the copy. Supply stable immutable `bytes`. |
| Payload secrecy | No DLL file is created here, but mapped code and data remain readable from process memory or a full dump. Authentication and dump policy belong to the caller. |

Remote tests prove imports, attach, export calls, unwind registration return values, relocation at a nonpreferred base, post-attach header and relocation-block discard, and unload in a child Notepad. A separate 32-bit `cmd.exe` test proves the WOW64 gate. Remote exception unwinding, TLS-capable hosts, alternate compilers, and target termination during mapping or unload remain unverified.

## Validation

Ignored fixture sources, builders, and tests live under `.ignore/pe_map/`, not `scripts/`. With MSVC available, run from that directory:

```powershell
..\..\.venv\Scripts\python.exe -m unittest -v test_pe_map
..\..\.venv\Scripts\python.exe test_remote_notepad.py
..\..\.venv\Scripts\python.exe test_wow64_gate.py
```

The local C fixtures exercise attach, exports, detach, TLS callbacks, unwind lookup, eager delay imports, forwarders, static TLS rejection, and header/relocation-block discard. A simulated host checks rebase, rollback, callback ordering, gate rejection, and partial discard failure. The remote test starts and terminates its own Notepad child, changes and restores its title through `Process.call`, checks discard and unload, and leaves generated DLL binaries ignored.
