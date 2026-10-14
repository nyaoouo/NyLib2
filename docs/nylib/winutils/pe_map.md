# nylib.winutils.pe_map

Map an AMD64 DLL from verified PE bytes into the current process or a selected `Process`.

Keywords: PE, manual mapping, memory DLL, Process.current, remote Process, InstallTier, SectSkip

```python
from nylib.winutils.pe_map.process import InstallTier, load

# Supply verified DLL bytes; this API does not take a file path.
with load(payload, tier=InstallTier.RUNTIME) as image:
    result = image.call_export('add', 3, 4)
```

The parser stays independent of process access. The loader uses a `MapHost` for memory, imports, calls, TLS, and unwind registration; `pe_map.process` supplies local and remote Process hosts.

- [Loading and installation tiers](pe_map/loading.md): local and remote use, supported DLL features, exports, and unload.
- [Core and host contracts](pe_map/hosts.md): pure planning, alternate hosts, and custom CRT initialization.
- [Post-attach block discard](pe_map/retention.md): opt-in `SectSkip` callbacks for mapped headers and sections.
- [Limitations and validation](pe_map/limitations.md): unsupported features, remaining risks, and fixture commands.

The API avoids creating a DLL file. Code and data required at runtime remain readable from the target process, including in a full memory dump.
