# Post-attach block discard

`on_block=` is an optional Python callback invoked after TLS process callbacks and the DLL entry have returned. It receives the final `ImagePlan` and each `MappedBlock`: one `headers` block followed by one `section` block per PE section. A block has `kind`, `name`, `index`, image-relative `rva`, page-aligned `size`, absolute `address`, and the `SectionPlan` where applicable. Raising `SectSkip` requests that block's pages be decommitted.

```python
from nylib.winutils.pe_map import SectSkip
from nylib.winutils.pe_map.process import load

def on_block(plan, block):
    if block.kind == 'section' and block.name == '.reloc':
        raise SectSkip()

with load(payload, on_block=on_block) as image:
    print([block.name for block in image.discarded_blocks])
```

Core still parses and validates every section, and the loader copies all of them for initialization. The loader gathers every `SectSkip` request before changing memory, then rejects blocks that overlap known required entry, direct export, IAT, TLS, unwind, or security-cookie locations. Each requested block must occupy complete pages inside the allocation. The Process hosts use `Process.free(address, size)` to decommit them. `LoadedImage.discarded_blocks` records successful operations; its cached metadata permits mapper-owned unload without rereading the headers.

The check cannot prove that a DLL will never again read a header, resource, constant, or other data in a requested block. Declare blocks only for a payload whose runtime and detach behavior you control and have verified. A block sharing a page with a known required location is rejected; other runtime references cannot be inferred. The callback runs in Python; a target DLL called through `Process.call` cannot raise `SectSkip` across the process boundary. Other callback exceptions propagate and trigger the normal load rollback before any discard occurs.

`BlockDiscardError` means a host operation failed after attach. It carries `loaded` and `block`; `loaded` remains active because earlier blocks or part of the failing block may already have been decommitted. The caller must decide how to handle that partial state and eventually call `loaded.unload()` when safe. A custom host without `discarder=` rejects `SectSkip` requests before decommitting anything.

Block discard does not erase the caller's original payload buffer and does not conceal runtime code or data from a memory dump. It is independent of `InstallTier`; the default keeps every block.
