# nylib.utils

Collection of utilities for pip package management, CPU instruction assembly, event loops, HTTP downloads, and script packing.

Keywords: pip, install, package, keystone, capstone, assemble, disassemble, event loop, schedule, thread, async call, download, web, pack, archive, delegate, enum, mutex, template

## Quick start

Choose by task: lazy package install, CPU assembly, scheduled events, or downloads.

```python
# needs: installs packages on first call
from nylib.utils import pip, ks_asm, eventloop
if pip.required('requests'):
    import requests
bytecode = ks_asm.comp(b'mov rax, rbx', 0x1000)
loop = eventloop.EventLoop()
h = loop.create_event(print, args=('hi',), delay=1.0, repeat=True)
```

## Lazy pip install

Install packages on first use if missing, or test presence without side effects.

```python
# needs: changes pip configuration and installs packages
from nylib.utils import pip
if pip.required('numpy', 'requests'):
    import numpy as np
    import requests
```

Check if packages are installed:

```python
from nylib.utils import pip

installed = pip.is_installed('pytest', 'black')
```

## Assemble and disassemble CPU code

Use Keystone (Intel/ARM assembly) and Capstone (disassembly) for x86, x64, ARM, and other ISAs.

```python
from nylib.utils import ks_asm

# Assemble with address and label resolves
bytecode = ks_asm.comp(b'mov rax, 42\nret', address=0x1000)

# Resolve labels and relocations
resolved = ks_asm.comp(
    b'jmp target\ndata: .byte 1\ntarget: nop',
    address=0x0,
    resolves={'target': 0x3}
)
```

## Event loops and async calls

Schedule events with delay and repetition, or manage concurrent calls.

```python
from nylib.utils.eventloop import EventLoop
import time

loop = EventLoop()
h = loop.create_event(print, args=('tick',), delay=1.0, repeat=True)
time.sleep(3)
loop.cancel_event(h)
loop.terminate()
```

Wait for a result in a background thread:

```python
from nylib.utils.threading_ import ResEvent
import threading

event = ResEvent()
t = threading.Thread(target=lambda: event.set(42))
t.start()
result = event.wait(timeout=5)
```

Manage multiple async calls:

```python
from nylib.utils.async_call import AsyncCallManager

mgr = AsyncCallManager()
mgr.call('job1', int, '42')
result = mgr.get_result('job1')
```

## Download files

Download with optional progress and automatic temp-file cleanup on error.

```python
# needs: requires network access
from nylib.utils import web
web.download('https://example.com/file.zip', '/tmp/file.zip', show_progress=True)
```

## Pack scripts

Compress Python files or packages into self-extracting code.

```python
# needs: requires actual script/package files
from nylib.utils import pkg_archive
packed = pkg_archive.pack('script.py', is_main=True)
packed = pkg_archive.pack('pkg/', is_main=True, package_name='myapp')
```

## Other utilities

| Module | Purpose | Main class/function |
|--------|---------|---|
| `delegate` | Event handler pattern, single or grouped | `Delegate`, `GroupDelegate` |
| `enum` | Enum helpers for fallback on missing values | `missing()`, `auto_missing()` |
| `handles` | Allocate and free integer handles | `Handles.get()`, `.free()` |
| `mutex` | Cross-process file-based lock | `Mutex(__enter__, __exit__)` |
| `preprocessor` | Compile-time macro and conditional code processor | `IProcessors` |
| `prime` | Prime testing and generation | `miller_rabin()`, utilities |
| `simple` | Alignment helpers, thread-safe counter | `aligned4/8/16()`, `Counter` |
| `template` | Function template parameters (thread-local) | `@template`, `template_args` |
| `tmp_file_writer` | Atomic file writes with temp file and rollback | `TmpFileWritter` |
| `yaml2json` | Convert YAML to JSON | `parse()` |

## Notes

- `pip.required()` sets pip's default index on first call; order matters with mirror lists.
- `ks_asm` (Keystone/Capstone) is pre-installed; no `# needs:` marker required.
- Call `eventloop.EventLoop.terminate()` before exit; events run in daemon threads.
- `web.download()` blocks; wrap with `AsyncCallManager` for non-blocking use.
- `pkg_archive.pack()` supports bytecode transforms via the `o=` parameter.
