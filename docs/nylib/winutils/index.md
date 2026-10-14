# nylib.winutils

Windows utilities: process enumeration, PE inspection and mapping, pipes, RPC, drivers, inline hooks, and toolchain management.

Keywords: process, version, PE, PE exports, PE unmap, PE map, memory DLL, pipe, RPC, IPC, driver, service, MSVC, toolchain, inline hook, PDB, Win32

## Quick start

Import directly from `nylib.winutils`; subpackages `breakpoint`, `sign`, `python_loader`, `python_hijack`, and `pe_map` have their own pages.

```python
from nylib.winutils import iter_processes
from nylib.winutils.version import get_file_version_info
from nylib.process import Process

for proc in iter_processes():
    if proc.szExeFile == b'explorer.exe':
        print(proc.th32ProcessID)

info = get_file_version_info('C:/Windows/System32/kernel32.dll')
exports = list(Process.current.enum_exports('kernel32.dll'))[:3]
```

## Process

Enumerate processes, enable SeDebugPrivilege, elevate to admin.

```python
from nylib.winutils import iter_processes, enable_privilege

for p in iter_processes():
    print(f'{p.th32ProcessID} {p.szExeFile.decode()}')
enable_privilege()
```

## Version

Read PE version resource and Shell Property Store (Explorer Details tab).

```python
from nylib.winutils.version import get_file_version_info, get_file_properties

info = get_file_version_info('C:/Windows/System32/user32.dll')
props = get_file_properties('C:/Windows/notepad.exe', key_style='canonical')
```

## PE Exports

Read export tables via `Process.enum_exports(dll)`. Use `ExportTable(process, base)` for remote or fine-grained access.

```python
from nylib.process import Process

exports = list(Process.current.enum_exports('kernel32.dll'))[:5]
for exp in exports:
    print(f'{exp.name} {hex(exp.address)}')
```

## PE Unmap

Convert in-memory PE image (full `SizeOfImage`) to on-disk layout; 64-bit only.

```python
# needs: memory dump of a PE image
from nylib.winutils.pe_unmap import pe_unmap
disk = pe_unmap(memory)
if disk:
    with open('out.exe', 'wb') as f:
        f.write(disk)
```

## PE Map

Validate and map an AMD64 DLL from bytes in the current process or another `Process`. The parser and host contracts are separate from both Process adapters. See [pe_map.md](pe_map.md) for installation tiers, target requirements, and limitations.

```python
from nylib.process import Process
from nylib.winutils.pe_map.process import InstallTier, load

with load(dll_bytes, tier=InstallTier.RUNTIME) as image:
    result = image.call_export('add', 3, 4)

# needs: an initialized AMD64 target with the DLL's imports already loaded
target = Process(child_pid)
try:
    with load(dll_bytes, process=target, tier=InstallTier.RUNTIME) as image:
        result = target.call(image.get_export('add'), 3, 4)
finally:
    target.close()
```

## Pipe

Named pipes: server/client handlers with overlapped I/O.

```python
# needs: full server/client lifecycle
from nylib.winutils.pipe import PipeServer, PipeServerHandler, PipeClient

class Echo(PipeServerHandler):
    def on_data_received(self, data):
        self.send(b'echo: ' + data)

server = PipeServer(r'\\.\pipe\test', handler_class=Echo)
client = PipeClient(r'\\.\pipe\test')
client.connect()
client.send(b'hello')
```

## Pipe RPC

Pickle RPC over named pipes; server publishes callables, client calls with local syntax.

```python
# needs: full server/client lifecycle
from nylib.winutils.pipe_rpc import RpcServer, RpcClient

def add(a, b):
    return a + b

server = RpcServer(r'\\.\pipe\rpc', {'add': add})
client = RpcClient(r'\\.\pipe\rpc')
client.connect()
result = client.rpc.add(2, 3)
```

## Driver

Service management and kernel driver loading.

```python
# needs: admin mode, .sys driver
from nylib.winutils.driver import DrvLoader
loader = DrvLoader.open('C:\\driver.sys', 'MyDriver', 'My Driver')
loader.close()
```

## MSVC

Locate MSVC and load compiler environment.

```python
# needs: MSVC or Build Tools installed
from nylib.winutils.msvc import msvc14_find_vc2017, load_vcvarsall
ver, path = msvc14_find_vc2017()
if path:
    env = load_vcvarsall('x86_amd64')
```

## Ensure Env

Download and install toolchains on demand.

```python
# needs: internet, admin mode
from nylib.winutils.ensure_env import ensure_git, ensure_cmake
git = ensure_git()
cmake = ensure_cmake()
```

## LLVM PDB

Parse PDB files via LLVM pdbutil.

```python
# needs: llvm-pdbutil.exe, .pdb, PyYAML
from nylib.winutils.llvm_pdb import get_pdb_data
import pathlib
pdb = get_pdb_data(pathlib.Path('cache'), pathlib.Path('pdbutil'), pathlib.Path('debug.pdb'))
```

## Inline Hook

Inline code hooks with capstone/keystone.

```python
# needs: target process, capstone, keystone
from nylib.winutils.inline_hook import InlineHook
hook = InlineHook(p, b'\\x90\\x90', addr=0x401000)
hook.enabled = True
```

## Notes

- `iter_processes()` enumerates local processes via ToolHelp32 API.
- `enable_privilege()` tries to enable `SeDebugPrivilege`; silently succeeds or fails.
- `run_admin()` re-launches via `ShellExecuteW("runas")` if not already admin, then raises.
- `read_exports(base)` reads only this process and never raises; use `Process.enum_exports(dll)` instead.
- `ExportTable(process, base)` works on any process via `ReadProcessMemory`.
- Named pipes are local per-machine only.
- Subpackages: [breakpoint.md](breakpoint.md), [sign.md](sign.md), [python_loader.md](python_loader.md), [python_hijack.md](python_hijack.md), [pe_map.md](pe_map.md).

