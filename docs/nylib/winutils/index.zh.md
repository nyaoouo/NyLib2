> 本文档为 index.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="index.md" -->

<!-- dt:section id="__preamble__" hash="7e3364c2d3a7" -->
# nylib.winutils

Windows 工具库：进程枚举、PE 检查与映射、管道、RPC、驱动程序、内联挂钩和工具链管理。

关键词: process, version, PE, PE exports, PE unmap, PE map, memory DLL, pipe, RPC, IPC, driver, service, MSVC, toolchain, inline hook, vtable hook, call queue, PDB, Win32

<!-- dt:section id="quick-start-0" hash="6289afa907c8" -->
## 快速开始

直接从 `nylib.winutils` 导入；子包 `breakpoint`、`sign`、`python_loader`、`python_hijack` 和 `pe_map`，以及 `inline_call` 调用队列，有各自的页面。

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

<!-- dt:section id="process-0" hash="7399ec5393f0" -->
## 进程

枚举进程、启用 SeDebugPrivilege、提升到管理员。

```python
from nylib.winutils import iter_processes, enable_privilege

for p in iter_processes():
    print(f'{p.th32ProcessID} {p.szExeFile.decode()}')
enable_privilege()
```

<!-- dt:section id="version-0" hash="efc5ef3f27ad" -->
## 版本

读取 PE 版本资源和 Shell 属性存储（资源管理器详情选项卡）。

```python
from nylib.winutils.version import get_file_version_info, get_file_properties

info = get_file_version_info('C:/Windows/System32/user32.dll')
props = get_file_properties('C:/Windows/notepad.exe', key_style='canonical')
```

<!-- dt:section id="pe-exports-0" hash="23b531c05097" -->
## PE 导出表

通过 `Process.enum_exports(dll)` 读取导出表。使用 `ExportTable(process, base)` 进行远程或细粒度访问。

```python
from nylib.process import Process

exports = list(Process.current.enum_exports('kernel32.dll'))[:5]
for exp in exports:
    print(f'{exp.name} {hex(exp.address)}')
```

<!-- dt:section id="pe-unmap-0" hash="0e4ed52187ac" -->
## PE 解映射

将内存中的 PE 镜像（完整的 `SizeOfImage`）转换为磁盘布局；仅限 64 位。

```python
# needs: memory dump of a PE image
from nylib.winutils.pe_unmap import pe_unmap
disk = pe_unmap(memory)
if disk:
    with open('out.exe', 'wb') as f:
        f.write(disk)
```

<!-- dt:section id="pe-map-0" hash="96779ead3014" -->
## PE 映射

验证 DLL 字节并将 AMD64 DLL 映射到当前进程或另一个 `Process`。解析器和 Host 契约与两种 Process 适配器分离。安装层次、目标要求和限制详见 [pe_map.zh.md](pe_map.zh.md)。

```python
# needs: the bytes of an AMD64 DLL that exports add
from nylib.process import Process
from nylib.winutils.pe_map.process import InstallTier, load

with load(dll_bytes, tier=InstallTier.RUNTIME) as image:
    result = image.call_export('add', 3, 4)
```

```python
# needs: an initialized AMD64 target with the DLL's imports already loaded
target = Process(child_pid)
try:
    with load(dll_bytes, process=target, tier=InstallTier.RUNTIME) as image:
        result = target.call(image.get_export('add'), 3, 4)
finally:
    target.close()
```

<!-- dt:section id="pipe-0" hash="9c6a28213099" -->
## 管道

命名管道：具有重叠 I/O 的服务器/客户端处理程序。

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

<!-- dt:section id="pipe-rpc-0" hash="3f7f1fe25c1c" -->
## 管道 RPC

通过命名管道的 Pickle RPC；服务器发布可调用对象，客户端使用本地语法调用。

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

<!-- dt:section id="driver-0" hash="1b86dbca5567" -->
## 驱动程序

服务管理和内核驱动程序加载。

```python
# needs: admin mode, .sys driver
from nylib.winutils.driver import DrvLoader
loader = DrvLoader.open('C:\\driver.sys', 'MyDriver', 'My Driver')
loader.close()
```

<!-- dt:section id="msvc-0" hash="09598d2e860a" -->
## MSVC

定位 MSVC 并加载编译器环境。

```python
# needs: MSVC or Build Tools installed
from nylib.winutils.msvc import msvc14_find_vc2017, load_vcvarsall
ver, path = msvc14_find_vc2017()
if path:
    env = load_vcvarsall('x86_amd64')
```

<!-- dt:section id="ensure-env-0" hash="a42fc264ed5e" -->
## 确保环境

按需下载并安装工具链。

```python
# needs: internet, admin mode
from nylib.winutils.ensure_env import ensure_git, ensure_cmake
git = ensure_git()
cmake = ensure_cmake()
```

<!-- dt:section id="llvm-pdb-0" hash="364576325fe6" -->
## LLVM PDB

通过 LLVM pdbutil 解析 PDB 文件。

```python
# needs: llvm-pdbutil.exe, .pdb, PyYAML
from nylib.winutils.llvm_pdb import get_pdb_data
import pathlib
pdb = get_pdb_data(pathlib.Path('cache'), pathlib.Path('pdbutil'), pathlib.Path('debug.pdb'))
```

<!-- dt:section id="inline-hook-0" hash="197f0e6bc00e" -->
## 内联挂钩

使用 capstone/keystone 的内联代码挂钩。

```python
# needs: target process, capstone, keystone
from nylib.winutils.inline_hook import InlineHook
hook = InlineHook(p, b'\\x90\\x90', addr=0x401000)
hook.enabled = True
```

<!-- dt:section id="vtable-hook-0" hash="81551d9403a4" -->
## 虚表挂钩

替换虚函数指针，运行挂钩代码，然后跳转到原始函数。

```python
# needs: target process with a vtable
from nylib.winutils.vtable_hook import VTableHook
hook = VTableHook(p, b'\x90', addr=vtable_at + index * 8)
hook.enabled = True
hook.free()
```

请在通过该槽位的调用处于静止状态时安装和释放它。该槽位必须 8 字节对齐。

对于任一类挂钩的批量调用，参见 [inline_call.md](inline_call.md)。

<!-- dt:section id="notes-0" hash="7df787cad56e" -->
## 注意

- `iter_processes()` 通过 ToolHelp32 API 枚举本地进程。
- `enable_privilege()` 尝试启用 `SeDebugPrivilege`；无声地成功或失败。
- `run_admin()` 如果还不是管理员，则通过 `ShellExecuteW("runas")` 重新启动，然后抛出异常。
- `read_exports(base)` 仅读取此进程且不抛出异常；改用 `Process.enum_exports(dll)`。
- `ExportTable(process, base)` 通过 `ReadProcessMemory` 在任何进程上工作。
- 命名管道仅限本地每台机器。
- 各自的页面：[breakpoint.md](breakpoint.md)、[sign.md](sign.md)、[python_loader.md](python_loader.md)、[python_hijack.md](python_hijack.md)、[pe_map.zh.md](pe_map.zh.md)、[inline_call.md](inline_call.md)。
