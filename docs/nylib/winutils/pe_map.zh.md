> 本文档为 pe_map.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="pe_map.md" -->

<!-- dt:section id="__preamble__" hash="651ad5d81546" -->
# nylib.winutils.pe_map

从 PE 文件字节将 AMD64 DLL 映射到当前进程或指定的远程 `Process`。

关键词: PE, manual mapping, DLL, memory loading, Process.current, remote Process, relocations, imports, TLS, x64 unwind, delay imports, exports

<!-- dt:section id="quick-start-0" hash="8e4f27e2c9e2" -->
## 快速开始

加载到当前进程：

```python
from nylib.winutils.pe_map.process import InstallTier, load

# needs: verified AMD64 DLL bytes supplied by the caller
payload = obtain_and_verify_dll_bytes()
with load(payload, tier=InstallTier.RUNTIME) as image:
    address = image.get_export('add')
    result = image.call_export('add', 3, 4)
```

加载到调用方持有的 AMD64 进程，其中所需的导入模块已经加载：

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

`load(payload)` 使用 `Process.current`；`load(payload, process=target)` 则构造 `RemoteProcessHost`。也可以自行构造 `LocalProcessHost` 或 `RemoteProcessHost` 并通过 `host=` 传入。`process=` 和 `host=` 只能选一个。目标进程句柄由调用方持有，必须保持打开直到 `unload()` 完成。

`get_export` 接受名称或序号，返回缓存的绝对地址，也支持已解析的转发导出。`call_export` 委托所选 Host 的 `Process.call`，适合简单的整数和指针参数。对远程镜像应传入远程地址，或使用 `Process.call` 的字节参数功能；不能把远程地址在调用方进程中转成 `ctypes` 函数。仅对于当前进程的镜像，需要精确 C 函数签名的调用方可以使用 `ctypes`。在 `unload()` 后调用导出函数会抛出 `RuntimeError`。

`LoadedImage` 保存 `base`、`size`、`entry_point`、已解析的导出地址、TLS 回调地址、Host 引用、依赖项令牌、TLS 状态、异常展开表注册令牌和 CRT 清理状态。`unload()` 使用这些状态，不重新读取源字节，也不重新解析已映射的 PE 头。调用方必须保留仍在使用的函数、TLS 回调和 DLL 入口所需的代码与数据，并确保卸载时没有线程正在该镜像中执行。加载器在安装后不会修改镜像。

<!-- dt:section id="architecture-0" hash="bf4a011f0e7f" -->
## 架构

PE 解析、Host 操作和安装过程彼此分离：

| 模块 | 职责 |
| --- | --- |
| `pe_map.core` | 验证 PE 字节，生成不可变的布局、重定位、导入、TLS、导出和异常展开元数据；不使用 `Process` 或 Win32 API。 |
| `pe_map.contracts` | 定义内存、模块解析、运行时和 CRT 契约；`MapHost` 为同一地址空间组合这些能力。 |
| `pe_map.loader` | 通过 `MapHost` 应用 `ImagePlan`，管理已加载镜像的生命周期；不直接调用 `Process` 或 Win32 API。 |
| `pe_map.process` | 提供本进程及远程 `Process` Host 和便捷的 `load` 入口。 |

公共加载器接受字节，而非文件路径；它不会生成临时 DLL 文件。网络缓存、日志记录和载荷认证由调用方负责。在客户端运行的代码仍可从内存中检查，也可能被完整进程转储获取。

<!-- dt:section id="installation-tiers-0" hash="d7cf7bfdfb7b" -->
## 安装层次

| 层次 | 行为 | 拒绝的需求 |
| --- | --- | --- |
| `MINIMAL` | 复制头和节、应用基址重定位、解析普通导入、设置页保护、调用 DLL 入口、缓存导出，并在卸载时执行分离和释放。 | TLS、异常表、延迟导入和加载配置。 |
| `RUNTIME` | 增加本进程 TLS 附加/分离回调、x64 函数表注册、预先解析延迟导入、依赖项记录和失败回滚。 | 静态 TLS 模板及零填充、CFG 和不支持的镜像特性；远程 Host 还拒绝所有 TLS 目录。 |
| `STRICT` | 执行 RUNTIME 行为，并额外要求完整的 TLS 线程生命周期。 | 两种 Process Host 中的任何 TLS 目录，以及所有 RUNTIME 拒绝项。 |

所有层次都要求 AMD64 DLL 且节按页对齐；远程适配器还会在映射前拒绝 WOW64 目标。加载器会拒绝 CLR 镜像、可写且可执行的节、CFG 镜像、不支持的重定位，以及缺少重定位信息却需要更换基址的镜像。两种 Process Host 都使用 `Process.get_proc_address`，要求被导入的模块已经加载。映射后的镜像不会注册到 Windows 加载器的模块列表；依赖该注册的 API（例如常规模块枚举和部分资源查询）可能不可用。`STRICT` 是更严格的已知特性检查，不等同于 `LdrLoadDll`。

本进程 `RUNTIME` Host 会调用 TLS 的进程回调，但不会安装 PE 静态 TLS 数据，也不会发出线程附加/分离通知。`TlsAlloc` 分配的槽位与加载器管理的静态 TLS 数组是两种不同机制；使用 `__declspec(thread)` 或 `thread_local` 的 DLL 需要另一种运行时 Host。远程 Host 会在分配内存前拒绝整个 TLS 目录，因为 `Process.call` 的各次调用运行在不同的远程线程中。`IImageRuntime.prepare_tls` 及其能力标志为更完整的 Host 预留了接口。延迟导入会预先解析，而不是使用编译器的延迟加载辅助函数。

<!-- dt:section id="pure-planning-and-other-hosts-0" hash="96414dfc0018" -->
## 纯解析、规划与其他 Host

```python
from nylib.winutils.pe_map import build_plan, parse_image

parsed = parse_image(payload)
plan = build_plan(parsed, target_base=0x180000000)
```

`parse_image` 返回元数据和 SHA-256 指纹，不保留载荷字节。`build_plan` 在目标基址已知后计算重定位增量。这两个调用没有进程副作用，可以独立于两种 Process Host 使用。`PEFormatError` 表示输入格式错误；`UnsupportedImageError` 表示实现不支持某个镜像特性。

其他目标可以实现 `pe_map.contracts` 中的协议，并将 `MapHost` 传给 `pe_map.loader.load`：

```python
from nylib.winutils.pe_map.contracts import MapHost
from nylib.winutils.pe_map.loader import InstallTier, load

host = MapHost(memory=my_memory, modules=my_modules, runtime=my_runtime, machine=0x8664)
loaded = load(payload, host=host, tier=InstallTier.RUNTIME)
```

内存、解析器和运行时组件必须面向同一个目标。`IImageMemory.alloc` 必须返回清零且可写的区域，并负责读写、页保护和指令缓存操作。`IModuleResolver.acquire` 为依赖项返回令牌；`resolve` 和 `base` 使用该令牌，`release` 在回滚或卸载时执行。`IImageRuntime` 负责函数调用、TLS 准备/释放，以及异常展开表注册。其 `supports_tls_process_callbacks`、`supports_static_tls` 和 `supports_tls_thread_lifecycle` 标志在分配内存前用于检查镜像。包内提供本进程及远程 Process Host；其他目标仍可实现相同契约。

<!-- dt:section id="crt-extension-0" hash="74a9fa4a04a3" -->
## CRT 扩展接口

默认的 `NoopCrtGlue` 不执行额外操作。普通 MSVC DLL 的入口 `_DllMainCRTStartup` 会自行初始化 CRT。使用自定义入口或有其他编译器/运行时要求的 DLL 可以提供 `ICrtGlue`：

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

`prepare` 在布局、重定位、导入、页保护和异常展开表注册之后执行；成功执行 `prepare` 后，`cleanup` 会在卸载或回滚期间执行。调用方必须了解 DLL 实际使用的编译器和入口契约。加载器不会仅凭 PE 元数据推断或调用 CRT 内部函数。

<!-- dt:section id="known-limitations-and-unverified-behavior-0" hash="7f26d0a96394" -->
## 已知限制与尚未验证的行为

| 领域 | 当前行为与影响 |
| --- | --- |
| 依赖项加载 | 两种 Process Host 都只能解析目标中已加载模块的导入；不会调用 `LoadLibrary`，也不持有依赖项引用计数。缺少导入模块时映射会失败。 |
| 与系统加载器集成 | 镜像不在 Windows 加载器的模块列表中。模块查找、资源、加载器通知以及假设存在原生 `HMODULE` 的代码可能失败。 |
| TLS | 本进程映射仅支持进程附加/分离回调，不支持静态 TLS 或线程回调。远程映射拒绝所有 TLS 目录，因为每次 `Process.call` 都会创建不同的远程线程。 |
| 运行时特性 | CLR 和 CFG 镜像、可执行且可写的节、小于页的节对齐、EXE、非 AMD64 执行和不支持的重定位形式均会被拒绝。`STRICT` 不等同于原生加载器。 |
| 加载配置 | 解析器会记录安全 Cookie 地址和 GuardFlags，但不会实现其余由系统加载器管理的加载配置特性。不使用 CFG、却依赖这些特性的镜像可能通过当前检查后仍在运行时失败。 |
| 镜像间隙 | 分配初始为可写。最终页保护覆盖头和节；两者都未覆盖的对齐间隙整页仍保持可写。 |
| 自定义 CRT | `ICrtGlue.prepare` 和 `cleanup` 在调用方 Python 进程中运行。远程 CRT 辅助逻辑必须明确使用目标 `Process`；映射器无法推断非标准编译器的初始化方式。 |
| 调用与卸载 | 远程 `Process.call` 每次都会创建目标线程；镜像附加过程不在 Windows 加载器锁下运行。目标代码挂起时，附加、导出调用和分离都可能阻塞。调用方必须保持目标存活，并确保卸载时没有线程执行已映射代码；加载器不能暂停目标线程或恢复已崩溃的进程。 |
| 部分清理 | 分离、注销异常展开表、释放依赖项或释放内存失败后，剩余清理步骤仍会尝试执行并报告错误，但目标中可能留有状态；卸载过程不能作为事务重试。 |
| 可变输入 | 加载器在复制前检查源缓冲区指纹，但无法阻止其他线程在复制过程中修改 `bytearray` 或可写的 `memoryview`。应提供稳定、不可变的 `bytes`。 |
| 载荷保密 | 此 API 不创建 DLL 文件，但映射后的代码与数据仍可从进程内存或完整转储中读取。载荷认证和转储策略由调用方负责。 |

远程测试已在一个 Notepad 子进程中验证导入解析、进程附加、导出调用、x64 函数表注册的返回值、非首选基址重定位和卸载。另一个 32 位 `cmd.exe` 测试验证了 WOW64 限制。远程异常展开、支持 TLS 的 Host、其他编译器，以及映射或卸载期间目标进程退出的情况尚未验证。

<!-- dt:section id="validation-0" hash="e8be6f9b4a05" -->
## 验证

被忽略的 `.ignore/pe_map/` 目录包含 C 测试 DLL 源码、构建器和 `unittest` 脚本。安装 MSVC 后，从仓库根目录运行：

```powershell
cd .ignore\pe_map
..\..\.venv\Scripts\python.exe -m unittest -v test_pe_map
```

测试会构建 DLL，通过 `Process.current` 映射它们，并验证附加、导出调用、分离、TLS 回调、异常展开表注册、预先解析延迟导入、拒绝静态 TLS，以及模拟 Host 在非首选基址的加载。生成的 DLL 留在 `.ignore/pe_map/`，不属于包产物。

被忽略的远程测试脚本会启动并终止自己的 Notepad 子进程，通过 `load(payload, process=target)` 使用库里的 `RemoteProcessHost`，强制映射到非首选基址，用 `Process.call` 修改窗口标题并返回旧标题，然后恢复标题并检查卸载：

```powershell
cd .ignore\pe_map
..\..\.venv\Scripts\python.exe test_remote_notepad.py
..\..\.venv\Scripts\python.exe test_wow64_gate.py
```
