> 本文档为 pe_map.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="pe_map.md" -->

<!-- dt:section id="__preamble__" hash="0645e406e00e" -->
# nylib.winutils.pe_map

从 PE 文件字节在当前进程中映射 AMD64 DLL，并调用其导出函数。

关键词: PE, manual mapping, DLL, memory loading, Process.current, relocations, imports, TLS, x64 unwind, delay imports, exports

<!-- dt:section id="quick-start-0" hash="2a09631d709d" -->
## 快速开始

```python
from nylib.winutils.pe_map.process import InstallTier, load

# needs: verified AMD64 DLL bytes supplied by the caller
payload = obtain_and_verify_dll_bytes()
with load(payload, tier=InstallTier.RUNTIME) as image:
    address = image.get_export('add')
    result = image.call_export('add', 3, 4)
```

`get_export` 接受名称或序号，返回缓存的绝对地址，也支持已解析的转发导出。`call_export` 使用 `Process.current.call`，适合简单的整数和指针参数；如果需要精确的 C 函数签名，可以将返回的地址交给 `ctypes`。在 `unload()` 后调用导出函数会抛出 `RuntimeError`。

`LoadedImage` 保存 `base`、`size`、`entry_point`、已解析的导出地址、TLS 回调地址、Host 引用、依赖项令牌、TLS 状态、异常展开表注册令牌和 CRT 清理状态。`unload()` 使用这些状态，不重新读取源字节，也不重新解析已映射的 PE 头。调用方必须保留仍在使用的函数、TLS 回调和 DLL 入口所需的代码与数据，并确保卸载时没有线程正在该镜像中执行。加载器在安装后不会修改镜像。

<!-- dt:section id="architecture-0" hash="fab6e7689e6a" -->
## 架构

PE 解析、Host 操作和安装过程彼此分离：

| 模块 | 职责 |
| --- | --- |
| `pe_map.core` | 验证 PE 字节，生成不可变的布局、重定位、导入、TLS、导出和异常展开元数据；不使用 `Process` 或 Win32 API。 |
| `pe_map.contracts` | 定义内存、模块解析、运行时和 CRT 契约；`MapHost` 为同一地址空间组合这些能力。 |
| `pe_map.loader` | 通过 `MapHost` 应用 `ImagePlan`，管理已加载镜像的生命周期；不直接调用 `Process` 或 Win32 API。 |
| `pe_map.process` | 提供已实现的 `Process.current` Host 和便捷的 `load` 入口。 |

公共加载器接受字节，而非文件路径；它不会生成临时 DLL 文件。网络缓存、日志记录和载荷认证由调用方负责。在客户端运行的代码仍可从内存中检查，也可能被完整进程转储获取。

<!-- dt:section id="installation-tiers-0" hash="af78d783dd4e" -->
## 安装层次

| 层次 | 行为 | 拒绝的需求 |
| --- | --- | --- |
| `MINIMAL` | 复制头和节、应用基址重定位、解析普通导入、设置页保护、调用 DLL 入口、缓存导出，并在卸载时执行分离和释放。 | TLS、异常表、延迟导入和加载配置。 |
| `RUNTIME` | 增加 TLS 进程附加/分离回调、x64 函数表注册、预先解析延迟导入、依赖项生命周期钩子和失败回滚。 | 静态 TLS 模板及零填充、CFG 和不支持的镜像特性。 |
| `STRICT` | 执行 RUNTIME 行为，并额外要求完整的 TLS 线程生命周期。 | 当前本地 Host 中的任何 TLS 目录，以及所有 RUNTIME 拒绝项。 |

所有层次都要求 AMD64 DLL 且节按页对齐。加载器会拒绝 CLR 镜像、可写且可执行的节、CFG 镜像、不支持的重定位，以及缺少重定位信息却需要更换基址的镜像。本地解析器使用 `Process.get_proc_address`，要求被导入的模块已经加载。映射后的镜像不会注册到 Windows 加载器的模块列表；依赖该注册的 API（例如常规模块枚举和部分资源查询）可能不可用。`STRICT` 是更严格的已知特性检查，不等同于 `LdrLoadDll`。

本地 `RUNTIME` Host 会调用 TLS 的进程回调，但不会安装 PE 静态 TLS 数据，也不会发出线程附加/分离通知。`TlsAlloc` 分配的槽位与加载器管理的静态 TLS 数组是两种不同机制；使用 `__declspec(thread)` 或 `thread_local` 的 DLL 需要另一种运行时 Host。`IImageRuntime.prepare_tls` 及其能力标志为此预留了接口。延迟导入会预先解析，而不是使用编译器的延迟加载辅助函数。

<!-- dt:section id="pure-planning-and-other-hosts-0" hash="1ddc912b8e9d" -->
## 纯解析、规划与其他 Host

```python
from nylib.winutils.pe_map import build_plan, parse_image

parsed = parse_image(payload)
plan = build_plan(parsed, target_base=0x180000000)
```

`parse_image` 返回元数据和 SHA-256 指纹，不保留载荷字节。`build_plan` 在目标基址已知后计算重定位增量。这两个调用没有进程副作用，可以独立于当前进程适配器使用。`PEFormatError` 表示输入格式错误；`UnsupportedImageError` 表示实现不支持某个镜像特性。

其他目标可以实现 `pe_map.contracts` 中的协议，并将 `MapHost` 传给 `pe_map.loader.load`：

```python
from nylib.winutils.pe_map.contracts import MapHost
from nylib.winutils.pe_map.loader import InstallTier, load

host = MapHost(memory=my_memory, modules=my_modules, runtime=my_runtime, machine=0x8664)
loaded = load(payload, host=host, tier=InstallTier.RUNTIME)
```

内存、解析器和运行时组件必须面向同一个目标。`IImageMemory.alloc` 必须返回清零且可写的区域，并负责读写、页保护和指令缓存操作。`IModuleResolver.acquire` 为依赖项返回令牌；`resolve` 和 `base` 使用该令牌，`release` 在回滚或卸载时执行。`IImageRuntime` 负责函数调用、TLS 准备/释放，以及异常展开表注册。其 `supports_static_tls` 和 `supports_tls_thread_lifecycle` 标志在分配内存前用于检查镜像。此包暂未提供其他 Host 实现。

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

<!-- dt:section id="local-validation-0" hash="f2b1d5bdf5dc" -->
## 本地验证

被忽略的 `.ignore/pe_map/` 目录包含 C 测试 DLL 源码、构建器和 `unittest` 脚本。安装 MSVC 后，从仓库根目录运行：

```powershell
cd .ignore\pe_map
..\..\.venv\Scripts\python.exe -m unittest -v test_pe_map
```

测试会构建 DLL，通过 `Process.current` 映射它们，并验证附加、导出调用、分离、TLS 回调、异常展开表注册、预先解析延迟导入、拒绝静态 TLS，以及模拟 Host 在非首选基址的加载。生成的 DLL 留在 `.ignore/pe_map/`，不属于包产物。
