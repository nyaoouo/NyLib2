> 本文档为 hosts.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="hosts.md" -->

<!-- dt:section id="__preamble__" hash="80e6a883b63e" -->
# Core 与 Host 契约

<!-- dt:section id="architecture-0" hash="f6cd1e56f333" -->
## 架构

| 模块 | 职责 |
| --- | --- |
| `pe_map.core` | 验证 PE 字节并生成不可变的布局、重定位、导入、TLS、导出和异常展开元数据；不调用 `Process` 或 Win32。 |
| `pe_map.contracts` | 定义内存、模块解析、运行时、可选的块抛弃及 CRT 职责；`MapHost` 组合一个地址空间的能力。 |
| `pe_map.loader` | 应用 `ImagePlan`、调用回调并管理镜像生命周期；不直接调用 `Process` 或 Win32。 |
| `pe_map.process` | 将 `Process.current` 或远程 `Process` 适配成 Host。 |

公共加载器接受字节，不接受文件路径，也不创建临时 DLL 文件。载荷交付、缓存、日志及认证由调用方负责。

<!-- dt:section id="pure-planning-and-alternate-hosts-0" hash="398a554416f1" -->
## 纯规划与其他 Host

```python
from nylib.winutils.pe_map import build_plan, parse_image

parsed = parse_image(payload)
plan = build_plan(parsed, target_base=0x180000000)
```

`parse_image` 返回元数据和 SHA-256 指纹，不保留载荷字节。`build_plan` 在目标基址确定后计算重定位增量。两者都不访问进程。`PEFormatError` 表示格式错误；`UnsupportedImageError` 表示实现不支持某个特性。

其他地址空间可实现 `pe_map.contracts` 的协议：

```python
from nylib.winutils.pe_map.contracts import MapHost
from nylib.winutils.pe_map.loader import InstallTier, load

host = MapHost(memory=my_memory, modules=my_modules, runtime=my_runtime, machine=0x8664)
loaded = load(payload, host=host, tier=InstallTier.RUNTIME)
```

内存、解析器和运行时职责必须面向同一个地址空间。`IImageMemory.alloc` 返回清零且可写的区域，并负责读写、页保护和指令缓存。`IModuleResolver.acquire` 返回供 `resolve`、`base` 和 `release` 使用的依赖项令牌。`IImageRuntime` 负责调用、TLS 和异常展开注册；能力标志在内存分配前拒绝不支持的 TLS。

若使用可选的[块抛弃](retention.zh.md)，可把 `IImageDiscard` 作为 `MapHost` 的第五个参数或 `discarder=` 传入；它在附加后反提交整页。未提供此能力的 Host 在未请求抛弃时仍可照常运行。内置 Process Host 使用 `Process.free(address, size)`。

<!-- dt:section id="crt-extension-0" hash="e763bf414285" -->
## CRT 扩展

默认的 `NoopCrtGlue` 不执行额外操作。普通 MSVC `_DllMainCRTStartup` 会自行初始化 CRT。自定义入口的 DLL 可以提供 `ICrtGlue`：

```python
class MyCrtGlue:
    def prepare(self, plan):
        return initialize_compiler_state(plan.target_base)

    def cleanup(self, plan, token):
        finalize_compiler_state(plan.target_base, token)

loaded = load(payload, crt_glue=MyCrtGlue())
```

`prepare` 在布局、修复、导入、页保护和异常展开注册后，TLS 回调和 DLL 入口前执行；已完成的 `prepare` 对应的 `cleanup` 会在卸载或回滚时执行。mapper 不推断编译器内部行为。远程镜像的自定义辅助逻辑须明确使用目标 `Process`；Python 回调在调用方进程运行。
