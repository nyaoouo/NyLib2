> 本文档为 limitations.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="limitations.md" -->

<!-- dt:section id="__preamble__" hash="fbe0916da633" -->
# 限制与验证

<!-- dt:section id="known-limitations-0" hash="e5478ca2e772" -->
## 已知限制

| 领域 | 当前行为与影响 |
| --- | --- |
| 依赖项加载 | 两种 Process Host 只解析目标中已加载模块的导入；不会调用 `LoadLibrary`，也不持有依赖项引用计数。 |
| 与系统加载器集成 | 镜像不在 Windows 加载器的模块列表中。模块查找、资源访问、加载器通知及假定存在原生 `HMODULE` 的代码可能失败。 |
| TLS | 本进程仅支持进程回调，不支持静态 TLS 或线程回调；远程映射拒绝所有 TLS 目录。 |
| 运行时特性 | CLR、CFG、可执行且可写的节、小于页的节对齐、EXE、非 AMD64 执行及不支持的重定位均被拒绝。`STRICT` 不等同原生加载器。 |
| 加载配置 | Core 记录安全 Cookie 地址和 GuardFlags，但未处理所有由系统加载器管理的加载配置字段。镜像可能通过检查，却仍在运行时失败。 |
| 镜像间隙 | 头和节的保护范围之外，位于对齐间隙中的整页保留分配时的可写权限。 |
| 自定义 CRT | `ICrtGlue` 方法在调用方 Python 进程运行；远程辅助逻辑必须明确访问目标进程。 |
| 调用与卸载 | 远程 `Process.call` 每次创建一个目标线程。附加过程不持有 Windows 加载器锁；调用可能挂起。调用方须保持目标存活，并确保卸载时没有线程执行映射代码。 |
| 部分清理 | 分离、注销异常展开表、释放依赖项或释放内存可能在其他清理步骤后失败；卸载不是可重试事务。[块抛弃失败](retention.zh.md)则会在异常中保留活动镜像。 |
| 可变输入 | 复制前会检查指纹，但另一线程仍可能在复制过程中修改 `bytearray` 或可写 `memoryview`；应提供稳定、不可变的 `bytes`。 |
| 载荷保密 | 此 API 不创建 DLL 文件，但映射后的代码和数据仍能从进程内存或完整转储读取。认证及转储策略由调用方负责。 |

远程测试已在 Notepad 子进程中验证导入、附加、导出调用、异常展开表注册返回值、非首选基址重定位、附加后头部与重定位块抛弃，以及卸载。独立的 32 位 `cmd.exe` 测试验证 WOW64 门禁。远程实际异常展开、支持 TLS 的 Host、其他编译器及映射或卸载期间目标退出的情况尚未验证。

<!-- dt:section id="validation-0" hash="150907ece3b2" -->
## 验证

被忽略的测试 DLL 源码、构建器和测试位于 `.ignore/pe_map/`，不在 `scripts/`。安装 MSVC 后，在该目录中运行：

```powershell
..\..\.venv\Scripts\python.exe -m unittest -v test_pe_map
..\..\.venv\Scripts\python.exe test_remote_notepad.py
..\..\.venv\Scripts\python.exe test_wow64_gate.py
```

本进程 C 测试覆盖附加、导出、分离、TLS 回调、异常展开查找、预先解析延迟导入、转发导出、静态 TLS 拒绝，以及头部和重定位块抛弃。模拟 Host 验证重定位、回滚、回调顺序、门禁拒绝和部分抛弃失败。远程测试自行启动及终止 Notepad 子进程，通过 `Process.call` 修改并恢复标题，检查块抛弃和卸载；生成的 DLL 二进制保持被忽略。
