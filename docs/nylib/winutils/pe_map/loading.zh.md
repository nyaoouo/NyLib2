> 本文档为 loading.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="loading.md" -->

<!-- dt:section id="__preamble__" hash="6593fbb124a3" -->
# 加载和安装层次

<!-- dt:section id="process-loaders-0" hash="65a19c4c7ad6" -->
## Process 加载器

`load(payload)` 使用 `Process.current`。要加载到调用方持有的 AMD64 目标进程，用 `process=`；目标中必须已经加载导入依赖：

```python
from nylib.process import Process
from nylib.winutils.pe_map.process import InstallTier, load

target = Process(child_pid)
try:
    with load(payload, process=target, tier=InstallTier.RUNTIME) as image:
        result = target.call(image.get_export('add'), 3, 4)
finally:
    target.close()
```

`host=` 可传入显式创建的 `LocalProcessHost` 或 `RemoteProcessHost`；`process=` 和 `host=` 只能选一个。调用方应保持目标句柄打开，直到 `unload()` 完成。远程镜像须使用远程地址或 `Process.call` 的字节参数，不能将远程地址转换成本进程的 `ctypes` 函数。

<!-- dt:section id="installation-tiers-0" hash="44fd37cb3e98" -->
## 安装层次

| 层次 | 行为 | 拒绝的需求 |
| --- | --- | --- |
| `MINIMAL` | 复制头和节、重定位、解析普通导入、设置页保护、调用 DLL 入口、缓存导出，并在卸载时分离和释放。 | TLS、x64 异常表、延迟导入及加载配置。 |
| `RUNTIME` | 增加本进程 TLS 进程回调、x64 函数表注册、预先解析延迟导入、依赖项记录和回滚。 | 静态 TLS 模板及零填充、CFG 和不支持的镜像特性；远程 Host 还拒绝所有 TLS 目录。 |
| `STRICT` | 执行 RUNTIME 行为，同时要求完整的 TLS 线程生命周期。 | 两种现有 Process Host 中的任何 TLS 目录，以及所有 RUNTIME 拒绝项。 |

所有层次都要求节按页对齐的 AMD64 DLL；远程 Host 拒绝 WOW64 目标。加载器拒绝 CLR、可执行且可写的节、CFG、不支持的重定位及缺少重定位信息却需要更换基址的镜像。`STRICT` 是更严格的特性门禁，不等同原生加载器。通用 Host 限制见[限制](limitations.zh.md)。

本进程 RUNTIME Host 调用 TLS 进程回调，但不安装静态 TLS，也不发送线程附加/分离通知。远程 Host 在分配内存前拒绝 TLS，因为 `Process.call` 每次在新的目标线程上调用。延迟导入在映射时解析，而不是首次使用时才解析。

<!-- dt:section id="exports-and-lifetime-0" hash="97a2f8241c20" -->
## 导出与生命周期

`get_export` 接受名称或序号，返回缓存的绝对地址，也支持已解析的转发导出。`call_export` 使用所选 Host 的 `Process.call`，适合简单的整数和指针参数。本进程镜像若需精确 C 函数签名，可用返回地址配合 `ctypes`。

`LoadedImage` 保存基址、大小、入口地址、已解析导出、TLS 回调地址、依赖项令牌、异常展开和 CRT 状态，以及[已抛弃的块](retention.zh.md)。`unload()` 不重新打开源字节或解析映射后的头。卸载后调用导出会抛出 `RuntimeError`。调用方须保留活动函数和分离回调所需的代码与数据，并确保卸载时没有线程在镜像中执行。
