> 本文档为 pe_map.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="pe_map.md" -->

<!-- dt:section id="__preamble__" hash="57c97de8f274" -->
# nylib.winutils.pe_map

从经过验证的 PE 字节将 AMD64 DLL 映射到当前进程或指定的 `Process`。

关键词: PE, manual mapping, memory DLL, Process.current, remote Process, InstallTier, SectSkip

```python
from nylib.winutils.pe_map.process import InstallTier, load

# Supply verified DLL bytes; this API does not take a file path.
with load(payload, tier=InstallTier.RUNTIME) as image:
    result = image.call_export('add', 3, 4)
```

解析器不依赖进程访问。加载器通过 `MapHost` 处理内存、导入、调用、TLS 和异常展开注册；`pe_map.process` 提供本进程与远程 Process Host。

- [加载和安装层次](pe_map/loading.zh.md)：本进程与远程用法、受支持的 DLL 特性、导出及卸载。
- [Core 与 Host 契约](pe_map/hosts.zh.md)：纯规划、其他 Host 及自定义 CRT 初始化。
- [附加后抛弃映射块](pe_map/retention.zh.md)：以 `SectSkip` 回调选择 PE 头或节。
- [限制与验证](pe_map/limitations.zh.md)：不支持的特性、剩余风险和测试命令。

此 API 不创建 DLL 文件。运行时所需的代码和数据仍能从目标进程读取，完整内存转储也可能包含它们。
