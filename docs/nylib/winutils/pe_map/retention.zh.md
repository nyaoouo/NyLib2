> 本文档为 retention.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="retention.md" -->

<!-- dt:section id="__preamble__" hash="d8e0fb9eb6ae" -->
# 附加后抛弃映射块

`on_block=` 是可选的 Python 回调，在 TLS 进程回调和 DLL 入口返回后执行。它接收最终的 `ImagePlan` 和逐个 `MappedBlock`：先是一个 `headers` 块，再按顺序给出每个 PE 节的 `section` 块。块含有 `kind`、`name`、`index`、相对镜像的 `rva`、按页计算的 `size`、绝对 `address`，以及适用时的 `SectionPlan`。抛出 `SectSkip` 即请求反提交该块的页面。

```python
from nylib.winutils.pe_map import SectSkip
from nylib.winutils.pe_map.process import load

def on_block(plan, block):
    if block.kind == 'section' and block.name == '.reloc':
        raise SectSkip()

with load(payload, on_block=on_block) as image:
    print([block.name for block in image.discarded_blocks])
```

Core 仍会解析和验证全部节，loader 也会先复制它们以完成初始化。loader 收齐 `SectSkip` 请求后才修改内存，并拒绝与已知必需位置重叠的块，包括 DLL 入口、直接导出、IAT、TLS、异常展开和安全 Cookie。请求的块必须是分配区域内的完整页面。Process Host 使用 `Process.free(address, size)` 反提交页面。`LoadedImage.discarded_blocks` 记录成功的操作；mapper 卸载所需元数据已经缓存，不再读取映射后的头。

这些检查不能证明 DLL 以后不会再次读取请求块中的头、资源、常量或其他数据。只应为你控制且已验证运行及分离行为的载荷声明要抛弃的块。块可能与仍需的内容共用页面；与已知必需位置重叠的请求会被拒绝。回调在 Python 中运行；通过 `Process.call` 调用的目标 DLL 不能跨进程抛出 `SectSkip`。其他回调异常会向上传播，并在抛弃任何块之前触发常规加载回滚。

`BlockDiscardError` 表示附加后 Host 操作失败。异常包含 `loaded` 和 `block`；此前的块或失败块的一部分可能已反提交，因此 `loaded` 仍保持活动状态。调用方须处理这种部分完成状态，并在安全时调用 `loaded.unload()`。自定义 Host 若没有 `discarder=`，会在执行反提交之前拒绝 `SectSkip` 请求。

块抛弃不会清除调用方持有的原始载荷，也无法让运行时代码或数据不出现在内存转储中。它独立于 `InstallTier`；默认保留全部块。
