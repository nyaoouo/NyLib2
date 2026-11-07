> 本文档为 bcn.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="bcn.md" -->

<!-- dt:section id="__preamble__" hash="4c76e5191055" -->
# nylib.utils.bcn

通过随附的 C DLL，将原生 BC1（DXT1）块解码为 RGBA8。运行时不需要编译器或额外的 Python 包。

Keywords: bcn, BC1, DXT1, decode_bc1, texture decode, block compression, RGBA8, ctypes, DLL, load, BcnError, GIL

<!-- dt:section id="quick-start-0" hash="eb23e9109824" -->
## 快速开始

解码一个合成块，然后解码由同一块构成的 136x136 瓦片：

```python
from nylib.utils import bcn

block = bytes.fromhex('ffff000000000000')
pixels = bcn.decode_bc1(block, 4, 4)
assert pixels == bytearray(b'\xff' * 64)

tile = block * (34 * 34)
pixels = bcn.decode_bc1(tile, 136, 136)
assert len(pixels) == 136 * 136 * 4
assert pixels == bytearray(b'\xff' * len(pixels))
```

<!-- dt:section id="input-and-output-0" hash="3e21e0bc64b0" -->
## 输入与输出

`decode_bc1(src, width, height)` 通过 `__index__` 接受整数尺寸；两者都必须是正的 4 的倍数。`src` 可以是 `bytes`、`bytearray`、`memoryview` 或任意 C 连续缓冲区。接受任何元素格式或形状；长度按字节计数。

源数据按行优先的块顺序排列 8 字节块。至少需要 `8 * (width // 4) * (height // 4)` 字节；末尾多余的字节会被忽略。每个块包含两个小端序的 RGB565 端点，以及一个小端序的 32 位索引字，其中每个纹素占两位，按行优先顺序排列。

结果是一个新的、可调整大小的 `bytearray`，长度为 `width * height * 4` 字节：紧密排列的 RGBA8，行从上到下。像素 `(x, y)` 起始于 `4 * (y * width + x)`。

RGB565 通道通过位复制进行扩展。当端点 0 大于端点 1 时，插值通道使用 `((2 * a + b) * 683) >> 11` 和 `((a + 2 * b) * 683) >> 11`。否则第三种颜色为 `(a + b) >> 1`，第四种为黑色。Alpha 始终为 255，包括三色模式下的索引 3。

对于整数尺寸以及元素为单字节的一维 C 连续缓冲区，输出和参数错误与 `nylib.ue.assets` 中的纯 Python BC1 解码器一致。这包括资产读取器传入的所有输入。

<!-- dt:section id="threads-and-the-gil-0" hash="9906fcfcb774" -->
## 线程与 GIL

`decode_bc1()` 和 `load()` 可以从多个线程并发调用。DLL 在锁保护下加载一次，之后保持加载状态。原生解码会释放 GIL；Python 参数检查、输出分配和缓冲区固定则持有 GIL。

在调用期间，源数据会被固定而不复制。线程可以共享它，但解码期间不得修改它。每次调用都会分配自己的输出；内存占用为结果加上固定的开销。解码在调用中途无法取消。

在 Python 3.12 和 3.14 上，对真实地图纹理的 512x512 区域进行测量：原生解码约耗时 0.8 ms，纯 Python 解码器约耗时 28-30 ms（35-38x）。完整的 `Texture.read_region()` 调用还包括读取和解压缩，单线程约每秒 490 个区域，两线程或四线程约为每秒 600 个。

<!-- dt:section id="errors-0" hash="d5aefe8c695e" -->
## 错误

参数检查在加载 DLL 之前运行：

| 错误 | 原因 |
| --- | --- |
| `TypeError` | 某个维度不支持 `__index__`，或 `src` 不是类字节串 |
| `ValueError` | 维度不是正的 4 的倍数、源数据不是 C 连续的，或者数据过短 |
| `BcnError` | 平台不受支持、DLL 加载失败、导出函数缺失，或原生返回值非零 |

其他缓冲区导出错误、来自 `__index__` 的异常以及内存分配失败会原样向外传播。`BcnError.path` 在适用时为 DLL 的绝对路径，否则为 `None`；DLL 加载失败时，其 `OSError` 作为原因（cause）保留。

使用 `load()` 显式检查原生模块是否可用。它不接受参数，返回 `None`；加载失败后可以重试：

```python
from nylib.utils import bcn

bcn.load()
```

<!-- dt:section id="notes-0" hash="049be92a1288" -->
## 说明

- 随附的 `bcn_win64.dll` 仅支持 Windows x64。导入该包时不加载任何 DLL；首次调用 `load()` 或有效解码时才会加载。Python 3.11 和自由线程的 3.14t 未经测试。
- `nylib.ue.assets` 在首次 BC1 解码时自动选择原生解码器。如果加载时抛出 `BcnError`，它会记录一条 WARNING，并在该进程的其余时间内改用纯 Python，输出的像素相同。`bcn.load()` 直接检查原生解码器是否可用。
- wheel 包含该 DLL。PyInstaller 钩子 `hook-nylib.utils.bcn.py` 会将其打包到 `nylib/utils/bcn/` 下；树内应用需要按 [readme.md](../../../readme.md#packaging-with-pyinstaller) 所述配置 nylib 的钩子目录。
- 来源、许可证、工具链和二进制哈希见 [PROVENANCE.md](../../../nylib/utils/bcn/PROVENANCE.md)。在检出目录中，`.\.venv\Scripts\python.exe scripts/bcn/build.py --check` 使用固定版本的 MSVC 工具链重新构建，并要求输出逐字节一致。`--install` 刷新随附的 DLL；`--scan PATH...` 检查是否嵌入了本地路径。
