> 本文档为 imagecodec.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="imagecodec.md" -->

<!-- dt:section id="__preamble__" hash="fbfebd0206cb" -->
# nylib.utils.imagecodec

将 RGBA8 像素编码为 JPEG（通过 Windows Imaging Component，使用 ctypes 调用）或 PNG（由 nylib 使用标准库的 `zlib` 写出）。这是对任意类字节缓冲区的无状态函数；用于从你已持有的像素中发布地图瓦片、概览图和图标。

关键词: imagecodec, encode_jpeg, encode_png, JPEG, PNG, RGBA, RGBA8, WIC, Windows Imaging Component, zlib, alpha, background, composite, quality, subsampling, ImageCodecError, ENCODER_REVISION, ctypes, tiles, icons

<!-- dt:section id="quick-start-0" hash="dab0b5ebff96" -->
## 快速开始

三个代码块都自行构建像素（每个像素为 R、G、B、A 字节，行从上到下）：

```python
from nylib.utils import imagecodec

w = h = 512
row = b''.join(bytes((x * 255 // (w - 1), 128, 255 - x * 255 // (w - 1), 255)) for x in range(w))
tile = imagecodec.encode_jpeg(row * h, w, h)  # quality 90, 4:2:0
assert tile[:2] == b'\xff\xd8' and tile[-2:] == b'\xff\xd9'
```

质量为 85 的概览图，以及一个带透明度的图标（PNG）：

```python
from nylib.utils import imagecodec

row = b''.join(bytes((x % 256, 90, 200, 255)) for x in range(4096))
overview = imagecodec.encode_jpeg(row * 4096, 4096, 4096, quality=85)

icon = b''.join(bytes((200, 30, 30, 255 if (x // 8 + y // 8) % 2 else 0)) for y in range(48) for x in range(140))
png = imagecodec.encode_png(icon, 140, 48)
assert png[:8] == b'\x89PNG\r\n\x1a\n'
print(len(overview), len(png))
```

<!-- dt:section id="pixels-0" hash="32334788f2b2" -->
## 像素

- RGBA8：每个像素四个字节，顺序为 R、G、B、A，行从上到下，行之间无填充，使用非预乘（straight，非 premultiplied）的 alpha。数值按原样存储，不做色彩转换。
- `pixels` 可以是任意 C 连续缓冲区：`bytes`、`bytearray`、`memoryview`、`array.array`、ctypes 数组，或形状为 `(height, width, 4)` 的 numpy `uint8` 数组。其元素格式无关紧要；其字节会被按 RGBA8 读取，且 `nbytes` 必须等于 `width * height * 4`。
- 缓冲区仅被读取、不会被保留，并在调用返回或抛出异常时释放。图像按每段最多 4 MiB 分段读取，因此不会复制整张图像。
- 对于 `nylib.ue.assets` 的 `Region`，请传入其字段。直接传入 `Region` 本身会抛出 `TypeError`，并指明此用法：

```python
# needs: a Region from nylib.ue.assets, with .pixels, .width and .height
from nylib.utils import imagecodec

jpeg = imagecodec.encode_jpeg(region.pixels, region.width, region.height)
```

<!-- dt:section id="jpeg-0" hash="4539df067edc" -->
## JPEG

- `encode_jpeg(pixels, width, height, *, quality=90, subsampling='4:2:0', background=None)`；`width` 和 `height` 取值 1..65500，`quality` 取值 1..100。
- 基线 JFIF，使用标准霍夫曼表（WIC 无法优化它们），并带有 72 x 72 dpi 的 APP0 头。
- 对于每个质量值，量化表均采用 libjpeg 的方式：当 `s = 5000 // q if q < 50 else 200 - 2 * q` 时，每个条目为 `min(255, max(1, (base * s + 50) // 100))`，基于标准的亮度和色度基表。
- `subsampling` 为 `'4:2:0'`（Y 为 2x2）、`'4:2:2'`（Y 为 2x1）或 `'4:4:4'`；Cb 和 Cr 均为 1x1。
- JPEG 没有 alpha，因此若像素不是不透明的，除非你提供 `background=(r, g, b)` 作为合成底色，否则会被拒绝。每个通道变为 `(c * a + bg * (255 - a) + 127) // 255`：alpha 为 255 时保留该像素，alpha 为 0 时得到背景色。全部不透明的图像会忽略 `background`。

```python
from nylib.utils import imagecodec

px = bytes((255, 0, 0, 128)) * 4 * 4
try:
    imagecodec.encode_jpeg(px, 4, 4)
except ValueError as e:
    print(e)  # 16 of 16 pixels are not opaque and JPEG has no alpha; pass background=(r, g, b) to composite them
jpeg = imagecodec.encode_jpeg(px, 4, 4, background=(0, 0, 0))  # red at half alpha over black
```

<!-- dt:section id="png-0" hash="4a6294114ddf" -->
## PNG

- `encode_png(pixels, width, height)`；`width` 和 `height` 取值 1..65535。
- 由 nylib 写出：签名、IHDR（8 位 RGBA，颜色类型 6，即使图像完全不透明也是如此）、IDAT 和 IEND，不包含其他任何块。每一行都使用滤波器 0，所有行组成一个 zlib 流，压缩级别为 9。
- 无损：解码后可以还原每一个字节，包括完全透明像素的 RGB。
- 扁平风格的图标图片体积很小（在 40 个游戏图标上，中位数为原始文件的 0.72 倍）。平滑内容的体积比使用自适应滤波器的编码器更大：4096x4096 的渐变图约为 WIC 输出的 2.7 倍。
- 字节输出取决于 Python 构建所用的 zlib：3.12（zlib 1.3.1）和 3.14（zlib-ng）写出的文件不同，但解码出的像素相同。
- 不进行 COM 调用，也不加载任何 DLL，因此可在所有平台和 32 位 Python 上运行。

<!-- dt:section id="threads-com-and-the-gil-0" hash="43ed6df8e180" -->
## 线程、COM 与 GIL

- 两个函数都不保存状态，可以同时在任意数量的线程上运行。
- 第一次调用 `encode_jpeg` 时会从系统目录加载 `windowscodecs.dll`，并调用一次 `CoIncrementMTAUsage`：该进程会一直保持多线程公寓（MTA），直到进程退出。除此之外不做其他设置；该调用从不在其所在线程上初始化 COM，并且可在没有 COM、STA 或 MTA 的线程上工作。
- 在 WIC 编码像素时（`WriteSource` 和 `WritePixels`，每段一次调用），以及首次调用时的 DLL 加载过程中，GIL 会被释放。其余时间持有 GIL：不透明度检查（每个瓦片 0.7 ms，每张概览图约 45 ms）、每段以及结果的复制。在概览图编码的同时运行纯 Python 线程，在 WIC 部分几乎能保持全速。
- PNG 每次 `compress` 调用压缩一段，zlib 在其内部释放 GIL。
- 一次调用自身的内存分配保持在 16 MiB + 2 x `len(result)` 以内；并发调用会累加。
- 线程池对瓦片有加速效果（见下方数据）。调用内部不支持取消。

<!-- dt:section id="errors-0" hash="20b70a629ebe" -->
## 错误

- 参数错误会在加载任何 DLL 或进行任何 COM 调用之前抛出 `TypeError` 或 `ValueError`，在所有平台上均如此。
- `encode_jpeg` 在以下情况下抛出 `ImageCodecError(message, *, func=None, hresult=None)`：WIC 或 Win32 调用失败（`func` 为调用名称，`hresult` 为无符号 32 位整数）、DLL 无法加载、像素格式不符合预期，或结果格式错误。在非 Windows 系统上，或在 32 位 Python 上，它会抛出同样的错误，且 `func` 和 `hresult` 均为 `None`；`encode_png` 仍然可用。

```python
from nylib.utils import imagecodec

try:
    imagecodec.encode_jpeg(b'\xff' * 16, 2, 2)
except imagecodec.ImageCodecError as e:
    print(e.func, hex(e.hresult or 0), e)
```

<!-- dt:section id="measured-0" hash="d115d15c468d" -->
## 测量数据

Windows 11 build 26200，CPython 3.14.4 / 3.12.10，每个用例在全新进程中运行。计时是在同一台机器上有其他任务运行时进行的，因此应将其视为上限；内存数据不受负载影响。

| case | time, 3.14 / 3.12 | process growth |
| --- | --- | --- |
| JPEG 512x512 q90 (z5 tile) | p50 2.0 / 2.0 ms; first call 5 ms | +1.4 / 1.6 MiB |
| JPEG 4096x4096 q85 (overview) | p50 124 / 117 ms; 7.0 MB | +17.2 / 17.5 MiB |
| JPEG 4096x4096 over a background, alpha ramp | 1.45 / 1.45 s | +13.7 / 15.5 MiB |
| the opacity check, 4096x4096 | 45 / 48 ms | none |
| PNG 140x48 icon | p50 1.8 / 2.4 ms | +0.3 MiB |
| PNG 256x256 icon | p50 3.3 / 5.5 ms | +0.6 / 0.55 MiB |
| PNG 4096x4096 overview | 2.2 / 3.1 s; 46 MB | +89 / 91 MiB |
| 1x1 JPEG, the fixed cost | p50 0.21 ms; first call of a process 4 ms | |
| 400 tiles, 1 and 4 threads | 441 / 959 and 499 / 897 tiles/s | |
| tile beside a busy Python thread | 15.4 / 15.5 ms (2.0 ms alone) | |

在真实的地图缓存上（36 个 q90 瓦片，3 个 q85 概览图），由 Windows 重新解码：瓦片的 PSNR 最小值为 42.8 dB，中位数为 48.8 dB；概览图的 PSNR 最小值为 45.2 dB。文件比缓存自身经过霍夫曼优化的文件大约 2%（中位数为 1.02 倍）。所有 40 个图标 PNG 都能解码回与输入完全一致的像素。

<!-- dt:section id="notes-0" hash="0cf0ae3594c5" -->
## 注意事项

- `ENCODER_REVISION`（`int` 类型，当前为 1）仅当输出的含义发生变化时才会递增：包括表规则、子采样、alpha 或合成规则、JFIF 头、PNG 块列表，或解码后的像素。对于含义相同但字节不同的情况（例如其他 Windows 版本或其他 Python 的 zlib）则不会递增。
- 在同一台机器上，相同参数产生相同字节；JPEG 字节在 3.12 和 3.14 下相同，PNG 字节则因 Python 构建而异。
- 不支持解码、其他格式、BGRA、步长（stride）或预乘（premultiplied）输入。`format=`、`stride=` 和 `premultiplied=` 为保留名称；目前它们会因关键字参数不被接受而抛出 Python 自身的 `TypeError`。
- JPEG 仅在 64 位 Windows 上经过测试；预计 ARM64 Windows 可以工作，但尚未验证。
