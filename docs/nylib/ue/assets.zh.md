> 本文档为 assets.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="assets.md" -->

<!-- dt:section id="__preamble__" hash="f25c92fd400e" -->
# nylib.ue.assets

用于 UE 5.7 游戏的 IoStore（`.utoc`/`.ucas`）容器的只读读取器：枚举包、读取 `Texture2D` 元数据，并将虚拟纹理 BC1 瓦片的有界区域解码为 RGBA8。Python，使用 Windows BCrypt 进行 AES 加密和捆绑的 Oodle DLL 进行解压缩；不依赖 FModel、CUE4Parse 或 Unreal。

关键词：IoStore, utoc, ucas, AesKey, open_installation, Installation, Texture, virtual texture, VT, BC1, DXT1, read_region, usmap, mapping, zen package, PackageInfo, TextureInfo, Region, ScriptObjects, Oodle

<!-- dt:section id="quick-start-0" hash="a823faa39ad4" -->
## 快速开始

```python
# needs: an installed UE 5.7 game, its AES key file and a matching .usmap
from nylib.ue.assets import open_installation, AesKey

key = AesKey.from_file('path/to/game-aes.txt')
with open_installation('path/to/MyGame/Content/Paks', engine='5.7',
                        usmap='path/to/MyGame.usmap', build=None, aes_key=key) as assets:
    print(assets)                                           # <Installation engine=5.7 build=unknown ...>
    tex = assets.texture('/Game/UI/Icons/T_Something')
    print(tex.info.width, tex.info.height, tex.info.readable)
    region = tex.read_region(0, 0, 0, 128, 128)               # mip 0, top-left 128x128, RGBA8
    print(region.width, region.height, len(region.pixels))
```

<!-- dt:section id="opening-0" hash="417f152afd13" -->
## 打开

```python
from nylib.ue.assets import AesKey

key = AesKey.from_hex('00' * 32)
print(repr(key))
```

- `aes_key=` 接受一个 `AesKey`、原始的 `bytes`/`bytearray`（用零 GUID 包装）、一个 `AesKey` 列表（每个容器 GUID 一个），或 `None` 表示无加密容器的安装。`AesKey` 也可以读取密钥文件（`AesKey.from_file(path)`）或原始/十六进制字节（`AesKey(key_bytes)`）；作为 `aes_key=` 传递的 `str` 会被拒绝，指向 `from_hex()` / `from_file()`，所以密钥永远不会意外地被输入到日志或 repr 中。
- `usmap=` 是游戏的 `.usmap` 映射文件（v0-v4；压缩选项为 None、Oodle 或 Python 3.14+ 上的 ZStd）。它在打开时被解析一次。
- `build=` 固定 exe 的 PE `TimeDateStamp`：传递你针对 `.usmap` 验证的 int，不匹配或缺少的 exe 会引发 `BuildMismatchError`。传递 `None` 跳过检查；`Installation.build` 仍然会报告找到的 exe（如果有的话）。
- `cache_bytes=` 限制共享的解压块缓存；默认 4 MiB（近似的测量时间见注释）。
- `Installation` 是一个上下文管理器；`close()` 是幂等的和线程安全的，未关闭的实例在被垃圾回收时会关闭自己并发出 `ResourceWarning`。

<!-- dt:section id="finding-packages-0" hash="4a8e137dd09d" -->
## 查找包

- `assets.has_package(name) -> bool` 在不读取任何容器数据的情况下进行检查。
- `assets.package(name) -> PackageInfo` 读取包头的摘要块。`name` 接受包路径（`/Game/UI/Icon`）、对象路径（`/Game/UI/Icon.Icon`）或 `.uasset`/`.umap` 文件路径（`Engine/Content/...` 或 `<Project>/Content/...`）。
- `assets.list_packages(prefix='/', *, match=None) -> list[PackageInfo]` 遍历每个挂载容器的目录索引（构建一次，缓存到 `close()` 为止）；`match` 是整个名称上的 `fnmatch` 样式的模式，ASCII 不区分大小写，与 `prefix` 相同。
- 名称大小写：`list_packages()` 报告容器的目录索引为路径记录的大小写；`package()` 和 `texture()` 报告包头本身记录的大小写。两者可能不同——在一个游戏上实测，212 个抽样名称中有 3 个不同，例如 `.../APC/Wavs/...` 与 `.../APC/WAVs/...`——但指的始终是同一个包：`PackageInfo.package_id` 相同，而且所有名称匹配都不区分 ASCII 大小写。
- 插件挂载根：`list_packages()` 也列出位于 `Engine/Plugins/.../Content/...` 或 `<Project>/Plugins/.../Content/...` 目录下的包，命名为 `/<mount>/<rest>`。当 `<mount>` 已经与条目记录的块 id 匹配时，它是插件文件夹名称；否则目录在其第一个不匹配的条目上花费一次摘要读取，从该条目的记录包名称学习 `<mount>`，然后为目录的其余部分重用它（在一个游戏上实测，22,313 个插件根文件中有 106 个需要学到的挂载，来自 2 次学习读取）。学到的 `<mount>` 保持记录名称的大小写；`<rest>` 始终保持目录索引的大小写。
- `.uasset`/`.umap` 文件路径形式不适用于插件根：位于 `Plugins/` 目录下的文件路径仍然会引发 `ValueError`。通过包路径或对象路径形式（`/<mount>/...`）或通过 `list_packages()` 返回的名称来寻址插件根包。

<!-- dt:section id="metadata-0" hash="8945c6344751" -->
## 元数据

- `assets.texture(name) -> Texture` 解析 `Texture2D` 导出并将其头部解析为 `Texture.info`（一个 `TextureInfo`）：`width`、`height`、`pixel_format`、`mips`（每个级别一个 `MipInfo`）、`alpha`（`'none'` 或 `'straight'`）、`virtual`（一个 `VirtualTextureInfo`，或对于普通纹理为 `None`）、`readable` 和 `unsupported`（理由，匹配 `read_region` 会引发的错误）。在一个安装上的第一个 `texture()` 调用较慢；请参阅注释。
- `assets.stats() -> ReadStats` 返回自打开以来的运行总计（`reads`、`bytes_read`、`blocks_decompressed`、`tiles_decoded`、`seconds` 等）。两个快照之间的差异测量一个跨度；`str(stats)` 是一行摘要。

<!-- dt:section id="reading-regions-0" hash="b720baf4354e" -->
## 读取区域

`tex.read_region(mip, x, y, width, height, *, clip=False, missing='raise', out=None, cancel=None) -> Region` 将像素数据解码为 RGBA8：虚拟纹理 BC1 瓦片，或普通 `PF_B8G8R8A8` 纹理的 mip 行。先检查 `info.readable`；当其为 False 时，`info.unsupported` 说明原因。

- 坐标是 mip `mip` 的像素坐标，原点左上，行从上到下返回；大小来自 `info.mips[mip]`，永远不会重新缩放。
- 输出是紧密堆积的 RGBA8：`len(region.pixels) == width * height * 4`，无 sRGB 转换。当 `info.alpha == 'none'` 时，Alpha 为 255。
- `clip=True` 将矩形缩小到 mip 的边界而不是抛出异常；`clip=False`（默认）在边界外抛出 `RegionOutOfBoundsError`。
- 虚拟纹理：`missing='raise'`（默认）如果任何接触的瓦片未存储则抛出 `MissingTileError`；`'transparent'` 用 `(0, 0, 0, 0)` 填充；`'fallback'` 用 `info.virtual.fallback[0]` 填充。`region.missing` 无论如何都列出填充的矩形，仅解码矩形接触的瓦片。
- 普通纹理：存储的字节顺序为 B、G、R、A；输出为 R、G、B、A，值仍为存储的值，仍无 sRGB 转换。没有瓦片，所以 `missing` 经过验证但没有其他效果，`region.missing` 始终为 `()`。仅读取 mip 的行 `y .. y + height - 1`。
- 无论如何，每个压缩块在每次调用中最多被获取和解压一次，结果与缓存状态、线程数或（对于虚拟纹理）填充区域外的 `missing` 策略无关。
- `out=` 写入调用者提供的可写缓冲区而不是分配新的 `bytes`；`cancel=` 是一个零参数可调用对象，在瓦片（虚拟纹理）或压缩块（普通纹理）之间轮询，当其返回真时抛出 `ReadCancelledError`。

兼容性：在早期版本中，每个普通（非虚拟）纹理都从 `read_region` 无条件地抛出 `UnsupportedAssetError(feature='non-virtual texture')`。现在可读的普通纹理进行解码，没有解码器的像素格式的普通纹理改为抛出 `UnsupportedPixelFormatError` -- 就像不支持的虚拟纹理层格式已经做的那样。两个错误类都派生自 `UnsupportedError`；只在 `read_region` 周围捕获 `UnsupportedAssetError` 的调用者会错过新的异常。

<!-- dt:section id="threads-and-cancellation-0" hash="2855875eb1b4" -->
## 线程与取消

- 任意数量的线程可以同时调用 `Installation` 和 `Texture` 方法；它们仅在每个容器块读取和共享块缓存周围短暂相互等待。Records 和 `AesKey` 是不可变的。
- GIL 在文件 I/O、AES 解密和 Oodle 解压期间被释放，在解析和 BC1 解码期间被持有，这些是纯 Python 代码。
- `close()` 等待在其他线程上运行的读取操作，除了调用它的线程本身；一旦它返回且没有自己的进行中读取，安装就不持有任何文件句柄、锁对象或缓存。
- `Installation`、`Texture` 和 `AesKey` 拒绝 pickling 和 `copy`/`deepcopy`；records 和错误类可以 pickle。

<!-- dt:section id="errors-0" hash="8e4481d5ff40" -->
## 错误

```text
UeError
└── AssetError                      every nylib.ue.assets failure but argument-type errors; .package, .container
    ├── InvalidKeyError             no/wrong AES key, GUID mismatch, bad key file; .key_guid, .reason, .path
    ├── InvalidMappingError         .usmap missing, invalid, or does not fit the data; .usmap, .class_name, .property_index, .property_name, .reason, .path
    │   └── BuildMismatchError      build= differs from the exe's own stamp; .expected, .found, .exe, .path
    ├── MissingAssetError           package or export not in a mounted container (a LookupError); .export
    │   └── MissingTileError        missing='raise' hit an unstored VT tile; .mip, .tiles
    ├── UnsupportedError             outside the supported profile; .feature
    │   ├── UnsupportedContainerError    TOC version, AES mode, compression method, or no usable Oodle
    │   ├── UnsupportedAssetError         asset class or native layout; .exports
    │   └── UnsupportedPixelFormatError   no decoder for this pixel format; .pixel_format
    ├── CorruptAssetError            structure or codec check failed; .detail (a block decode's __cause__ is an OodleError)
    ├── RegionOutOfBoundsError       rectangle or mip out of range (a ValueError); .mip, .rect, .size
    ├── ReadCancelledError           cancel() returned true
    └── InstallationClosedError      the installation is already closed (a ValueError)
```

- 错误的参数类型会抛出 `TypeError`，错误的值会抛出 `ValueError` -- 除了 `RegionOutOfBoundsError` 之外，永远不会抛出上面的任何类，`RegionOutOfBoundsError` 既是 `AssetError` 也是 `ValueError`。
- `AmbiguousNameError`（从 `nylib.ue` 重新导出，不在 `AssetError` 下）在短名称与多个导出匹配时由 `texture()` 抛出。
- 消息是一行英文；永远不包含超过基名的路径、关键材料、解密/解码字节、映射文件内容或属性名称。

<!-- dt:section id="supported-profile-0" hash="2818ac1b2b7f" -->
## 支持的配置文件

| 图层 | 该版本中支持 | 超出范围 |
|---|---|---|
| 容器 | IoStore TOC v8；AES-256-ECB；Oodle (Kraken) 及存储块；压缩块为 2 的幂，范围从 4 KiB 至 16 MiB | `UnsupportedContainerError`；`.pak` 文件列在 `containers` 中但永不被挂载 |
| 映射 | `.usmap` v0-v4；压缩 None、Oodle、ZStd (需要 Python 3.14+) | `InvalidMappingError` |
| 包 | zen 包、无版本属性 | `InvalidMappingError`、`CorruptAssetError` |
| 纹理元数据 | 每个 `Texture2D` 导出、虚拟和普通 | 另一类：`UnsupportedAssetError` |
| 虚拟纹理区域读取 | `RawGPU` 编解码器、一个图层、`PF_DXT1`、非遗留瓦片布局 | `UnsupportedAssetError` / `UnsupportedPixelFormatError`；`info.readable` 为 False 且说明原因 |
| 普通纹理区域读取 | `PF_B8G8R8A8` mips 内联在导出中，或在包的默认 `.ubulk` 中（cooked index 0） | `UnsupportedPixelFormatError` 用于其他像素格式；`UnsupportedAssetError` 用于没有序列化的 mips、mip 数据未与纹理一同序列化、压缩的 bulk data、可选的 bulk data (`.uptnl`)、内存映射的 bulk data (`.m.ubulk`)、其他 cooked index 下的 bulk data 或任何其他放置；`info.readable` 为 False 且说明原因 |

<!-- dt:section id="notes-0" hash="7e30faa7db8b" -->
## 说明

- 无重采样：一个mip的像素返回该mip自己的大小；缩放是调用者的工作。
- BC1解码是纯Python：它持有GIL，每像素消耗CPU，所以大区域读取在那部分是单核绑定的。
- 在安装上的第一个`texture()`调用也会加载全局ScriptObjects表一次（在测量的游戏中约4.66 MB），在一台测量的机器上总共成本约0.42秒，几乎全部是那个加载；后来的`texture()`调用重用该表。
- BC1三色块的索引-3纹素在这里解码为`(0, 0, 0, 255)`（CUE4Parse自己的填充是alpha 0）。测量的两个地图的块都未使用该索引（在1,560,299个采样的三色块中的0个），所以这在那里从未显示差异。
- 近似，一台机器：`open_installation`花费约0.22秒（其中约0.15秒用于解析`.usmap`）；无论`cache_bytes`为0、4 MiB默认值还是16 MiB，区域读取约为30 ms p50 -- 解码限制，所以更大的缓存主要帮助对相同瓦片的重复读取。
- 近似，一台机器，一个普通纹理地形瓦片（`PF_B8G8R8A8`、`.ubulk` mips）：一个2x2样本在1个压缩块上花费约0.1 ms；一个mip 0读取约为2.5 ms p50；`cancel=`在块之间增加了约0.3 ms的延迟。`list_packages()`的第一个调用（它也学习插件挂载根）花费了4.25-5.0秒。
- 仅限Windows x64（AES使用BCrypt；exe的PE和`.ucas`/`.utoc`布局）。将AES密钥文件及其内容视为秘密：永远不要记录、打印或提交它；通过路径传递。
