> 本文档为 assets.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="assets.md" -->

<!-- dt:section id="__preamble__" hash="59861a9e7d47" -->
# nylib.ue.assets

针对 UE 5.7 游戏 IoStore 容器（`.utoc`/`.ucas`）的只读读取器：枚举包，包括插件挂载根目录下的包；读取 `Texture2D` 元数据；读取类型化的导出属性和跨包引用；并将虚拟纹理 BC1 瓦片，以及普通的 `PF_B8G8R8A8`、`PF_DXT1`、`PF_DXT5` 和 `PF_BC7` 纹理，解码为 RGBA8 的有界区域，包括以可选批量数据（`.uptnl`）形式存储的普通 mip。使用 Python 实现，AES 使用 Windows BCrypt，解压使用随附的 Oodle DLL；不依赖 FModel、CUE4Parse 或 Unreal。

关键词：IoStore, utoc, ucas, AesKey, open_installation, Installation, Texture, virtual texture, VT, BC1, DXT1, DXT5, BC7, B8G8R8A8, .uptnl, ordinary texture, plugin, read_region, usmap, mapping, zen package, PackageInfo, TextureInfo, Region, ScriptObjects, Oodle, Exports, StructValue, DataTable, CurveTable, native struct, ObjectRef

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

<!-- dt:section id="opening-0" hash="2db4d27b48dd" -->
## 打开

```python
from nylib.ue.assets import AesKey

key = AesKey.from_hex('00' * 32)
print(repr(key))
```

- `aes_key=` 接受 `AesKey`、原始 `bytes`/`bytearray`（以零 GUID 包装）、`AesKey` 列表（每个容器 GUID 一个），或 `None`（用于没有加密容器的安装）。`AesKey` 还可以读取密钥文件（`AesKey.from_file(path)`）或原始/十六进制字节（`AesKey(key_bytes)`）；作为 `aes_key=` 传入的 `str` 会被拒绝，并提示使用 `from_hex()` / `from_file()`，从而确保密钥不会因疏忽而被输入到日志或 repr 中。
- `usmap=` 是游戏的 `.usmap` 映射文件（v0-v4；压缩方式为 None、Oodle 或 ZStd，ZStd 需 Python 3.14+），或来自 `load_usmap()` 的 `Usmap`。路径在打开时只解析一次；`Usmap` 会被复用，不会再次读取映射文件。
- `build=` 固定 exe 的 PE `TimeDateStamp`：传入你用来验证 `.usmap` 的整数值；exe 不匹配或缺失时会抛出 `BuildMismatchError`。传入 `None` 可跳过检查；`Installation.build` 仍会报告所找到的 exe（如有）。
- `exe=` 指定用于 `build=` 检查 PE 时间戳的游戏 exe。默认是 `<paks>/../../Binaries/Win64` 中唯一的 `*-Win64-Shipping.exe`；没有或超过一个都视为缺失。若游戏把 exe 放在其他位置，需要使用 `exe=`。
- `cache_bytes=` 限制共享的解压块缓存；默认 4 MiB（大致的实测耗时见说明）。
- `Installation` 是上下文管理器；`close()` 是幂等且线程安全的，未关闭的实例在被垃圾回收时会自行关闭并发出 `ResourceWarning`。

<!-- dt:section id="mappings-0" hash="fc8070f34955" -->
## 映射

`load_usmap(path, *, meta=None, custom_serialization=()) -> Usmap` 解析一次映射，用于检查、校验以及可选的内存中修改。它从不写入 `.usmap`。将得到的 `Usmap` 传给 `open_installation(usmap=u)`，即可通过其有效记录进行读取。

```python
# needs: an installed UE 5.7 game, its AES key file and a matching .usmap
from nylib.ue.assets import AesKey, MappingChange, Requirement, load_usmap, open_installation

u = load_usmap('path/to/MyGame.usmap')
u = u.with_changes([
    MappingChange.retype('Texture2D', 4, 'Struct<IntPoint>', before='Struct<None>'),
])
report = u.check({'textures': [Requirement('Texture2D', index=4, type='Struct<IntPoint>')]})
print(report)
key = AesKey.from_file('path/to/game-aes.txt')
with open_installation('path/to/MyGame/Content/Paks', engine='5.7',
                        usmap=u, build=None, aes_key=key) as assets:
    print(assets.usmap.digest, assets.identity)
```

当该槽位已经是 `Struct<IntPoint>` 时，示例中的 retype 会被跳过；它只是针对自身第 4 个索引需要该类型的映射所做的修复。应用修改前，请对照你的游戏布局检查映射。

- `Usmap` 是不可变的，只能由 `load_usmap()` 和 `with_changes()` 创建。`file` 是文件基本名；`sha256` 对原始文件字节做哈希；`digest` 标识文件及其已应用的修改，无修改时等于 `sha256`。`version`、`structs` 和 `enums` 描述有效映射，`changes` 按顺序列出已应用的修改。`repr(u)` 包含基本名、SHA-256 前缀、版本和计数。
- `u.record(name) -> RecordInfo | None` 以 ASCII 不区分大小写的方式查找记录；它包含 `name`、`super`、`count` 和 `properties`（每个声明的属性一项，静态数组不展开）。`u.records()` 按文件顺序迭代有效记录，之后是新增的记录。`u.properties(struct) -> tuple[PropertyInfo, ...] | None` 按链索引顺序展开整个父链的每个槽位；记录缺失或存在循环时返回 `None`。每个 `PropertyInfo` 包含 `index`、`element`、`owner`、`own_index`、`name`、`type` 和 `array_dim`：`index` 是链范围内的索引，而 `own_index` 是该属性在其声明记录内的第一个索引。
- `meta=` 显式指定 nylib 转储的 `meta.json`（UTF-8 JSON，最大 64 MiB）。`u.meta` 是包含 `created`、`exe`、`pe_timestamp`、`quality` 和 `reasons` 的 `DumpInfo`；没有文件时为 `None`。不会自动发现任何旁路文件，文件位置或记录数量都不能证明两者配对。`u.check(..., build=stamp).paired` 仅将该标记与 `meta.pe_timestamp` 比较，当任一方不可用时返回 `None`。打开安装时不会将 `build` 与 meta 比较；当该时间戳可用时，传入 `build=u.meta.pe_timestamp` 以固定 exe。
- `custom_serialization=` 是调用方提供的非空类名可迭代对象，按顺序保留；nylib 不提供内置类列表，此声明也不会添加任何解码器。`u.declared_custom(class_name_or_export_info)` 返回该类或其第一个匹配父类的对应条目（ASCII 不区分大小写），否则返回 `None`。

修改是 `MappingChange` 记录，由 `u.with_changes(iterable)` 按顺序应用，它返回新的 `Usmap` 且保持 `u` 不变。构造函数包括 `add(struct, own_index, name, type, *, array_dim=1, note=None)`、`retype(struct, own_index, type, *, before=None, note=None)`、`rename(struct, own_index, name, *, before=None, type=None, note=None)`、`set_count(struct, count, *, before=None, note=None)` 和 `record(struct, *, super=None, count, properties=(), note=None)`。记录的属性是 `(own_index, name, type[, array_dim])` 条目。`add` 需要记录计数范围内的空闲区间；`set_count` 不能使条目落在其范围之外。已存在且父类与计数相同的记录被视为已就位，不比较其属性列表。

`before` 用于守护先前的类型、名称或计数；重命名的可选 `type` 是另一个守护条件。已经就位的修改会被跳过且不列出（重命名的类型守护仍会检查）。不匹配的修改会抛出 `InvalidMappingError(reason='change does not apply')`；不会返回部分修改的映射。已应用的修改在可用时记录先前的值，并且上述构造函数使用 `by='patch'`。根据检查结果构造修改时，应使用 `found.owner` 和 `found.own_index`，绝不要使用 `found.index`：继承的属性具有不同的链索引。类型标签包括 `Float`、`Struct<IntPoint>`、`Array<Struct<Vector>>`、`Map<Name,Int>` 和 `Enum<MyEnum:Byte>`；`Struct<None>` 表示不存在的结构体名称。`Object<C>` 被拒绝，因为 `.usmap` 不存储对象属性的类。

`u.check(requirements, *, fallback=None, by=None, build=None) -> MappingReport` 从不改变 `u`。传入从族名到非空 `Requirement(struct, name=None, index=None, type=None)` 可迭代对象的映射，或为族名 `''` 传入单个非空可迭代对象。`index` 是链范围内的索引。仅含结构体的需求检查其整个链；仅含类型的需求需要一个匹配的属性。名称精确匹配，包括大小写。结果有六种状态：

| status | meaning |
| --- | --- |
| `ok` | 原始文件以相同槽位满足该需求 |
| `resolved` | 已应用的修改满足它，或 fallback 提出了重命名 |
| `missing` | 记录或槽位缺失，或父链存在循环 |
| `type mismatch` | 候选项具有另一种类型 |
| `index mismatch` | 名称位于另一个索引处，或请求的索引具有另一个名称 |
| `ambiguous` | 多个候选项或冲突的名称声明阻止了匹配 |

`report.families` 包含 `FamilyResult(name, verdict, items)` 记录。当有效映射满足每个需求时，verdict 为 `'usable'`；当应用提案并在没有 fallback 的情况下再次检查后该族得到满足时，为 `'usable after apply'`；否则为 `'not usable'`。只有 `'usable'` 时 `family.usable` 为真。`report.family(name)` 选择一个族；`covered` 只列出可用的族，`items` 将其结果展平，`counts` 是按表格顺序排列的 `(status, count)` 元组。每个结果包含 `family`、`requirement`、`status`、`found`、`change`、`by` 和 `detail`；`found` 是 `PropertyInfo` 或 `None`。`str(report)` 是关于计数、提案、修改和转储配对的 ASCII 摘要，不包含属性名称。

fallback 仅对链可解析但没有精确名称匹配的命名需求运行。传入 `fallback=callable, by='your-rule'`；`by` 必须非空、不含控制字符，且不等于 `'patch'`（没有 fallback 时保持 `None`）。它在检查线程上接收 `(requirement, chain)`，并返回该链中的一个槽位、`None`，或由不同候选槽位组成的元组。多个候选会产生 `ambiguous`；异常会向外传播。答案仍必须满足需求的类型和索引，跨族的冲突声明会被拒绝。提供两个可选启用的函数：

- `index_and_type_fallback` 同时要求 `index` 和 `type`，仅当该链索引处的槽位标签匹配时返回该槽位；它忽略名称。
- `unique_prefix_fallback` 在链内按任一方向的前缀匹配 `_aaa` 名称，使用元素 0 的槽位，并遵守所需类型。较短的前缀必须至少为 **6 个字符**；候选名称在比较前在其第一个 NUL 处截断。多个匹配返回多个候选。

fallback 答案是需要审阅的提案：即使是唯一前缀，当应有的属性缺失时，也可能选中错误的属性。`report.proposed` 包含带守护的重命名修改；请检查它们，然后使用 `u.with_changes(...)` 显式应用已接受的修改并重新检查。任何读取都不会运行 fallback 或应用提案。`report.changes` 保存已应用到 `u` 的修改，与提案分开。

映射记录是不可变的、可哈希的，并且支持 pickle/deepcopy 往返。除 `RecordInfo` 外，每个记录都有 `to_python()` 和 `from_python()`，用于转换为兼容 JSON 的字典；元组变为列表，`None` 变为 JSON `null`。紧凑的模式如下：

| record | dict keys |
| --- | --- |
| `PropertyInfo` | `index`, `element`, `owner`, `own_index`, `name`, `type`, `array_dim` |
| `Requirement` | `struct`, `name`, `index`, `type` |
| `MappingChange` | `kind`, `struct`, `own_index`, `name`, `type`, `array_dim`, `count`, `super`, `properties`, `before`, `by`, `note`; all 12 keys are emitted, and properties are four-item lists |
| `DumpInfo` | `created`, `exe`, `pe_timestamp`, `quality`, `reasons` |
| `RequirementResult` | `family`, nested `requirement`, `status`, nested `found` or `None`, nested `change` or `None`, `by`, `detail` |
| `FamilyResult` | `name`, `verdict`, nested `items` |
| `MappingReport` | `format='nylib.ue.assets.MappingReport'`, `format_version=1`, `file`, `sha256`, `digest`, `version`, `structs`, `enums`, `meta`, `build`, `paired`, `families`, `covered`, `counts` (a dict), `proposed`, `changes`, `custom_serialization`, `summary` |

要归档已应用的修改，请使用 `json.dumps([c.to_python() for c in u.changes])`；重放时使用 `load_usmap(path).with_changes(MappingChange.from_python(d) for d in json.loads(text))`。将原始文件哈希以及任何 meta/custom-serialization 参数与归档一同保存。JSON 默认的 `ensure_ascii=True` 会保留 NUL 和无法解码的名称字节。`MappingReport.from_python()` 可对报告归档进行往返，并验证其格式版本以及派生的配对/计数/覆盖情况；`summary` 仅为显示文本。读取器会拒绝缺失或未知的键以及错误类型；`MappingChange.from_python()` 接受省略的可选键，但使用 `own_index` 而非 `index`。`Usmap` 本身拒绝 pickle 和 copy/deepcopy：应在接收进程中加载文件并重放修改。

`Export.mapping_changes` 和 `Texture.mapping_changes` 按应用顺序列出适用于调用方所查找记录的已应用修改，否则为 `()`。类型化读取会解析整个链，而纹理属性遍历是惰性的，因此这两个元组不必相同。部分导出会列出失败前遇到的修改；其 `problem` 保留错误归因。`Export.mapping_changes` 不参与相等性、哈希和 repr。属性遍历失败（`InvalidMappingError` 和 `UnsupportedAssetError`）携带 `mapping_changes`（失败前查找过的记录），以及 `custom_serialization`（第一个声明的匹配项）：依次为导出的类/父类、属性路径中的结构体（按顺序），然后是错误的类和结构体名称。无关实例（包括映射加载/修改错误）两个属性均为 `None`。

| 失败归因 | 调用方操作 |
| --- | --- |
| 已设置 `custom_serialization` | 声明的自定义布局可能在任何映射下失败 |
| `mapping_changes` 非空 | 先检查这些修改；add/retype/count/record 可能改变布局，rename 不会 |
| 两者皆无，且为 `InvalidMappingError` | 检查 `reason`，了解文件为何不匹配 |
| 两者皆无，且为 `UnsupportedAssetError` | nylib 缺少原生布局或变体 |
| 其他错误类 | 超出映射范围进行排查 |

兼容性：名称、类型和槽位现在遵循有效映射；可选启用的重命名会改变 `Slot.name` 和 `to_python()` 的键。`Installation.identity` 跟随 `usmap.digest`，在没有已应用修改时保持不变。`Installation.usmap` 在 `close()` 之后仍可读取，在安装及其他映射引用释放之前保留已解析的记录（一个被测映射约 26 MiB）。无效的 `usmap=` 类型现在抛出 `TypeError`，消息为 `usmap must be a str, os.PathLike[str] or Usmap, got <type>`；返回 bytes 的 `PathLike` 保持其先前的 bytes 路径错误。现有路径打开保持其读取结果、消息和 repr 不变。新增的 12 个公共名称为 `load_usmap`、`Usmap`、`RecordInfo`、`PropertyInfo`、`MappingChange`、`Requirement`、`RequirementResult`、`FamilyResult`、`MappingReport`、`DumpInfo`、`index_and_type_fallback` 和 `unique_prefix_fallback`；现有导出仍可使用。

<!-- dt:section id="finding-packages-0" hash="142c59dbc544" -->
## 查找包

- `assets.has_package(name) -> bool` 在不读取任何容器数据的情况下进行检查。
- `assets.package(name) -> PackageInfo` 读取包头的摘要块。`name` 接受包路径（`/Game/UI/Icon`）、对象路径（`/Game/UI/Icon.Icon`）或 `.uasset`/`.umap` 文件路径（`Engine/Content/...` 或 `<Project>/Content/...`）；在接受名称的每个方法中（`has_package()`、`package()` 和 `exports()` 会忽略导出部分），名称现在还可以以子对象路径结尾，`/Pkg.Top:Sub.Sub`，通过其外层链命名一个嵌套的导出。这也是 `texture()` 在多个同名 `Texture2D` 导出中选择其中一个的方式：当 `AmbiguousNameError` 列出多个结果时，`texture('<pkg>.<outer>:<name>')` 会选中其中一个。
- `assets.list_packages(prefix='/', *, match=None) -> list[PackageInfo]` 遍历每个挂载容器的目录索引（构建一次，缓存到 `close()` 为止）；`match` 是整个名称上的 `fnmatch` 样式的模式，ASCII 不区分大小写，与 `prefix` 相同。
- 名称大小写：`list_packages()` 报告容器的目录索引为路径记录的大小写；`package()` 和 `texture()` 报告包头本身记录的大小写。两者可能不同——在一个游戏上实测，212 个抽样名称中有 3 个不同，例如 `.../APC/Wavs/...` 与 `.../APC/WAVs/...`——但指的始终是同一个包：`PackageInfo.package_id` 相同，而且所有名称匹配都不区分 ASCII 大小写。
- 插件挂载根：`list_packages()` 也列出位于 `Engine/Plugins/.../Content/...` 或 `<Project>/Plugins/.../Content/...` 目录下的包，命名为 `/<mount>/<rest>`。当 `<mount>` 已经与条目记录的块 id 匹配时，它是插件文件夹名称；否则目录在其第一个不匹配的条目上花费一次摘要读取，从该条目的记录包名称学习 `<mount>`，然后为目录的其余部分重用它（在一个游戏上实测，22,313 个插件根文件中有 106 个需要学到的挂载，来自 2 次学习读取）。学到的 `<mount>` 保持记录名称的大小写；`<rest>` 始终保持目录索引的大小写。
- `.uasset`/`.umap` 文件路径形式不适用于插件根：位于 `Plugins/` 目录下的文件路径仍然会引发 `ValueError`。通过包路径或对象路径形式（`/<mount>/...`）或通过 `list_packages()` 返回的名称来寻址插件根包。

<!-- dt:section id="metadata-0" hash="4394f9aff3c0" -->
## 元数据

- `assets.texture(name) -> Texture` 解析 `Texture2D` 导出并将其头部解析为 `Texture.info`（一个 `TextureInfo`）：`width`、`height`、`pixel_format`、`mips`（每个级别一个 `MipInfo`）、`alpha`（`'none'` 或 `'straight'`）、`virtual`（一个 `VirtualTextureInfo`，或对于普通纹理为 `None`）、`readable` 和 `unsupported`（理由，匹配 `read_region` 会引发的错误）。在一个安装上的第一个 `texture()` 调用较慢；请参阅注释。
- `assets.stats() -> ReadStats` 返回自打开以来的运行总计（`reads`、`bytes_read`、`blocks_decompressed`、`tiles_decoded`、`seconds` 等）；`reads` 现在还统计 `read()`、`Exports.read()`、`raw()` 和 `Exports.raw()` 调用，不仅是区域读取。两个快照之间的差异测量一个跨度；`str(stats)` 是一行摘要。

<!-- dt:section id="reading-regions-0" hash="236c9acbca46" -->
## 读取区域

`tex.read_region(mip, x, y, width, height, *, clip=False, missing='raise', out=None, cancel=None) -> Region` 将像素数据解码为 RGBA8：支持虚拟纹理的 BC1 瓦片，以及普通的 `PF_B8G8R8A8`、`PF_DXT1`（BC1）、`PF_DXT5`（BC3）和 `PF_BC7` mip。先检查 `info.readable`；当它为 False 时，`info.unsupported` 会说明原因。可读的纹理仍可能有某个可选 mip 的容器未安装；读取该 mip 会抛出 `MissingAssetError`（同时也是 `LookupError`），而其他 mip 仍可读取。

- 坐标为 mip `mip` 的像素坐标，原点在左上角，行按从上到下返回；尺寸取自 `info.mips[mip]`，且从不重新缩放。
- 输出为紧凑排列的 RGBA8：`len(region.pixels) == width * height * 4`，不做 sRGB 转换。当 `info.alpha == 'none'` 时，Alpha 始终为 255。
- `clip=True` 会将矩形收缩到 mip 的边界内，而不是抛出异常；`clip=False`（默认）在边界之外时抛出 `RegionOutOfBoundsError`。
- 虚拟纹理：`missing='raise'`（默认）在任一被触及的瓦片未存储时抛出 `MissingTileError`；`'transparent'` 用 `(0, 0, 0, 0)` 填充该区域；`'fallback'` 用 `info.virtual.fallback[0]` 填充该区域。无论哪种策略，`region.missing` 都会列出被填充的矩形，并且只解码矩形所触及的瓦片。
- 普通纹理：`PF_B8G8R8A8` 将存储的 B、G、R、A 字节转换为 R、G、B、A，且只读取被触及的像素行。块格式会读取被触及的整行块，并只解码矩形所触及的 4x4 块；边缘填充的 texel 会裁剪到 mip 自身的尺寸，包括 2x2 和 1x1 的尾部 mip。`PF_DXT1` 的 `alpha='none'`（A = 255）；`PF_B8G8R8A8`、`PF_DXT5` 和 `PF_BC7` 的 `alpha='straight'`（未预乘）。仍然不做 sRGB 转换。由于没有瓦片，`missing` 仅做校验而无其他作用，`region.missing` 始终为 `()`。
- 普通 mip 可能内联存放，也可能位于包的默认 `.ubulk` 中，或位于任一已挂载容器（cooked index 0）中包的可选 `.uptnl` 块中。缺失的可选块只会导致该 mip 的读取失败，且发生在任何 I/O 或第一次 `cancel` 轮询之前；`missing='transparent'` 或 `'fallback'` 不会填充它。
- 无论哪种情况，每个压缩块在单次调用中最多被获取和解压一次，且结果与缓存状态、线程数相同；对于虚拟纹理，在填充区域之外的结果也与 `missing` 策略无关。
- `out=` 写入调用方提供的可写缓冲区，而不是分配新的 `bytes`；`cancel=` 是一个无参可调用对象，在瓦片（虚拟纹理）或压缩块（普通纹理）之间轮询，当其返回真值时抛出 `ReadCancelledError`。

兼容性：在早期版本中，每个普通（非虚拟）纹理都会无条件地从 `read_region` 抛出 `UnsupportedAssetError(feature='non-virtual texture')`。现在，可读的普通纹理可以正常解码；而采用无解码器像素格式的普通纹理会改为抛出 `UnsupportedPixelFormatError`——这与此前不受支持的虚拟纹理层格式的行为一致。这两个错误类都派生自 `UnsupportedError`；如果调用方只在 `read_region` 外围捕获 `UnsupportedAssetError`，就会漏掉新的异常。普通纹理上的 `texture()` 现在也可能抛出 `CorruptAssetError`，原因是某个 mip 的尺寸、`.ubulk` 或已挂载的 `.uptnl` 范围，或序列化尺寸不一致。另外，若插件内容目录的学习读取失败，则只保留已与其文件夹名匹配的条目，其余条目会被丢弃，且仅在 DEBUG 日志中可见。

此前抛出 `UnsupportedPixelFormatError` 的普通 `PF_DXT1`、`PF_DXT5` 和 `PF_BC7` 纹理现在可以解码（在一次实测安装中多出 3,814 个纹理）。对于相同输入，`Installation.identity` 保持不变：升级时请清除缓存的“不可读”判定结果；仅以 identity 为键的缓存将继续保留这些判定。当可选内容缺失时，`info.readable=True` 不再保证每个 mip 都可以读取。

<!-- dt:section id="exports-and-properties-0" hash="ed6a28c2205c" -->
## 导出与属性

```python
# 需要：一个已安装的 UE 5.7 游戏、其 AES 密钥文件和匹配的 .usmap
from nylib.ue.assets import (
    open_installation, AesKey, Exports, ExportInfo, Export, StructValue, Slot,
    MapValue, EnumValue, TextValue, ObjectRef, SoftObjectRef, DataTable, CurveTable,
    AbsentPropertyError, AmbiguousNameError,
)

key = AesKey.from_file('path/to/game-aes.txt')
with open_installation('path/to/MyGame/Content/Paks', engine='5.7',
                        usmap='path/to/MyGame.usmap', build=None, aes_key=key) as assets:
    exp = assets.exports('/Game/Some/DataAsset')             # Exports：仅 cooked 包头，无导出数据
    print(exp.package.name, len(exp))                        # 包名及其导出数量
    export = exp.read(0)                                     # Export：导出 0 的类型化属性
    print(export.info.class_name, export.complete, export.exact, export.native_size)   # class_name 可能为 None，见下文 ExportInfo
    props = export.properties                                # StructValue，导出的顶层槽位
    print(props.struct, len(props.slots), props.state(0))     # 结构体名、槽位数、槽位 0 的状态
    try:
        props.at(0)
    except AbsentPropertyError as e:
        print(str(e))                                        # 未序列化：此处无法得知原型的值
```

- `assets.exports(name, *, cancel=None) -> Exports` 仅读取包的 cooked 包头（不含导出数据），返回一个 `Exports` 句柄：一个 `Sequence[ExportInfo]`，带有 `package`（一个 `PackageInfo`）、`stats`（本次调用的 `ReadStats`）、`find(name) -> ExportInfo`（不涉及 I/O）、`read(which, *, partial=False, cancel=None) -> Export` 以及 `raw(which, *, offset=0, limit, cancel=None) -> bytes`。`which` 可以是索引、名称或子对象路径，也可以是来自该句柄的 `ExportInfo`。直接调用 `Exports(...)` 会引发 `TypeError`；`Exports` 会保持其 `Installation` 处于打开状态，并拒绝被 pickle。调用 `close()` 之后，其 `read()` 和 `raw()` 会引发 `InstallationClosedError`；`len`、索引、迭代以及 `find()` 仍可正常使用。
- `assets.read(target, *, partial=False, cancel=None) -> Export` 直接读取单个导出：`target` 可以是包路径或对象路径（`str`，包含子对象路径）、`ExportInfo`、`ObjectRef` 或 `SoftObjectRef`（见下文"引用"）。`Export` 持有 `info`（`ExportInfo`）、`properties`（一个 `StructValue`）、`native`（一个 `DataTable`、`CurveTable` 或 `None`）、`native_size`（对象尾部之后的字节数，或者在有表格行时，表格行之后的字节数）、`exact`（即 `complete` 且 `native_size == 0`）、`guid`、`complete` 以及 `problem`（一个 `AssetError`，仅在部分读取结果上设置；见下文"部分读取"）。
- `ExportInfo`（来自 `Exports`、`find()` 或 `resolve()`）持有 `package`、`name`、`path`、`index`、`class_name`、`class_ref`、`super_ref`、`template_ref`（后三者为 `ObjectRef`）、`outer`（导出索引或 `None`）、`flags`、`size` 和 `container`。只有当 `class_ref.kind` 为 `'script'`（引擎类）或 `'export'`（同一包中的类）时才会设置 `class_name`；对于从其他包导入的类（蓝图的 `..._C` 类通常以此形式出现），它为 `None`，此时可用 `assets.resolve(info.class_ref).name` 获取类名。
- 对于简单类型（`bool`、`int`、`float`、`str`），每个属性会读取为一个普通的 Python 值，或读取为上述记录之一：引用对应 `ObjectRef` / `SoftObjectRef`，枚举对应 `EnumValue`，`FText` 对应 `TextValue`，数组或集合对应 `tuple`（字节数组则为 `bytes`），映射对应 `MapValue`，可选值对应其自身值或 `None`，结构体对应嵌套的 `StructValue` —— 可能是反射的（通过 `.usmap` 映射解码）或原生的（下文列出的内置布局之一）。
- `StructValue` 是一个只读的 `Mapping[str, object]`，带有 `struct`（其类名或结构体名）、`native`（`bool`）和 `slots`（一个 `Slot` 元组）；`sv[name]`、`sv.at(index)` 和 `sv.state(key)` 可按名称或按架构索引读取。槽位的状态可能是 `'serialized'`（其字节已被存储）、`'zero'`（包头将其标记为未设置；读取为该类型的零值）、`'absent'`（包头从未列出它 —— 真正的值来自类的原型（archetype），而这些数据并未包含该值，因此 `sv[name]` 会引发 `AbsentPropertyError`），或 `'unread'`（仅出现在部分读取结果中）。如果某个名称在类链中被多个属性共用，`sv[name]` 会引发 `AmbiguousNameError`；此时应改用 `sv.at(index)`。
- `StructValue.to_python()` 返回一个仅由列表、字典以及 `str`/`int`/`float`/`bool`/`None` 构成的普通 `dict` —— 可安全用于 `json.dumps(..., allow_nan=False)`；其中的浮点数可能是 NaN 或无穷大，普通的 `json.dumps` 会将其写成非标准 JSON。如果该值的任何槽位为 `'unread'`，它会引发 `problem`。其形状是固定的：

  | 值 | 普通形式 |
  | --- | --- |
  | 一个名称未被共用、所有槽位均为 serialized 或 zero 的属性 | 一个键:其值 |
  | 一个被多个属性共用的名称 | 每个共用该名称的属性一个键，`name#index`（`index` 为基础架构索引） |
  | 一个静态数组，没有缺失元素 | 一个 `list` |
  | 一个有部分缺失元素的静态数组 | 每个存在的元素一个键，`name[element]`（名称也被共用时为 `name#index[element]`） |
  | `MapValue` | 一个由 `[key, value]` 对组成的列表，包括重复的键 |
  | 原生结构体 | 其字段，遵循相同的规则 |
  | `ObjectRef` | 一个包含 `kind`、`package`、`name`、`path` 的字典；`'import'` 引用的 `name` 和 `path` 为 `None`，因此它本身无法标识其目标 —— 当目标很重要时，请先调用 `resolve()` |
  | `SoftObjectRef` | 一个包含 `package`、`asset`、`subpath`、`path` 的字典 |
  | `EnumValue` | 一个包含 `enum`、`name`、`value` 的字典 |
  | `TextValue` | 一个包含 `history`、`string`、`namespace`、`key`、`table`、`data` 的字典 |

  缺失的属性会被省略。关于此类读取可能占用的内存，以及不受信任的 `.usmap` 映射的风险，见下文注释。
- 除了映射所描述的反射形状外，还直接识别 121 个内置（"原生"）结构体布局：简单的固定大小数学类型（`Vector`、`Color`、`Guid`、`Matrix`、`Quat` 等），以及一小部分可变长度的引擎类型（`GameplayTagContainer`、`InstancedStruct` 及其容器/数组形式、属性包类型、`Spline`、`MovieScene*` 通道和求值树类型、`Niagara*` 变量类型、`PCGPointArray` 等）。每个都解码为 `native=True` 的 `StructValue`，每个字段一个 `Slot`，其命名和类型与任何其他属性相同；`slots` 和 `to_python()` 会为给定值列出它们。四种例外的读取方式不同：`InstancedStruct` 直接解码为其载荷值（空类型时为 `None`），而不是 `StructValue`；`InstancedStructContainer` 和 `InstancedStructArray` 解码为载荷的 `tuple`；软路径系列（`SoftObjectPath`、`SoftClassPath`、`StringAssetReference`、`StringClassReference`）解码为 `SoftObjectRef`；`InstancedPropertyBag` 和 `RigVMPropertyBag` 解码为 `native=False` 的 `StructValue`，其槽位可以像任何反射结构体一样是 serialized、zero 或 absent。原生集合之外的结构体名称仍会像任何反射结构体一样通过 `.usmap` 映射读取 —— 见下文"支持的原生结构体"。

<!-- dt:section id="references-0" hash="8d9561004695" -->
## 引用

- 属性值中的引用是 `ObjectRef`（用于 `Object`、`WeakObject` 和 `Interface` 属性；惰性指针则读取为一个普通的 GUID 字符串）或 `SoftObjectRef`（软/资源路径属性）。`ObjectRef.kind` 的取值为 `'null'`、`'export'`（指向同一包内）、`'import'`（指向另一个包，由 `package` 命名并通过其哈希惰性解析）或 `'script'`（引擎类或自身没有 cooked 导出的包，例如 `/Script/Engine.StaticMesh`）；`bool(ref)` 仅在 `'null'` 时为 `False`。两个 `ObjectRef` 仅在指向完全相同的对象时才比较相等，因此从同一个包导入的两个不同导出永远不会比较相等，即使它们的 `kind == 'import'` 且 `package` 相同。指向同一对象的导出引用和导入引用同样比较不相等，因为这两种引用从不携带相同的隐藏标识；当需要匹配的是目标而非引用本身的种类时，应比较 `resolve()` 结果的 `path`。
- `SoftObjectRef` 持有 `package`、`asset`、`subpath` 以及组合后的 `path`；`bool(ref)` 仅在 `path` 为空时为 `False`。
- `assets.resolve(ref, *, cancel=None) -> ExportInfo` 跟随一个 `ObjectRef` 或 `SoftObjectRef` 找到其指向的 `ExportInfo`，只读取目标包的 cooked 包头 -- 绝不读取该导出自身的数据，且调用之间不做任何缓存。`assets.read(ref)` 和 `assets.raw(ref)` 直接接受一个引用，并在一次调用中读取目标的数据。解析 `ObjectRef('null', ...)`，或是指向 `'script'` 对象的引用，会引发 `ValueError`：两者都没有可读取的 cooked 导出。

<!-- dt:section id="tables-and-curves-0" hash="1213dba93abf" -->
## 表与曲线

- `DataTable` 导出的 `Export.native` 是一个 `DataTable` 记录：`row_struct`（行结构体的名称，若来自另一个包则为 `None`——行仍会通过解析出的结构体进行解码）、`row_struct_ref`（一个 `ObjectRef`）以及 `rows`——一个从行名到该行的 `StructValue` 的 `MapValue`，按文件顺序排列。
- `CurveTable` 导出的 `Export.native` 是一个 `CurveTable` 记录：`mode`（`'Empty'`、`'SimpleCurves'` 或 `'RichCurves'`）、`rows`（如上所述，每行是一个 `SimpleCurve` 或 `RichCurve` 的 `StructValue`），以及 `keys(row) -> tuple[StructValue, ...]`——该行的键数组——按顺序排列的 `SimpleCurveKey` 或 `RichCurveKey` 值；对未知的行名，`keys()` 会抛出 `KeyError`。
- 对其他所有类，`Export.native` 均为 `None`；只有当一个类的类链中包含 `DataTable` 或 `CurveTable` 时，该类才会被当作表来读取。

<!-- dt:section id="partial-reads-and-raw-0" hash="308abd55468d" -->
## 部分读取与 `raw()`

- `read(target, *, partial=True)` 在某个属性、对象结尾（trailer）或某个表行解码失败时，返回一个尽力而为的 `Export`，而不是抛出异常：`complete` 为 `False`，`native` 为 `None`，`problem` 保存着非 partial 调用本应抛出的 `AssetError`。`properties` 保留了失败之前已完整读取的所有顶层槽位；失败的那个槽位，以及头部（header）列出的、位于其之后的每个槽位，均为 `'unread'`（读取其中任意一个会重新抛出 `problem`）；头部从未列出的槽位则照常为 `'absent'`。部分读取的值永远不会通过槽位暴露出来。有两种失败情况会使所有顶层槽位都为 `'unread'`，而不会混有 `'absent'`：头部本身解析失败；以及某个类块（class block）自身的槽位会超出解码预算——将未列出的槽位标记为 absent 本身就需要构建出预算所拒绝构建的那些槽位。
- `assets.raw(target, *, offset=0, limit, cancel=None) -> bytes` 和 `Exports.raw(which, ...)` 返回该导出项范围 `[offset, offset + limit)` 内的原始字节，并在导出项结尾处截断，不对任何内容进行解码；`limit` 没有默认值，且必须不超过 64 MiB，这与 `read()` 自身的导出项大小上限相同。只会读取该范围所涉及的压缩块。

<!-- dt:section id="supported-natives-0" hash="18fb291012a6" -->
## 支持的原生结构体

- 除了上文 Exports 和 properties 部分提到的上百种内置布局之外，遇到的其他每个结构体名称都会通过 `.usmap` 映射来读取，方式与任何反射结构体相同——其中包括几个看起来像引擎类型的名称（例如 `BodyInstance`、`ScalarParameterValue`、`VectorParameterValue`、`TextureParameterValue`），它们唯一的原生实现其实属于另一款 UE 游戏；对本游戏而言，这些名称只是普通的无版本数据，具体如何读取由映射自身的记录决定。
- 完全无法读取的结构体名称会抛出 `UnsupportedAssetError`，其中 `feature='native struct <name>'`，`struct_name` 设为该名称，`position` 为其字节开始处。这些情况分为两类：一类是 29 个独立于引擎、不在内置集合中、且在实测安装中从未出现过的原生结构体——`ColorMaterialInput`、`CompressedRichCurve`、`ExpressionInput`、`ScalarMaterialInput`、`VectorMaterialInput`、`Vector2MaterialInput`、`MaterialAttributesInput`、`SkeletalMeshSamplingRegionBuiltData`、`PannerDetails`、`LevelSequenceObjectReferenceMap`、`MaterialLayersFunctionsTree`、`MidiEvent`、`RawAnimSequenceTrack`、`SectionEvaluationDataTree`、`Transform3f`、`TypedParameter`、`UniqueNetIdRepl`、`ClothLODDataCommon`、`ClothLODData`、`ClothTetherData`、`AnimationAttributeIdentifier`、`AttributeCurve`、`PCGPoint`、`CacheEventTrack`、`DataCacheDuplicatedObjectData`、`EdGraphPinType`、`ControlRigOverrideContainer`、`UInt32Property`、`ZeroSizeProperty`——另一类是 74 个其唯一已知布局是为完全不同的另一款游戏编写的原生结构体（例如 `FixedPoint`、`GameplayEffectFloatMapping`、`NiagaraUserParameterModifier`）。无论是哪一类，读取时都会直接抛出异常，而不会去猜测一个本游戏数据未必遵循的布局。

<!-- dt:section id="threads-and-cancellation-0" hash="40cdd715716e" -->
## 线程与取消

- 任意数量的线程可以同时调用 `Installation`、`Exports` 和 `Texture` 的方法；它们只在每次容器块读取和共享块缓存周围短暂地相互等待。记录和 `AesKey` 是不可变的。
- 在文件 I/O、AES 解密和 Oodle 解压期间会释放 GIL；在解析以及 BC1、DXT5 和 BC7 解码期间持有 GIL，这些解码是纯 Python 实现的。
- `close()` 会等待其他线程上正在进行的读取，但不包括调用它的线程自身发起的读取；一旦它返回且自身没有进行中的读取，该安装就不再持有任何文件句柄、锁对象或缓存。
- `Installation`、`Exports`、`Texture`、`AesKey` 和 `Usmap` 拒绝 pickle 以及 `copy`/`deepcopy`；记录、值（包括 `StructValue` 和 `MapValue`）以及错误类可以 pickle 并完成 `deepcopy` 往返。`Usmap` 可以被任意数量的线程和安装共享，包括并发的 `check()` 调用；`load_usmap()` 没有 `cancel=` 参数。
- `exports()`、`read()`、`raw()` 和 `resolve()` 上的 `cancel=` 会在操作涉及的每个压缩块之前检查，在列出包的导出时每隔几千个导出映射条目检查一次，在解码属性或表行时每隔几千个已解码值检查一次。唯一的例外是 cooked 头部解析本身在最后一个块之后的部分：它没有检查点，且耗时随头部大小线性增长。在一次实测安装中，那里的最坏取消延迟约为：主映射的 `exports()` 约 0.2 秒，整个安装中最大的 cooked 头部约 0.45–0.48 秒。

<!-- dt:section id="errors-0" hash="91f0bcadd3eb" -->
## 错误

```text
UeError
└── AssetError                      every nylib.ue.assets failure but argument-type errors; .package, .container, .export
    ├── InvalidKeyError             no/wrong AES key, GUID mismatch, bad key file; .key_guid, .reason, .path
    ├── InvalidMappingError         .usmap missing, invalid, or does not fit the data; .usmap, .class_name, .property_index,
    │                               .property_name, .reason, .path, .property_path, .property_type, .position, .struct_name, .row,
    │                               .mapping_changes, .custom_serialization
    │   └── BuildMismatchError      build= differs from the exe's own stamp; .expected, .found, .exe, .path
    ├── MissingAssetError           package, export or optional mip not in a mounted container (a LookupError)
    │   └── MissingTileError        missing='raise' hit an unstored VT tile; .mip, .tiles
    ├── UnsupportedError             outside the supported profile; .feature
    │   ├── UnsupportedContainerError    TOC version, AES mode, compression method, or no usable Oodle
    │   ├── UnsupportedAssetError         asset class or native layout; .exports, .class_name, .property_index,
    │   │                                 .property_name, .property_path, .property_type, .position, .struct_name, .row,
    │   │                                 .mapping_changes, .custom_serialization
    │   └── UnsupportedPixelFormatError   no decoder for this pixel format; .pixel_format
    ├── CorruptAssetError            structure or codec check failed; .detail (a block decode's __cause__ is an OodleError)
    ├── RegionOutOfBoundsError       rectangle or mip out of range (a ValueError); .mip, .rect, .size
    ├── ReadCancelledError           cancel() returned true
    ├── InstallationClosedError      the installation is already closed (a ValueError)
    └── AbsentPropertyError          a property slot was not serialized, so its value is the archetype's one nylib does not
                                      hold (also a KeyError); .class_name, .property_index, .property_name
```

- 参数类型错误抛出 `TypeError`，参数值错误抛出 `ValueError`，绝不会抛出上面列出的类，唯一例外是 `RegionOutOfBoundsError`，它既是 `AssetError` 也是 `ValueError`。`Exports` 的索引越界，或 `StructValue.at()` 或 `StructValue.state()` 的索引越界，抛出 `IndexError`；`sv[name]` 或 `CurveTable.keys()` 的未知名称抛出 `KeyError`。
- `AmbiguousNameError`（从 `nylib.ue` 重新导出，不在 `AssetError` 之下）在包名或对象路径的导出名匹配多个 Texture2D 导出时由 `texture()` 抛出，在名称匹配多个导出时由 `read()`、`raw()` 和 `Exports.find()` 抛出；它不是 `AssetError`。
- `AbsentPropertyError` 同时也是 `KeyError`，但它覆写了 `__str__`，因此即使 `KeyError` 会为消息加引号，`str(err)` 仍是纯文本消息；`StructValue.get()` 和 `in` 将其视为缺失，与真正的 `KeyError` 一样。部分 `Export`（见下文）携带的 `problem` 绝不是 `KeyError`，因此 `get()` 不会悄悄地把未读取的属性变成默认值。
- 在读取单个导出的属性时发现的失败——在属性块、对象尾部、表行或原生结构体内部引发的 `InvalidMappingError` 或 `UnsupportedAssetError`——会携带 `property_path`：从导出的类到失败处的各个步骤，例如 `WDWeaponStatsData#1.WDWeaponStats#36`，数组索引写作 `[3]`，映射的键或值写作 `[key 0]` / `[value 0]`，表行写作 `[row 2]`。`class_name`、`property_index`、`property_name` 和 `property_type` 描述最后一步；`position` 是失败读取开始的位置；`struct_name` 在存在时命名相关的原生结构体；`row` 在失败位于某一表行内部时命名该表行。消息本身仍然从不重复属性名或行名，这些名称只保存在属性中。
- 消息为一行英文；除基本文件名外绝不包含路径，也不包含密钥材料、解密或解码后的字节、映射文件内容或属性名。`load_usmap()` 将映射/元数据失败报告为 `InvalidMappingError`；缺少元数据文件时 `reason='meta.json not found'`，UTF-8/JSON 无效时为 `'meta.json not JSON'`，转储模式错误时为 `'meta.json schema'`。`with_changes()` 的拒绝情况为 `reason='change does not apply'`；名称请检查属性和变更记录。报告摘要和需求详情同样省略属性名。

<!-- dt:section id="supported-profile-0" hash="7d71a3f75dc9" -->
## 支持的范围

| 层 | 本版本支持 | 超出部分 |
|---|---|---|
| 容器 | IoStore TOC v8，一个或多个分区（分区 `p >= 1` 从 `<base>_s<p>.ucas` 读取）；AES-256-ECB；Oodle（Kraken）和存储块（stored blocks）；压缩块大小为 2 的幂，从 4 KiB 到 16 MiB | `UnsupportedContainerError`（分区数为 0：`feature='zero partitions'`；只要有一个这样的容器，`open_installation` 就会对整个安装失败）；分区文件缺失或块跨越分区末尾：`CorruptAssetError`；`.pak` 会列在 `containers` 中，但从不挂载 |
| 映射 | `.usmap` v0-v4；压缩方式 None、Oodle、ZStd（需要 Python 3.14+）；可复用的 `Usmap`、内存中的修改和依赖检查 | `InvalidMappingError`；没有 `.usmap` 写入器，也没有自动名称修复 |
| 包 | zen 包，无版本属性 | `InvalidMappingError`、`CorruptAssetError` |
| 导出与类型化属性 | 每种属性类型和引用（`exports()`、`read()`、`raw()`、`resolve()`）；121 种内置原生结构布局；其他任何结构名称通过 `.usmap` 映射读取 | 本版本不读取的原生结构（见上方 Supported natives）：`UnsupportedAssetError` |
| 纹理元数据 | 每个 `Texture2D` 导出，包括虚拟纹理和普通纹理 | 其他类：`UnsupportedAssetError` |
| 虚拟纹理区域读取 | `RawGPU` 编解码器，单层，`PF_DXT1`，非旧版 tile 布局 | `UnsupportedAssetError` / `UnsupportedPixelFormatError`；`info.readable` 为 False，并说明原因。其他任何虚拟纹理层格式（包括 `PF_DXT5` 和 `PF_BC7`）仍会报告 `has no decoder in this nylib version`，尽管这些格式在普通纹理上可以解码 |
| 普通纹理区域读取 | `PF_B8G8R8A8`、`PF_DXT1`、`PF_DXT5`、`PF_BC7`；内联 mip、默认 `.ubulk` 或可选 `.uptnl`（烘焙索引 0，位于任何已挂载的容器中） | 其他像素格式：`UnsupportedPixelFormatError`；没有序列化的 mip、mip 数据未与纹理一同序列化、压缩或内存映射的批量数据（`.m.ubulk`）、其他烘焙索引、可选块分布在多个容器中、可选数据同时标记为内联，或任何其他位置：`UnsupportedAssetError`；`info.readable` 为 False，并说明原因。未挂载的可选块会使 `info.readable=True` 保持不变，但该 mip 的读取会抛出 `MissingAssetError` |

<!-- dt:section id="notes-0" hash="9be337b05d80" -->
## 说明

- 不做重采样：mip 的像素以该 mip 自身的尺寸返回；缩放由调用方负责。
- BC1、DXT5 和 BC7 解码都是纯 Python 实现：它们持有 GIL，因此大范围读取在解码期间受单核限制。在一台机器上对整个 mip 的原型测量显示，DXT1 约为 25-30 Mpx/s，DXT5 约为 2.6-2.9 Mpx/s，BC7 约为 0.6-1.0 Mpx/s，具体取决于块内容。按这些速率，整个 4096x4096 的 BC7 mip 需要约 17-27 s；交互式读取请使用有界区域。
- 在一台其他任务同时运行的机器上测得：普通 512x512 区域读取的 p50 耗时，DXT1 约为 27 ms，DXT5 约为 97 ms，BC7 约为 239 ms（分别为 16、32 和 32 个压缩块）。2x2 采样在 1 个块上的 p50 约为 0.07-0.13 ms，其中包括可选 `.uptnl` mip 约 0.09 ms。这些格式测得的取消延迟分别约为 13 ms、24 ms 和 60 ms；轮询发生在压缩块之间，因此延迟包含两次轮询之间的解码工作。这些数据不能说明冷缓存下的性能。
- 安装对象上首次调用 `texture()`、`exports()`、`read()`、`raw()` 或 `resolve()` 时，会一次性加载全局 ScriptObjects 表（在被测游戏上约 4.66 MB），在一台被测机器上总耗时约 0.42 s，其中几乎全部是加载开销；之后的调用会复用该表。
- 与 CUE4Parse 相比：DXT1 中索引为 3 的三色纹素，这里是不透明黑色 `(0, 0, 0, 255)`，而 CUE4Parse 给出 alpha 0。DXT5 严格遵循其 BCDecoder 的运算，包括 alpha 插值的舍入以及强制四色块。BC7 遵循 BPTC 规范，与 CUE4Parse 的 AssetRipper 路径一致；其 Windows Detex 路径在模式 6 中某个通道可能相差 1。不在 4 像素网格上的 mip 会被解码为填充块，再裁剪到其声明尺寸；CUE4Parse 的 BC1/BC3 解码器无法解码这些尺寸，其 BC7 路径则返回填充后的图像。
- 近似值，一台机器：`open_installation` 耗时约 0.22 s（其中约 0.15 s 用于解析一个 `.usmap`；一个 3.3 MB 的较大映射文件，其原型解析耗时约 0.26 s，并保留约 26 MiB）；无论 `cache_bytes` 为 0、默认的 4 MiB 还是 16 MiB，区域读取的 p50 都约为 30 ms——瓶颈在解码，因此更大的缓存主要对同一瓦片的重复读取有帮助。
- 在一台其他任务同时运行的机器上，使用 Python 3.12/3.14 测得：`load_usmap()` 在三个映射文件上耗时约 0.15-0.30 s，峰值工作集增长约 17-31 MiB。检查 100 个需求，在没有回退时约需 2.6-4.1 ms，使用前缀回退及其应用/重新检查步骤（6 个提议）时约需 6.4-7.5 ms。应用 3,167 个合成重命名约需 35-47 ms，另加约 7-12 ms 用于摘要计算。使用已加载的映射打开耗时约 68-94 ms，而通过其路径打开为 387-437 ms；在 1,598 次读取中，映射变更归因的 p50 开销约为 5-6 微秒。这些都是近似观测，不是冷缓存测量，也不是吞吐量保证。
- 近似值，一台机器，普通纹理的地形瓦片（`PF_B8G8R8A8`，`.ubulk` mip）：2x2 采样在 1 个压缩块上约耗时 0.1 ms；mip 0 读取的 p50 约为 2.5 ms，`cancel=` 大约每个压缩块轮询一次，在被测瓦片上约每 0.3 ms 一次——它本身不会增加那么多延迟。`list_packages()` 的首次调用还会学习插件挂载根，耗时 4.25-5.0 s。
- 近似值，一台机器，导出与类型化读取：主地图的已烹饪头部的 `exports()` 耗时约 0.28-0.30 s，并保留约 35-38 MiB；小导出的 `read()` 的 p50 远低于 1 ms；通过 `Exports` 句柄进行的 64 字节 `raw()` 读取了 1 个压缩块（当范围跨越块边界时为 2 个）；通过 `assets.raw()` 则读取了 3 个，因为该调用还会读取目标的已烹饪头部。在安装包中每六十分之一的抽样中（1,787 个包，21,141 个导出），整个遍历本身耗时数秒；该抽样中解码值最多的导出（394,305 个，一个 `AudioImpulseResponse`）约在 0.13 s 内读完，相对基线的峰值工作集增长约 17 MiB。在主地图的 `exports()` 期间取消，p50 延迟约为 93 ms（最坏情况 198 ms，来源于上文“线程与取消”一节中提到的间隔）；在解码中途取消约为 1 ms。
- 单次 `read()` 的限制：已烹饪头部或导出数据超过 64 MiB 会抛出 `CorruptAssetError`；结构嵌套超过 16 层的值会以原因 `struct nesting` 抛出 `InvalidMappingError`，计入容器后超过 64 层的会以 `value nesting` 抛出；解码值与已构建槽位之和超过导出字节数加 65,536 的读取会抛出 `decode budget`。在一个被测安装中，没有导出触及后两项限制，最大的读取在 65,536 之上每字节使用 0.375 个单位。
- 内存随解码出的值增长，这些值是 Python 对象：当结果存活时，主要由小型原生结构体组成的导出，每个输入字节最多保留约 190 字节，因此 64 MiB 的 `Color` 值导出会占用约 12 GiB。请一次读取一个大导出，或改用 `raw()`。
- `.usmap` 是受信任的输入：对于手工构造的映射，两次读取得到的值之间的 `==` 比较以及 `to_python()` 在几个字节的数据上也可能耗时数秒，因为它们会展开一次读取所共享的零掩码结构体。
- 仅限 Windows x64（AES 使用 BCrypt；涉及可执行文件的 PE 以及 `.ucas`/`.utoc` 布局）。AES 密钥文件及其内容属于机密：切勿记录、打印或提交，应通过路径传递。
