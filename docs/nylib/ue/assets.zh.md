> 本文档为 assets.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="assets.md" -->

<!-- dt:section id="__preamble__" hash="04560f388810" -->
# nylib.ue.assets

对 UE 5.7 游戏的 IoStore（`.utoc`/`.ucas`）容器进行只读读取：枚举包（包括插件挂载根目录下的包），读取 `Texture2D` 元数据，读取类型化的导出属性和跨包引用，并将虚拟纹理 BC1 瓦片以及普通的 `PF_B8G8R8A8`、`PF_DXT1`、`PF_DXT5` 和 `PF_BC7` 纹理的有界区域解码为 RGBA8，包括以可选批量数据（`.uptnl`）形式存储的普通 mip。基于 Python，AES 使用 Windows BCrypt，解压缩使用随附的 Oodle DLL；不依赖 FModel、CUE4Parse 或 Unreal。

Keywords: IoStore, utoc, ucas, AesKey, open_installation, Installation, Texture, virtual texture, VT, BC1, DXT1, DXT5, BC7, B8G8R8A8, .uptnl, ordinary texture, plugin, read_region, usmap, mapping, zen package, PackageInfo, TextureInfo, Region, ScriptObjects, Oodle, Exports, StructValue, DataTable, CurveTable, native struct, ObjectRef, pak, read_file, FileInfo, locres, locmeta, localization, InstanceData, instanced mesh

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

<!-- dt:section id="loose-files-0" hash="440dc7904c37" -->
## 散文件

同一个安装实例可以读取旧版 `.pak` 版本 11 和 12 的散文件，包括加密条目。打开时仍然需要 `.usmap` 和 IoStore 安装；没有独立的 `.pak` 打开器。`.pak` 内的包保持未挂载：对于已挂载的 IoStore 包，请使用包 API。

```python
# 需要：一个名为 assets 的已打开 Installation，且其中包含所列的散文件
path = 'Wardogs/Content/Localization/Game/en/Game.locres'
info = assets.file(path)
data = assets.read_file(info)
sample = assets.read_file(path, offset=100000, limit=70000)
print(info.size, len(data), len(sample))
```

- `assets.has_file(path: str) -> bool` 检查某个已列出的路径；`assets.file(path: str) -> FileInfo` 返回其记录，若不存在则抛出 `MissingAssetError`。
- `assets.list_files(prefix='', *, match=None) -> list[FileInfo]` 返回一个新列表，按路径前缀以及可选的、针对整个路径的 `fnmatch` 模式进行过滤。两者都按 ASCII 不区分大小写匹配；两个过滤参数都允许任意字符串。结果按 `(ASCII-lower(path), path, container)` 排序。
- `FileInfo` 是不可变的：`path` 保留索引中的大小写，`container` 是 `.pak` 的基本文件名，`size` 是未压缩字节数，`stored_size` 是存储字节数，`compression` 为 `'None'`、方法名，或对于未命名方法索引为 `'#k'`，`encrypted` 描述条目本身。将 `FileInfo` 传给 `read_file()` 时只使用其 `path`，并在该安装实例中查找。
- 查找路径是非空的相对路径，使用 `/` 分隔符，例如上面的示例。反斜杠、开头或结尾的 `/`、空段（`//`），以及 `.` 或 `..` 段都会抛出 `ValueError`；查找按 ASCII 不区分大小写进行。条目路径会将挂载点（去掉开头的 `../../../`）、目录和文件名拼接起来，合并重复的 `/` 并去掉开头的 `/`。无效的条目路径、超过 1,024 个字符的路径、控制字符、Unicode 行/段落分隔符、孤立代理项以及无法解码的文件名都会被跳过，删除记录同样会被跳过。
- 重复路径（包括同一 `.pak` 内的大小写变体）不会按补丁顺序解析：`has_file()` 返回 True，`list_files()` 会列出两者，但 `file()` 和 `read_file()` 会抛出 `UnsupportedContainerError(feature='patch containers')`。
- 这四个调用中的第一个会加载所有可识别的 `.pak` 索引，校验两个索引的 SHA-1 哈希，并将结果保留到 `close()`。加密索引使用打开时提供的、GUID 与页脚匹配的 `aes_key=`；不会再次读取密钥文件。密钥缺失或错误会抛出 `InvalidKeyError`，索引损坏会抛出 `CorruptAssetError`，其他版本会抛出 `UnsupportedContainerError(feature='pak version <v>')`，没有完整目录索引则会抛出 `UnsupportedContainerError(feature='pak without a full directory index')`。任何失败都会丢弃整个加载结果；下一次调用会重新尝试。打开本身仍只读取页脚，因此这些失败会在首次使用散文件时出现。
- `assets.read_file(path, *, offset=0, limit=None, cancel=None) -> bytes` 只读取范围所涉及的压缩块，对于存储条目则按 64 KiB 分块读取。`offset` 必须是不大于 `size` 的非负整数；`limit` 是 0 到 67,108,864（64 MiB）之间的整数，或为 `None`（表示从 `offset` 读到末尾），同样受此上限约束。这里布尔值不被视为整数。显式指定的 limit 会在 EOF 处截断；空范围返回 `b''`。无效参数会在任何 I/O 之前失败。超过上限的文件可以分段读取。
- 只支持 `'None'` 和 `'Oodle'` 压缩；其他方法会抛出 `UnsupportedContainerError(feature='compression <method>')`。加密条目同样使用 `.pak` 页脚 GUID 对应的密钥；密钥缺失会抛出 `InvalidKeyError`。在解密之前，AES 窗口会按 16 字节对齐，解密后再截取所请求的范围。读取使用调用本地的句柄，并绕过共享的块缓存。`read_file()` 返回 UE 存储的原始字节；游戏为这些字节添加的加密由调用方自行处理。

一个密钥校验的限制：如果条目是加密的，但其索引未加密，并且没有其他任何东西校验该 GUID 对应的密钥，那么错误的密钥会对存储条目返回错误的字节；对于压缩条目，则会抛出 `CorruptAssetError`。实测的安装实例全部使用加密索引，因此该情况在那里没有被测试。

兼容性：`.pak` 行仍然具有 `mounted=False`。受支持的 221 字节页脚的 `reason` 现在为 `'legacy .pak: loose files only, through read_file()'`。其他版本保持 `'legacy .pak is not read by this nylib version'`；可识别的 222、225 和 262 字节页脚现在会报告其版本和索引加密标志，并带有 `compression=()`，但不会进一步读取。无法识别或无法读取的页脚保留其原有原因，并在索引加载时被跳过。`Installation.identity` 及其 repr 保持不变，不会标识 `.pak` 的内容；密钥本地化按 `Locres.sha256` 进行缓存。`nylib.ue.assets.__all__` 中新增的七个惰性公共名称（现为 59 个）为 `FileInfo`、`parse_locres`、`parse_locmeta`、`Locres`、`LocresEntry`、`Locmeta` 和 `InstanceData`；`nylib.ue.__all__` 保持不变。

<!-- dt:section id="localization-0" hash="3ee60b16f34e" -->
## 本地化

`parse_locres(data, *, file=None) -> Locres` 读取版本 3；`parse_locmeta(data, *, file=None) -> Locmeta` 读取版本 2。两者都接受 `bytes`、`bytearray` 或 `memoryview`，不保留对可变输入的引用，并使用可选的字符串 `file=` 作为错误上下文。其他版本会抛出 `UnsupportedAssetError`，其 `feature='locres version <v>'` 或 `'locmeta version <v>'`；缺少 `.locres` 魔数时按旧版本 0 处理。缺少 `.locmeta` 魔数以及受支持版本的格式错误数据会抛出 `CorruptAssetError`。在一个实测安装中，82 个 `.locres` 中只有 38 个、8 个 `.locmeta` 中只有 2 个具有受支持的版本；较旧的文件会被拒绝。

```python
# 需要：名为 assets 的已打开 Installation，以及名为 tv 的 Base TextValue
from nylib.ue.assets import Locres, parse_locres, parse_locmeta

root = 'Wardogs/Content/Localization/Game/'
meta_path = root + 'Game.locmeta'
meta = parse_locmeta(assets.read_file(meta_path), file=meta_path)
loc_path = root + meta.native_locres
loc = parse_locres(assets.read_file(loc_path), file=loc_path)
translated = tv.string
if tv.history == 'Base':
    try:
        entry = loc.entry(tv.namespace, tv.key)
    except KeyError:
        pass
    else:
        if Locres.source_hash(tv.string) == entry.source_hash:
            translated = entry.string
```

- `Locres` 是不可变的，且只能由 `parse_locres()` 创建：`version`、`sha256`（完整输入的 SHA-256）、`namespaces` 和 `entries`（按文件顺序排列的元组）。空的 namespace 会被保留。`len(loc)` 统计条目数；`loc.get(namespace, key, default=None)` 返回本地化字符串或默认值；`loc.entry(namespace, key)` 返回 `LocresEntry`，否则抛出 `KeyError`。两个查找参数都必须是字符串。每个条目包含 `namespace`、`key`、`string` 以及存储的无符号 32 位 `source_hash`。相等性与哈希比较 version、namespaces 和 entries，不包括 `sha256`。
- `Locres.source_hash(text)` 实现 UE 的 `FCrc::StrCrc32`：取第一个 NUL 之前的文本，按 UTF-16 代码单元（代理对计为两个单元）计算，每个单元以四个小端字节输入 CRC-32。空文本的哈希值为 0。如上所述，在替换 `Base` 文本之前，应将其与条目的源哈希进行比较；解析器本身不提供过期策略。
- `Locmeta` 包含 `version`、`native_culture`、`native_locres`（相对于元数据文件所在文件夹）、`cultures`（按文件顺序排列的已编译 culture 元组）和 `ugc`（`bool`）。列出的 culture 不必在安装中存在对应的 `.locres`。
- 不存在自动 culture 回退、目标合并或 `TextValue.localize()`。`StringTableEntry` 文本需要来自 `StringTable` 原生尾部的 namespace，而本读取器不解码该部分。
- 两个解析器都持有 GIL，且不接受 `cancel=`。安装关闭后其记录仍可使用，并支持 pickle 和 `deepcopy`。

<!-- dt:section id="metadata-0" hash="c12f4de5f5b1" -->
## 元数据

- `assets.texture(name) -> Texture` 解析 `Texture2D` 导出项，并将其头部解析为 `Texture.info`（一个 `TextureInfo`）：`width`、`height`、`pixel_format`、`mips`（每个 mip 级别一个 `MipInfo`）、`alpha`（`'none'` 或 `'straight'`）、`virtual`（一个 `VirtualTextureInfo`，普通纹理则为 `None`）、`readable`，以及 `unsupported`（原因，与 `read_region` 会抛出的错误一致）。安装中第一次调用 `texture()` 较慢；参见注释。
- `assets.stats() -> ReadStats` 返回自打开以来的累计总数（`reads`、`bytes_read`、`blocks_decompressed`、`tiles_decoded`、`seconds` 等）；`reads` 还会统计 `read()`、`Exports.read()`、`raw()`、`Exports.raw()` 和 `read_file()` 的调用次数。两个快照相减即可测量一段时间；`str(stats)` 为单行摘要。
- `has_file()`、`file()` 和 `list_files()` 不会增加 `reads`。加载松散文件索引的调用会为每个 `.pak` 计入两个 `blocks_read`（主索引和目录索引），其存储字节计入 `bytes_read`，并计入 I/O/AES 时间。`read_file()` 会计入每个压缩块或存储片段的读取，包括加密对齐字节，并按适用情况计入 Oodle/AES 计数器，不计缓存命中。本地化解析器不增加任何计数；实例尾部解析计入导出读取的 `seconds_decode`。

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

<!-- dt:section id="exports-and-properties-0" hash="2d5ea55f2eec" -->
## 导出与属性

```python
# 需要：一个已安装的 UE 5.7 游戏、其 AES 密钥文件以及匹配的 .usmap
from nylib.ue.assets import (
    open_installation, AesKey, Exports, ExportInfo, Export, StructValue, Slot,
    MapValue, EnumValue, TextValue, ObjectRef, SoftObjectRef, DataTable, CurveTable,
    AbsentPropertyError, AmbiguousNameError,
)

key = AesKey.from_file('path/to/game-aes.txt')
with open_installation('path/to/MyGame/Content/Paks', engine='5.7',
                        usmap='path/to/MyGame.usmap', build=None, aes_key=key) as assets:
    exp = assets.exports('/Game/Some/DataAsset')             # Exports：仅包含烘焙后的头部，没有导出数据
    print(exp.package.name, len(exp))                        # 包名及其导出数量
    export = exp.read(0)                                     # Export：导出 0 的类型化属性
    print(export.info.class_name, export.complete, export.exact, export.native_size)   # class_name 可能为 None，见下文 ExportInfo
    props = export.properties                                # StructValue，即该导出的顶层槽位
    print(props.struct, len(props.slots), props.state(0))     # 结构体名称、槽位数量、槽位 0 的状态
    try:
        props.at(0)
    except AbsentPropertyError as e:
        print(str(e))                                        # 未序列化：此处不知原型的值
```

- `assets.exports(name, *, cancel=None) -> Exports` 仅读取包的烘焙头部（无导出数据），并返回一个 `Exports` 句柄：即一个 `Sequence[ExportInfo]`，带有 `package`（一个 `PackageInfo`）、`stats`（本次调用的 `ReadStats`）、`find(name) -> ExportInfo`（无 I/O）、`read(which, *, partial=False, cancel=None, instances=False) -> Export` 以及 `raw(which, *, offset=0, limit, cancel=None) -> bytes`。`which` 可以是索引、名称或子对象路径，也可以是来自该句柄的 `ExportInfo`。直接调用 `Exports(...)` 会抛出 `TypeError`；`Exports` 会使其 `Installation` 保持存活，并拒绝 pickle。调用 `close()` 之后，其 `read()` 和 `raw()` 会抛出 `InstallationClosedError`；`len`、索引、迭代以及 `find()` 仍然可用。
- `assets.read(target, *, partial=False, cancel=None, instances=False) -> Export` 直接读取一个导出：`target` 可以是包或对象路径（`str`，包括子对象路径）、一个 `ExportInfo`、一个 `ObjectRef` 或一个 `SoftObjectRef`（见下文的引用）。`Export` 包含 `info`（`ExportInfo`）、`properties`（一个 `StructValue`）、`native`（一个 `DataTable`、`CurveTable`、`InstanceData` 或 `None`）、`native_size`（在尾部及任何已解码的原生尾部之后未消耗的字节数）、`exact`（`complete` 且 `native_size == 0`）、`guid`、`complete` 以及 `problem`（一个 `AssetError`，仅在部分结果中设置；见下文的部分读取）。
- `ExportInfo`（来自 `Exports`、`find()` 或 `resolve()`）包含 `package`、`name`、`path`、`index`、`class_name`、`class_ref`、`super_ref`、`template_ref`（后三者为 `ObjectRef`）、`outer`（导出索引或 `None`）、`flags`、`size` 和 `container`。仅当 `class_ref.kind` 为 `'script'`（引擎类）或 `'export'`（同一包中的类）时才会设置 `class_name`；对于从其他包导入的类（蓝图的 `..._C` 类通常以这种方式出现），它为 `None`，此时可通过 `assets.resolve(info.class_ref).name` 获得类名。
- 对于简单类型（`bool`、`int`、`float`、`str`），每个属性会读取为普通的 Python 值；对于其他类型，则读取为上述记录之一：引用为 `ObjectRef` / `SoftObjectRef`，枚举为 `EnumValue`，`FText` 为 `TextValue`，数组或集合为 `tuple`（字节数组则为 `bytes`），映射为 `MapValue`，可选类型为其值本身或 `None`，结构体为嵌套的 `StructValue`——既可以是反射的（通过 `.usmap` 映射解码），也可以是原生的（下文内置布局之一）。
- `StructValue` 是只读的 `Mapping[str, object]`，具有 `struct`（其类或结构体名称）、`native`（`bool`）和 `slots`（`Slot` 的元组）；`sv[name]`、`sv.at(index)` 和 `sv.state(key)` 分别按名称或按架构索引读取。槽位的状态可以是 `'serialized'`（其字节已存储）、`'zero'`（头部将其标记为未设置；读取时为其类型的零值）、`'absent'`（头部从未列出它——真实值属于类的原型，而此数据不包含该原型，因此 `sv[name]` 会抛出 `AbsentPropertyError`），或 `'unread'`（仅出现在部分结果中）。若某个名称在类链中被多个属性共享，则 `sv[name]` 会抛出 `AmbiguousNameError`；此时请改用 `sv.at(index)`。
- `StructValue.to_python()` 返回一个普通的 `dict`，它仅由列表、字典以及 `str`/`int`/`float`/`bool`/`None` 构成——可安全用于 `json.dumps(..., allow_nan=False)`；其中的浮点数可能是 NaN 或无穷大，普通的 `json.dumps` 会将其写成非标准 JSON。如果该值的任一槽位为 `'unread'`，则会抛出 `problem`。其形式是固定的：

  | 值 | 普通形式 |
  | --- | --- |
  | 名称未被共享的属性，其所有槽位均已序列化或为零 | 一个键：其值 |
  | 被多个属性共享的名称 | 每个共享该名称的属性一个键，即 `name#index`（`index` 为基础架构索引） |
  | 静态数组，无缺失元素 | 一个 `list` |
  | 含部分缺失元素的静态数组 | 每个存在的元素一个键，即 `name[element]`（若名称同时被共享，则为 `name#index[element]`） |
  | `MapValue` | 由 `[key, value]` 对组成的列表，允许重复的键 |
  | 原生结构体 | 其字段，遵循相同规则 |
  | `ObjectRef` | 包含 `kind`、`package`、`name`、`path` 的字典；`'import'` 引用的 `name` 和 `path` 为 `None`，因此它本身无法标识其目标——当目标很重要时，请先调用 `resolve()` |
  | `SoftObjectRef` | 包含 `package`、`asset`、`subpath`、`path` 的字典 |
  | `EnumValue` | 包含 `enum`、`name`、`value` 的字典 |
  | `TextValue` | 包含 `history`、`string`、`namespace`、`key`、`table`、`data` 的字典 |

  缺失的属性会被省略。关于此类读取在内存方面的开销，以及不受信任的 `.usmap` 映射所带来的风险，请见下文的注意事项。
- 除了映射所描述的反射形式之外，还可直接识别 121 种内置（“原生”）结构体布局：简单的定长数学类型（`Vector`、`Color`、`Guid`、`Matrix`、`Quat` 等），以及一小部分变长引擎类型（`GameplayTagContainer`、`InstancedStruct` 及其容器/数组形式、属性包类型、`Spline`、`MovieScene*` 通道与求值树类型、`Niagara*` 变量类型、`PCGPointArray` 以及其他一些类型）。每个类型都解码为 `StructValue`，其 `native=True`，每个字段对应一个 `Slot`，其命名和类型方式与其他任何属性相同；对于给定的值，`slots` 和 `to_python()` 会列出它们。有四个例外，读取方式不同：`InstancedStruct` 直接解码为其负载值（若为空类型则为 `None`），而非 `StructValue`；`InstancedStructContainer` 和 `InstancedStructArray` 解码为由负载组成的 `tuple`；软路径系列（`SoftObjectPath`、`SoftClassPath`、`StringAssetReference`、`StringClassReference`）解码为 `SoftObjectRef`；`InstancedPropertyBag` 和 `RigVMPropertyBag` 解码为 `native=False` 的 `StructValue`，其槽位与任何反射结构体一样可以是已序列化、零值或缺失。原生集合之外的结构体名称仍会像任何反射结构体一样通过 `.usmap` 映射读取——见下文的受支持原生类型。

<!-- dt:section id="references-0" hash="8d9561004695" -->
## 引用

- 属性值中的引用是 `ObjectRef`（用于 `Object`、`WeakObject` 和 `Interface` 属性；惰性指针则读取为一个普通的 GUID 字符串）或 `SoftObjectRef`（软/资源路径属性）。`ObjectRef.kind` 的取值为 `'null'`、`'export'`（指向同一包内）、`'import'`（指向另一个包，由 `package` 命名并通过其哈希惰性解析）或 `'script'`（引擎类或自身没有 cooked 导出的包，例如 `/Script/Engine.StaticMesh`）；`bool(ref)` 仅在 `'null'` 时为 `False`。两个 `ObjectRef` 仅在指向完全相同的对象时才比较相等，因此从同一个包导入的两个不同导出永远不会比较相等，即使它们的 `kind == 'import'` 且 `package` 相同。指向同一对象的导出引用和导入引用同样比较不相等，因为这两种引用从不携带相同的隐藏标识；当需要匹配的是目标而非引用本身的种类时，应比较 `resolve()` 结果的 `path`。
- `SoftObjectRef` 持有 `package`、`asset`、`subpath` 以及组合后的 `path`；`bool(ref)` 仅在 `path` 为空时为 `False`。
- `assets.resolve(ref, *, cancel=None) -> ExportInfo` 跟随一个 `ObjectRef` 或 `SoftObjectRef` 找到其指向的 `ExportInfo`，只读取目标包的 cooked 包头 -- 绝不读取该导出自身的数据，且调用之间不做任何缓存。`assets.read(ref)` 和 `assets.raw(ref)` 直接接受一个引用，并在一次调用中读取目标的数据。解析 `ObjectRef('null', ...)`，或是指向 `'script'` 对象的引用，会引发 `ValueError`：两者都没有可读取的 cooked 导出。

<!-- dt:section id="tables-and-curves-0" hash="c04ed9d1c7a5" -->
## 表与曲线

- `DataTable` 导出项的 `Export.native` 是一条 `DataTable` 记录：`row_struct`（行结构体的名称；当它来自另一个包时为 `None`，行仍通过已解析的结构体解码）、`row_struct_ref`（一个 `ObjectRef`）以及 `rows`，即从行名到该行 `StructValue` 的 `MapValue`，按文件顺序排列。
- `CurveTable` 导出项的 `Export.native` 是一条 `CurveTable` 记录：`mode`（`'Empty'`、`'SimpleCurves'` 或 `'RichCurves'`）、`rows`（同上，每行为一个 `SimpleCurve` 或 `RichCurve` 的 `StructValue`），以及 `keys(row) -> tuple[StructValue, ...]`，即该行的键数组，按顺序排列的 `SimpleCurveKey` 或 `RichCurveKey` 值；对于未知的行名，`keys()` 会抛出 `KeyError`。
- 只有当类的继承链包含 `DataTable` 或 `CurveTable` 时，该类才会被读取为表；这些优先于实例化网格（instanced meshes）。其他类的 `native=None`，除非下文请求了实例解码。

<!-- dt:section id="instanced-meshes-0" hash="c06bcf81d39b" -->
## 实例化网格

`assets.read(target, *, partial=False, cancel=None, instances=False)` 和 `Exports.read(which, *, partial=False, cancel=None, instances=False)` 接受一个可选启用的布尔参数 `instances`。为 True 时，映射类链包含 `InstancedStaticMeshComponent` 的非 CDO 导出会将其原生尾部数据作为 `InstanceData` 返回。其他导出的读取方式保持不变；默认值仍为 False。`raw()`、`resolve()` 和 `texture()` 没有此关键字参数。

```python
# 需要：名为 assets 的已打开 Installation 以及一个实例化组件对象路径
from nylib.ue.assets import InstanceData

export = assets.read('/Game/Maps/MyMap.MyMap:PersistentLevel.Actor.InstancedComponent',
                     instances=True)
if isinstance(export.native, InstanceData):
    print(len(export.native.matrices), len(export.native.custom_data))
```

- `InstanceData.matrices` 是由每个实例的元组组成的元组：每个元组都是一个 `FMatrix` 的精确 16 个 double 值，按行主序排列，元素 `(r, c)` 位于 `4 * r + c`。不进行变换分解，也不做 float32 舍入。`custom_data` 是一个扁平元组，包含 float32 值（精确扩展为 Python float），按实例顺序排列；其长度是实例数的整数倍，若没有实例则为零。该不可变记录支持 pickle 和 `deepcopy` 往返；其紧凑 repr 会报告实例数和自定义浮点数数量。
- 读取器会跳过 actor-component 的记账数据和 static-mesh LOD 载荷，读取实例数组，然后跳过所有分层簇节点数组。边界、LOD 载荷和 HISM 簇树均不对外暴露。仅当导出自身的 `SceneComponent.bComputeBoundsOnceForGame` 槽位被序列化且为 True 时，才会读取场景边界块；槽位缺失或被零掩码清零时，不读取该块。此规则同样支持 HLOD 尾部：所有 120,022 个已测量的 HLOD 导出均遵循该规则。在已测量的安装包中，565,893 个族尾部共包含 9,587,851 个实例，单个导出最多含 23,340 个实例。
- 成功的尾部读取结果为 `native_size=0`、`exact=True`、`complete=True`；实例数组缺失时返回 `InstanceData((), ())`。未知的尾部布局会抛出 `UnsupportedAssetError(feature='<class> tail')`，cooked 实例渲染数据则抛出 `feature='instanced mesh cooked data'`。两者都携带类、失败的 `position` 以及空的 `property_path`，并按常规规则附带映射变更/自定义序列化的归因信息。
- 使用 `partial=True` 时，尾部读取失败会保留已解码的属性和尾部 GUID，设置 `complete=False`、`native=None`、`native_size=0`、`exact=False`，并将错误放入 `problem`；任何已成功解码的槽位都不会变为未读。每个矩阵、自定义浮点数和 LOD 条目都计入解码预算，并且每 4,096 个值设置一个检查点。
- 兼容性：`Export.native` 现在除 `DataTable`、`CurveTable` 或 `None` 外，还可以是 `InstanceData`。对于族导出，启用该关键字会改变 `native`、`native_size`、`exact`，因此也会改变相等性比较；不传该关键字时，结果保持不变。导出对象存活期间，每个实例约占用 570 字节，每个自定义浮点数约占用 32 字节；大型结果应在两次读取之间及时释放。

<!-- dt:section id="partial-reads-and-raw-0" hash="308abd55468d" -->
## 部分读取与 `raw()`

- `read(target, *, partial=True)` 在某个属性、对象结尾（trailer）或某个表行解码失败时，返回一个尽力而为的 `Export`，而不是抛出异常：`complete` 为 `False`，`native` 为 `None`，`problem` 保存着非 partial 调用本应抛出的 `AssetError`。`properties` 保留了失败之前已完整读取的所有顶层槽位；失败的那个槽位，以及头部（header）列出的、位于其之后的每个槽位，均为 `'unread'`（读取其中任意一个会重新抛出 `problem`）；头部从未列出的槽位则照常为 `'absent'`。部分读取的值永远不会通过槽位暴露出来。有两种失败情况会使所有顶层槽位都为 `'unread'`，而不会混有 `'absent'`：头部本身解析失败；以及某个类块（class block）自身的槽位会超出解码预算——将未列出的槽位标记为 absent 本身就需要构建出预算所拒绝构建的那些槽位。
- `assets.raw(target, *, offset=0, limit, cancel=None) -> bytes` 和 `Exports.raw(which, ...)` 返回该导出项范围 `[offset, offset + limit)` 内的原始字节，并在导出项结尾处截断，不对任何内容进行解码；`limit` 没有默认值，且必须不超过 64 MiB，这与 `read()` 自身的导出项大小上限相同。只会读取该范围所涉及的压缩块。

<!-- dt:section id="supported-natives-0" hash="18fb291012a6" -->
## 支持的原生结构体

- 除了上文 Exports 和 properties 部分提到的上百种内置布局之外，遇到的其他每个结构体名称都会通过 `.usmap` 映射来读取，方式与任何反射结构体相同——其中包括几个看起来像引擎类型的名称（例如 `BodyInstance`、`ScalarParameterValue`、`VectorParameterValue`、`TextureParameterValue`），它们唯一的原生实现其实属于另一款 UE 游戏；对本游戏而言，这些名称只是普通的无版本数据，具体如何读取由映射自身的记录决定。
- 完全无法读取的结构体名称会抛出 `UnsupportedAssetError`，其中 `feature='native struct <name>'`，`struct_name` 设为该名称，`position` 为其字节开始处。这些情况分为两类：一类是 29 个独立于引擎、不在内置集合中、且在实测安装中从未出现过的原生结构体——`ColorMaterialInput`、`CompressedRichCurve`、`ExpressionInput`、`ScalarMaterialInput`、`VectorMaterialInput`、`Vector2MaterialInput`、`MaterialAttributesInput`、`SkeletalMeshSamplingRegionBuiltData`、`PannerDetails`、`LevelSequenceObjectReferenceMap`、`MaterialLayersFunctionsTree`、`MidiEvent`、`RawAnimSequenceTrack`、`SectionEvaluationDataTree`、`Transform3f`、`TypedParameter`、`UniqueNetIdRepl`、`ClothLODDataCommon`、`ClothLODData`、`ClothTetherData`、`AnimationAttributeIdentifier`、`AttributeCurve`、`PCGPoint`、`CacheEventTrack`、`DataCacheDuplicatedObjectData`、`EdGraphPinType`、`ControlRigOverrideContainer`、`UInt32Property`、`ZeroSizeProperty`——另一类是 74 个其唯一已知布局是为完全不同的另一款游戏编写的原生结构体（例如 `FixedPoint`、`GameplayEffectFloatMapping`、`NiagaraUserParameterModifier`）。无论是哪一类，读取时都会直接抛出异常，而不会去猜测一个本游戏数据未必遵循的布局。

<!-- dt:section id="threads-and-cancellation-0" hash="ef730b146b80" -->
## 线程与取消

- 任意数量的线程可以同时调用 `Installation`、`Exports` 和 `Texture` 的方法；容器块读取和共享块缓存使用短时锁。松散文件索引的加载有自己的锁，并发布一个不可变的索引；其他调用者等待该索引。记录和 `AesKey` 都是不可变的。
- 在文件 I/O、AES 解密和 Oodle 解压期间会释放 GIL；在解析以及 BC1、DXT5 和 BC7 解码期间持有 GIL，这些解码是纯 Python 实现的。
- `close()` 会等待其他线程上正在进行的读取完成，但不包括调用它的线程自身发起的那一次读取；一旦它返回，且没有自身发起的读取仍在进行，该安装就不再持有任何文件句柄、锁对象或缓存。
- `Installation`、`Exports`、`Texture`、`AesKey` 和 `Usmap` 拒绝 pickle 以及 `copy`/`deepcopy`；记录、值（包括 `StructValue` 和 `MapValue`）以及错误类可以 pickle 并完成 `deepcopy` 往返。`Usmap` 可以被任意数量的线程和安装共享，包括并发的 `check()` 调用；`load_usmap()` 没有 `cancel=` 参数。
- `exports()`、`read()`、`raw()` 和 `resolve()` 上的 `cancel=` 会在操作涉及的每个压缩块之前检查；在列出包的导出时，每隔几千个导出映射条目检查一次；在解码属性或表行时，每隔几千个已解码值检查一次。唯一的例外是 cooked 头部本身在最后一个块之后的解析：它没有检查点，且耗时随头部大小线性增长。在一次实测安装中，此处的最坏取消延迟约为：主映射的 `exports()` 约 0.2 s，整个安装中最大的 cooked 头部约 0.45-0.48 s。
- `read_file()` 会在任何读取之前、每个 `.pak` 的索引读取之前、等待另一个调用加载索引期间约每 50 ms、以及每个压缩块或存储片段之前检查取消。取消会抛出 `ReadCancelledError`，且不返回任何字节。四个松散文件方法在关闭后会抛出 `InstallationClosedError`；正在进行的读取会在其下一个检查点发现关闭。`close()` 会释放索引、保留的密钥和解密器；任何一次调用结束后都不会残留 `.pak` 句柄。返回的文件、本地化和实例记录的生命周期都长于该安装。

<!-- dt:section id="errors-0" hash="0ffb0b9d733c" -->
## 错误

```text
UeError
└── AssetError                      every nylib.ue.assets failure but argument-type errors; .package, .container, .export, .file
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

- 错误的参数类型抛出 `TypeError`，错误的值抛出 `ValueError` —— 除 `RegionOutOfBoundsError` 外，绝不会是上述类之一，它同时是 `AssetError` 和 `ValueError`。超出范围的 `Exports` 索引，或传给 `StructValue.at()` 或 `StructValue.state()` 的越界索引，抛出 `IndexError`；传给 `sv[name]` 或 `CurveTable.keys()` 的未知名称抛出 `KeyError`。
- 每个 `AssetError` 都有 `file` 属性，默认为 `None`：涉及某一路径的散装文件失败会将其设为该路径，本地化解析器失败则使用提供的 `file=`。这些失败不带 mapping-change 或 custom-serialization 归因。`Locres.entry()` 对缺失的 namespace/key 组合抛出 `KeyError`。
- `AmbiguousNameError`（从 `nylib.ue` 重新导出，不在 `AssetError` 之下）在包名或对象路径的导出名匹配多个 Texture2D 导出时由 `texture()` 抛出，在名称匹配多个导出时由 `read()`、`raw()` 和 `Exports.find()` 抛出；它不是 `AssetError`。
- `AbsentPropertyError` 同时也是 `KeyError`，但覆写了 `__str__`，因此尽管 `KeyError` 会加引号，`str(err)` 仍是纯文本消息；`StructValue.get()` 和 `in` 将其视为缺失，与真正的 `KeyError` 一样。部分 `Export`（见下文）携带的 `problem` 绝不是 `KeyError`，因此 `get()` 绝不会静默地把未读取的属性变成默认值。
- 在读取单个导出的属性时发生的失败——从属性块、对象尾部、表格行或原生结构内部抛出的 `InvalidMappingError` 或 `UnsupportedAssetError`——会携带 `property_path`：从导出的类到失败处的各步骤，例如 `WDWeaponStatsData#1.WDWeaponStats#36`，数组索引写作 `[3]`，映射的键或值写作 `[key 0]` / `[value 0]`，表格行写作 `[row 2]`。`class_name`、`property_index`、`property_name` 和 `property_type` 描述最后一步；`position` 是失败读取开始的位置；`struct_name` 在涉及原生结构时命名该结构；`row` 在失败位于某个表格行内时命名该行。消息本身仍然绝不重复属性名或行名——这些只存在于属性中。
- 消息为一行英文；路径使用基本名，但带引号的包内路径和对象路径除外。消息绝不包含密钥材料、解密/解码后的字节、本地化文本、映射文件内容或属性名。`load_usmap()` 将映射/元数据失败报告为 `InvalidMappingError`；缺失元数据文件的 `reason='meta.json not found'`，无效的 UTF-8/JSON 为 `'meta.json not JSON'`，错误的转储架构为 `'meta.json schema'`。`with_changes()` 的拒绝带有 `reason='change does not apply'`；如需名称，请检查属性和变更记录。报告摘要和需求细节同样省略属性名。

<!-- dt:section id="supported-profile-0" hash="9338388ceb02" -->
## 支持的范围

| 层 | 本版本支持 | 超出部分 |
|---|---|---|
| 容器 | IoStore TOC v8，一个或多个分区（分区 `p >= 1` 从 `<base>_s<p>.ucas` 读取）；AES-256-ECB；Oodle（Kraken）和未压缩块；压缩块大小为 2 的幂，范围从 4 KiB 到 16 MiB。旧版 `.pak` v11/v12 散装文件，带完整目录索引，存储或 Oodle 编码，包括加密索引和条目 | `UnsupportedContainerError`（IoStore 分区数为 0 时：`feature='zero partitions'`；只要有一个此类容器，`open_installation` 就会对整个安装失败）；分区缺失或块跨越其末端：`CorruptAssetError`。其他 `.pak` 版本、没有完整目录索引或其他条目编解码器的包不受支持；`.pak` 包保持未挂载 |
| 映射 | `.usmap` v0-v4；压缩方式 None、Oodle、ZStd（需要 Python 3.14+）；可复用的 `Usmap`、内存中的更改以及需求检查 | `InvalidMappingError`；没有 `.usmap` 写入器，也没有自动名称修复 |
| 包 | zen 包，无版本属性 | `InvalidMappingError`、`CorruptAssetError` |
| 导出与有类型属性 | 每一种属性类型和引用（`exports()`、`read()`、`raw()`、`resolve()`）；121 种内置原生结构布局；其他任意结构名称通过 `.usmap` 映射解析 | 本版本不读取的原生结构（见上方 Supported natives 中列出的）：`UnsupportedAssetError` |
| 本地化 | 基于字节的 `.locres` v3 和 `.locmeta` v2；命名空间/键查找以及源哈希 | 其他版本：`UnsupportedAssetError`；受支持但数据格式错误：`CorruptAssetError`；没有文化区域回退、目标合并或 StringTable 尾部 |
| 实例化网格体 | 对映射的实例化静态网格体家族可选启用 `instances=True`，包括 HISM 和 HLOD；精确矩阵和自定义浮点数 | 烘焙的实例渲染数据或其他尾部布局：`UnsupportedAssetError`；簇树和矩阵分解不对外暴露 |
| 纹理元数据 | 每个 `Texture2D` 导出，包括虚拟纹理和普通纹理 | 其他类：`UnsupportedAssetError` |
| 虚拟纹理区域读取 | `RawGPU` 编解码器，单层，`PF_DXT1`，非旧版图块布局 | `UnsupportedAssetError` / `UnsupportedPixelFormatError`；`info.readable` 为 False 并说明原因。其他任何 VT 层格式（包括 `PF_DXT5` 和 `PF_BC7`）仍报告 `has no decoder in this nylib version`，尽管这些格式在普通纹理上可以解码 |
| 普通纹理区域读取 | `PF_B8G8R8A8`、`PF_DXT1`、`PF_DXT5`、`PF_BC7`；内联 mip、默认 `.ubulk` 或可选 `.uptnl`（烘焙索引 0，位于任何已挂载的容器中） | 其他像素格式：`UnsupportedPixelFormatError`；没有序列化 mip、mip 数据未与纹理一起序列化、压缩或内存映射的批量数据（`.m.ubulk`）、其他烘焙索引、位于多个容器中的可选块、可选数据同时标记为内联，或任何其他位置：`UnsupportedAssetError`；`info.readable` 为 False 并说明原因。未挂载的可选块会使 `info.readable=True` 保持不变，但该 mip 的读取会抛出 `MissingAssetError` |

<!-- dt:section id="notes-0" hash="a686545b52ce" -->
## 说明

- 在一台与其他工作同时运行的共享机器上测量，Python 3.12/3.14：产品首次加载 16 个 `.pak` 文件、5,976 个条目的松散文件索引耗时约 60-94 毫秒，保留 6.1-6.3 MiB（峰值 6.1-6.4 MiB）；之后的索引查找耗时约 5 微秒。松散文件读取的 p50 约 0.53-0.54 毫秒，p95 约 0.63-0.68 毫秒；读取全部 219 个加密条目耗时约 24 毫秒。早前的范围探测在每个 Game `.locres` 的 2 个块中读取了 70,000 字节，并在 2 个存储分片中读取了 70,000 字节的影片尾部。这些是近似观测值，不包含冷缓存声明，也不保证吞吐量。
- 在该共享机器上，产品解析 Game `en`（525,364 字节，5,948 个条目，169 个命名空间）耗时约 13-15 毫秒，保留约 2.1 MiB；最大的 `.locres`（6,892,728 字节）耗时约 145-183 毫秒，保留 19.1-19.6 MiB。早前对两个 Game 语言区域的原型探测分别耗时约 12-14 毫秒，各保留 2.2 MiB。解析器的内存和时间随字符串和条目增长，解析过程没有取消检查点。
- 在同一共享机器上，读取某主地图的 43,117 个导出项，不含实例时耗时约 9.0-10.6 秒，含实例时耗时 10.1-13.1 秒；一个 23,340 个实例的导出项耗时约 12-14 毫秒，峰值跟踪分配为 15.5-15.7 MiB。早前的整个安装目录探测发现约 8% 的额外尾部工作；这与该地图的工作负载不同。实测取消延迟在实例解析期间约为 1.7-2.1 毫秒，在存储的松散文件读取期间约为 0.10-0.14 毫秒。
- `read_file()` 保留返回的字节以及工作缓冲区：实测跟踪分配在 64 MiB 存储范围上峰值接近 128 MiB，在 33.8 MiB 的 Oodle 文件上为 67.5 MiB，在这些输入上处于 `2 * returned_bytes + 4 MiB` 之内。使用较小的范围可降低峰值内存。
- 不进行重采样：mip 的像素以该 mip 自身的尺寸返回；缩放由调用方负责。
- BC1、DXT5 和 BC7 解码是纯 Python 实现：它们持有 GIL，因此大范围读取在解码期间受单核限制。在一台机器上的整 mip 原型测量显示，DXT1 约为 25-30 Mpx/s，DXT5 约为 2.6-2.9 Mpx/s，BC7 约为 0.6-1.0 Mpx/s，具体取决于块。按这些速率，整个 4096x4096 的 BC7 mip 需要约 17-27 秒；交互式读取请使用有界区域。
- 在一台与其他工作同时运行的机器上测量：普通 512x512 区域读取的 p50 耗时，DXT1 约为 27 毫秒，DXT5 为 97 毫秒，BC7 为 239 毫秒（分别为 16、32 和 32 个压缩块）。2x2 采样在 1 个块上的 p50 耗时约为 0.07-0.13 毫秒，其中包括可选 `.uptnl` mip 约 0.09 毫秒。这些格式的实测取消延迟分别约为 13 毫秒、24 毫秒和 60 毫秒；轮询发生在压缩块之间，因此延迟包括两次轮询之间的解码工作。这些数字不能证明冷缓存性能。
- 在一台被测机器上，对安装目录首次调用 `texture()`、`exports()`、`read()`、`raw()` 或 `resolve()` 会加载一次全局 ScriptObjects 表（在被测游戏上约 4.66 MB），总计约 0.42 秒，其中几乎全部是该加载耗时；之后的调用会复用该表。
- 与 CUE4Parse 相比：DXT1 的三色 index-3 纹素在此处为不透明黑色 `(0, 0, 0, 255)`，而 CUE4Parse 给出 alpha 0。DXT5 完全遵循其 BCDecoder 运算，包括 alpha 插值舍入和强制四色块。BC7 遵循 BPTC 规范，与 CUE4Parse 的 AssetRipper 路径一致；其 Windows Detex 路径在模式 6 中某通道可能相差 1。不在 4 像素网格上的 mip 会被解码为填充块并裁剪到其声明尺寸；CUE4Parse 的 BC1/BC3 解码器无法解码这些尺寸，其 BC7 路径则返回填充后的图像。
- 近似值，单机：`open_installation` 耗时约 0.22 秒（其中约 0.15 秒用于解析一个 `.usmap`；一个更大的 3.3 MB 映射的原型解析耗时约 0.26 秒，保留约 26 MiB）；无论 `cache_bytes` 为 0、默认的 4 MiB 还是 16 MiB，区域读取的 p50 都约为 30 毫秒——受解码限制，因此更大的缓存主要对同一瓦片的重复读取有帮助。
- 在一台与其他工作同时运行的机器上测量，Python 3.12/3.14：`load_usmap()` 在三个映射文件上耗时约 0.15-0.30 秒，工作集峰值增长约 17-31 MiB。检查 100 个需求在没有回退时耗时约 2.6-4.1 毫秒，带前缀回退及其应用/复查过程（6 个提案）时耗时 6.4-7.5 毫秒。应用 3,167 个合成重命名耗时约 35-47 毫秒，另加摘要计算约 7-12 毫秒。使用已加载的映射打开耗时约 68-94 毫秒，而通过其路径打开耗时 387-437 毫秒；映射变更归因在 1,598 次读取中耗时约 5-6 微秒 p50。这些是近似观测值，并非冷缓存测量，也不保证吞吐量。
- 近似值，单机，普通纹理的地形瓦片（`PF_B8G8R8A8`，`.ubulk` mip）：2x2 采样在 1 个压缩块上耗时约 0.1 毫秒；mip 0 读取的 p50 约为 2.5 毫秒，`cancel=` 每个压缩块轮询一次，在被测瓦片上约每 0.3 毫秒一次——它本身不会增加那么多延迟。`list_packages()` 的首次调用（同时会了解插件挂载根）耗时 4.25-5.0 秒。
- 近似值，单机，导出项与类型化读取：主地图的 cooked 头部的 `exports()` 耗时约 0.28-0.30 秒，保留约 35-38 MiB；小型导出项的 `read()` p50 远低于 1 毫秒；通过 `Exports` 句柄的 64 字节 `raw()` 读取了 1 个压缩块（当范围跨越块边界时为 2 个）；通过 `assets.raw()` 则读取了 3 个，因为该调用还会读取目标的 cooked 头部。在安装包的每六十分之一采样（1,787 个包，21,141 个导出项）中，遍历本身耗时数秒，该采样中解码值最多的导出项（394,305 个，一个 `AudioImpulseResponse`）耗时约 0.13 秒读取完成，相对基线的工作集峰值增长约 17 MiB。在主地图的 `exports()` 期间取消的 p50 延迟约为 93 毫秒（最坏情况 198 毫秒，来自上文 Threads and cancellation 中提到的间隙）；解码中途取消约为 1 毫秒。
- 单次 `read()` 的限制：cooked 头部或导出项数据超过 64 MiB 会抛出 `CorruptAssetError`；超过 16 层结构嵌套的值会抛出 `InvalidMappingError`，原因为 `struct nesting`，计入容器时超过 64 层的会抛出 `value nesting`；解码值和已构建槽位超过导出项字节数加 65,536 的读取会抛出 `decode budget`。在一个被测安装中，没有导出项达到后两个限制，最大的读取超出 65,536 的部分每字节使用 0.375 单位。
- 内存随解码值增长，解码值是 Python 对象：主要由小型原生结构体组成的导出项，在结果存活期间每个输入字节最多占用约 190 字节，因此 64 MiB 的 `Color` 值导出项将占用约 12 GiB。请逐个读取大型导出项，或使用 `raw()`。
- `.usmap` 是受信任的输入：对于手工构造的映射，两次读取的值之间的 `==` 以及 `to_python()` 可能在几个字节的数据上耗时数秒，因为它们会展开一次读取共享的零掩码结构体。
- 仅限 Windows x64（AES 使用 BCrypt；exe 的 PE 以及 `.ucas`/`.utoc` 布局）。请将 AES 密钥文件及其内容视为机密：绝不记录、打印或提交，通过路径传递。
