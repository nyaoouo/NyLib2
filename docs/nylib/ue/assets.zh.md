> 本文档为 assets.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="assets.md" -->

<!-- dt:section id="__preamble__" hash="f7beed4e7f53" -->
# nylib.ue.assets

用于 UE 5.7 游戏的 IoStore（`.utoc`/`.ucas`）容器的只读读取器：枚举包（包括插件挂载根下的包）、读取 `Texture2D` 元数据，并将虚拟纹理 BC1 瓦片和普通 `PF_B8G8R8A8` 纹理的有界区域解码为 RGBA8。Python，使用 Windows BCrypt 进行 AES 加密和捆绑的 Oodle DLL 进行解压缩；不依赖 FModel、CUE4Parse 或 Unreal。

关键词：IoStore, utoc, ucas, AesKey, open_installation, Installation, Texture, virtual texture, VT, BC1, DXT1, B8G8R8A8, ordinary texture, plugin, read_region, usmap, mapping, zen package, PackageInfo, TextureInfo, Region, ScriptObjects, Oodle, Exports, StructValue, DataTable, CurveTable, native struct, ObjectRef

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

<!-- dt:section id="finding-packages-0" hash="667416b3d9d1" -->
## 查找包

- `assets.has_package(name) -> bool` 在不读取任何容器数据的情况下进行检查。
- `assets.package(name) -> PackageInfo` 读取包头的摘要块。`name` 接受包路径（`/Game/UI/Icon`）、对象路径（`/Game/UI/Icon.Icon`）或 `.uasset`/`.umap` 文件路径（`Engine/Content/...` 或 `<Project>/Content/...`）；对于 `exports()`、`read()`、`raw()`、`Exports.find()`、`Exports.read()` 和 `Exports.raw()`，名称还可以以子对象路径结尾，`/Pkg.Top:Sub.Sub`，通过其外层链命名一个嵌套的导出。
- `assets.list_packages(prefix='/', *, match=None) -> list[PackageInfo]` 遍历每个挂载容器的目录索引（构建一次，缓存到 `close()` 为止）；`match` 是整个名称上的 `fnmatch` 样式的模式，ASCII 不区分大小写，与 `prefix` 相同。
- 名称大小写：`list_packages()` 报告容器的目录索引为路径记录的大小写；`package()` 和 `texture()` 报告包头本身记录的大小写。两者可能不同——在一个游戏上实测，212 个抽样名称中有 3 个不同，例如 `.../APC/Wavs/...` 与 `.../APC/WAVs/...`——但指的始终是同一个包：`PackageInfo.package_id` 相同，而且所有名称匹配都不区分 ASCII 大小写。
- 插件挂载根：`list_packages()` 也列出位于 `Engine/Plugins/.../Content/...` 或 `<Project>/Plugins/.../Content/...` 目录下的包，命名为 `/<mount>/<rest>`。当 `<mount>` 已经与条目记录的块 id 匹配时，它是插件文件夹名称；否则目录在其第一个不匹配的条目上花费一次摘要读取，从该条目的记录包名称学习 `<mount>`，然后为目录的其余部分重用它（在一个游戏上实测，22,313 个插件根文件中有 106 个需要学到的挂载，来自 2 次学习读取）。学到的 `<mount>` 保持记录名称的大小写；`<rest>` 始终保持目录索引的大小写。
- `.uasset`/`.umap` 文件路径形式不适用于插件根：位于 `Plugins/` 目录下的文件路径仍然会引发 `ValueError`。通过包路径或对象路径形式（`/<mount>/...`）或通过 `list_packages()` 返回的名称来寻址插件根包。

<!-- dt:section id="metadata-0" hash="4394f9aff3c0" -->
## 元数据

- `assets.texture(name) -> Texture` 解析 `Texture2D` 导出并将其头部解析为 `Texture.info`（一个 `TextureInfo`）：`width`、`height`、`pixel_format`、`mips`（每个级别一个 `MipInfo`）、`alpha`（`'none'` 或 `'straight'`）、`virtual`（一个 `VirtualTextureInfo`，或对于普通纹理为 `None`）、`readable` 和 `unsupported`（理由，匹配 `read_region` 会引发的错误）。在一个安装上的第一个 `texture()` 调用较慢；请参阅注释。
- `assets.stats() -> ReadStats` 返回自打开以来的运行总计（`reads`、`bytes_read`、`blocks_decompressed`、`tiles_decoded`、`seconds` 等）；`reads` 现在还统计 `read()`、`Exports.read()`、`raw()` 和 `Exports.raw()` 调用，不仅是区域读取。两个快照之间的差异测量一个跨度；`str(stats)` 是一行摘要。

<!-- dt:section id="reading-regions-0" hash="8a2b91064b5b" -->
## 读取区域

`tex.read_region(mip, x, y, width, height, *, clip=False, missing='raise', out=None, cancel=None) -> Region` 将像素数据解码为 RGBA8：虚拟纹理 BC1 瓦片，或普通 `PF_B8G8R8A8` 纹理的 mip 行。先检查 `info.readable`；当其为 False 时，`info.unsupported` 说明原因。

- 坐标是 mip `mip` 的像素坐标，原点左上，行从上到下返回；大小来自 `info.mips[mip]`，永远不会重新缩放。
- 输出是紧密堆积的 RGBA8：`len(region.pixels) == width * height * 4`，无 sRGB 转换。当 `info.alpha == 'none'` 时，Alpha 为 255。
- `clip=True` 将矩形缩小到 mip 的边界而不是抛出异常；`clip=False`（默认）在边界外抛出 `RegionOutOfBoundsError`。
- 虚拟纹理：`missing='raise'`（默认）如果任何接触的瓦片未存储则抛出 `MissingTileError`；`'transparent'` 用 `(0, 0, 0, 0)` 填充；`'fallback'` 用 `info.virtual.fallback[0]` 填充。`region.missing` 无论如何都列出填充的矩形，仅解码矩形接触的瓦片。
- 普通纹理：存储的字节顺序为 B、G、R、A；输出为 R、G、B、A，值仍为存储的值，仍无 sRGB 转换。没有瓦片，所以 `missing` 经过验证但没有其他效果，`region.missing` 始终为 `()`。仅读取 mip 的行 `y .. y + height - 1`。
- 无论如何，每个压缩块在每次调用中最多被获取和解压一次，结果与缓存状态、线程数或（对于虚拟纹理）填充区域外的 `missing` 策略无关。
- `out=` 写入调用者提供的可写缓冲区而不是分配新的 `bytes`；`cancel=` 是一个零参数可调用对象，在瓦片（虚拟纹理）或压缩块（普通纹理）之间轮询，当其返回真时抛出 `ReadCancelledError`。

兼容性：在早期版本中，每个普通（非虚拟）纹理都从 `read_region` 无条件地抛出 `UnsupportedAssetError(feature='non-virtual texture')`。现在可读的普通纹理进行解码，没有解码器的像素格式的普通纹理改为抛出 `UnsupportedPixelFormatError` -- 就像不支持的虚拟纹理层格式已经做的那样。两个错误类都派生自 `UnsupportedError`；只在 `read_region` 周围捕获 `UnsupportedAssetError` 的调用者会错过新的异常。普通纹理上的 `texture()` 现在也可能抛出 `CorruptAssetError`，原因是某个 mip 的大小、`.ubulk` 范围或序列化大小（serial size）不一致。另外，学习读取失败的插件内容目录只列出已与其文件夹名称匹配的条目；其余条目被丢弃，仅在 DEBUG 日志中可见。

<!-- dt:section id="exports-and-properties-0" hash="4924be64c7c6" -->
## 导出与属性

```python
# needs: an installed UE 5.7 game, its AES key file and a matching .usmap
from nylib.ue.assets import (
    open_installation, AesKey, Exports, ExportInfo, Export, StructValue, Slot,
    MapValue, EnumValue, TextValue, ObjectRef, SoftObjectRef, DataTable, CurveTable,
    AbsentPropertyError, AmbiguousNameError,
)

key = AesKey.from_file('path/to/game-aes.txt')
with open_installation('path/to/MyGame/Content/Paks', engine='5.7',
                        usmap='path/to/MyGame.usmap', build=None, aes_key=key) as assets:
    exp = assets.exports('/Game/Some/DataAsset')             # Exports: the cooked header only, no export data
    print(exp.package.name, len(exp))                        # a package name and its export count
    export = exp.read(0)                                     # Export: typed properties of export 0
    print(export.info.class_name, export.complete, export.exact, export.native_size)
    props = export.properties                                # StructValue, the export's top-level slots
    print(props.struct, len(props), props.state(0))           # struct name, slot count, slot 0's state
    try:
        props.at(0)
    except AbsentPropertyError as e:
        print(str(e))                                        # not serialized: the archetype's value is unknown here
```

- `assets.exports(name, *, cancel=None) -> Exports` 仅读取包的 cooked 包头(不含导出数据),返回一个 `Exports` 句柄:一个 `Sequence[ExportInfo]`,带有 `package`(一个 `PackageInfo`)、`stats`(本次调用的 `ReadStats`)、`find(name) -> ExportInfo`(不涉及 I/O)、`read(which, *, partial=False, cancel=None) -> Export` 以及 `raw(which, *, offset=0, limit, cancel=None) -> bytes`。`which` 可以是索引、名称或子对象路径,也可以是来自该句柄的 `ExportInfo`。直接调用 `Exports(...)` 会引发 `TypeError`;`Exports` 会保持其 `Installation` 处于打开状态,并拒绝被 pickle。
- `assets.read(target, *, partial=False, cancel=None) -> Export` 直接读取单个导出:`target` 可以是包路径或对象路径(`str`,包含子对象路径)、`ExportInfo`、`ObjectRef` 或 `SoftObjectRef`(见下文“引用”)。`Export` 持有 `info`(`ExportInfo`)、`properties`(一个 `StructValue`)、`native`(一个 `DataTable`、`CurveTable` 或 `None`)、`native_size`(解析完属性后剩余的字节数)、`exact`(即 `native_size == 0`)、`guid`、`complete` 以及 `problem`(一个 `AssetError`,仅在部分读取结果上设置;见下文“部分读取”)。
- 对于简单类型(`bool`、`int`、`float`、`str`),每个属性会读取为一个普通的 Python 值,或读取为上述记录之一:引用对应 `ObjectRef` / `SoftObjectRef`,枚举对应 `EnumValue`,`FText` 对应 `TextValue`,数组或集合对应 `tuple`(字节数组则为 `bytes`),映射对应 `MapValue`,可选值对应其自身值或 `None`,结构体对应嵌套的 `StructValue` —— 可能是反射的(通过 `.usmap` 映射解码)或原生的(下文列出的内置布局之一)。
- `StructValue` 是一个只读的 `Mapping[str, object]`,带有 `struct`(其类名或结构体名)、`native`(`bool`)和 `slots`(一个 `Slot` 元组);`sv[name]`、`sv.at(index)` 和 `sv.state(key)` 可按名称或按模式索引读取。槽位的状态可能是 `'serialized'`(其字节已被存储)、`'zero'`(包头将其标记为未设置;读取为该类型的零值)、`'absent'`(包头从未列出它 —— 真正的值来自类的原型(archetype),而这些数据并未包含该值,因此 `sv[name]` 会引发 `AbsentPropertyError`),或 `'unread'`(仅出现在部分读取结果中)。如果某个名称在类链中被多个属性共用,`sv[name]` 会引发 `AmbiguousNameError`;此时应改用 `sv.at(index)`。
- `StructValue.to_python()` 返回一个仅由列表、字典以及 `str`/`int`/`float`/`bool`/`None` 构成的普通 `dict` —— 可安全用于 `json.dumps` —— 其形状如上所述:每个存在的属性对应一个键,`MapValue` 表示为 `[key, value]` 对组成的列表,引用表示为包含其字段的小字典,依此类推;如果该值的任何槽位为 `'unread'`,它会引发 `problem`。解码预算限制的是单次读取可构建的值和槽位数量(大致每输入字节一个单位,外加一些余量),而不是这些值变成 Python 对象后所占的字节数:像 `Color` 这样固定且小的原生类型,每输入字节可占用多达约 190 字节的 Python 层内存,因此一个几乎全由 `Color` 值组成的 64 MiB 导出,在被任何限制阻止之前可能构建出多达约 12 GiB 的内存。而且由于 `to_python()` 和 `==` 会遍历整个值,包括每个零掩码(zero-masked)结构体,调用者提供的 `.usmap` 映射 —— 而非 nylib 另行校验过的游戏数据 —— 仍可能使这种遍历比上述原始字节数所暗示的要大得多;对待不受信任的映射,应与对待任何其他不受信任的输入一样保持谨慎。
- 除了映射所描述的反射形状之外,还有超过一百种内置("原生")结构体布局会被直接识别:简单的固定大小数学类型(`Vector`、`Color`、`Guid`、`Matrix`、`Quat` 及类似类型),以及一小部分可变长度的引擎类型(`GameplayTagContainer`、`InstancedStruct` 及其容器/数组形式、属性包(property-bag)类型、`Spline`、`MovieScene*` 通道与求值树类型、`Niagara*` 变量类型、`PCGPointArray` 等)。每种类型都会解码为一个 `native=True` 的 `StructValue`,恰好带有该结构体文档所记录的字段,每个字段对应一个 `Slot`;若结构体名称不在该集合中,则仍会像任何反射结构体一样通过 `.usmap` 映射读取 —— 见下文“支持的原生类型”。

<!-- dt:section id="references-0" hash="9d955e3bef9a" -->
## References

- 属性值中的引用是 `ObjectRef`(用于 `Object`、`WeakObject` 和 `Interface` 属性;惰性指针则读取为一个普通的 GUID 字符串)或 `SoftObjectRef`(软/资源路径属性)。`ObjectRef.kind` 的取值为 `'null'`、`'export'`(指向同一包内)、`'import'`(指向另一个包,由 `package` 命名并通过其哈希惰性解析)或 `'script'`(引擎类或自身没有 cooked 导出的包,例如 `/Script/Engine.StaticMesh`);`bool(ref)` 仅在 `'null'` 时为 `False`。两个 `ObjectRef` 仅在指向完全相同的对象时才比较相等,因此从同一个包导入的两个不同导出永远不会比较相等,即使它们的 `kind == 'import'` 且 `package` 相同。
- `SoftObjectRef` 持有 `package`、`asset`、`subpath` 以及组合后的 `path`;`bool(ref)` 仅在 `path` 为空时为 `False`。
- `assets.resolve(ref, *, cancel=None) -> ExportInfo` 跟随一个 `ObjectRef` 或 `SoftObjectRef` 找到其指向的 `ExportInfo`,只读取目标包的 cooked 包头 -- 绝不读取该导出自身的数据,且调用之间不做任何缓存。`assets.read(ref)` 和 `assets.raw(ref)` 直接接受一个引用,并在一次调用中读取目标的数据。解析 `ObjectRef('null', ...)`,或是指向 `'script'` 对象的引用,会引发 `ValueError`:两者都没有可读取的 cooked 导出。

<!-- dt:section id="tables-and-curves-0" hash="1213dba93abf" -->
## 表与曲线

- `DataTable` 导出的 `Export.native` 是一个 `DataTable` 记录：`row_struct`（行结构体的名称，若来自另一个包则为 `None`——行仍会通过解析出的结构体进行解码）、`row_struct_ref`（一个 `ObjectRef`）以及 `rows`——一个从行名到该行的 `StructValue` 的 `MapValue`，按文件顺序排列。
- `CurveTable` 导出的 `Export.native` 是一个 `CurveTable` 记录：`mode`（`'Empty'`、`'SimpleCurves'` 或 `'RichCurves'`）、`rows`（如上所述，每行是一个 `SimpleCurve` 或 `RichCurve` 的 `StructValue`），以及 `keys(row) -> tuple[StructValue, ...]`——该行的键数组——按顺序排列的 `SimpleCurveKey` 或 `RichCurveKey` 值；对未知的行名，`keys()` 会抛出 `KeyError`。
- 对其他所有类，`Export.native` 均为 `None`；只有当一个类的类链中包含 `DataTable` 或 `CurveTable` 时，该类才会被当作表来读取。

<!-- dt:section id="partial-reads-and-raw-0" hash="dddc2641bf66" -->
## 部分读取与 `raw()`

- `read(target, *, partial=True)` 在某个属性、对象结尾(trailer)或某个表行解码失败时，返回一个尽力而为的 `Export`，而不是抛出异常：`complete` 为 `False`，`native` 为 `None`，`problem` 保存着非 partial 调用本应抛出的 `AssetError`。`properties` 保留了失败之前已完整读取的所有顶层槽位；失败的那个槽位，以及头部(header)列出的、位于其之后的每个槽位，均为 `'unread'`（读取其中任意一个会重新抛出 `problem`）；头部从未列出的槽位则照常为 `'absent'`。部分读取的值永远不会通过槽位暴露出来。
- `assets.raw(target, *, offset=0, limit, cancel=None) -> bytes` 和 `Exports.raw(which, ...)` 返回该导出项范围 `[offset, offset + limit)` 内的原始字节，并在导出项结尾处截断，不对任何内容进行解码；`limit` 没有默认值，且必须不超过 64 MiB，这与 `read()` 自身的导出项大小上限相同。只会读取该范围所涉及的压缩块。

<!-- dt:section id="supported-natives-0" hash="94c778247612" -->
## 支持的原生结构体

- 除了上文 Exports 和 properties 部分提到的上百种内置布局之外，遇到的其他每个结构体名称都会通过 `.usmap` 映射来读取，方式与任何反射结构体相同——其中包括几个看起来像引擎类型的名称（例如 `BodyInstance`、`ScalarParameterValue`、`VectorParameterValue`、`TextureParameterValue`），它们唯一的原生实现其实属于另一款 UE 游戏；对本游戏而言，这些名称只是普通的无版本数据，具体如何读取由映射自身的记录决定。
- 完全无法读取的结构体名称会抛出 `UnsupportedAssetError`，其中 `feature='native struct <name>'`，`struct_name` 设为该名称，`position` 为其字节开始处。这些情况分为两类：一类是独立于引擎、不在内置集合中、且在实测安装中从未出现过的原生结构体（例如 `ClothLODDataCommon`、`CompressedRichCurve`、`RawAnimSequenceTrack`、`EdGraphPinType`）；另一类是其唯一已知布局是为完全不同的另一款游戏编写的原生结构体（例如 `FixedPoint`、`GameplayEffectFloatMapping`、`NiagaraUserParameterModifier`）。无论是哪一类，读取时都会直接抛出异常，而不会去猜测一个本游戏数据未必遵循的布局。

<!-- dt:section id="threads-and-cancellation-0" hash="3c7a8f37525c" -->
## 线程与取消

- 任意数量的线程可以同时调用 `Installation` 和 `Texture` 方法；它们仅在每个容器块读取和共享块缓存周围短暂相互等待。Records 和 `AesKey` 是不可变的。
- GIL 在文件 I/O、AES 解密和 Oodle 解压期间被释放，在解析和 BC1 解码期间被持有，这些是纯 Python 代码。
- `close()` 等待在其他线程上运行的读取操作，除了调用它的线程本身；一旦它返回且没有自己的进行中读取，安装就不持有任何文件句柄、锁对象或缓存。
- `Installation`、`Texture` 和 `AesKey` 拒绝 pickling 和 `copy`/`deepcopy`；records 和错误类可以 pickle。
- `exports()`、`read()`、`raw()` 和 `resolve()` 上的 `cancel=` 会在操作涉及的每个压缩块之前被检查，在列出包的导出时每隔几千个导出映射条目检查一次，在解码属性或表行时每隔几千个解码值检查一次。唯一的例外是 cooked 包头解析本身，在其最后一个块之后没有检查点，并随包头大小线性增长：在一次测得的安装中，主地图 `exports()` 的最坏情况取消延迟约为 0.15 秒，整个安装中最大 cooked 包头约为 0.48 秒。

<!-- dt:section id="errors-0" hash="1e28da9d5d08" -->
## 错误

```text
UeError
└── AssetError                      every nylib.ue.assets failure but argument-type errors; .package, .container, .export
    ├── InvalidKeyError             no/wrong AES key, GUID mismatch, bad key file; .key_guid, .reason, .path
    ├── InvalidMappingError         .usmap missing, invalid, or does not fit the data; .usmap, .class_name, .property_index,
    │                               .property_name, .reason, .path, .property_path, .property_type, .position, .struct_name, .row
    │   └── BuildMismatchError      build= differs from the exe's own stamp; .expected, .found, .exe, .path
    ├── MissingAssetError           package or export not in a mounted container (a LookupError)
    │   └── MissingTileError        missing='raise' hit an unstored VT tile; .mip, .tiles
    ├── UnsupportedError             outside the supported profile; .feature
    │   ├── UnsupportedContainerError    TOC version, AES mode, compression method, or no usable Oodle
    │   ├── UnsupportedAssetError         asset class or native layout; .exports, .class_name, .property_index,
    │   │                                 .property_name, .property_path, .property_type, .position, .struct_name, .row
    │   └── UnsupportedPixelFormatError   no decoder for this pixel format; .pixel_format
    ├── CorruptAssetError            structure or codec check failed; .detail (a block decode's __cause__ is an OodleError)
    ├── RegionOutOfBoundsError       rectangle or mip out of range (a ValueError); .mip, .rect, .size
    ├── ReadCancelledError           cancel() returned true
    ├── InstallationClosedError      the installation is already closed (a ValueError)
    └── AbsentPropertyError          a property slot was not serialized, so its value is the archetype's one nylib does not
                                      hold (also a KeyError); .class_name, .property_index, .property_name
```

- 错误的参数类型会抛出 `TypeError`，错误的值会抛出 `ValueError` -- 除了 `RegionOutOfBoundsError` 之外，永远不会抛出上面的任何类，`RegionOutOfBoundsError` 既是 `AssetError` 也是 `ValueError`。
- `AmbiguousNameError`（从 `nylib.ue` 重新导出，不在 `AssetError` 下）在包名称，或对象路径的导出名称，与多个 Texture2D 导出匹配时由 `texture()` 抛出，并在名称与多个导出匹配时由 `read()`、`raw()` 和 `Exports.find()` 抛出；它不是 `AssetError`。
- `AbsentPropertyError` 也是 `KeyError`，但重写了 `__str__`，因此 `str(err)` 是纯文本消息，不带 `KeyError` 的引号；`StructValue.get()` 和 `in` 将其视为缺失，就像真正的 `KeyError` 一样。部分 `Export`（见下文）携带的 `problem` 永远不是 `KeyError`，因此 `get()` 永远不会把一个未读取的属性静默地当作默认值。
- 读取某个导出的属性时发现的失败 -- 从属性块、对象尾部、表行或原生结构体内部抛出的 `InvalidMappingError` 或 `UnsupportedAssetError` -- 携带 `property_path`：从导出的类到失败位置的步骤，例如 `WDWeaponStatsData#1.WDWeaponStats#36`，数组索引写作 `[3]`，映射的键或值写作 `[key 0]` / `[value 0]`，表行写作 `[row 2]`。`class_name`、`property_index`、`property_name` 和 `property_type` 描述最后那一步；`position` 是失败的读取开始的位置；`struct_name` 在涉及原生结构体时命名该结构体；`row` 在失败发生在表行内部时命名该行。消息本身仍然永远不会重复属性或行名称 -- 它们只存在于属性中。
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

<!-- dt:section id="notes-0" hash="cc23d30e75b9" -->
## 说明

- 无重采样：一个mip的像素返回该mip自己的大小；缩放是调用者的工作。
- BC1解码是纯Python：它持有GIL，每像素消耗CPU，所以大区域读取在那部分是单核绑定的。
- 在安装上的第一个`texture()`调用也会加载全局ScriptObjects表一次（在测量的游戏中约4.66 MB），在一台测量的机器上总共成本约0.42秒，几乎全部是那个加载；后来的`texture()`调用重用该表。
- BC1三色块的索引-3纹素在这里解码为`(0, 0, 0, 255)`（CUE4Parse自己的填充是alpha 0）。测量的两个地图的块都未使用该索引（在1,560,299个采样的三色块中的0个），所以这在那里从未显示差异。
- 近似，一台机器：`open_installation`花费约0.22秒（其中约0.15秒用于解析`.usmap`）；无论`cache_bytes`为0、4 MiB默认值还是16 MiB，区域读取约为30 ms p50 -- 解码限制，所以更大的缓存主要帮助对相同瓦片的重复读取。
- 近似，一台机器，一个普通纹理地形瓦片（`PF_B8G8R8A8`、`.ubulk` mips）：一个2x2样本在1个压缩块上花费约0.1 ms；一个mip 0读取约为2.5 ms p50，`cancel=`每个压缩块轮询一次，在测量的瓦片上约每0.3 ms一次 -- 它本身并不会增加那么多延迟。`list_packages()`的第一个调用（它也学习插件挂载根）花费了4.25-5.0秒。
- 近似，一台机器，导出和类型化读取：`exports()`对一个主地图cooked包头的调用花费约0.28-0.30秒，并保留约35-38 MiB；小导出的`read()`远低于1 ms p50；一个64字节的`raw()`无论导出的大小如何，都恰好涉及1个压缩块。在该安装的六十分之一包样本（1,787个包，21,141个导出）上，扫描本身花费了几秒钟，样本中解码值最多的导出（394,305个，一个`AudioImpulseResponse`）读取用了约0.13秒，峰值工作集比基线增长约17 MiB。在主地图的`exports()`期间取消的延迟约为93 ms p50（最坏情况198 ms，源自上文"线程与取消"一节中提到的间隔）；在解码中途取消约为1 ms。
- 单次`read()`的限制：cooked包头或导出的数据超过64 MiB会引发`CorruptAssetError`；超过16个结构体层级深的值会引发原因为`struct nesting`的`InvalidMappingError`，计入容器超过64个层级深的值会引发`value nesting`；解码值和构建的槽位之和超过导出字节大小加65,536的读取会引发`decode budget`。在一个测量的安装上，没有导出达到最后两种限制，最大的一次读取在65,536之上使用了每字节0.375个单位。
- 内存跟随解码值，它们是Python对象：一个主要由小型原生结构体组成的导出，在其结果存活期间每输入字节最多保留约190字节，所以一个64 MiB的`Color`值导出会占用约12 GiB。大导出应逐个读取，或使用`raw()`。
- `.usmap`是可信输入：对于手工构造的映射，两次读取得到的值之间的`==`以及`to_python()`在几字节数据上可能耗费数秒，因为它们会展开一次读取共享的零掩码结构体。
- 仅限Windows x64（AES使用BCrypt；exe的PE和`.ucas`/`.utoc`布局）。将AES密钥文件及其内容视为秘密：永远不要记录、打印或提交它；通过路径传递。
