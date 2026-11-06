> 本文档为 dump.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="dump.md" -->

<!-- dt:section id="__preamble__" hash="847ee3a86119" -->
# Dump

[Index](index.md) · 代码：`nylib/ue/pipeline.py`、`nylib/ue/snapshot.py`、`nylib/ue/cli.py`

<!-- dt:section id="probe-and-dump-0" hash="176f67f8af06" -->
## 探测与导出

```python
# 需要正在运行的游戏
from nylib.ue import probe, dump

report = probe('TRIANGLE_STRATEGY-Win64-Shipping.exe')   # 查找全局变量和偏移，不写入任何内容
print(report.ok, report.stem)
for v in report.values:
    print(v.name, v.value, v.how, 'UNVERIFIED' if v.unverified else '')

result = dump('TRIANGLE_STRATEGY-Win64-Shipping.exe', out=r'D:\ue_dumps')
print(result.path)            # D:\ue_dumps\TRIANGLE_STRATEGY\20261002-024137
print(result.counts, result.unverified, result.warnings, result.export_paths)
```

- 目标：exe 名称（可省略 `.exe`）、PID（`int`），或 `None` 表示当前进程（游戏内部）。两个同名进程会引发 `AmbiguousTargetError`；此时请传入 PID。
- `probe()` 和 `dump()` 接受 `cache_bytes=`：`None` 使用默认的页缓存上限（游戏外为 1 GiB，游戏内为 128 MiB），`0` 表示不使用缓存读取，或传入不小于 `0x10000` 的整数，以字节为单位设置上限。`bool` 或其他非 `int` 类型会引发 `TypeError`；负值或 `1..0xFFFF` 会引发 `ValueError`。不使用缓存的读取更慢，并且会看到游戏在此期间创建的对象；一次下游 attach 的实测为：不使用缓存 23.4 秒，使用缓存 5.83 秒。
- `nylib.ue.pipeline.list_targets()` 会列出看起来像 UE 游戏的运行中进程。
- 输出：`<out>/<GameName>/<YYYYmmdd-HHMMSS>/`。根目录为 `out=`，否则为环境变量 `NYLIB_UE_OUT`，否则为当前目录下的 `.\ue_dumps`。在游戏内部没有默认值：必须传入 `out=` 或设置 `NYLIB_UE_OUT`。
- Profile：`<out>/profiles/` 下 `[match] exe` 与目标匹配的 TOML 文件会被自动使用（两个同时匹配 exe 和构建约束的文件会引发 `ProfileError`；传入 `profile=` 以选择）；`nylib.ue.pipeline.write_profile(report)` 会写出一个为该构建固定 GObjects 和 GNames 的 profile。Profile 永远不能启用调用。
- 当 probe 自行探测到 ProcessEvent 索引和 GWorld rva 时（`how` 以 `auto:` 开头，而非 `profile:` 或 `fallback:`），`write_profile` 也会记录它们，但只作为注释行，位于 "found by this probe; check it before pinning" 之下。取消注释即成为固定项；添加 `[match] build` 可将其限制在该构建（见下文）。随后 `probe --write-profile` 会打印 `wrote <path> (pins: gobjects, gnames; rva pins hold for build 0x...; hints are commented out)`。
- 写入 profile 从不覆盖已有文件。若文件已存在，`write_profile` 会抛出 `FileExistsError`（`e.args[0]` 为路径），其 `e.profile_text` 中是它本会写入的文本。随后 `probe --write-profile` 会打印该文本，提示手动合并并以退出码 1 结束；使用 `--json` 时，错误文档包含 `path` 和 `profile_text`。若 `<out>/profiles` 是一个文件，`write_profile` 则改为抛出 `NotADirectoryError`，并指明该路径。
- `[match] build`（PE 的 TimeDateStamp，取值范围 `0..0xFFFFFFFF` 的整数）会把整个 profile 限制在该构建。可选的 `[match] image_size`（SizeOfImage，`1..0xFFFFFFFF`）还会检查映像大小，并且要求同时有 `build`；布尔值会被拒绝。自动加载遇到不匹配时会跳过并输出 WARNING；显式传入的 `profile=` 则会在探测目标内存之前引发 `ProfileError`。当目标的 SizeOfImage 读出为 0 时，自动加载仍可仅按 build 匹配，但会把要求 `image_size` 的 profile 视为无法检查而跳过；显式传入的 profile 则与 0 比较，并在不匹配时引发错误。没有 `[match] build` 时，只有 `[globals]` 中的 rva 固定项（`gobjects`、`gnames`）会与构建进行核对：`process_event` 以及 `[offsets]` 固定项（包括 `Off.InSDK.World.GWorld`）仍适用于该 exe 的每个构建，并计为已验证。`write_profile` 不会写入 `[match] build`；请手动添加。
- 解析 profile 时会检查 `[offsets]` 的键：每个键的拼写必须与 `nylib.ue.engine.offsets.PINNABLE_KEYS` 中一致（`Off.UStruct.Size`，而不是 `UStruct.Size`），否则抛出 `ProfileError: [offsets] unknown key ...`。自动加载会跳过任何解析失败的 profile，并输出 WARNING；只有 `[match] exe` 与目标匹配的 profile 中的这一错误，才会让 probe、dump 或 attach 失败。
- 在代码中，`nylib.ue.profiles.parse_profile(text)` 和 `load_profile(path)` 会构建一个 `Profile`（`path`、`exe`、`pins`、`offsets`、`hooks`、`build`、`image_size`），`profile=` 可像路径一样接受它。内存中的 profile 在消息中显示为 `<string>`，且不能使用 `[hooks]`（`ProfileError`：hooks 需要 profile 文件）。
- 质量：`result.quality`（以及 `meta.json` 中的 `quality`）会报告一个 `verdict`，即 `complete` 或 `degraded`，并附带 `reasons`、按类别统计的问题 `counts`，以及所应用的 `thresholds`。只要出现任何 `unreadable_type`、`unreadable_fields`、`unreadable_name` 或 `unreadable_interfaces`，或者类型相关行（classes、structs、functions、enums、packages）中的 `index_mismatch` 超过其中的 0.1%，就会判定为 degraded；其他问题类别只报告，从不参与判定（一个枚举未能解析的 `EnumProperty` 属于 `unresolved_reference`）。空枚举（样本 `enum is null in the game`）是游戏一侧的缺口，例如一个已烹饪的蓝图从发行版中不存在的模块导入了原生枚举；任何转储器都无法为其命名，usmap 将其命名为 `None`。`unresolved_reference` 还会统计函数参数和局部变量，而 usmap 并不编码它们，因此其计数可能超过 usmap 警告中的数量。来自某个类所列函数的样本会注明函数名。`meta.json` 的 `issues` 按类别保留计数以及第一个和最后一个样本，每个样本截断为 200 个字符。每个样本都会完整地以 DEBUG 级别记录到 `nylib.ue.reflect`，因此从较长的函数样本中截掉的结尾（例如 `enum is null in the game`）仍保留在保留 DEBUG 记录的日志中，例如命令行的 `<out>/_logs/dump.log`，或 `dump(log_file=...)` 所指定的文件。如果 usmap 导出发现某属性指向缺失的枚举或结构体，`result.warnings` 会新增一条 `usmap: N properties referenced a missing enum or struct (first: ...)` 条目。`strict=True`（命令行：`--strict`）会在发布任何内容之前，把 degraded 判定转为抛出的错误，磁盘上只留下 `.partial` 文件夹；默认（`strict=False`）只报告。

### Profile 文件

```toml
[match]
exe = "TRIANGLE_STRATEGY-Win64-Shipping.exe"
build = 0x67890ABC
image_size = 0x6F00000   # 可选；需要 build

[globals]
gobjects = { rva = 0x4A2B3C0, build = 0x67890ABC, image_size = 0x6F00000 }   # rva 需要 build
gnames = { sig = "48 8D 0D ? ? ? ? E8" }                                     # sig 不需要 build；它必须恰好匹配一处
process_event = { index = 76 }

[offsets]
"Off.InSDK.World.GWorld" = 0x4C7D1A8
```

从 `probe --write-profile` 开始，它会写出 `[match]` 以及 `gobjects` / `gnames` 的 rva 固定项，并附带注释形式的提示（见上文）。手动编辑时，你可以在任何 `[globals]` 固定项中添加 `note`（字符串），在 `gobjects` 中添加 `elements_per_chunk` 和 `layout`，还可以添加 `[hooks] decrypt_objects = "hooks.py:decrypt_objects"`（位于 profile 旁边的文件；它会在转储进程中以 Python 运行，因此只使用你信任的 profile；不能与 `gobjects` 固定项同用，后者是在未解密的情况下读取的）。`gobjects` / `gnames` 固定项必须恰好包含 `rva` 和 `sig` 之一。

<!-- dt:section id="exports-0" hash="41472624ebf8" -->
## 导出项（Exports）

`dump(exports=...)` 默认导出全部五项；`exports=()` 只写出快照（snapshot）。

- `gobjects`：`GObjects-Dump.txt`，Dumper-7 的对象列表。
- `gobjects-props`：`GObjects-Dump-WithProperties.txt`，同上但带属性。
- `idmap`：`IDAMappings/<stem>.idmap`，Dumper-7 的 IDA 映射（V1）。
- `image`：`image/<exe>`，游戏主模块的 PE 文件，其 ImageBase 为运行时基址。它包含游戏的代码：不要共享包含它的快照文件夹。
- `usmap`：`Mappings/<stem>.usmap`，Dumper-7 格式的类型映射，供 `.usmap` 读取器（FModel、CUE4Parse）使用，未压缩。

<!-- dt:section id="calls-during-a-dump-allow-calls-0" hash="e3f5eb48c823" -->
## dump 期间的调用（`allow_calls`）

```python
# 需要一个正在运行的游戏；每次调用都可能使游戏崩溃
from nylib.ue import probe, dump

result = dump('TRIANGLE_STRATEGY-Win64-Shipping.exe', allow_calls=('text', 'game-info', 'append-string'))
for r in result.remote_calls:
    print(r.feature, r.ran, r.ok, r.detail)
```

- `text`：通过一次 `Conv_StringToText` 调用找到 FText 布局，之后即可读取 FText 值。
- `game-info`：通过 `GetGameName` / `GetEngineVersion` 读取游戏名称和引擎版本；它们构成命名导出文件的 stem。
- `append-string`：用 `FName::AppendString` 对一批名称样本检查名称解码器。
- 调用在游戏中的一个新线程上运行（在游戏内部：即调用线程），而不是游戏线程，并且可能使游戏崩溃。当探测留下未验证的偏移量时，不会进行任何调用（两个 FText 键、两个游戏名键，以及 `Off.FFieldClass.Id`、`Off.FFieldClass.ClassFlags`、`Off.FFieldClass.SuperClass` 除外）。失败的功能会变成警告；dump 继续进行。已运行的调用列在 `meta.json`（`remote_calls`）中。

<!-- dt:section id="load-a-snapshot-0" hash="bf8aeb328105" -->
## 加载快照

```python
from nylib.ue import load_snapshot

with load_snapshot(r'ue_dumps\TRIANGLE_STRATEGY\20261002-024137') as snap:
    print(snap.stem, len(snap.objects), snap.meta['counts'])
    actor = snap.type('/Script/Engine.Actor')                      # ClassRecord
    print(actor.cpp_name, actor.super, hex(actor.size))
    for p in actor.properties[:3]:
        print(p.name, hex(p.offset), p.type.kind)
    fn = snap.type('/Script/Engine.Actor:K2_SetActorLocation')     # FunctionRecord
    print([p.name for p in fn.params])
    i = snap.objects.index_of_path('/Script/Engine.Default__KismetSystemLibrary')
    print(snap.objects[i], snap.objects.full_name(i))
```

该文件夹包含 `meta.json`、`offsets.json`、`objects.jsonl`、`fields.jsonl`、`types.jsonl` 和 `types.idx.json`，以及导出文件。类型在首次使用时才会加载。快照包含类型、布局和对象列表，但不包含属性值，甚至不包含类默认值；属性值需从实时会话中读取（`ue.cdo(...)`、`ue.find(...)`）。

<!-- dt:section id="command-line-0" hash="d2b53fc2ac99" -->
## 命令行

```text
python -m nylib.ue list
python -m nylib.ue probe TRIANGLE_STRATEGY-Win64-Shipping.exe [--write-profile] [--explain]
python -m nylib.ue dump TRIANGLE_STRATEGY-Win64-Shipping.exe [--out DIR] [--exports idmap,gobjects] [--allow-calls [text,game-info,append-string]] [--strict]
python -m nylib.ue export <snapshot> --format idmap
python -m nylib.ue info <snapshot>
```

`list`、`probe` 和 `dump` 需要一个正在运行的游戏。`list` 会打印每个进程匹配的配置文件及其状态：`build matches`、`build differs`、`no rva pins`、`ambiguous (N profiles)` 或 `invalid`（未知的 `[offsets]` 键；日志会指出它）。`[match] build` 和 `image_size` 用于为 `list` 筛选配置文件：一个匹配报告 `build matches`，多个匹配报告 `ambiguous (N profiles)`，只有不匹配时才报告 `build differs`；没有 `[match] build` 时，状态仍取决于 rva 固定值。当三个或更多镜像槽位指向同一个 UWorld 时，`--explain` 会列出 GWorld 候选 rva。如果没有唯一的候选，未验证的 GWorld 标签和一条 WARNING 最多会列出八个不同的 rva，以帮助选择配置文件固定值；它们并不验证其中任何一个。不带值的 `--allow-calls` 表示全部三项。`--json`（除 `export` 外都支持）输出机器可读的结果。日志写入 `<out>/_logs/<command>.log`，除非给出了 `--log-file`。退出码：0 成功，1 错误，2 用法错误，3 检测失败，4 无法打开目标或目标已退出，130 被中断。

<!-- dt:section id="own-memory-backend-0" hash="401a834c7488" -->
## 自有内存后端

私有的 `_open_target=` 工厂让 `probe`、`dump` 和 `Unreal.attach` 使用你自己的类 `nylib.process.Process` 对象（`read`、`write`、`iter_memory_region`、`virtual_query`、`enum_ldr_data`、`process_id`、`still_alive`），而不是自行打开目标：

```python
# 需要一个正在运行的游戏
from nylib.process import Process
from nylib.ue import memory, pipeline, probe

proc = Process.from_name('TRIANGLE_STRATEGY-Win64-Shipping.exe')   # 你自己的句柄

def factory(target, *, write, remote_calls, cache_bytes):
    source = (memory.ProcessSource(proc, cache=False) if cache_bytes == 0 else
              memory.ProcessSource(proc, max_cache_bytes=pipeline.CACHE_CAP_EXTERNAL if cache_bytes is None else cache_bytes))
    return pipeline.OpenedTarget(source, pipeline.target_info(source, mode='external', pid=proc.process_id),
                                 process=proc, check_alive=proc.still_alive)

report = probe(proc.process_id, _open_target=factory)
```

工厂按原样接收 `cache_bytes`，包括 `None` 和 `0`；由它决定如何兑现该值。没有 `closer=`，因此你保留自己的句柄；只有当你传入 `closer=` 时，`OpenedTarget.close()` 才会关闭它。`nylib.ctype` 访问器则改为成为 `memory.MemorySource` 的子类（`_read`、`_readable_ranges`、`regions`、`modules`）；该关键字是私有的，可能会更改。

`_readable_ranges` 必须只报告你的后端确实能读取的内存；不确定时就不要报告。dump 器信任它来选择要解引用的指针和要读取的范围，因此多报会使探测失败，或悄悄丢掉一个被扫描的区段。对于无法读取的字节，`_read` 会抛出 `nylib.ue.errors.MemoryReadError`。

当对你的源的每次读取都是一次缓慢的调用时，例如驱动，请在工厂中包装它：`source = memory.PagedSource(my_source)`。该包装器以 64 KiB 页读取你的源。某页读取失败时，它改以 4 KiB 小块读取该页；某个小块也失败时，它会用原始地址和大小调用你的 `_read`。因此，只要你的源能读取它整体可读取的跨度中的任意一部分，一次读取要么返回这些字节，要么抛出你的源本会抛出的错误。页会保留其首次读取的字节，直到 `refresh()`，`dump` 在遍历前会调用一次它。`fresh` 不经缓存地读取你的源，写入会丢弃其触及的页。`page_size=` 接受 0x1000 到 0x100000 之间的 2 的幂，`max_cache_bytes=` 是 LRU 上限：默认 1 GiB，`None` 表示无上限。`ProcessSource` 已经缓存了其读取，而 capture 读取的是本地文件，因此包装其中任何一个都没有收益。
