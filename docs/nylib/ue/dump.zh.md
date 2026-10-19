> 本文档为 dump.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="dump.md" -->

<!-- dt:section id="__preamble__" hash="847ee3a86119" -->
# Dump

[Index](index.md) · 代码：`nylib/ue/pipeline.py`、`nylib/ue/snapshot.py`、`nylib/ue/cli.py`

<!-- dt:section id="probe-and-dump-0" hash="2cb4f37d595f" -->
## 探测与导出

```python
# needs a running game
from nylib.ue import probe, dump

report = probe('TRIANGLE_STRATEGY-Win64-Shipping.exe')   # finds globals and offsets, writes nothing
print(report.ok, report.stem)
for v in report.values:
    print(v.name, v.value, v.how, 'UNVERIFIED' if v.unverified else '')

result = dump('TRIANGLE_STRATEGY-Win64-Shipping.exe', out=r'D:\ue_dumps')
print(result.path)            # D:\ue_dumps\TRIANGLE_STRATEGY\20261002-024137
print(result.counts, result.unverified, result.warnings, result.export_paths)
```

- 目标：exe 名称（可省略 `.exe`）、PID（`int`），或 `None` 表示当前进程（游戏内部）。两个同名进程会引发 `AmbiguousTargetError`；此时请传入 PID。
- `nylib.ue.pipeline.list_targets()` 会列出看起来像 UE 游戏的运行中进程。
- 输出：`<out>/<GameName>/<YYYYmmdd-HHMMSS>/`。根目录为 `out=`，否则为环境变量 `NYLIB_UE_OUT`，否则为当前目录下的 `.\ue_dumps`。在游戏内部没有默认值：必须传入 `out=` 或设置 `NYLIB_UE_OUT`。
- Profile：`<out>/profiles/` 下 `[match] exe` 匹配目标的 TOML 文件会被自动使用（或传入 `profile=`）；`nylib.ue.pipeline.write_profile(report)` 会为该构建写出一个固定 GObjects 和 GNames 的 profile。Profile 永远不能启用调用。

<!-- dt:section id="exports-0" hash="41472624ebf8" -->
## 导出项（Exports）

`dump(exports=...)` 默认导出全部五项；`exports=()` 只写出快照（snapshot）。

- `gobjects`：`GObjects-Dump.txt`，Dumper-7 的对象列表。
- `gobjects-props`：`GObjects-Dump-WithProperties.txt`，同上但带属性。
- `idmap`：`IDAMappings/<stem>.idmap`，Dumper-7 的 IDA 映射（V1）。
- `image`：`image/<exe>`，游戏主模块的 PE 文件，其 ImageBase 为运行时基址。它包含游戏的代码：不要共享包含它的快照文件夹。
- `usmap`：`Mappings/<stem>.usmap`，Dumper-7 格式的类型映射，供 `.usmap` 读取器（FModel、CUE4Parse）使用，未压缩。

<!-- dt:section id="calls-during-a-dump-allow-calls-0" hash="b41c07bda7be" -->
## 转储过程中的调用 (`allow_calls`)

```python
# needs a running game; each call can crash the game
from nylib.ue import probe, dump

result = dump('TRIANGLE_STRATEGY-Win64-Shipping.exe', allow_calls=('text', 'game-info', 'append-string'))
for r in result.remote_calls:
    print(r.feature, r.ran, r.ok, r.detail)
```

- `text`:通过一次 `Conv_StringToText` 调用找出 FText 的布局，以便之后能够读取 FText 值。
- `game-info`:通过 `GetGameName` / `GetEngineVersion` 读取游戏名称和引擎版本;它们构成了命名导出文件的词干。
- `append-string`:在一组名称样本上,用 `FName::AppendString` 校验名称解码器。
- 调用在游戏内的一个新线程(在该线程内部:即调用线程)上运行,而不是在游戏线程上,并且可能导致游戏崩溃。只要探测过程留下了未验证的偏移,就不会发起调用(FText 和游戏名称的调用除外)。失败的功能会变为警告;转储会继续进行。实际运行了哪些调用会列在 `meta.json` 中(`remote_calls`)。

<!-- dt:section id="load-a-snapshot-0" hash="635e81ab34b7" -->
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

该文件夹包含 `meta.json`、`offsets.json`、`objects.jsonl`、`fields.jsonl`、`types.jsonl` 和 `types.idx.json`，以及导出文件。类型在首次使用时才会加载。

<!-- dt:section id="command-line-0" hash="69ea06d72da3" -->
## 命令行（Command line）

```text
python -m nylib.ue list
python -m nylib.ue probe TRIANGLE_STRATEGY-Win64-Shipping.exe [--write-profile] [--explain]
python -m nylib.ue dump TRIANGLE_STRATEGY-Win64-Shipping.exe [--out DIR] [--exports idmap,gobjects] [--allow-calls [text,game-info,append-string]]
python -m nylib.ue export <snapshot> --format idmap
python -m nylib.ue info <snapshot>
```

`list`、`probe` 和 `dump` 都需要一个正在运行的游戏。`--allow-calls` 不带值表示启用全部三项。`--json`（除 `export` 外的所有命令）会输出机器可读的结果。日志会写入 `<out>/_logs/<command>.log`，除非指定了 `--log-file`。退出码：0 表示成功，1 表示错误，2 表示用法错误，3 表示检测失败，4 表示无法打开目标或目标已退出，130 表示被中断。

<!-- dt:section id="own-memory-backend-0" hash="60eb0fa5b2a5" -->
## 自定义内存后端

私有的 `_open_target=` 工厂让 `probe`、`dump` 和 `Unreal.attach` 使用你自己的类似 `nylib.process.Process` 的对象(`read`、`write`、`iter_memory_region`、`virtual_query`、`enum_ldr_data`、`process_id`、`still_alive`),而不是让它们自己去打开目标:

```python
# needs a running game
from nylib.process import Process
from nylib.ue import memory, pipeline, probe

proc = Process.from_name('TRIANGLE_STRATEGY-Win64-Shipping.exe')   # your own handle

def factory(target, *, write, remote_calls, cache_bytes):
    source = memory.ProcessSource(proc, max_cache_bytes=cache_bytes or pipeline.CACHE_CAP_EXTERNAL)
    return pipeline.OpenedTarget(source, pipeline.target_info(source, mode='external', pid=proc.process_id),
                                 process=proc, check_alive=proc.still_alive)

report = probe(proc.process_id, _open_target=factory)
```

没有传入 `closer=`,所以你的句柄仍由你自己持有;只有在你传入了 closer 时,`OpenedTarget.close()` 才会去关闭它。`nylib.ctype` 的访问器会改成 `memory.MemorySource` 的子类(`_read`、`_readable_ranges`、`regions`、`modules`);这个关键字是私有的,可能会变动。

`_readable_ranges` 必须只报告你的后端真正能读取的内存;拿不准的内存就不要报告。dumper 会信任它来决定该解引用哪些指针、读取哪些范围,因此过度报告会导致 probe 失败,或者悄悄丢失被扫描的某一段。`_read` 对无法读取的字节会抛出 `nylib.ue.errors.MemoryReadError`。

如果你的源每次读取都是一次较慢的调用(例如驱动),就在工厂里包装它:`source = memory.PagedSource(my_source)`。包装器以 64 KiB 的页读取你的源。某页读取失败时,它改以 4 KiB 为单位读取该页;某一块也失败时,它用原始地址和大小调用你的 `_read`。因此,一次读取返回的字节或抛出的错误与你的源相同,前提是你的源能读取一整段时,也能读取其中任意一部分。页保留首次读取时的字节,直到 `refresh()`;`dump` 会在遍历(walk)之前调用它一次。`fresh` 不经缓存直接读取你的源,写入会丢弃它触及的页。`page_size=` 取 0x1000 到 0x100000 之间的 2 的幂,`max_cache_bytes=` 是 LRU 上限:默认 1 GiB,`None` 表示不设上限。`ProcessSource` 本身已缓存读取,捕获文件读取的是本地文件,所以包装二者都没有收益。
