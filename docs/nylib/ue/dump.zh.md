> 本文档为 dump.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="dump.md" -->

<!-- dt:section id="__preamble__" hash="847ee3a86119" -->
# Dump

[Index](index.md) · 代码：`nylib/ue/pipeline.py`、`nylib/ue/snapshot.py`、`nylib/ue/cli.py`

<!-- dt:section id="probe-and-dump-0" hash="01d13749944d" -->
## 探测与导出（Probe and dump）

```python
# needs a running game
from nylib.ue import pipeline

report = pipeline.probe('TRIANGLE_STRATEGY-Win64-Shipping.exe')   # finds globals and offsets, writes nothing
print(report.ok, report.stem)
for v in report.values:
    print(v.name, v.value, v.how, 'UNVERIFIED' if v.unverified else '')

result = pipeline.dump('TRIANGLE_STRATEGY-Win64-Shipping.exe', out=r'D:\ue_dumps')
print(result.path)            # D:\ue_dumps\TRIANGLE_STRATEGY\20261002-024137
print(result.counts, result.unverified, result.warnings, result.export_paths)
```

- 目标（Target）：一个 exe 名称（可以省略 `.exe`）、一个 PID（`int`），或 `None` 表示当前进程（在游戏内部）。两个同名进程会引发 `AmbiguousTargetError`，需传入 PID。
- `pipeline.list_targets()` 列出看起来像 UE 游戏的正在运行的进程。
- 输出：`<out>/<GameName>/<YYYYmmdd-HHMMSS>/`。根目录为 `out=` 参数，否则为环境变量 `NYLIB_UE_OUT`，否则为当前目录下的 `.\ue_dumps`。在游戏内部没有默认值：必须传入 `out=` 或设置 `NYLIB_UE_OUT`。
- 配置文件（Profiles）：`<out>/profiles/` 下若有某个 TOML 文件的 `[match] exe` 与目标匹配，则会自动使用（或传入 `profile=`）；`pipeline.write_profile(report)` 会为该构建写出一个固定 GObjects 与 GNames 的配置文件。配置文件永远不能启用调用（calls）。

<!-- dt:section id="exports-0" hash="6c7943cdb8e3" -->
## 导出项（Exports）

`dump(exports=...)` 默认导出全部四项；`exports=()` 只写出快照（snapshot）。

- `gobjects`：`GObjects-Dump.txt`，Dumper-7 的对象列表。
- `gobjects-props`：`GObjects-Dump-WithProperties.txt`，同上但带属性。
- `idmap`：`IDAMappings/<stem>.idmap`，Dumper-7 的 IDA 映射（V1）。
- `image`：`image/<exe>`，游戏主模块的 PE 文件，其 ImageBase 为运行时基址。它包含游戏的代码：不要共享包含它的快照文件夹。

<!-- dt:section id="calls-during-a-dump-allow-calls-0" hash="3f54b5322283" -->
## 导出过程中的调用（`allow_calls`）

```python
# needs a running game; each call can crash the game
result = pipeline.dump('TRIANGLE_STRATEGY-Win64-Shipping.exe', allow_calls=('text', 'game-info', 'append-string'))
for r in result.remote_calls:
    print(r.feature, r.ran, r.ok, r.detail)
```

- `text`：通过一次 `Conv_StringToText` 调用找出 FText 的布局，以便之后能读取 FText 的值。
- `game-info`：通过 `GetGameName` / `GetEngineVersion` 读取游戏名称和引擎版本；它们构成用于命名导出文件的 stem。
- `append-string`：在一组名称样本上，用 `FName::AppendString` 校验名称解码器。
- 调用在游戏内的一个新线程上运行（在游戏内部时：即调用线程），而非游戏线程，并可能导致游戏崩溃。只要探测（probe）阶段留下了未验证的偏移量，就不会进行任何调用（FText 和游戏名相关的调用除外）。失败的功能会变成一条警告；导出会继续进行。实际执行过的内容会记录在 `meta.json`（`remote_calls`）中。

<!-- dt:section id="load-a-snapshot-0" hash="7d9a8311cc6f" -->
## 加载快照（Load a snapshot）

```python
from nylib.ue.snapshot import Snapshot

with Snapshot.load(r'ue_dumps\TRIANGLE_STRATEGY\20261002-024137') as snap:
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

该文件夹中有 `meta.json`、`offsets.json`、`objects.jsonl`、`fields.jsonl`、`types.jsonl` 和 `types.idx.json`，以及导出项。类型（Types）在首次使用时才会加载。

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
