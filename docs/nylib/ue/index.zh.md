> 本文档为 index.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="index.md" -->

<!-- dt:section id="__preamble__" hash="2abf00b74f9a" -->
# nylib.ue

`nylib.ue` 读取 Unreal Engine 游戏(UE 4.25+ 和 UE5,Windows x64)的反射数据。

- [Dump](dump.md):找到引擎全局变量和偏移量,遍历每个 class、struct、enum 和 function,写出一个带版本号的快照文件夹以及 Dumper-7 格式的导出(GObjects 转储、一个 `.idmap`、以 PE 文件形式保存的游戏主模块)。
- [Runtime](runtime.md):附加到正在运行的游戏,从 Python 中使用其对象:读取成员、写入它们(可选)、调用 UFunction(可选)。
- [IDA](ida.md):将快照的名称、类型和注释导入 IDA 9.x。
- [Stubs](stubs.md):为快照的类型写出 `.pyi` stub,供编辑器补全使用。

默认情况下它在游戏外部(另一个进程)工作,也可以在游戏内部工作(注入的 Python)。
详细信息在代码及其 docstring 中;这些页面只展示如何使用它。

<!-- dt:section id="prerequisites-0" hash="750d67c0b068" -->
## 前置条件

- Windows x64 以及一个 64 位的 UE 4.25+ 或 UE5 游戏。
- Python 3.11 或更新版本(`pyproject.toml`);nylib.ue 已在 3.12 和 3.14 下测试过。它不需要任何第三方包。
- 从本仓库安装 nylib:`pip install -e .`(参见 readme)。

<!-- dt:section id="quick-start-0" hash="75b948bf744e" -->
## 快速开始

```python
# needs a running game
from nylib.ue import dump, Unreal

exe = 'TRIANGLE_STRATEGY-Win64-Shipping.exe'
result = dump(exe)                               # writes .\ue_dumps\<game>\<timestamp>\
print(result.path, result.counts)

with Unreal.attach(exe, dump=result.path) as ue:  # read-only session, types from the snapshot
    world = ue.world()
    print(world, world.PersistentLevel)
    print(ue.local_player_controller().Pawn)
```

快照在没有游戏运行的情况下依然可用：[加载它](dump.md#load-a-snapshot)、将其导入 [IDA](ida.md)，或用它生成 [stubs](stubs.md)。

<!-- dt:section id="safety-0" hash="35996b607970" -->
## 安全性

- 读取是默认行为。dumper 和默认会话打开游戏时只拥有读取权限,从不在游戏中执行代码。
- 写入需要在 `Unreal.attach` 上设置 `write=True`。写入会直接作用于游戏的内存。
- UFunction 调用需要在 `Unreal.attach` 上设置 `calls=`(游戏外用 `'remote-thread'`,游戏内用 `'any-thread'`)。dumper 自身的调用需要 `allow_calls=`(CLI 为 `--allow-calls`)。
- 调用会在非游戏线程上运行 `ProcessEvent`。它会与游戏线程及其垃圾回收器产生竞争,可能导致游戏崩溃或状态损坏。
- 潜在函数(接受 `FLatentActionInfo` 的函数)会被拒绝。
- dumper 无法验证的偏移量会阻止写入和调用;错误信息会列出这些偏移量以及修复方法。
- Profile 的 hooks 是 dumper 运行的 Python 代码(在内部模式下在游戏内运行):只使用你信任的 profile。
- 调用可能会在游戏中留下内存:引擎为输出参数分配的内存,以及调用超时或被中断时其自身占用的内存。
- 在 remote-thread 调用期间按 Ctrl+C 可能导致游戏崩溃。
- 向已经加载了相同 `python3XY.dll` 的游戏注入 Python 会使其崩溃。缺失的 `python_loader.dll` 会在首次使用时构建,这需要 MSVC,且当 MSVC 缺失时会下载并安装 Visual Studio Build Tools;可以提前用 `python -m nylib.winutils.python_loader build` 构建一次。

<!-- dt:section id="tested-with-0" hash="3b50822537c5" -->
## 已测试环境

- PalServer(UE 5.1,build 25247047)、TRIANGLE STRATEGY(UE 4.27,build 11410614)以及 FrostBound(UE 5.4,build 24486464)。
- Dumps:已在三者的捕获文件上验证,并在三者上针对 Dumper-7 进行了实机验证;内部(注入式)dump 在 PalServer 上进行了实机验证。
- IDA 导入器、runtime 读取、调用参数布局、`--allow-calls` 目标以及 stubs:已在三者的捕获文件上检查过;该导入器已在 IDA 9.3 中应用过。
- 尚未在真实游戏上验证:runtime 会话(读取、写入、调用)、`--allow-calls`、`attach_current`。
