> 本文档为 index.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="index.md" -->

<!-- dt:section id="__preamble__" hash="39093993b7b6" -->
# nylib.ue

`nylib.ue` 读取虚幻引擎游戏的反射数据（UE 4.25+ 和 UE5，Windows x64）。

关键词: Unreal Engine, UE4, UE5, reflection, dump, Unreal.attach, snapshot, Dumper-7, GObjects, FName, UObject, UFunction, offsets, idmap, usmap, IDA import, pyi stubs, game modding, runtime objects, IoStore, utoc, texture, virtual texture, BC1

- [Dump](dump.md)：找到引擎全局变量和偏移量，遍历每个类、结构体、枚举和函数，并写入一个版本控制的快照文件夹以及 Dumper-7 格式的导出文件（GObjects 转储、`.idmap`、`.usmap`、游戏的主模块作为 PE 文件）。
- [Runtime](runtime.md)：附加到运行中的游戏并从 Python 使用其对象：读取成员、写入成员（可选）、调用 UFunctions（可选）。
- [IDA](ida.md)：将快照的名称、类型和注释导入到 IDA 9.x。
- [Stubs](stubs.md)：为编辑器补全写入快照类型的 `.pyi` 存根。
- [Assets](assets.md)：只读 IoStore 资源访问 —— `open_installation`、包查找、`Texture2D` 元数据、类型化的导出属性和跨包引用，以及针对 UE 5.7 游戏的受限虚拟纹理 BC1 区域读取。

默认情况下，它从游戏外部（另一个进程）工作，也可以从游戏内部（注入的 Python）工作。
详情在代码及其文档字符串中；这些页面只展示如何使用它。

<!-- dt:section id="prerequisites-0" hash="40c0d95dc4c1" -->
## 前置条件

- Windows x64 以及一个 64 位的 UE 4.25+ 或 UE5 游戏。
- Python 3.11 或更新版本(`pyproject.toml`);nylib.ue 已在 3.12 和 3.14 下测试过。除了 `calls='game-thread'` 需要 `keystone-engine` 和 `capstone` 之外,它不需要任何第三方包(`pip install ".[asm]"`;参见 [运行时](runtime.md#call-ufunctions))。
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

<!-- dt:section id="safety-0" hash="d89527537698" -->
## 安全性

- 默认只读。转储器和默认会话仅以读取权限打开游戏,从不在其中运行代码。
- 写入需要在 `Unreal.attach` 上设置 `write=True`。写入会直接进入游戏内存。
- UFunction 调用需要在 `Unreal.attach` 上设置 `calls=`:`'game-thread'` 通过经过过滤的 `ProcessEvent` 钩子排队,`'remote-thread'` 创建一个线程,`'any-thread'` 可在游戏内部使用。自定义 `Caller` 可以使用其他调用机制。转储器自身的调用需要 `allow_calls=`(CLI:`--allow-calls`)。
- 在新线程或任意线程上调用可能与游戏线程及其垃圾回收器发生竞争,导致游戏崩溃或状态损坏。游戏线程钩子需要一次自然发生的 `ProcessEvent` 入口,并且会一直留在游戏中,直到 `close()`、解释器正常退出或游戏重启。
- 延迟函数(接受 `FLatentActionInfo` 的函数)会被拒绝。
- 转储器无法验证的偏移会阻止写入和调用,但两个游戏名称键以及 `Off.FFieldClass.Id`、`Off.FFieldClass.ClassFlags`、`Off.FFieldClass.SuperClass` 除外(对于调用,还有两个 FText 键除外);错误信息会列出它们以及修复方法。
- 配置文件的钩子是转储器运行的 Python 代码(在内部模式下于游戏内运行):仅使用你信任的配置文件。
- 一次调用可能在游戏中遗留内存:引擎为输出参数分配的内存,以及调用超时或被中断时调用自身的内存。
- 在远程线程调用期间按 Ctrl+C 可能使游戏崩溃。
- 向已加载同一 `python3XY.dll` 的游戏注入 Python 会使其崩溃。在冻结应用之外,缺失的 `python_loader.dll` 会在首次使用时构建,这需要 MSVC,并且当它缺失时会下载并安装 Visual Studio Build Tools;请事先用 `python -m nylib.winutils.python_loader build` 构建一次。在冻结应用中,对于缺失的 DLL,`ensure_loader_dll()` 会改为抛出 `FileNotFoundError`。

<!-- dt:section id="tested-with-0" hash="86be06e7399b" -->
## 测试环境

- PalServer(UE 5.1,build 25247047)、TRIANGLE STRATEGY(UE 4.27,build 11410614)和 FrostBound(UE 5.4,build 24486464)。
- 转储:已在这三者的捕获数据上验证,并在这三者上与 Dumper-7 进行了实时对照;内部(注入式)转储已在 PalServer 上实时验证;`.usmap` 导出与 Dumper-7 在这三者捕获数据上的结果一致。
- IDA 导入器、运行时读取、调用参数布局、`--allow-calls` 目标和桩:已在这三者的捕获数据上检查;导入器已在 IDA 9.3 中应用。
- 在 FrostBound(主菜单)上实时验证:通过两种类型来源的运行时读取、一次属性写入(已恢复)、一次远程线程 UFunction 调用,以及启用全部三项功能的 `dump --allow-calls`,并与 Dumper-7 对同一 build 的输出进行了核对。
- 一位下游用户报告称,在 nylib `68ae975` 下,`calls='game-thread'` 在一款 UE 5.7 游戏上可用:附加时的一次 `Conv_StringToText` 调用和两次调用均已返回,且 `close()` 恢复了函数序言。本项目没有进行该次运行。
- 尚未在真实游戏上验证:`attach_current`、`calls='any-thread'` 和自定义 `Caller`;PalServer 和 TRIANGLE STRATEGY 上的运行时会话和 `--allow-calls`;带输入的调用,或带字符串、数组或 FText 输出的调用。
