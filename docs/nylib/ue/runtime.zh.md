> 本文档为 runtime.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="runtime.md" -->

<!-- dt:section id="__preamble__" hash="36422f87c4d2" -->
# Runtime

[Index](index.md) · 代码:`nylib/ue/runtime/session.py`(`Unreal`)、`nylib/ue/runtime/types.py`、`nylib/ue/runtime/invoke.py`

本页的每个代码片段都需要一个正在运行的游戏。

<!-- dt:section id="attach-0" hash="ce8d690abe21" -->
## 附加（Attach）

```python
from nylib.ue import Unreal

ue = Unreal.attach('TRIANGLE_STRATEGY-Win64-Shipping.exe', dump='latest')
print(ue)          # <Unreal external pid 1234 TRIANGLE_STRATEGY-Win64-Shipping.exe types=snapshot read-only>
ue.close()         # 或者: with Unreal.attach(...) as ue:
```

- `dump=None`（默认）：现在探测游戏，并在首次使用时从其中读取类型。
- `dump='latest'`：输出根目录下（见 [Dump](dump.md)）由该构建生成的最新快照；若没有匹配的快照则抛出 `DumpMismatchError`。
- `dump='auto'`：与上面相同，但如果没有匹配的快照会先执行 dump。这是使用默认导出项的完整 dump，包括 `image`（游戏的主模块，其中包含其代码：[Dump](dump.md#exports)）。
- `dump=r'<snapshot folder>'`：使用该快照；它必须与正在运行的构建匹配。
- `profile=`（一个路径，或 `nylib.ue.profiles.parse_profile(text)`）为探测（`dump=None`）以及 `dump='auto'` 生成的 dump 固定取值。快照会话会忽略 `profile=`，因为快照的偏移量在 dump 时就已固定：请先在 profile 中固定，然后重新 dump。若不传 `profile=`，探测会使用 `<out>/profiles/` 中 `[match] exe` 指向目标的那个 profile，并且 `probe:` 日志行会写明所用的 profile；为避免误选，请传入 `profile=`。Profile：[Dump](dump.md#probe-and-dump)。
- `out=` 是快照和 profile 的输出根目录；默认为环境变量 `NYLIB_UE_OUT`，否则为当前目录下的 `.\ue_dumps`。
- `call_timeout=`（秒，默认 10，`None` 表示永远等待）是 `ue.call_timeout` 的初始值（见 [调用 UFunction](#call-ufunctions)），也是该处附加时调用的等待时间。即使不带 `calls=` 也会检查它：`bool`，或任何非 `int` 和 `float` 的值会抛出 `TypeError`；零、负数、NaN 或无穷大会抛出 `ValueError`。
- `dump_exports=` 是一个 list 或 tuple，列出 `dump='auto'` 在需要 dump 时写出的导出格式，用以替代默认的五种（[Dump](dump.md#exports)；`()` 只写快照）。无论使用哪种 `dump=` 都会检查它，但仅在那里使用：不是由 `str` 组成的 list 或 tuple 时抛出 `TypeError`，未知格式抛出 `ValueError`。
- 在游戏内部（通过 `python -m nylib.winutils.python_loader inject --process <exe> --script <file>` 注入的脚本）：使用相同参数调用 `Unreal.attach_current(...)`；`dump='latest'` 和 `'auto'` 需要设置 `out=` 或环境变量 `NYLIB_UE_OUT`。
- 使用你自己的内存后端而不是进程句柄：[Own memory backend](dump.md#own-memory-backend)。

<!-- dt:section id="find-objects-0" hash="733cba957961" -->
## 查找对象

```python
world = ue.world()                                     # GWorld
pc = ue.local_player_controller()                      # 世界 -> 游戏实例 -> 第一个本地玩家
ue.find('/Script/Engine.Default__KismetSystemLibrary')   # 按完整路径查找，找不到则为 None
ue.find_class('GameEngine')                            # 短名称或路径；AmbiguousNameError 会列出匹配项
ue.objects_of('/Script/Engine.GameEngine')             # 某个类及其子类的实例，不含默认对象
ue.search('*PlayerController*')                        # 对对象名称做 glob 匹配；class_= 可缩小范围
ue.cdo('/Script/Engine.KismetSystemLibrary')           # 类的默认对象（CDO）
ue.component(pc.Pawn, '/Script/Engine.SceneComponent')   # 由某个 actor 拥有的该类的第一个组件
ue.enum('/Script/Engine.ENetRole').ROLE_Authority      # 一个 IntEnum
ue.object_at(pc._address_)                             # GObjects 列出该地址的对象，否则为 None
ue.refresh()                                           # 在对象增减之后重新读取对象列表
```

`object_at` 对于 GObjects 未列出的地址返回 None。它并不是存活性检查：一个已失效的地址若被新对象占用，则会返回该新对象。0 地址返回 None；负数或过大的地址会抛出 `ValueError`；`bool` 或其他非 `int` 类型会抛出 `TypeError`。

首次按名称查找（`find`、`find_class`、`objects_of`、`search`、`component`，以及按名称的 `cdo`）会构建所有对象的表，并一直保留到 `refresh()`；在一款 UE 5.7 游戏上，对 302,170 个对象耗时约 8 秒。在实时会话（`dump=None`）中，第一个类型化对象（例如 `ue.world()`）也会承担这一开销，因为读取第一个类型时会按名称查找两个类。快照会话在其首次查找时承担这一开销，即附加时的 FText 调用（参见 [调用 UFunction](#call-ufunctions)），或在首次读取快照中缺失的类型时；只有最后这种情况下 `object_at` 才会构建该表。

启用类型检查时，检查器并不知道查找到的对象的成员（查找结果返回的是基础对象类型）；请生成 stub 并使用 `typing.cast`，参见 [stubs.md](stubs.md)。

<!-- dt:section id="read-0" hash="5f7b6bbae32d" -->
## 读取

```python
pawn = pc.Pawn                       # 对象以其运行时类进行类型化；空指针为 None
pawn._path_, pawn._full_name_, pawn._address_
pawn.CustomTimeDilation              # 按 UE 名称访问成员（区分大小写）
pawn.RootComponent.RelativeLocation  # 对游戏内存的一个结构体视图（struct view）
for actor in world.PersistentLevel.Actors:   # TArray：len()、[i]、迭代、.to_list()
    print(actor)
pawn._get_('CustomTimeDilation')     # 按名称访问，用于不是合法 Python 名称的情况
pawn.cast('/Script/Engine.Actor')    # 以另一个类的视角查看同一对象
```

字符串以 `str` 返回，名称以 `str` 子类返回，map 带有 `.items()` / `.get()`。`FText` 在其布局已知后可通过 `str(value)` 读取：来自 calls 会话、使用 `allow_calls=('text',)` dump 的快照，或一个 profile（快照会话需要用它重新 dump 一次）。

<!-- dt:section id="write-0" hash="837c1e06c778" -->
## 写入

```python
ue = Unreal.attach('TRIANGLE_STRATEGY-Win64-Shipping.exe', dump='latest', write=True)
pawn = ue.local_player_controller().Pawn
pawn.CustomTimeDilation = 2.0
pawn.RootComponent.RelativeLocation.Z += 100.0   # 结构体字段是原地写入的
```

未带 `write=True` 的会话会抛出 `ReadOnlySessionError`。写入是原地修改值：新字符串必须能放入旧字符串的缓冲区，容器不能改变大小，`FText` 不能被写入。当偏移量未经验证时，`write=True` 会拒绝附加（`UnverifiedOffsetsError` 会列出它们）：可在 profile 中固定它们（快照会话需要用它重新 dump 一次），传入 `allow_unverified=True`，使用以 `allow_calls=('text',)` dump 的快照，或使用 `calls=` 附加（此时会话会通过一次调用解析两个 FText 偏移量）。两个游戏名称键（`Settings.Generator.GameName`、`GameVersion`）不会阻止写入；它们仍保留在 `ue.unverified` 中。

<!-- dt:section id="call-ufunctions-0" hash="353ff51b7c88" -->
## 调用 UFunction

```python
ue = Unreal.attach('TRIANGLE_STRATEGY-Win64-Shipping.exe', dump='latest', calls='remote-thread')
ksl = ue.cdo('/Script/Engine.KismetSystemLibrary')   # 静态函数在 CDO 上调用
print(ksl.GetEngineVersion())                       # 单个输出：即值本身
pawn = ue.local_player_controller().Pawn
r = pawn.K2_SetActorLocation((0.0, 0.0, 500.0), False, True)   # NewLocation, bSweep, bTeleport
print(r.ReturnValue, r.SweepHitResult)              # 多个输出：一个具名元组（named tuple），返回值在前
ue.call_timeout = 5.0                               # 单位为秒；默认 10，None 表示永久等待
```

- `calls='game-thread'` 会将调用排入队列，等待游戏线程下一次自然进入 `ProcessEvent` 时执行，无论是在游戏内部还是外部。它需要 `keystone-engine` 和 `capstone`：除非设置了 `PYTHON_PIP_ALL_REQ_INSTALLED`，或应用已被冻结，否则 `nylib.utils.pip` 会在首次使用时安装它们，因此请事先运行 `pip install ".[asm]"`。如果它们仍无法导入，附加会在触及游戏之前以 `CallError(refused='dependencies')` 失败。在冻结的应用中，错误信息会指出捆绑包以及 nylib 的 PyInstaller 钩子（`hook-keystone.py`、`hook-capstone.py`），而不是 pip。
- 当游戏线程会话必须解析 FText 布局时（通常是探测，或未使用 `allow_calls=('text',)` dump 的快照），它会在 `Unreal.attach` 期间给 `ProcessEvent` 打补丁；否则会在首次调用时打补丁。随后附加会最多等待 `call_timeout`（默认 10 秒）以等待该入口，并以前缀 `attach FText call:` 记录该调用。`ue.attach_call` 是该调用的 `FeatureResult`（`ok`、`detail`），在 `close()` 之后仍保留；若附加期间未进行任何调用（FText 偏移量已知，或未指定 `calls=`），则为 `None`。如果该调用失败或超时，附加仍会成功（使用 `write=True` 时会抛出 `UnverifiedOffsetsError`）：请查看日志、`ue.attach_call` 或 `ue.unverified` 中的两个 FText 键。如果该调用被拒绝（`CallError.refused` 已设置，见下文），附加会改为抛出该 `CallError`，并在此之前关闭调用方、快照和目标。
- `CallError.refused` 是程序可以测试的标签；对于没有标签的失败，它为 `None`。标签有：`'dependencies'`（见上文）；`'prologue'`，触发器的开头指令无法被重定位到 hook 中（跳转、调用、返回或 RIP 相对操作数，这是遗留 hook 的表现形式，或序言跨越页边界），由调用时抛出；`'vtable'`，`ProcessEvent` 的 vtable 项不是可执行代码，因此没有调用任何东西。会话还会在调用开始前对其拒绝的调用加上标签：`'delegate'`、`'latent'`、`'destroyed'`、`'not found'`、`'not a class function'`、`'no default object'`、`'class'`。任何其他 hook 安装失败会显示 "the hook could not install"，且不带标签。
- 如果游戏线程停止进入该函数，调用可能超时；从同一线程发起调用会被拒绝。当一个已超时的调用仍处于未完成（pending）状态时，`close()` 会抛出 `PendingCallsError`（它同时是 `SessionError` 和 `RuntimeError`；`.pending` 统计调用数）。会话仍保持打开且可用：待该调用执行完毕后重试 `close()`。`ue.pending_calls` 统计会阻止 `close()` 完成的调用；在没有调用、`close()` 之后，以及游戏进程消失后，它为 0，因此等待循环会在游戏退出或崩溃时结束。`close()` 没有 `wait=` 参数：请自行轮询并设定截止时间。
- hook 会一直保留在游戏中，直到 `close()` 或游戏重启（当附加失败而其自身的调用仍未完成时也是如此：此时没有 `ue` 可供关闭）；遗留 hook 之上的后续 game-thread 会话中，每次调用都会抛出 `CallError(refused='prologue')`。请使用 `with Unreal.attach(...) as ue:` 或 `try ... finally: ue.close()`。
- 程序正常退出解释器时，nylib 会移除它仍持有的游戏线程 hook。这绝不会运行游戏代码，也绝不会等待未完成的调用：正在使用、有调用未完成或无法移除的 hook 会保持安装，并输出一条 WARNING，其中写明其地址。被杀死或崩溃的解释器，或 `os._exit`，会使 hook 残留，直到游戏重启。
- 附加失败时留下的 hook（见上文），会在本解释器下一次对同一进程使用 `calls=` 附加时被重试：若可以移除则会被移除，其目标句柄也会被关闭。仍有未完成调用而忙碌的 hook 会保持安装，并输出一条 WARNING `parked game-thread hook at <address> in process <pid> stays installed`。不带 `calls=` 的附加，或附加到另一个进程，永远不会触碰它。
- `calls='remote-thread'` 会在游戏中的一个新线程上运行每次调用；在游戏内部，`attach_current(calls='any-thread')` 会在调用线程上运行它。这些方式可能与游戏线程及其垃圾回收器发生竞争。`call_timeout` 适用于 `game-thread` 和 `remote-thread`；`any-thread` 会忽略它。
- `ue.game_thread()` 会打开检测到的游戏线程：即名为 `GameThread` 的那个线程，否则为最早创建的线程。以下情况会抛出 `DetectionError`：没有线程符合条件、线程扫描失败、线程在打开前已退出，或打开被拒绝（受保护的游戏可能拒绝该访问）。`HookCaller` 或 `ApcCaller` 的默认线程在附加时会抛出同样的错误。请关闭返回的 `Thread` 句柄，或将其用于 `with`。
- 对于 APC，请传入 `calls=calls.ApcCaller(thread)`（`from nylib.ue import calls`）而不是字符串。`thread` 可以是 TID、`Thread`，或 `None`（表示检测到的游戏线程）。该线程必须进入可警报等待（alertable wait）；超时的 APC 之后可能仍会运行，并保留其调用内存。
- 若要选择线程或被 hook 的函数，请传入 `calls=calls.HookCaller(thread_id=None, trigger=None, capacity=16)`。`thread_id` 会覆盖检测到的游戏线程。`trigger` 是另一个函数的地址，该函数的入口会在该线程上清空队列（默认：`ProcessEvent`）；调用本身仍经过 `ProcessEvent`，因此其索引必须经过验证。`capacity` 是队列大小，为 1 到 64 之间的 2 的幂。
- 输入按反射顺序或按关键字传入。省略的输入为零；`FText` 类型的输入不能省略。结构体输入可以是结构体本身、元组或字典。Out 参数永远不会被传入；它们会在结果中返回。
- 结果是拷贝。没有输出的调用返回 `None`。UE 会在没有任何提示的情况下跳过某些调用，因此零输出也可能意味着“未执行”。
- `calls=` 会在偏移量未经验证时拒绝附加（`UnverifiedOffsetsError`），但两个 FText 键和两个游戏名称键除外。在探测会话中，profile 中的 `[globals] process_event = { index = ... }` 固定项会验证 ProcessEvent 索引。
- 未设置 `calls=` 时，调用会抛出 `CallsDisabledError`。Latent 函数会被拒绝。参数错误会抛出 `MarshalError`；调用失败或超时会抛出 `CallError`。

若要在关闭前等待未完成的调用（游戏消失后它会自行停止）：

```python
import time

deadline = time.monotonic() + 30.0
while ue.pending_calls and time.monotonic() < deadline:
    time.sleep(0.05)
ue.close()    # 若仍有调用未完成，则抛出 PendingCallsError
```

若要使用已有的游戏线程泵（pump），请传入一个 `Caller` 实例。其 `call` 必须返回目标的整数 `rax`，并在执行失败或结果不确定时抛出 `CallError`：

```python
from nylib.ue import calls

class MyQueueCaller(calls.Caller):
    policy = 'game-thread'

    def __init__(self, queue):
        super().__init__()
        self.queue = queue

    def arena(self):
        return calls.CallArena(self.process)

    def call(self, function, *args, timeout):
        return self.queue.run_on_game_thread(function, args, timeout)

ue = Unreal.attach(target, calls=MyQueueCaller(my_queue))
```

会话会调用一次 `bind(site)`；基类实现会为 `arena()` 保存 `site.process`。`site` 还提供 ProcessEvent 的索引和地址、游戏线程打开器，以及默认超时。调用方拥有其安装的任何 hook，并应在 `close()` 中将其释放。
