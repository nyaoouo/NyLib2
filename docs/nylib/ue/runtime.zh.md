> 本文档为 runtime.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="runtime.md" -->

<!-- dt:section id="__preamble__" hash="36422f87c4d2" -->
# Runtime

[Index](index.md) · 代码:`nylib/ue/runtime/session.py`(`Unreal`)、`nylib/ue/runtime/types.py`、`nylib/ue/runtime/invoke.py`

本页的每个代码片段都需要一个正在运行的游戏。

<!-- dt:section id="attach-0" hash="d20d6ed0f85e" -->
## 附加（Attach）

```python
from nylib.ue import Unreal

ue = Unreal.attach('TRIANGLE_STRATEGY-Win64-Shipping.exe', dump='latest')
print(ue)          # <Unreal external pid 1234 TRIANGLE_STRATEGY-Win64-Shipping.exe types=snapshot read-only>
ue.close()         # 或者: with Unreal.attach(...) as ue:
```

- `dump=None`（默认）：现在探测游戏，并在首次使用时从其中读取类型。
- `dump='latest'`：输出根目录下（见 [Dump](dump.md)）由该构建生成的最新快照；若没有则抛出 `DumpMismatchError`。
- `dump='auto'`：与上面相同，但如果没有匹配的快照会先执行 dump。这是使用默认导出项的完整 dump，包括 `image`（游戏的主模块，其中包含其代码：[Dump](dump.md#exports)）。
- `dump=r'<snapshot folder>'`：使用该快照；它必须与正在运行的构建匹配。
- `profile=`（一个路径，或 `nylib.ue.profiles.parse_profile(text)`）为探测（`dump=None`）以及 `dump='auto'` 生成的 dump 固定取值。快照会话会忽略 `profile=`，因为快照的偏移量在 dump 时就已固定：请先在 profile 中固定，然后重新 dump。若不传 `profile=`，探测会使用 `<out>/profiles/` 中 `[match] exe` 及可选的构建约束与目标匹配的那个 profile，并且 `probe:` 日志行会写明所用的 profile；为避免误选，请传入 `profile=`。Profile：[Dump](dump.md#probe-and-dump)。
- `out=` 是快照和 profile 的输出根目录；默认为 `NYLIB_UE_OUT`，否则为当前目录下的 `.\ue_dumps`。
- `call_timeout=`（秒，默认 10，`None` 表示永远等待）是 `ue.call_timeout` 的初始值（见 [调用 UFunction](#call-ufunctions)），也是该处附加时调用的等待时间。即使不带 `calls=` 也会检查它：`bool`，或任何非 `int` 和 `float` 的值会抛出 `TypeError`；零、负数、NaN、无穷大或大于 `threading.TIMEOUT_MAX` 的值（Windows 上为 4294967 秒）会抛出 `ValueError`。`ue.call_timeout`、内置调用器 `call()` 的 `timeout=` 以及 `nylib.ue.remote_calls` 函数的 `timeout=` 适用同样的规则。
- `cache_bytes=` 控制探测以及 `dump='auto'` dump 的遍历：`None` 使用默认的页缓存上限（游戏外为 1 GiB，游戏内为 128 MiB），`0` 表示不使用缓存读取，不小于 `0x10000` 的整数则以字节为单位设置上限。`bool` 或其他非 `int` 类型会抛出 `TypeError`；负值或 `1..0xFFFF` 会抛出 `ValueError`，且发生在目标打开或绑定调用器之前。附加之后通过 `ue` 进行的读取无论如何都不使用缓存。
- `dump_exports=` 是一个 list 或 tuple，列出 `dump='auto'` 在需要 dump 时写出的导出格式，用以替代默认的五种（[Dump](dump.md#exports)；`()` 只写快照）。无论使用哪种 `dump=` 都会检查它，但仅在那里使用：不是由 `str` 组成的 list 或 tuple 时抛出 `TypeError`，未知格式抛出 `ValueError`。
- 在游戏内部（通过 `python -m nylib.winutils.python_loader inject --process <exe> --script <file>` 注入的脚本）：使用相同参数调用 `Unreal.attach_current(...)`；`dump='latest'` 和 `'auto'` 需要设置 `out=` 或 `NYLIB_UE_OUT`。
- 使用 `attach_current(calls='game-thread')` 时，钩子在附加时或首次调用时安装，并在空闲状态下于 `close()` 或解释器正常退出时移除。当被注入解释器的另一个 Python 线程正在运行时，这些步骤可能让游戏卡住：在钩子安装、移除和代码释放期间，请让那些线程保持空闲（[队列说明](../winutils/inline_call.md#notes)）。在进程内以 `replace_stale=True` 移除残留 hook 同样有此风险。
- 使用你自己的内存后端而不是进程句柄：[Own memory backend](dump.md#own-memory-backend)。

<!-- dt:section id="find-objects-0" hash="0e5ed0c4a0e6" -->
## 查找对象

```python
world = ue.world()                                     # GWorld
pc = ue.local_player_controller()                      # 世界 -> 游戏实例 -> 第一个本地玩家
ue.find('/Script/Engine.Default__KismetSystemLibrary')   # 按完整路径查找，找不到则为 None
ue.find_class('GameEngine')                            # 短名称或路径；AmbiguousNameError 会列出匹配项
ue.objects_of('/Script/Engine.GameEngine')             # 某个类及其子类的实例，不含默认对象
ue.search('*PlayerController*')                        # 对对象名称做 glob 匹配；class_= 可缩小范围
ue.cdo('/Script/Engine.KismetSystemLibrary')           # 类的默认对象
ue.component(pc.Pawn, '/Script/Engine.SceneComponent')   # 由某个 actor 拥有的该类的第一个组件
ue.enum('/Script/Engine.ENetRole').ROLE_Authority      # 一个 IntEnum
ue.object_at(pc._address_)                             # GObjects 列出该地址的对象，否则为 None
ue.struct_at('/Script/CoreUObject.Vector', address)      # 位于某地址的 struct 视图，地址为 0 时为 None
ue.refresh()                                           # 在对象增减之后重新读取对象列表
```

`object_at` 对于 GObjects 未列出的地址返回 None。它并不是存活性检查：一个已失效的地址若被新对象占用，则会返回该新对象。0 地址返回 None；负数或过大的地址会抛出 `ValueError`；`bool` 或其他非 `int` 类型会抛出 `TypeError`。

`struct_at(struct, address)` 接受 struct 路径，或来自本会话 `ue.type()` 的 struct 类。它创建一个视图，但不读取该地址；成员在访问时才读取内存，写入则遵循 `write=`。对于相同的类型和地址，它与反射得到的成员视图比较相等。地址必须是 `0..0xFFFFFFFFFFFFFFFF` 范围内且不是 `bool` 的 `int`（类型错误抛出 `TypeError`，超出范围抛出 `ValueError`）；在类型解析之后，0 得到 `None`。未知路径，或类、枚举的路径，会抛出 `LookupError`；对象类、其他会话的 struct 类、实例，或任何不是 `str` 的其他 `struct`，会抛出 `TypeError`。已关闭的会话抛出 `SessionError`；无法读取的成员抛出 `MemoryReadError`。

首次按名称或类查找（`find`、`find_class`、`objects_of`、`search`、`component`，以及按名称的 `cdo`）会构建所有对象的表，并一直保留到 `refresh()`；在一款 UE 5.7 游戏上，对 302,170 个对象耗时约 8 秒。在实时会话（`dump=None`）中，第一个类型化对象（例如 `ue.world()`）也会承担这一开销，因为读取第一个类型时会按名称查找两个类。快照会话在其首次查找时承担这一开销，即附加时的 FText 调用（参见 [调用 UFunction](#call-ufunctions)），或在首次读取快照中缺失的类型时；只有最后这种情况下 `object_at` 才会构建该表。

启用类型检查时，检查器并不知道查找到的对象的成员（查找结果返回的是基础对象类型）；请生成 stub 并使用 `typing.cast`，参见 [stubs.md](stubs.md)。

<!-- dt:section id="read-0" hash="43bb3d0697aa" -->
## 读取

```python
pawn = pc.Pawn                       # 对象按其运行时类返回对应类型；空指针返回 None
pawn._path_, pawn._full_name_, pawn._address_
pawn.CustomTimeDilation              # 成员使用其 UE 名称访问（区分大小写）
pawn.RootComponent.RelativeLocation  # 指向游戏内存的结构体视图
for actor in world.PersistentLevel.Actors:   # TArray：len()、[i]、迭代、.to_list()
    print(actor)
pawn._get_('CustomTimeDilation')     # 按原始 UE 名称访问
pawn.cast('/Script/Engine.Actor')    # 将同一对象视为另一个类
```

属性名遵循 `make_name_valid`：标识符中无效的字符变为 `_`，开头的数字变为单词，`bool` 变为 `Bool`，`NULL` 变为 `NULLL`。随后运行时会为 Python 关键字加上结尾的 `_`。函数遵循同样的规则：`Give Perfect Window` 变为 `Give_Perfect_Window`。当某个属性无法访问某个成员或函数时，请使用 `_get_(raw_ue_name)`、`_set_(raw_ue_name, value)` 和 `_call_(raw_ue_name, *args, **kwargs)`：例如 `cast`、以 `_` 开头并以 `_` 结尾的名称，或属性名与另一个函数冲突的第二个函数。

字符串以 `str` 返回，名称以 `str` 子类返回，映射带有 `.items()` / `.get()`。一旦布局已知，`FText` 可用 `str(value)` 读取：布局来自调用会话、用 `allow_calls=('text',)` dump 的快照，或配置文件（快照会话需要用它重新做一次 dump）。`str()` 给出源字符串；对于本地化文本，它是源语言字符串，或在某些游戏中是其本地化键，而不是游戏显示的文本。

<!-- dt:section id="write-0" hash="dfe042c65e99" -->
## 写入

```python
ue = Unreal.attach('TRIANGLE_STRATEGY-Win64-Shipping.exe', dump='latest', write=True)
pawn = ue.local_player_controller().Pawn
pawn.CustomTimeDilation = 2.0
pawn.RootComponent.RelativeLocation.Z += 100.0   # 结构体字段就地写入
```

没有 `write=True` 的会话会抛出 `ReadOnlySessionError`。写入就地修改值：新字符串必须能放入旧字符串的缓冲区，容器不能改变大小，`FText` 不能写入。偏移量未验证时，`write=True` 会拒绝附加（`UnverifiedOffsetsError` 会列出它们）：请在配置文件中固定它们（快照会话需要用它重新做一次 dump）、传入 `allow_unverified=True`、使用用 `allow_calls=('text',)` dump 的快照，或使用 `calls=` 附加（会话随后通过一次调用解析两个 FText 偏移量）。两个游戏名键（`Settings.Generator.GameName`、`GameVersion`）以及 `Off.FFieldClass.Id`、`Off.FFieldClass.ClassFlags`、`Off.FFieldClass.SuperClass` 不会阻止写入；它们保留在 `ue.unverified` 中。没有任何写入或调用路径会读取这三个 FFieldClass 键。

<!-- dt:section id="call-ufunctions-0" hash="46b3f19e11b5" -->
## 调用 UFunction

```python
ue = Unreal.attach('TRIANGLE_STRATEGY-Win64-Shipping.exe', dump='latest', calls='remote-thread')
ksl = ue.cdo('/Script/Engine.KismetSystemLibrary')   # 静态函数在 CDO 上调用
print(ksl.GetEngineVersion())                       # 一个输出：直接是该值
pawn = ue.local_player_controller().Pawn
r = pawn.K2_SetActorLocation((0.0, 0.0, 500.0), False, True)   # NewLocation, bSweep, bTeleport
print(r.ReturnValue, r.SweepHitResult)              # 多个输出：具名元组，返回值在前
ue.call_timeout = 5.0                               # 秒；默认 10，None 表示永远等待
```

- `calls='game-thread'` 把调用排入队列，等游戏线程下一次自然进入 `ProcessEvent` 时执行，无论在游戏内部还是外部。它需要 `keystone-engine` 和 `capstone`：除非设置了 `PYTHON_PIP_ALL_REQ_INSTALLED` 或应用已被冻结，否则 `nylib.utils.pip` 会在首次使用时安装它们，因此请事先运行 `pip install ".[asm]"`。如果仍然无法导入它们，附加会在打开目标之前以 `CallError(refused='dependencies')` 失败。在冻结的应用中，该消息指明的是打包产物和 nylib 的 PyInstaller hook（`hook-keystone.py`、`hook-capstone.py`），而不是 pip。
- 当会话必须解析 FText 布局时（通常是探测，或在没有 `allow_calls=('text',)` 的情况下 dump 的快照），游戏线程会话会在 `Unreal.attach` 期间给它的触发点（`ProcessEvent`，除非 `HookCaller(trigger=)` 指定了另一个函数）打补丁，否则在第一次调用时打补丁。对于默认触发点，附加的 WARNING 会写明 `ProcessEvent`；对于显式的 `HookCaller(trigger=)`，则写明触发点地址。随后附加最多等待 `call_timeout`（默认 10 秒）以等到该次进入，并以前缀 `attach FText call:` 记录这次调用。`ue.attach_call` 是该调用的 `FeatureResult`（`ok`、`detail`），在 `close()` 之后仍保留；若没有进行附加时的调用（FText 偏移量已知，或没有 `calls=`），则为 `None`。如果该调用失败或超时，附加仍会成功（带 `write=True` 时则抛出 `UnverifiedOffsetsError`）：请检查日志、`ue.attach_call`，或 `ue.unverified` 中的两个 FText 键。如果该调用被拒绝（设置了 `CallError.refused`，见下文），附加会在关闭调用方、快照和目标之后抛出该 `CallError`。
- `CallError.refused` 是程序可以测试的标签；对于没有标签的失败，它为 `None`。标签有：`'dependencies'`（见上文）；`'prologue'`，触发点的起始指令无法被重定位到 hook 中（跳转、调用、返回或 RIP 相对操作数，残留的 hook 就是这样表现的，或者序言跨越了页边界），由某次调用抛出；`'vtable'`，`ProcessEvent` 的 vtable 条目不是可执行代码，因此没有调用任何东西。会话还会为在开始前就被它拒绝的调用打上标签：`'delegate'`、`'latent'`、`'destroyed'`、`'not found'`、`'not a class function'`、`'no default object'`、`'class'`。任何其他 hook 安装失败，都显示为 "the hook could not install"，不带标签。
- `CallError.state` 描述执行情况：`'not started'` 保证什么都没有运行，重试是安全的；`'unknown'` 表示它可能已经运行或仍在运行，因此不要重试非幂等的调用；`'finished'` 表示它已运行，`partial` 中保存着在某次输出读取失败之前已解码的输出。`timed_out=True` 表示等待在其截止时间结束：此时 `remote-thread` 和 `apc` 报告 `'unknown'`，因为调用可能仍在运行；游戏线程的结果见下文。`exited=True` 表示游戏已开始退出。`remote-thread` 和 `apc` 共用一个退出辅助函数，即使调用尚未返回也会报告 `'finished'`。`exception` 保存 `any-thread` 在本进程中失败时的异常文本。自定义的 `Caller` 提供 `state` 和 `exited`；nylib 把缺失的 `state` 视为 `'unknown'`。
- 在开始之前就超时的游戏线程调用会被撤回，且绝不会运行。如果它在撤回之前于截止时间完成，则返回其结果。已开始的调用保持未完成；撤回失败同样会给出 `timed_out=True`、`state='unknown'`，且消息中带有 `withdrawing it failed`。另一个线程可以通过 `caller.withdraw_pending()` 或 `ue.withdraw_pending_calls()` 撤回每一个正在等待的调用。

| 游戏线程 `CallError` | `timed_out` | `exited` | `state` |
| --- | --- | --- | --- |
| 超时，正在等待的调用已撤回；它绝不会运行 | `True` | `None` | `'not started'` |
| 超时，调用已经开始；仍未完成 | `True` | `None` | `'unknown'` |
| 另一个线程在调用开始之前将其撤回 | `None` | `None` | `'not started'` |
| 检测到退出，正在等待的调用已撤回；即使退出中的线程之后进入触发点，它也绝不会运行 | `None` | `True` | `'not started'` |
| 检测到退出，调用已完成 | `None` | `True` | `'finished'` |
| 检测到退出，调用正在运行或无法确定其状态 | `None` | `True` | `'unknown'` |

- 如果游戏线程不再进入该函数，调用可能会超时；从该线程自身发起调用会被拒绝。当某个已超时的调用仍未完成时，`close()` 会抛出 `PendingCallsError`（既是 `SessionError` 又是 `RuntimeError`；`.pending` 统计调用数）。会话保持打开且可用：待该调用运行之后再重试 `close()`。`ue.pending_calls` 统计使 `close()` 无法完成的调用数；没有调用时、`close()` 之后、以及游戏进程消失之后它都为 0，因此基于它的等待循环会在游戏退出或崩溃时结束。`close()` 没有 `wait=`：请用你自己的截止时间轮询。对于 `HookCaller`，`caller.pending == 0`（或 `ue.pending_calls == 0`）表示它排入队列的每个调用都已完成或已撤回，或游戏已不存在；此时你为某个已超时的调用分配的内存（其代码和参数）可以被释放。已撤回的调用不计入，且由于它绝不会运行，其内存在被撤回之后即可释放。调用按提交顺序运行，跳过已撤回的调用，因此后一个调用返回也意味着在它之前的每个调用都已返回或已撤回。
- `ue.withdraw_pending_calls()` 返回它撤回了多少个正在等待的游戏线程调用；已开始的调用继续运行。在已关闭、没有调用，或使用 `HookCaller` 以外的内置调用方时，它返回 0；自定义调用方可以实现 `withdraw_pending()`。`ue.close(withdraw_pending=True)` 会在关闭之前撤回正在等待的调用，并在其数量非零时以 INFO 记录该数量。当有已开始的调用仍未完成时，它仍会抛出 `PendingCallsError`，并使会话保持打开。默认值为 `False`；非 `bool` 会抛出 `TypeError`，即使已经关闭也是如此。
- hook 会一直留在游戏中，直到 `close()`、解释器正常退出或游戏重启（在附加失败而它自己的调用仍未完成时也是如此：此时没有可供关闭的 `ue`）。默认情况下，之后的游戏线程会话在残留 hook 之上发起的调用，会抛出 `CallError(refused='prologue', state='not started')`。消息会区分三种情形：“a game-thread hook this process installed”（在其调用完成或被撤回之后关闭它的会话；正常退出也会移除它，下一次启用 calls 的附加会重试失败的附加所搁置的那个 hook）、“a nylib game-thread hook that this process does not hold”（关闭持有它的会话，或在它已残留时使用下文的 `replace_stale=True`），以及一个“that is not a nylib game-thread hook this version recognises”的跳转（其他工具或版本；对于已结束的会话留下的 hook，重启游戏）。请使用 `with Unreal.attach(...) as ue:` 或 `try ... finally: ue.close()`。
- `calls=calls.HookCaller(replace_stale=True)` 表示选择在安装新 hook 之前，先移除已识别的残留 nylib 游戏线程 hook。它会拒绝本进程仍持有的 hook、无法识别的跳转、其安装者进程仍在运行并映射着其队列的 hook，或其安装者无法检查的 hook（例如本宿主无法读取的提权进程）。拒绝消息在已知时会写明安装者的 pid，并说明 `which still runs` 或 `could not be checked`。来自早于安装者跟踪功能的 nylib 版本的已识别 hook 视为残留；移除它会使那个旧宿主的调用停止，并在它仍在运行时使其 `close()` 失败。在运行它的进程中，只有本 nylib 副本的队列算作被持有，因此它也会移除另一个 nylib 副本，或那里重新加载的 `nylib.winutils.inline_call` 模块仍在使用的 hook；该会话的调用随后会停止，其 `close()` 会失败。`replace_stale` 默认为 `False`；非 `bool` 会抛出 `TypeError`。
- 成功移除残留 hook 时会记录一条 WARNING，写明触发点、目标 pid、dispatcher 页面，以及被丢弃的先前已排队调用的数量。如果在移除停止重试时，旧的清空操作仍在运行（例如一个永不返回的调用），移除会恢复触发点，但会泄漏旧页面和队列视图，记录一条 WARNING 并安装新的 hook。写有 `could not be removed` 的拒绝通常会让残留 hook 保留原样；它也可能出现在原始触发点字节已被恢复之后的保护恢复或线程恢复失败时：此时旧页面和视图会泄漏，下一次调用会正常安装。
- 解释器正常退出时，nylib 会移除它仍持有的游戏线程 hook。这绝不会运行游戏代码，也绝不会等待未完成的调用：正在使用、仍有未完成调用或无法移除的 hook 会保持安装，并附带写明其地址的 WARNING。被终止或崩溃的解释器，或 `os._exit`，会让该 hook 一直留到残留 hook 的移除或游戏重启。
- 失败的附加所搁置的 hook（见上文），会在本解释器下一次对同一进程进行带 `calls=` 的附加时重试：如果可以移除，就会移除它，并关闭其目标句柄。仍因未完成的调用而忙碌的 hook 保持安装，并附带 WARNING `parked game-thread hook at <address> in process <pid> stays installed`。不带 `calls=` 的附加，或对另一个进程的附加，绝不会触及它。
- `calls='remote-thread'` 在游戏中的一个新线程上运行每次调用；在游戏内部，`attach_current(calls='any-thread')` 在调用线程上运行它。这些方式可能与游戏线程及其垃圾回收器产生竞争。`call_timeout` 适用于 `game-thread` 和 `remote-thread`；`any-thread` 忽略它。
- `ue.game_thread()` 打开检测到的游戏线程：名为 `GameThread` 的那个唯一线程，否则是最早创建的线程。当没有线程符合条件、线程扫描失败、线程在被打开之前已退出，或打开被拒绝（受保护的游戏可能拒绝该访问）时，它抛出 `DetectionError`。`HookCaller` 或 `ApcCaller` 的默认线程在附加时会抛出相同的错误。请关闭返回的 `Thread` 句柄，或将其用于 `with`。`ue.call_thread_id` 是该会话的 `HookCaller` 所服务的线程 id，没有 `HookCaller` 或在关闭之后则为 `None`。`game_thread()` 会重新检测，因此可能与它不同，例如在使用 `thread_id=` 之后。
- 对于 APC，请传入 `calls=calls.ApcCaller(thread)`（`from nylib.ue import calls`）而不是字符串。`thread` 是一个 TID、一个 `Thread`，或 `None`（表示检测到的游戏线程）。该线程必须进入可警报等待；已超时的 APC 之后仍可能运行，并保留其调用内存。
- 要选择线程或被 hook 的函数，请传入 `calls=calls.HookCaller(thread_id=None, trigger=None, capacity=16, replace_stale=False)`。`thread_id` 覆盖检测到的游戏线程。`trigger` 是另一个函数的地址，其入口会在该线程上清空队列（默认：`ProcessEvent`）；不在已提交的可执行内存中的触发点会在附加时抛出 `ValueError`；调用本身仍经由 `ProcessEvent` 进行，因此必须验证它的索引。`capacity` 是队列大小，为 1 到 64 之间的 2 的幂。
- 输入按反射顺序或按关键字传入。省略的输入为零；`FText` 输入不能省略。结构体输入接受该结构体、tuple、list 或 dict。输出参数永远不传入；它们在结果中返回。`ref` 参数像输入一样传入，并同样在结果中返回：只有一个输出时是裸值，否则是返回值在前的具名元组。对于结构体 ref，请传入 tuple、list 或 dict，绝不要传 `StructView`。Ref 输入在任何深度都不能包含非空字符串、数组、集合或映射，也不能包含任何 FText（`MarshalError`）；空字符串和空容器可以接受。
- 结果是副本。没有输出的调用返回 `None`。UE 会不作任何提示地跳过某些调用，因此零个输出可能意味着“没有运行”。
- 当存在未验证的偏移量时，`calls=` 拒绝附加（`UnverifiedOffsetsError`），但两个 FText 键、两个游戏名称键，以及 `Off.FFieldClass.Id`、`Off.FFieldClass.ClassFlags`、`Off.FFieldClass.SuperClass` 除外。在探测会话中，profile 的 `[globals] process_event = { index = ... }` 固定值会验证 ProcessEvent 索引。
- 不带 `calls=` 时，调用会抛出 `CallsDisabledError`。Latent 函数会被拒绝。错误的参数抛出 `MarshalError`；失败或超时的调用抛出 `CallError`。

要在关闭之前等待未完成的调用（游戏消失时它会自行停止）：

```python
import time

deadline = time.monotonic() + 30.0
while ue.pending_calls and time.monotonic() < deadline:
    time.sleep(0.05)
ue.close()    # 若仍有调用未完成则抛出 PendingCallsError
```

要使用现有的游戏线程泵，请传入一个 `Caller` 实例。它的 `call` 必须返回目标的整数 `rax`，并对失败或不确定的执行抛出 `CallError`：

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

会话会调用一次 `bind(site)`；基类实现会为 `arena()` 保存 `site.process`。`site` 还提供 ProcessEvent 的索引和地址、一个游戏线程打开器，以及默认超时。调用方拥有它所安装的任何 hook，并应在 `close()` 中释放它。来自 `caller.arena()` 的 arena 使用会话的进程句柄，而在从游戏外部附加的会话中，`ue.close()` 会关闭该句柄：请在关闭会话之前释放该 arena（或对其调用 `leak()`）。只有在确知调用未开始或已完成时（`CallError.state`，或对 `HookCaller` 而言 `caller.pending == 0`）才可释放它；否则请 `leak()` 它。
