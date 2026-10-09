> 本文档为 runtime.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="runtime.md" -->

<!-- dt:section id="__preamble__" hash="36422f87c4d2" -->
# Runtime

[Index](index.md) · 代码:`nylib/ue/runtime/session.py`(`Unreal`)、`nylib/ue/runtime/types.py`、`nylib/ue/runtime/invoke.py`

本页的每个代码片段都需要一个正在运行的游戏。

<!-- dt:section id="attach-0" hash="f76362eae5c9" -->
## 附加（Attach）

```python
from nylib.ue import Unreal

ue = Unreal.attach('TRIANGLE_STRATEGY-Win64-Shipping.exe', dump='latest')
print(ue)          # <Unreal external pid 1234 TRIANGLE_STRATEGY-Win64-Shipping.exe types=snapshot read-only>
ue.close()         # or: with Unreal.attach(...) as ue:
```

- `dump=None`（默认）：现在探测游戏，并在首次使用时从其中读取类型。
- `dump='latest'`：输出根目录下（见 [Dump](dump.md)）由该构建生成的最新快照；若没有匹配的快照则抛出 `DumpMismatchError`。
- `dump='auto'`：与上面相同，但如果没有匹配的快照会先执行 dump。
- `dump=r'<snapshot folder>'`：使用该快照；它必须与正在运行的构建匹配。
- 在游戏内部（通过 `python -m nylib.winutils.python_loader inject --process <exe> --script <file>` 注入的脚本）：使用 `Unreal.attach_current(...)`，参数相同；`dump='latest'` 和 `'auto'` 需要 `out=` 或 `NYLIB_UE_OUT`。
- 使用你自己的内存后端而不是进程句柄：[Own memory backend](dump.md#own-memory-backend)。

<!-- dt:section id="find-objects-0" hash="e697870e5288" -->
## 查找对象

```python
world = ue.world()                                     # GWorld
pc = ue.local_player_controller()                      # world -> game instance -> first local player
ue.find('/Script/Engine.Default__KismetSystemLibrary')   # by full path, or None
ue.find_class('GameEngine')                            # short name or path; AmbiguousNameError lists matches
ue.objects_of('/Script/Engine.GameEngine')             # instances of a class and its subclasses, no default objects
ue.search('*PlayerController*')                        # glob over object names; class_= narrows it
ue.cdo('/Script/Engine.KismetSystemLibrary')           # the class default object
ue.component(pc.Pawn, '/Script/Engine.SceneComponent')   # first component of that class owned by an actor
ue.enum('/Script/Engine.ENetRole').ROLE_Authority      # an IntEnum
ue.refresh()                                           # re-read the object list after objects came and went
```

启用类型检查时，检查器并不知道查找到的对象的成员（查找结果返回的是基础对象类型）；请生成 stub 并使用 `typing.cast`，参见 [stubs.md](stubs.md)。

<!-- dt:section id="read-0" hash="fe783bb257f6" -->
## 读取

```python
pawn = pc.Pawn                       # 对象以其运行时类进行类型化;空指针为 None
pawn._path_, pawn._full_name_, pawn._address_
pawn.CustomTimeDilation              # 按 UE 名称访问成员(大小写敏感)
pawn.RootComponent.RelativeLocation  # 对游戏内存的一个结构体视图(struct view)
for actor in world.PersistentLevel.Actors:   # TArray:len()、[i]、迭代、.to_list()
    print(actor)
pawn._get_('CustomTimeDilation')     # 按名称访问,用于不是合法 Python 名称的情况
pawn.cast('/Script/Engine.Actor')    # 将同一对象以另一个类的视角查看
```

字符串以 `str` 返回,名称(name)以 `str` 子类返回,map 带有 `.items()` / `.get()`。`FText` 一旦其布局已知,即可通过 `str(value)` 读取:来自一个 calls 会话、使用 `allow_calls=('text',)` dump 的快照,或一个 profile。

<!-- dt:section id="write-0" hash="dc41a59b3df8" -->
## 写入

```python
ue = Unreal.attach('TRIANGLE_STRATEGY-Win64-Shipping.exe', dump='latest', write=True)
pawn = ue.local_player_controller().Pawn
pawn.CustomTimeDilation = 2.0
pawn.RootComponent.RelativeLocation.Z += 100.0   # 结构体字段是原地写入的
```

未带 `write=True` 的会话会抛出 `ReadOnlySessionError`。写入是原地修改值:新字符串必须适配旧缓冲区的大小,容器不能改变大小,`FText` 不能被写入。`write=True` 在偏移量未经验证时会拒绝附加(`UnverifiedOffsetsError` 会列出这些偏移量):可以在 profile 中固定它们,传入 `allow_unverified=True`,使用以 `allow_calls=('text',)` dump 的快照,或以 `calls=` 附加(此时会话会用一次调用解析这两个 FText 偏移量)。

<!-- dt:section id="call-ufunctions-0" hash="7873d96eb046" -->
## 调用 UFunction

```python
ue = Unreal.attach('TRIANGLE_STRATEGY-Win64-Shipping.exe', dump='latest', calls='remote-thread')
ksl = ue.cdo('/Script/Engine.KismetSystemLibrary')   # 静态函数在 CDO 上调用
print(ksl.GetEngineVersion())                       # 单个输出:即值本身
pawn = ue.local_player_controller().Pawn
r = pawn.K2_SetActorLocation((0.0, 0.0, 500.0), False, True)   # NewLocation, bSweep, bTeleport
print(r.ReturnValue, r.SweepHitResult)              # 多个输出:一个 named tuple,返回值在前
ue.call_timeout = 5.0                               # 仅用于 remote-thread;单位为秒,默认 10,None 表示永久等待
```

- `calls='remote-thread'` 会在游戏中的一个新线程上运行每次调用;在游戏内部使用 `attach_current(calls='any-thread')`,它会在调用线程上运行。两者都不是游戏线程:一次调用可能导致游戏崩溃或使其状态损坏。
- 输入按反射顺序或按关键字传入。省略的输入为零值;`FText` 类型的输入不能省略。结构体输入可以是该结构体本身、一个元组或一个字典。Out 参数永远不会被传入;它们会在结果中返回。
- 结果是拷贝。没有输出的调用返回 `None`。UE 会在没有任何提示的情况下跳过某些调用,所以零输出也可能意味着“未被执行”。
- 未设置 `calls=` 时,调用会抛出 `CallsDisabledError`。Latent 函数会被拒绝。参数错误会抛出 `MarshalError`;调用失败或超时会抛出 `CallError`。
