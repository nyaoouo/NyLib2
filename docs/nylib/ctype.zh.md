> 本文档为 ctype.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="ctype.md" -->

<!-- dt:section id="__preamble__" hash="0480c2de62fe" -->
# nylib.ctype

在内存中声明并访问类似 C 的数据结构，使用自定义访问器，能够通过统一接口在本进程或远程进程中透明地读写。

关键词: CData, Struct, Pointer, Array, Accessor, SimpleCData, Field, memory layout, bit field, SField, BField, local accessor, process accessor, allocate, remote memory

<!-- dt:section id="quick-start-0" hash="5d6f98760408" -->
## Quick start

通过继承 `Struct` 声明结构，使用 `Field()` 或 `SField()` 定义字段，在本地分配并读取/修改它。

```python
from nylib.ctype import Struct, SField, c_int32, c_uint8

class Player(Struct):
    hp = SField(c_int32)
    level = SField(c_uint8)

player = Player()  # 在本地进程自动分配
player.hp = 100
print(player.hp)  # 通过默认本地访问器从内存读取
```

<!-- dt:section id="declare-a-struct-and-read-from-local-process-0" hash="1135bf3b1a6e" -->
## Declare a struct and read from local process

使用 `SField()` 定义标量字段（自动转换为 `.value`），使用 `Field()` 定义嵌套的 CData 类型。

```python
from nylib.ctype import Struct, SField, Field, c_int32, c_uint64, Pointer

class Entity(Struct):
    id = SField(c_int32)
    x = SField(c_int32)
    y = SField(c_int32)
    next_ptr = Field(Pointer[c_int32])

# 在本地地址自动分配，可以立即使用
entity = Entity()
entity.id = 42
entity.x = 10
entity.y = 20
print(f"Entity: id={entity.id}, pos=({entity.x}, {entity.y})")
```

<!-- dt:section id="use-arrays-and-pointers-0" hash="3b23390da28d" -->
## Use arrays and pointers

数组可以是固定大小或无边界的。固定大小的数组自动分配；无边界数组需要显式地址。

```python
from nylib.ctype import Struct, SField, Field, Array, c_int32

class Stats(Struct):
    scores = Field(Array[c_int32, 10])  # 固定大小的 10 个整数数组

stats = Stats()
for i in range(10):
    # 通过 __getitem__ 访问数组元素
    scores_raw = stats.scores[i]
    scores_raw.value = i * 10
    
# 遍历数组元素
for score in stats.scores:
    print(score.value)
```

<!-- dt:section id="access-in-process-memory-by-address-0" hash="0d32287734be" -->
## Access in-process memory by address

提供已知地址和本地访问器，无需分配即可读取现有的进程内数据。

```python
from nylib.ctype import Struct, SField, c_int32, CAccessorLocal
import ctypes

class MyData(Struct):
    value = SField(c_int32)

# 在已知地址创建一些进程内数据
buf = ctypes.create_string_buffer(b'\x2a\x00\x00\x00')
addr = ctypes.addressof(buf)

# 将该地址读取为 MyData（无分配，仅查看）
data = MyData(_address_=addr, _accessor_=CAccessorLocal.get_instance())
print(data.value)  # 输出 42
```

<!-- dt:section id="read-from-remote-process-0" hash="ef5cbd3ac2b7" -->
## Read from remote process

```python
# 需要：目标进程和已知地址，需要管理员权限
from nylib.process import Process
from nylib.ctype import Struct, SField, c_int32

class RemoteEntity(Struct):
    id = SField(c_int32)
    x = SField(c_int32)

target_pid = 1234
remote_address = 0x140000000

remote_proc = Process(target_pid)
entity = remote_proc.read(remote_address, RemoteEntity)
print(f"Remote entity id: {entity.id}")
```

<!-- dt:section id="notes-0" hash="2818fbc466fb" -->
## Notes

- **访问器生命周期：** 如果未传递 `_accessor_`，结构会自动使用 `CAccessorLocal.get_instance()`；远程访问需要传递 `CAccessorProcess` 或显式设置结构的 `_accessor_`。
- **自分配 vs 地址提供：** `Struct` 如果未提供 `_address_` 会通过其访问器自动分配；使用 `_address_=addr` 来读取现有内存。
- **字段类型：** `SField` 自动解包标量值（访问时使用 `.value`）；`Field` 返回 CData 对象（使用 `.value` 获取标量）。位字段通过 `BField` 需要显式的 bit_size 和 offset。
- **指针解引用：** `Pointer[T][index]` 返回该偏移量处的 `T` 实例；`.content` 是 `[0]` 的语法糖。`c_char_p` 读取以空字符结尾的字符串。
- **内存所有权：** 自分配的结构（构造时未提供 `_address_`）在删除时清理；显式地址的清理由调用者负责。
