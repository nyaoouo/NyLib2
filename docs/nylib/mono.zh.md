> 本文档为 mono.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="mono.md" -->

<!-- dt:section id="__preamble__" hash="4e81e90b20f0" -->
# nylib.mono

从 Python 检查和交互 Mono 或 IL2CPP 运行时。在注入后进程内工作：浏览程序集、查找类和方法，并调用它们且 Python 类型自动转换。

关键词: mono, il2cpp, unity, runtime inspection, mono_get_root_domain, monoapi, MonoClass, MonoMethod, MonoField, invocation, static field, instance field, method call

<!-- dt:section id="quick-start-0" hash="c8f5722945ba" -->
## Quick start

按名称获取类并迭代其方法以查看其签名。

```python
# needs: a running Mono/IL2CPP process with Python injected
from nylib.mono import Mono

mono = Mono.get_instance()
cls = mono.find_class('Player', namespace='Game')

for method in cls.methods:
    print(f"{method.name}{method.signature}")
```

<!-- dt:section id="find-classes-and-assemblies-0" hash="3a71232d2dbe" -->
## Find classes and assemblies

浏览运行时加载的程序集和类。

```python
# needs: a running Mono/IL2CPP process with Python injected
from nylib.mono import Mono

mono = Mono.get_instance()

# By class name across all assemblies
cls = mono.find_class('Player', namespace='Game')

# Or iterate assemblies and their images
for assembly in mono.assemblies:
    for cls in assembly.image.clss:
        print(f"{cls.namespace}::{cls.name}")

# Find method by fully qualified name
image = mono.assemblies[0].image
method = image.find_method_by_desc('Game.Player:TakeDamage(i)')
```

<!-- dt:section id="read-fields-and-properties-0" hash="ea5ff4f74b8a" -->
## Read fields and properties

使用其地址访问实例和静态字段。

```python
# needs: a running Mono/IL2CPP process with Python injected
from nylib.mono import Mono

mono = Mono.get_instance()
cls = mono.find_class('Player', namespace='Game')

# Get field metadata
for field in cls.fields:
    if field.name == 'hp':
        print(f"Field offset: {field.offset:#x}")
        print(f"Field type: {field.type.name}")
        print(f"Is static: {bool(field.flags & 0x0010)}")
        break
```

<!-- dt:section id="call-methods-0" hash="e34aa60c39b1" -->
## Call methods

使用自动类型转换从 Python 调用 Mono 方法。

```python
# needs: a running Mono/IL2CPP process with Python injected
from nylib.mono import Mono

mono = Mono.get_instance()
cls = mono.find_class('Math', namespace='System')
method = cls.find_method('Max', 2)

# Static call signature: invoke(this=None, *args)
print(method.signature)
print(f"Params: {method.params}")
print(f"Return: {method.return_type.name}")
```

<!-- dt:section id="inspect-with-imgui-0" hash="543c31f1003b" -->
## Inspect with ImGui

使用基于 ImGui 的交互式检查器浏览运行时。

```python
# needs: a running pyimgui context in a Unity game window
from nylib.mono import Mono
from nylib.mono.imgui_inspect import MonoInspector

mono = Mono.get_instance()
inspector = MonoInspector(mono)

# In your ImGui render loop:
inspector.render()
```

<!-- dt:section id="notes-0" hash="f10faf3227fc" -->
## Notes

- 该模块需要在运行的 Unity/Mono 进程中注入 Python 解释器。
- `Mono.get_instance()` 自动检测当前进程中的 mono.dll 或 il2cpp.dll。
- 方法调用需要匹配参数类型；使用 `method.signature` 查看预期签名。
- 对于静态字段，调用 `field.get_value_addr()` 且不带实例参数；对于实例字段，传递对象。
- IL2CPP（Unity IL2CPP 后端）与经典 Mono 一起支持。API 分支根据 `is_il2cpp` 标志选择。
