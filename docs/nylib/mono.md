# nylib.mono

Inspect and interact with the Mono or IL2CPP runtime from Python. Works in-process after injection: browse assemblies, find classes and methods, and invoke them with Python types automatically converted.

Keywords: mono, il2cpp, unity, runtime inspection, mono_get_root_domain, monoapi, MonoClass, MonoMethod, MonoField, invocation, static field, instance field, method call

## Quick start

Get a class by name and iterate its methods to see their signatures.

```python
# needs: a running Mono/IL2CPP process with Python injected
from nylib.mono import Mono

mono = Mono.get_instance()
cls = mono.find_class('Player', namespace='Game')

for method in cls.methods:
    print(f"{method.name}{method.signature}")
```

## Find classes and assemblies

Browse the runtime's loaded assemblies and classes.

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

## Read fields and properties

Access instance and static fields using their addresses.

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

## Call methods

Invoke Mono methods from Python with automatic type conversion.

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

## Inspect with ImGui

Use the interactive ImGui-based inspectors to browse the runtime.

```python
# needs: a running pyimgui context in a Unity game window
from nylib.mono import Mono
from nylib.mono.imgui_inspect import MonoInspector

mono = Mono.get_instance()
inspector = MonoInspector(mono)

# In your ImGui render loop:
inspector.render()
```

## Notes

- The module requires an injected Python interpreter in a running Unity/Mono process.
- `Mono.get_instance()` auto-detects mono.dll or il2cpp.dll in the current process.
- Method invocation needs matching parameter types; use `method.signature` to see the expected signature.
- For static fields, call `field.get_value_addr()` with no instance argument; for instance fields, pass the object.
- IL2CPP (Unity IL2CPP backend) is supported alongside classic Mono. The API branch selected based on `is_il2cpp` flag.
