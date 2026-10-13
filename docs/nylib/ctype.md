# nylib.ctype

Declare and access C-like data structures in memory with custom accessors, enabling transparent read/write in your own process or a remote process via a uniform interface.

Keywords: CData, Struct, Pointer, Array, Accessor, SimpleCData, Field, memory layout, bit field, SField, BField, local accessor, process accessor, allocate, remote memory

## Quick start

Declare a struct by subclassing `Struct`, define fields with `Field()` or `SField()`, allocate locally and read/modify it.

```python
from nylib.ctype import Struct, SField, c_int32, c_uint8

class Player(Struct):
    hp = SField(c_int32)
    level = SField(c_uint8)

player = Player()  # auto-allocated in local process
player.hp = 100
print(player.hp)  # reads from memory via default local accessor
```

## Declare a struct and read from local process

Use `SField()` for scalar fields (auto converts to `.value`), `Field()` for nested CData types.

```python
from nylib.ctype import Struct, SField, Field, c_int32, c_uint64, Pointer

class Entity(Struct):
    id = SField(c_int32)
    x = SField(c_int32)
    y = SField(c_int32)
    next_ptr = Field(Pointer[c_int32])

# Auto-allocated at a local address, ready to use
entity = Entity()
entity.id = 42
entity.x = 10
entity.y = 20
print(f"Entity: id={entity.id}, pos=({entity.x}, {entity.y})")
```

## Use arrays and pointers

Arrays can be fixed-size or unbounded. Fixed-size arrays allocated automatically; unbounded arrays need explicit address.

```python
from nylib.ctype import Struct, SField, Field, Array, c_int32

class Stats(Struct):
    scores = Field(Array[c_int32, 10])  # fixed-size array of 10 ints

stats = Stats()
for i in range(10):
    # Access array elements via __getitem__
    scores_raw = stats.scores[i]
    scores_raw.value = i * 10
    
# Iterate over array elements
for score in stats.scores:
    print(score.value)
```

## Access in-process memory by address

Provide a known address and the local accessor to read existing in-process data without allocating.

```python
from nylib.ctype import Struct, SField, c_int32, CAccessorLocal
import ctypes

class MyData(Struct):
    value = SField(c_int32)

# Create some in-process data at a known address
buf = ctypes.create_string_buffer(b'\x2a\x00\x00\x00')
addr = ctypes.addressof(buf)

# Read that address as MyData (no allocation, just view)
data = MyData(_address_=addr, _accessor_=CAccessorLocal.get_instance())
print(data.value)  # prints 42
```

## Read from remote process

```python
# needs: target process with known address, admin rights
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

## Notes

- **Accessor lifecycle:** structs auto-use `CAccessorLocal.get_instance()` if no `_accessor_` is passed; remote access requires passing a `CAccessorProcess` or setting the struct's `_accessor_` explicitly.
- **Self-allocated vs address-provided:** `Struct` auto-allocates via its accessor if `_address_` is not provided; use `_address_=addr` to read existing memory.
- **Field types:** `SField` auto-unwraps scalar values (`.value` on access); `Field` returns the CData object (use `.value` to get the scalar). Bit fields via `BField` need explicit bit_size and offset.
- **Pointer dereferencing:** `Pointer[T][index]` returns a `T` instance at that offset; `.content` is sugar for `[0]`. `c_char_p` reads null-terminated strings.
- **Memory ownership:** auto-allocated structs (no `_address_` at construction) clean up on deletion; explicit addresses are caller's responsibility to free if needed.
