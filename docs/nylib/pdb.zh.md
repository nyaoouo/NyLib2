> 本文档为 pdb.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="pdb.md" -->

<!-- dt:section id="__preamble__" hash="75bb652351d8" -->
# nylib.pdb

通过 Microsoft DIA 读取 PDB 文件，并从纯 Python 模型写入 PDB 文件。

| 部分 | 功能 | 需要编译的扩展 |
|---|---|---|
| `Session` | 读取符号和类型 | 是 |
| `export.export_pdb` | PDB -> 模型 | 是 |
| `model` | 模型、JSON 加载/保存、验证 | 否 |
| `writer.write_pdb` | 模型 -> PDB | 否 |
| `pe_info` | 读取 PE 的机器类型、节和 RSDS 条目 | 否 |

<!-- dt:section id="build-the-extension-0" hash="78cdbf266c26" -->
## 构建扩展

```
python scripts/pdb/build.py
```

为运行的解释器构建 `nylib/pdb/_ny_pdb.<tag>.pyd` 并将 `msdia140.dll` 复制到其旁边。
它需要 Visual Studio (MSVC 和 DIA SDK) 和 pybind11。在 `scripts/pdb/src` 更改后重新构建。

<!-- dt:section id="read-a-pdb-0" hash="95e02ada7429" -->
## 读取 PDB

```python
from nylib.pdb import Session, SymTag

# 首先查看 PE 旁边，然后查看本地缓存，最后查看 Microsoft 符号服务器。
with Session.from_pe('C:/Windows/System32/user32.dll') as s:
    for sym in s.find_symbols('MessageBox*', tag=SymTag.PublicSymbol):
        print(sym.name, hex(sym.rva))
    print(s.describe(sym.rva + 4))              # 例如 'MessageBoxW+0x4'

with Session('C:/re/game.pdb') as s:            # 直接打开 .pdb
    t = s.find_type('Player')
    for m in t.fields():                         # 数据成员；members() 也列出基类等。
        print(m.name, m.offset, m.type.name)
```

要使用另一个符号服务器，传递 `symsrv_url=`（例如 `symbol_server.MOZILLA_SYMBOLS`）。
下载被缓存在 `_NT_SYMBOL_PATH` 缓存目录中，否则在 `%LOCALAPPDATA%/nylib/symbols` 中。

<!-- dt:section id="write-a-pdb-0" hash="1e7b574b0622" -->
## 写入 PDB

```python
from nylib.pdb import model as m, writer

pdb = m.PdbModel(
    types=[m.Udt(name='Player', size=0x10, fields=[
        m.Field(name='hp', type='int', offset=0),
        m.Field(name='name', type=m.Pointer(to='char'), offset=8),
    ])],
    functions=[m.Function(name='update_player', rva=0x1000, length=0x40,
                          type=m.FunctionType(args=[m.Pointer(to='Player')]))],
    data=[m.Data(name='g_player', rva=0x34000, type=m.Pointer(to='Player'))],
    publics=[m.Public(name='update_player', rva=0x1000, function=True)],
)
writer.write_pdb(pdb, pe_path='C:/re/game.exe')  # 写出 C:/re/<exe 里记录的 PDB 名>.pdb
```

- `pe_path` 从 exe 获取 GUID、age、machine 和 sections，这样调试器就能为其加载 PDB。
  exe 必须有一个 CodeView (RSDS) 调试条目，并且它永远不会被修改。
- 如果没有 exe，请改为传递 `out_path` 加上 `guid`、`age`、`machine` 和 `sections`。
- 除非 `overwrite=True`，否则不会替换现有文件。
- 类型按名称引用（`'int'`、`'Player'`）。指针、数组（`m.Array(of=..., count=...)`）、
  限定符（`m.Modifier(of=..., const=True)`）和函数类型是嵌套对象。
  还有 `m.Enum(name=..., underlying='int', values={...})` 和 `m.Typedef(name=..., type=...)`。
- `pdb.validate()` 检查模型。错误是 `m.ModelError`，带有路径例如
  `types[0].fields[1].type`。

<!-- dt:section id="export-and-edit-an-existing-pdb-0" hash="d2c927f2e677" -->
## 导出并编辑现有的 PDB

```python
from nylib.pdb import export, model, writer

res = export.export_pdb('C:/re/game.pdb')       # 也可以传入已打开的 Session
print(res.dropped)                               # 模型无法表示的内容：Dropped(category, name, detail)
res.model.save('C:/re/game.json')                # 修改 JSON，或直接修改对象

edited = model.PdbModel.load('C:/re/game.json')
writer.write_pdb(edited, pe_path='C:/re/game.exe', overwrite=True)
```

`export_pdb(..., strict=True)` 在有内容会被舍弃时直接抛出 `export.ExportError`。
常见的舍弃项有成员函数、虚函数表指针、虚基类、常量和线程局部数据。
其余内容可以完整往返：再导出写出的 PDB 会得到相同的模型。

<!-- dt:section id="json-format-0" hash="0e4be8f0dc6b" -->
## JSON 格式

`model.save()` 写入此格式。整数可以是十进制或 `"0x..."` 字符串。

```json
{
  "format": "nylib.pdb.model",
  "version": 1,
  "types": [
    {"kind": "struct", "name": "Player", "size": 16, "fields": [
      {"name": "hp", "type": "int", "offset": 0},
      {"name": "name", "type": {"kind": "pointer", "to": "char"}, "offset": 8}
    ]}
  ],
  "functions": [{"name": "update_player", "rva": "0x1000", "length": "0x40"}]
}
```

<!-- dt:section id="scope-0" hash="8d99e2cf6815" -->
## 范围

- 涵盖的内容：
  - 公共符号（publics）、函数和全局数据；
  - 结构体、类和联合体，包括字段、位域和基类；
  - 枚举、指针、数组、限定符、typedef 和函数类型。
- 不涵盖的内容：局部变量、行号、源文件、FPO/unwind 数据。
- 目标：x64 和 x86。
- 非虚基类的 `Member.offset` 是该基类子对象的字节偏移；虚基类返回 -1。
