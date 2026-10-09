# nylib.pdb

Read PDB files through Microsoft DIA, and write PDB files from a plain Python model.

| Part | What it does | Needs the compiled extension |
|---|---|---|
| `Session` | read symbols and types | yes |
| `export.export_pdb` | PDB -> model | yes |
| `model` | the model, JSON load/save, validation | no |
| `writer.write_pdb` | model -> PDB | no |
| `pe_info` | read a PE's machine, sections and RSDS entry | no |

## Build the extension

```
python scripts/pdb/build.py
```

Builds `nylib/pdb/_ny_pdb.<tag>.pyd` for the running interpreter and copies `msdia140.dll` next to it.
It needs Visual Studio (MSVC and the DIA SDK) and pybind11. Rebuild after `scripts/pdb/src` changes.

## Read a PDB

```python
from nylib.pdb import Session, SymTag

# Looks next to the PE first, then the local cache, then the Microsoft symbol server.
with Session.from_pe('C:/Windows/System32/user32.dll') as s:
    for sym in s.find_symbols('MessageBox*', tag=SymTag.PublicSymbol):
        print(sym.name, hex(sym.rva))
    print(s.describe(sym.rva + 4))              # e.g. 'MessageBoxW+0x4'

with Session('C:/re/game.pdb') as s:            # open a .pdb directly
    t = s.find_type('Player')
    for m in t.fields():                         # data members; members() also lists bases etc.
        print(m.name, m.offset, m.type.name)
```

To use another symbol server, pass `symsrv_url=` (for example `symbol_server.MOZILLA_SYMBOLS`).
Downloads are cached in the `_NT_SYMBOL_PATH` cache directory, else in `%LOCALAPPDATA%/nylib/symbols`.

## Write a PDB

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
writer.write_pdb(pdb, pe_path='C:/re/game.exe')  # writes C:/re/<PDB name from the exe>.pdb
```

- `pe_path` takes the GUID, age, machine and sections from the exe, so debuggers load the PDB for it.
  The exe must have a CodeView (RSDS) debug entry, and it is never modified.
- Without an exe, pass `out_path` plus `guid`, `age`, `machine` and `sections` instead.
- An existing file is not replaced unless `overwrite=True`.
- Types are referenced by name (`'int'`, `'Player'`). Pointers, arrays (`m.Array(of=..., count=...)`),
  qualifiers (`m.Modifier(of=..., const=True)`) and function types are nested objects.
  There are also `m.Enum(name=..., underlying='int', values={...})` and `m.Typedef(name=..., type=...)`.
- `pdb.validate()` checks the model. Errors are `m.ModelError`, with a path such as
  `types[0].fields[1].type`.

## Export and edit an existing PDB

```python
from nylib.pdb import export, model, writer

res = export.export_pdb('C:/re/game.pdb')       # or an open Session
print(res.dropped)                               # what the model cannot hold: Dropped(category, name, detail)
res.model.save('C:/re/game.json')                # edit the JSON, or the objects directly

edited = model.PdbModel.load('C:/re/game.json')
writer.write_pdb(edited, pe_path='C:/re/game.exe', overwrite=True)
```

`export_pdb(..., strict=True)` raises `export.ExportError` instead of dropping anything.
Typical drops are member functions, vtable pointers, virtual bases, constants and thread-local data.
The rest round-trips: exporting the written PDB gives the same model.

## JSON format

`model.save()` writes this format. Integers may be decimal or `"0x..."` strings.

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

## Scope

- Covered:
  - publics, functions and global data;
  - structs, classes and unions, with fields, bitfields and base classes;
  - enums, pointers, arrays, qualifiers, typedefs and function types.
- Not covered: local variables, line numbers, source files, FPO/unwind data.
- Targets: x64 and x86.
- `Member.offset` of a non-virtual base class is its byte offset; a virtual base reports -1.
