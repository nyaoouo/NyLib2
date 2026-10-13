# nylib.pattern

Pattern matching for searching bytecode sequences in PE files and process memory. Supports wildcards, value extraction, and nested matching.

Keywords: compile_pattern, StaticPatternSearcher, CachedRawMemoryPatternScanner, pattern matching, bytecode search, memory scanning, signature scanning, AOB scan, sig scan, find_address, search_unique, relative references

## Quick start

Compile a pattern string and search for it in memory or a PE file.

```python
from nylib.pattern import compile_pattern
from nylib.process import Process

# Search in the current process
proc = Process.current
pattern = compile_pattern('48 89 5C 24 ??')  # common x64 prologue
for addr, vals in proc.base_scanner().search(pattern):
    print(hex(addr), vals)
```

## Pattern syntax

A human-readable bytecode search syntax: space-separated hex bytes with wildcards and value extraction.

```python
from nylib.pattern import compile_pattern

# Literal byte: 55 8B EC (space-separated)
# Unknown byte: ? (not captured by default)
# String bytes: ^ (captured by default)
# Jump target: * (relative reference, stored by default)
# Byte range: [00:FF] or alternatives [00|FF|20]
# Repetition: ? {n} or ? {n:m} (same kind space-separated groups together)
# Groups: ( ... ) non-capturing, < ... > capturing
# Secondary matching: <* * *: FF FF> matches the captured bytes

pattern = compile_pattern('55 8B EC [00:07] 83 EC ?')
pattern = compile_pattern('<* * * *> 83 EC')  # capture 4 bytes
pattern = compile_pattern('(? ?) 89 04 24')  # 2 unknowns, then bytes
```

## Search in memory

Scan a process region or entire module using dynamic memory reads.

```python
# needs: target process running
from nylib.process import Process
from nylib.pattern import compile_pattern

proc = Process.from_name('game.exe')
scanner = proc.scanner('kernel32.dll')  # CachedRawMemoryPatternScanner
# or
scanner = proc.base_scanner()  # main module

pattern = compile_pattern('E8 ?? ?? ?? ??')  # CALL instruction
for addr, vals in scanner.search(pattern):
    print(f'Found at {hex(addr)}: {vals}')

# For one match
try:
    addr, vals = scanner.search_unique(pattern)
except KeyError:
    print('not found or not unique')
```

## Search in PE files

Scan code sections of a compiled binary without running it.

```python
from nylib.pattern import StaticPatternSearcher, compile_pattern

# From file path
searcher = StaticPatternSearcher('C:\\Windows\\System32\\kernel32.dll', base_address=0)
# or from pefile.PE object
import pefile
pe = pefile.PE('C:\\Windows\\System32\\kernel32.dll')
searcher = StaticPatternSearcher(pe, base_address=0)

pattern = compile_pattern('55 8B EC 83 EC')
for addr, vals in searcher.search(pattern):
    print(f'RVA {hex(addr)}: {vals}')
```

## Extract captured values

Results from groups and wildcards become a list of integers or bytes.

```python
from nylib.pattern import compile_pattern, Pattern

# Capturing group: < ... >
# Syntax: * (relative reference), ^ (raw bytes), ? (unknown byte, usually not stored)
# When matched, res_is_ref flags indicate whether each result is offset (True) or value (False)

pattern = compile_pattern('<* * * *> 83 EC ??')
# The 4 captured bytes via <*>: stored as RVA (offset + group end)
# Other captured groups: <^> as raw bytes, <? ?> captures position only

# Accessing results from search
matches = list(pattern.finditer(b'\x48\x89\x5C\x24\x08\x83\xEC\x20'))
if matches:
    offset, vals = matches[0]
    print(f'Found at offset {offset}, captured values: {vals}')
    print(f'Flags (is_ref): {pattern.res_is_ref}')
```

## Notes

- Patterns require space between bytes: `55 8B EC`, not `558BEC`.
- Each `?`, `^`, or `*` token (possibly doubled like `??`) followed by a space forms one capture group in the regex.
- Jump patterns (`*`) in a group yield the RVA of the jump target's end offset (relative references; decode with post-processing).
- `StaticPatternSearcher` requires `pefile`; it is installed in `.venv`.
- Secondary patterns `<* *: XX XX>` run on captured bytes (from the group itself), not the source memory; only works with captured groups.
- `LocalMemoryPatternScanner` is zero-copy for the current process; `MemoryPatternScanner` copies data via `ReadProcessMemory` for remote targets.
