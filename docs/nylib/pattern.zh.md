> 本文档为 pattern.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="pattern.md" -->

<!-- dt:section id="__preamble__" hash="df535f94e30f" -->
# nylib.pattern

用于在 PE 文件和进程内存中搜索字节码序列的模式匹配。支持通配符、值提取和嵌套匹配。

关键词: compile_pattern, StaticPatternSearcher, CachedRawMemoryPatternScanner, pattern matching, bytecode search, memory scanning, signature scanning, AOB scan, sig scan, find_address, search_unique, relative references

<!-- dt:section id="quick-start-0" hash="0d776a410c0f" -->
## 快速开始

编译一个模式字符串并在内存或 PE 文件中搜索它。

```python
from nylib.pattern import compile_pattern
from nylib.process import Process

# 在当前进程中搜索
proc = Process.current
pattern = compile_pattern('48 89 5C 24 ??')  # common x64 prologue
for addr, vals in proc.base_scanner().search(pattern):
    print(hex(addr), vals)
```

<!-- dt:section id="pattern-syntax-0" hash="3ef3a2d5012e" -->
## 模式语法

人类可读的字节码搜索语法：空格分隔的十六进制字节，包含通配符和值提取。

```python
from nylib.pattern import compile_pattern

# 字面字节: 55 8B EC (空格分隔)
# 未知字节: ? (默认不捕获)
# 字符串字节: ^ (默认捕获)
# 跳转目标: * (相对引用，默认存储)
# 字节范围: [00:FF] 或替代项 [00|FF|20]
# 重复: ? {n} 或 ? {n:m} (相同类型的空格分隔组放在一起)
# 组: ( ... ) 非捕获，< ... > 捕获
# 二级匹配: <* * *: FF FF> 匹配捕获的字节

pattern = compile_pattern('55 8B EC [00:07] 83 EC ?')
pattern = compile_pattern('<* * * *> 83 EC')  # capture 4 bytes
pattern = compile_pattern('(? ?) 89 04 24')  # 2 unknowns, then bytes
```

<!-- dt:section id="search-in-memory-0" hash="7999a2106562" -->
## 在内存中搜索

使用动态内存读取扫描进程区域或整个模块。

```python
# 需要: 目标进程运行中
from nylib.process import Process
from nylib.pattern import compile_pattern

proc = Process.from_name('game.exe')
scanner = proc.scanner('kernel32.dll')  # CachedRawMemoryPatternScanner
# 或
scanner = proc.base_scanner()  # 主模块

pattern = compile_pattern('E8 ?? ?? ?? ??')  # CALL 指令
for addr, vals in scanner.search(pattern):
    print(f'Found at {hex(addr)}: {vals}')

# 获取单个匹配
try:
    addr, vals = scanner.search_unique(pattern)
except KeyError:
    print('not found or not unique')
```

<!-- dt:section id="search-in-pe-files-0" hash="d7257b5982fd" -->
## 在 PE 文件中搜索

扫描已编译二进制文件的代码部分，无需运行它。

```python
from nylib.pattern import StaticPatternSearcher, compile_pattern

# 从文件路径
searcher = StaticPatternSearcher('C:\\Windows\\System32\\kernel32.dll', base_address=0)
# 或从 pefile.PE 对象
import pefile
pe = pefile.PE('C:\\Windows\\System32\\kernel32.dll')
searcher = StaticPatternSearcher(pe, base_address=0)

pattern = compile_pattern('55 8B EC 83 EC')
for addr, vals in searcher.search(pattern):
    print(f'RVA {hex(addr)}: {vals}')
```

<!-- dt:section id="extract-captured-values-0" hash="6ccafcfd5ac8" -->
## 提取捕获的值

来自组和通配符的结果变为整数或字节的列表。

```python
from nylib.pattern import compile_pattern, Pattern

# 捕获组: < ... >
# 语法: * (相对引用)，^ (原始字节)，? (未知字节，通常不存储)
# 匹配时，res_is_ref 标志指示每个结果是偏移量 (True) 还是值 (False)

pattern = compile_pattern('<* * * *> 83 EC ??')
# 通过 <*> 捕获的 4 个字节: 存储为 RVA (偏移量 + 组结束)
# 其他捕获组: <^> 作为原始字节，<? ?> 仅捕获位置

# 访问搜索结果
matches = list(pattern.finditer(b'\x48\x89\x5C\x24\x08\x83\xEC\x20'))
if matches:
    offset, vals = matches[0]
    print(f'Found at offset {offset}, captured values: {vals}')
    print(f'Flags (is_ref): {pattern.res_is_ref}')
```

<!-- dt:section id="notes-0" hash="6fb011ac79da" -->
## 注释

- 模式要求字节之间有空格: `55 8B EC`，而不是 `558BEC`。
- 每个 `?`、`^` 或 `*` 标记 (可能加倍如 `??`) 后跟空格形成正则表达式中的一个捕获组。
- 组中的跳转模式 (`*`) 产生跳转目标的结束偏移量的 RVA (相对引用；使用后处理解码)。
- `StaticPatternSearcher` 需要 `pefile`; 它安装在 `.venv` 中。
- 二级模式 `<* *: XX XX>` 在捕获的字节 (来自组本身) 上运行，而不是源内存；仅适用于捕获的组。
- `LocalMemoryPatternScanner` 对当前进程是零复制的；`MemoryPatternScanner` 通过 `ReadProcessMemory` 为远程目标复制数据。
