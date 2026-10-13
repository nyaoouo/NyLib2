> 本文档为 utils.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="utils.md" -->

<!-- dt:section id="__preamble__" hash="b0c4b1ed9653" -->
# nylib.utils

用于 pip 包管理、CPU 指令汇编、事件循环、HTTP 下载和脚本打包的实用工具集。

关键词: pip, install, package, keystone, capstone, assemble, disassemble, event loop, schedule, thread, async call, download, web, pack, archive, delegate, enum, mutex, template

<!-- dt:section id="quick-start-0" hash="6eef819fef74" -->
## 快速开始

按任务选择：延迟包安装、CPU 汇编、计划事件或下载。

```python
# needs: installs packages on first call
from nylib.utils import pip, ks_asm, eventloop
if pip.required('requests'):
    import requests
bytecode = ks_asm.comp(b'mov rax, rbx', 0x1000)
loop = eventloop.EventLoop()
h = loop.create_event(print, args=('hi',), delay=1.0, repeat=True)
```

<!-- dt:section id="lazy-pip-install-0" hash="ef50de57d403" -->
## 延迟 pip 安装

首次使用时安装缺失的包，或无副作用地测试包是否存在。

```python
# needs: changes pip configuration and installs packages
from nylib.utils import pip
if pip.required('numpy', 'requests'):
    import numpy as np
    import requests
```

检查包是否已安装：

```python
from nylib.utils import pip

installed = pip.is_installed('pytest', 'black')
```

<!-- dt:section id="assemble-and-disassemble-cpu-code-0" hash="6867dac4c466" -->
## 汇编和反汇编 CPU 代码

使用 Keystone（Intel/ARM 汇编）和 Capstone（反汇编）处理 x86、x64、ARM 和其他 ISA。

```python
from nylib.utils import ks_asm

# Assemble with address and label resolves
bytecode = ks_asm.comp(b'mov rax, 42\nret', address=0x1000)

# Resolve labels and relocations
resolved = ks_asm.comp(
    b'jmp target\ndata: .byte 1\ntarget: nop',
    address=0x0,
    resolves={'target': 0x3}
)
```

<!-- dt:section id="event-loops-and-async-calls-0" hash="87cbb6b29f81" -->
## 事件循环和异步调用

使用延迟和重复来计划事件，或管理并发调用。

```python
from nylib.utils.eventloop import EventLoop
import time

loop = EventLoop()
h = loop.create_event(print, args=('tick',), delay=1.0, repeat=True)
time.sleep(3)
loop.cancel_event(h)
loop.terminate()
```

在后台线程中等待结果：

```python
from nylib.utils.threading_ import ResEvent
import threading

event = ResEvent()
t = threading.Thread(target=lambda: event.set(42))
t.start()
result = event.wait(timeout=5)
```

管理多个异步调用：

```python
from nylib.utils.async_call import AsyncCallManager

mgr = AsyncCallManager()
mgr.call('job1', int, '42')
result = mgr.get_result('job1')
```

<!-- dt:section id="download-files-0" hash="29b4c373935d" -->
## 下载文件

支持可选进度显示，发生错误时自动清理临时文件。

```python
# needs: requires network access
from nylib.utils import web
web.download('https://example.com/file.zip', '/tmp/file.zip', show_progress=True)
```

<!-- dt:section id="pack-scripts-0" hash="488325d498d7" -->
## 打包脚本

将 Python 文件或包压缩为自解压代码。

```python
# needs: requires actual script/package files
from nylib.utils import pkg_archive
packed = pkg_archive.pack('script.py', is_main=True)
packed = pkg_archive.pack('pkg/', is_main=True, package_name='myapp')
```

<!-- dt:section id="other-utilities-0" hash="6160f090ff0d" -->
## 其他实用工具

| 模块 | 用途 | 主要类/函数 |
|--------|---------|---|
| `delegate` | 事件处理程序模式，单个或分组 | `Delegate`, `GroupDelegate` |
| `enum` | Enum 辅助工具，用于缺失值的回退 | `missing()`, `auto_missing()` |
| `handles` | 分配和释放整数句柄 | `Handles.get()`, `.free()` |
| `mutex` | 跨进程基于文件的锁 | `Mutex(__enter__, __exit__)` |
| `preprocessor` | 编译时宏和条件代码处理器 | `IProcessors` |
| `prime` | 质数测试和生成 | `miller_rabin()`, utilities |
| `simple` | 对齐辅助工具、线程安全计数器 | `aligned4/8/16()`, `Counter` |
| `template` | 函数模板参数（线程本地） | `@template`, `template_args` |
| `tmp_file_writer` | 使用临时文件和回滚的原子文件写入 | `TmpFileWritter` |
| `yaml2json` | 将 YAML 转换为 JSON | `parse()` |

<!-- dt:section id="notes-0" hash="95587a07db08" -->
## 注意

- `pip.required()` 在首次调用时设置 pip 的默认索引；使用镜像列表时顺序很重要。
- `ks_asm`（Keystone/Capstone）预装；不需要 `# needs:` 标记。
- 退出前调用 `eventloop.EventLoop.terminate()`；事件在守护线程中运行。
- `web.download()` 阻塞；使用 `AsyncCallManager` 包装以实现非阻塞使用。
- `pkg_archive.pack()` 通过 `o=` 参数支持字节码转换。
