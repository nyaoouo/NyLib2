> 本文档为 logging.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="logging.md" -->

<!-- dt:section id="__preamble__" hash="5ae54abe10b2" -->
# nylib.logging

配置根日志记录器，支持彩色控制台输出、可选的文件日志记录和轮转功能，以及自定义详细程度。多行消息、异常和堆栈跟踪用分隔线格式化。

关键词: install, std2file, 彩色控制台, 日志文件, 文件轮转, 归档, 重定向stdout, 重定向stderr, 多行日志, Verbose1, Verbose2, Verbose3, 自定义日志级别, logging, handlers

<!-- dt:section id="quick-start-0" hash="30c9826578ae" -->
## 快速开始

启动时调用一次 `install()` 来设置日志记录，包括颜色和（可选的）轮转文件处理程序。

```python
import logging
from nylib.logging import install

install(level=logging.DEBUG, file_name='debug.log')

logging.debug('starting')
logging.info('service ready')
logging.warning('timeout')
logging.error('connection lost')
```

<!-- dt:section id="color-console-output-0" hash="8a7b2382e5d2" -->
## 彩色控制台输出

启用彩色输出（默认启用）并使用 DEBUG 以下的自定义详细程度。

```python
# needs: logging already initialized with install()
import logging
from nylib.logging import Verbose1, Verbose2, Verbose3

logging.log(Verbose1, 'very detailed trace')   # level 9
logging.log(Verbose2, 'detailed info')         # level 8
logging.log(Verbose3, 'trace info')            # level 7
logging.debug('standard debug')                 # level 10
```

<!-- dt:section id="log-to-file-with-rotation-0" hash="cb1e48ced212" -->
## 日志文件轮转

配置文件日志记录，支持自动轮转：当文件超过 `file_size` 时，它会被归档到 zip 并启动新的日志。

```python
# needs: demonstrates install() with file handler
import logging
from nylib.logging import install

install(
    level=logging.DEBUG,
    file_name='app.log',
    file_size=1024 * 1024 * 10,
    archive_zip='logs/archive.zip'
)

logging.info('logged to both console and app.log')
```

<!-- dt:section id="redirect-stdout-and-stderr-0" hash="821e6d2b0168" -->
## 重定向标准输出和标准错误

将 print() 和 sys.stderr.write() 直接捕获到文件，使用相同的轮转行为。

```python
# needs: demonstrates sys.stdout/stderr redirection
import sys
from nylib.logging import std2file, STDALL

std2file('output.log', select_type=STDALL)

print('hello world')
sys.stderr.write('error message\n')
```

<!-- dt:section id="multiline-message-formatting-0" hash="ba1d1b45f26e" -->
## 多行消息格式化

多行消息、异常和堆栈跟踪会自动分割并用分隔线包装。

```python
import logging

logging.info('line 1\nline 2\nline 3')
```

<!-- dt:section id="notes-0" hash="5bc5e74265de" -->
## 注意事项

- `install()` 配置 `logging.basicConfig()` 并全局影响根日志记录器；在启动时调用一次。
- 预定义了三个自定义级别：`Verbose1=9`、`Verbose2=8`、`Verbose3=7`（在 DEBUG=10 以下）。
- 文件轮转在每次写入时检查；轮转后的日志会归档到 zip 中，名称格式为 `<stem>_YYYY_MM_DD_HH_MM_SS<ext>`。
- 当 `use_color=True` 时，Windows 控制台颜色支持自动启用。
- `std2file()` 创建相同类型的轮转文件写入器；使用 `STDOUT`、`STDERR` 或 `STDALL` 来选择流。
