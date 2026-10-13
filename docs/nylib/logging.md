# nylib.logging

Configure the root logger with color console output, optional file logging with rotation, and custom verbosity levels. Multiline messages, exceptions and stack traces are formatted with separator lines.

Keywords: install, std2file, color console, log to file, file rotation, archive, redirect stdout, redirect stderr, multiline log, Verbose1, Verbose2, Verbose3, custom log levels, logging, handlers

## Quick start

Call `install()` once at startup to set up logging with colors and (optionally) a rotating file handler.

```python
import logging
from nylib.logging import install

install(level=logging.DEBUG, file_name='debug.log')

logging.debug('starting')
logging.info('service ready')
logging.warning('timeout')
logging.error('connection lost')
```

## Color console output

Enable colored output (on by default) and use custom verbosity levels below DEBUG.

```python
# needs: logging already initialized with install()
import logging
from nylib.logging import Verbose1, Verbose2, Verbose3

logging.log(Verbose1, 'very detailed trace')   # level 9
logging.log(Verbose2, 'detailed info')         # level 8
logging.log(Verbose3, 'trace info')            # level 7
logging.debug('standard debug')                 # level 10
```

## Log to file with rotation

Configure file logging with automatic rotation: when the file exceeds `file_size`, it is archived to zip and a new log starts.

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

## Redirect stdout and stderr

Capture print() and sys.stderr.write() directly to a file with the same rotation behavior.

```python
# needs: demonstrates sys.stdout/stderr redirection
import sys
from nylib.logging import std2file, STDALL

std2file('output.log', select_type=STDALL)

print('hello world')
sys.stderr.write('error message\n')
```

## Multiline message formatting

Multiline messages, exceptions and stack traces are automatically split and wrapped with separator lines.

```python
import logging

logging.info('line 1\nline 2\nline 3')
```

## Notes

- `install()` configures `logging.basicConfig()` and affects the root logger globally; call it once at startup.
- Three custom levels are pre-defined: `Verbose1=9`, `Verbose2=8`, `Verbose3=7` (below DEBUG=10).
- File rotation checks on each write; rotated logs are archived into the zip with timestamped names like `<stem>_YYYY_MM_DD_HH_MM_SS<ext>`.
- Windows console color support is auto-enabled when `use_color=True`.
- `std2file()` creates the same type of rotating file writer; use `STDOUT`, `STDERR`, or `STDALL` to select streams.
