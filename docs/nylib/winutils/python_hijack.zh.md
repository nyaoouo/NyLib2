> 本文档为 python_hijack.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="python_hijack.md" -->

<!-- dt:section id="__preamble__" hash="80d6405c7e02" -->
# nylib.winutils.python_hijack

构建一个代理 DLL，转发目标 DLL 的所有导出，并在目标应用程序加载它时运行 Python 代码。用于将 Python 注入到硬加载特定 DLL 的应用程序中。

关键词: DLL proxy, DLL hijacking, DLL forwarding, export forwarding, pefile, MSVC, injection, process attach, main.py, pyHijack.ini, x86, x64, bitness, hijack, create_src

<!-- dt:section id="quick-start-0" hash="f8b7bf5c0ca0" -->
## 快速开始

构建一个代理 DLL，当目标应用程序加载被劫持的 DLL 时运行 `main.py`：

```python
# needs: MSVC (Visual Studio), target DLL path
from nylib.winutils.python_hijack import hijack

hijack(
    pe_path=r"C:\target\mylib.dll",
    dst_dir=r"C:\target",
    plat_spec='x86_amd64',  # or 'x86' for 32-bit
)
# Output: C:\target\mylib.dll (proxy), C:\target\mylib.pyHijack.dll (original renamed)
# Config: C:\target\pyHijack.ini
```

<!-- dt:section id="build-the-proxy-dll-0" hash="93a725d4f3d1" -->
## 构建代理 DLL

调用 `hijack()` 并提供目标 DLL 路径和目标目录。该函数生成 C++ 和汇编源代码，用 MSVC 编译它们，并将代理 DLL 放在原始文件所在的位置。原始文件被重命名为 `.pyHijack` 后缀：

```python
# needs: MSVC
from nylib.winutils.python_hijack import hijack

hijack(
    pe_path=r"C:\app\engine.dll",
    dst_dir=r"C:\app",
    default_config={
        'python_main': r'.\my_script.py',
        'python_dll': r'C:\Python310\python310.dll',
        'create_console': '1',  # 1 to show console, '' to hide
    },
    plat_spec='x86_amd64',
)
```

参数：
- `pe_path` — 目标 DLL 的路径（读取以提取导出）
- `dst_dir` — 放置代理 DLL 的位置（默认：与 `pe_path` 相同的目录）
- `default_config` — 字典，包含以下键：`orig`（原始 DLL 路径，自动设置；如果代理被放在目标位置，原始文件被重命名为 `.pyHijack.<ext>` 并且 `orig` 指向重命名的文件），`python_dll`（Python 运行时 DLL 的完整路径，如果未设置则从当前解释器自动检测），`python_main`（脚本的路径，相对或绝对路径；默认为 `.\main.py`），`create_console`（1 或空字符串，是否在加载时显示控制台）
- `build_dir` — 编译中间文件的临时目录（如果未设置则自动创建）
- `plat_spec` — `'x86_amd64'`（64 位，默认）或 `'x86'`（32 位）；必须与目标 DLL 匹配

代理转发来自原始 DLL 的所有导出。当目标应用程序加载它时，代理加载真实 DLL，初始化 Python，并在后台线程中运行在 `python_main` 中指定的脚本。

<!-- dt:section id="configuration-and-python-script-0" hash="88e977d6a937" -->
## 配置和 Python 脚本

构建会在代理 DLL 旁生成 `pyHijack.ini`，其中的路径在运行时读取。`[Python]` 部分保存构建时的 `sys.path`；编辑它可以添加库路径。脚本的目录（`python_main` 的父目录）始终被添加到 `sys.path`：

```ini
[Hijack]
orig = C:\app\engine.pyHijack.dll
python_dll = C:\Python310\python310.dll
python_main = .\main.py
create_console = 1

[Python]
path = C:\mylibs;C:\other\libs
```

脚本在真实 DLL 加载后在后台线程中运行。它可以从应用程序的 Python 环境中导入，并通过 ctypes 或其他机制调用回到应用程序中。脚本的 `__file__` 被设置为配置中 `python_main` 的值（默认为 `.\main.py`，相对于运行时的当前工作目录）。

<!-- dt:section id="notes-0" hash="083149267bea" -->
## 注意

- **位数必须匹配。** 代理 DLL 的体系结构（`plat_spec`）必须与目标应用程序的位数匹配（x86 应用程序 ← x86 DLL；x64 应用程序 ← x64 DLL）。不匹配会导致加载器失败。
- **构建需要 MSVC。** 代理使用 MSVC（`cl.exe`、`ml.exe`/`ml64.exe`）编译；确保已安装 Visual Studio 和 C++ 工具集以及 Windows SDK。`ensure_msvc()` 会自动调用。
- **配置文件位置。** `pyHijack.ini` 必须在运行时与代理 DLL 位于同一目录中。如果缺失，将使用模板中的默认值。
- **原始 DLL 路径。** 如果 `dst_dir == pe_path.parent`（目标目录），原始文件被重命名为 `<name>.pyHijack.<ext>` 以避免冲突。否则，在 `default_config` 中指定 `orig` 以指向真实的 DLL。
- **Python DLL 和解释器。** 默认情况下，活跃的 Python 解释器的 DLL 会自动检测。在 `default_config` 中设置 `python_dll` 以覆盖。脚本以该解释器的版本和构建时的 `sys.path` 运行。
