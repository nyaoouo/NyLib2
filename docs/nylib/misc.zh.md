> 本文档为 misc.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="misc.md" -->

<!-- dt:section id="__preamble__" hash="7e73d3c32d28" -->
# nylib.structs, nylib.tkinter_, nylib.__pyinstaller

三个小包：`structs` 用于远程进程数据结构，`tkinter_` 用于样式化的 tkinter 小部件，以及 `__pyinstaller` 用于将 nylib 冻结成捆绑包的钩子。

关键词: ExStruct, ExField, ExPtr, ExArr, remote struct, Div, Button, Label, BorderlessWindow, tkinter widgets, CSS styling, PyInstaller, freeze, hidden imports, hook discovery

<!-- dt:section id="quick-start-0" hash="df6cbadaba31" -->
## 快速开始

构建带有可拖动、可调整大小的框架和自定义按钮的样式化 tkinter 窗口。

```python
# needs: display
import tkinter
from nylib.tkinter_ import Div, Button, Label

root = tkinter.Tk()
root.geometry('400x300')

panel = Div(root, css={'background': '#2b2b2b'})
panel.pack(fill=tkinter.BOTH, expand=True)

header = Div(panel, css={'background': '#1e1e1e', 'height': 40})
header.pack(fill=tkinter.X, padx=5, pady=5)

Label(header, text='Hello').pack(side=tkinter.LEFT)
Button(header, text='Click', preset='info').pack(side=tkinter.RIGHT, padx=5)

root.mainloop()
```

<!-- dt:section id="nylib-structs-0" hash="9d262cd49ed3" -->
## nylib.structs

将远程进程内存中的字段作为与 `Process` 绑定的实时 Python 对象进行访问。

每个类从 `ExStruct` 继承，并通过 `ExField` 描述符在固定偏移量或通过动态偏移量表声明字段。
读取和写入任何字段；嵌套结构、指针和数组都被透明地处理。

```python
# needs: target process with allocated memory
import ctypes
from nylib.structs import ExStruct, ExField, ExPtr
from nylib.process import Process

class RemoteVec2(ExStruct):
    _size_ = 8
    x = ExField(ctypes.c_float, 0)
    y = ExField(ctypes.c_float, 4)

p = Process(pid)
v = RemoteVec2(p, address=0x140000000)
print(v.x)                          # reads from remote memory
v.x = 5.0                            # writes to remote memory
```

使用 `ExVfunc` 在远程实例上调用虚函数，或使用 `ExStaticFunc` 调用静态函数。
使用 `ExStruct.__new__(..., address=None)` 在远程进程中分配和释放 — 结构自动管理生命周期。

<!-- dt:section id="nylib-tkinter-0" hash="7f67dbf7e5bc" -->
## nylib.tkinter_

具有类似 CSS 样式的高级 tkinter 小部件：`Div`（Frame）、`Label` / `LabelCantSelect`、`Button`、`Input`、`BorderlessWindow`、`Scrollable` 和容器类型（`Aside`、`Header`、`Footer`）。

每个小部件拥有一个 `css` 属性，接受字典或链式调用；CSS 值被监视并触发重绘。

```python
# needs: display
from nylib.tkinter_ import Div, Button
import tkinter

root = tkinter.Tk()
panel = Div(root, css={'background': '#3c3c3c', 'padding': 10})
panel.pack(fill=tkinter.BOTH, expand=True)

btn = Button(panel, text='Confirm', preset='success')
btn.pack(pady=5)
btn.css({'button-border-width': 2, 'font-size': 14})

btn.events.add('OnClick', lambda: print('clicked'))
root.mainloop()
```

`BorderlessWindow` 包装一个 `Tk` 或 `Toplevel`，隐藏原生框架，并添加带有最小化/最大化/关闭按钮的可拖动标题栏。
所有小部件通过一个 `GroupDelegate` 发出事件，你可以在其上注册回调。

<!-- dt:section id="nylib-pyinstaller-0" hash="8fa9a64e30d5" -->
## nylib.__pyinstaller

PyInstaller 钩子包，将 C 扩展（`nylib.pyimgui` 及其前端后端）和 ctypes 库（`keystone`、`capstone`）捆绑到冻结的捆绑包中。
通过入口点获取钩子目录：

```python
import nylib.__pyinstaller as h
dirs = h.get_hook_dirs()
print(dirs[0])
```

对于已安装的包，在 `pyproject.toml` 中声明入口点：

```toml
[project.entry-points."pyinstaller40"]
hook-dirs = "nylib.__pyinstaller:get_hook_dirs"
```

对于树内使用，在 PyInstaller 命令行中传递 `--additional-hooks-dir`：

```python
# needs: PyInstaller build
import nylib.__pyinstaller as h
import PyInstaller.__main__

PyInstaller.__main__.run([
    'your_app.py',
    *(f'--additional-hooks-dir={d}' for d in h.get_hook_dirs()),
])
```

有关更多详细信息，请参见 [../../nylib/__pyinstaller/README.md](../../nylib/__pyinstaller/README.md)。
