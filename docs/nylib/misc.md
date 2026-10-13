# nylib.structs, nylib.tkinter_, nylib.__pyinstaller

Three small packages: `structs` for remote process data structures, `tkinter_` for styled tkinter widgets, and `__pyinstaller` hooks for freezing nylib into bundles.

Keywords: ExStruct, ExField, ExPtr, ExArr, remote struct, Div, Button, Label, BorderlessWindow, tkinter widgets, CSS styling, PyInstaller, freeze, hidden imports, hook discovery

## Quick start

Build a styled tkinter window with draggable, resizable frames and custom buttons.

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

## nylib.structs

Access fields in remote process memory as live Python objects tied to a `Process`.

Each class inherits from `ExStruct` and declares fields with `ExField` descriptors at fixed offsets or via a dynamic offset table.
Read and write any field; nested structs, pointers, and arrays are handled transparently.

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

Call virtual functions on a remote instance with `ExVfunc`, or static functions with `ExStaticFunc`.
Allocate and deallocate in the remote process with `ExStruct.__new__(..., address=None)` — the struct manages lifetime automatically.

## nylib.tkinter_

High-level tkinter widgets with CSS-like styling: `Div` (Frame), `Label` / `LabelCantSelect`, `Button`, `Input`, `BorderlessWindow`, `Scrollable`, and container types (`Aside`, `Header`, `Footer`).

Every widget owns a `css` property that accepts dicts or chained calls; CSS values are watched and trigger redraws.

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

`BorderlessWindow` wraps a `Tk` or `Toplevel`, hides the native frame, and adds a draggable title bar with minimize/maximize/close buttons.
All widgets emit events through a `GroupDelegate` that you register callbacks on.

## nylib.__pyinstaller

PyInstaller hook package that bundles C extensions (`nylib.pyimgui` and its frontend backends) and ctypes libraries (`keystone`, `capstone`) into frozen bundles.
Get the hooks directory via the entry point:

```python
import nylib.__pyinstaller as h
dirs = h.get_hook_dirs()
print(dirs[0])
```

For installed packages, declare the entry point in `pyproject.toml`:

```toml
[project.entry-points."pyinstaller40"]
hook-dirs = "nylib.__pyinstaller:get_hook_dirs"
```

For in-tree usage, pass `--additional-hooks-dir` on the PyInstaller command line:

```python
# needs: PyInstaller build
import nylib.__pyinstaller as h
import PyInstaller.__main__

PyInstaller.__main__.run([
    'your_app.py',
    *(f'--additional-hooks-dir={d}' for d in h.get_hook_dirs()),
])
```

For more detail see [../../nylib/__pyinstaller/README.md](../../nylib/__pyinstaller/README.md).
