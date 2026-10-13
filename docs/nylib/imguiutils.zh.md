> 本文档为 imguiutils.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="imguiutils.md" -->

<!-- dt:section id="__preamble__" hash="435957edf9e2" -->
# nylib.imguiutils

用于通知、对话框、文件选择和交互式内存调试器（反汇编器、十六进制查看器、断点管理器、模式扫描器）的 Dear ImGui 小部件和实用程序。

关键词: toast notifications, message box, file dialog, window manager, Dear ImGui widgets, memory debugger, hex viewer, disassembler, breakpoints, debug view

<!-- dt:section id="quick-start-0" hash="29b53df682f9" -->
## 快速开始

```python
# needs: running pyimgui window
from nylib.imguiutils import Alerts, MessageBox, window_manager
from nylib.pyimgui import imgui
from nylib.pyimgui.imgui import ctx as imgui_ctx

alerts = Alerts()
alerts.add("Operation complete", Alerts.INFO, timeout=3.0)

MessageBox("Save changes?", buttons=[("Yes", True), ("No", False)])
window_manager.render()
```

<!-- dt:section id="notifications-alerts-0" hash="916c283fce45" -->
## 通知（Alerts）

```python
# needs: running pyimgui window
from nylib.imguiutils import Alerts

alerts = Alerts(pop_at=Alerts.TOP_RIGHT, margin=5)
alerts.add("Message", level=Alerts.WARNING, timeout=5.0, dismissible=True)
alerts.render()
```

`Alerts` 显示非阻塞型 toast 通知。等级有 `DEBUG`、`INFO`、`WARNING`、`ERROR`；位置有 `TOP_LEFT`、`TOP_CENTER`、`TOP_RIGHT`。在窗口内每帧调用一次 `render()`。

<!-- dt:section id="modal-dialogs-messagebox-0" hash="1258b8580184" -->
## 模态对话框（MessageBox）

```python
# needs: running pyimgui window
from nylib.imguiutils import MessageBox

def on_choice(result):
    if result is True:
        print("Clicked Yes")

MessageBox(
    message="Continue?",
    title="Confirm",
    buttons=[("Yes", True), ("No", False)],
    callback=on_choice
)
```

创建一个带按钮的模态对话框。用户选择按钮（值 = 负载）或关闭窗口（值 = `None`）时，回调触发。自动注册到全局窗口管理器；每帧必须调用 `window_manager.render()`。

<!-- dt:section id="file-dialogs-filedialog-0" hash="dd8612768fdc" -->
## 文件对话框（FileDialog）

```python
# needs: a running pyimgui window with window_manager integration
from nylib.imguiutils import FileDialog

def on_file_selected(path):
    print(f"Selected: {path}")

fd = FileDialog(
    title="Open File",
    filters=[("Python", "*.py"), ("All", "*")],
    initial_dir="./",
    on_ok=on_file_selected
)
```

交互式文件浏览器。过滤器为 `(label, pattern)` 元组；模式使用 `*` 和 `?`。设置 `ask_save_file=True` 来提示覆盖，设置 `select_dir=True` 来选择目录。自动注册到窗口管理器。使用 `go_path()`、`go_back()`、`go_forward()`、`go_up()`、`refresh()` 进行导航。

<!-- dt:section id="window-management-windowmanager-0" hash="6e2066b8395e" -->
## 窗口管理（WindowManager）

```python
# needs: running pyimgui window with imgui imported
from nylib.imguiutils import window_manager

def my_render_fn():
    from nylib.pyimgui import imgui
    opened, _open = imgui.Begin("My Dialog")
    if not opened:
        return False
    imgui.Text("Hello")
    return True

handle = window_manager.add(my_render_fn)
window_manager.render()
window_manager.close(handle)
```

管理一个渲染函数栈。每个已注册函数返回 `bool`：`True` 保留在管理器中，`False` 移除。渲染函数按栈序调用（从后到前），所以后注册的显示在上面。使用 `bring_to_front`、`send_to_back`、`move(handle, delta)` 或 `reorder(handle, position)` 来重新排列。

<!-- dt:section id="utilities-0" hash="29268fc67c06" -->
## 实用程序

- `BeginFullScreenBackGround(name, open, flags)` - 全屏不可停靠窗口，填充视口。
- `PushDisabledButtonStyle(color)` - 上下文管理器，将按钮变为灰色并禁用。
- `Inspector` - 可过滤双窗格选择器的基类。覆盖 `init_items()`、`item_name()`、`on_item_selected()`。

<!-- dt:section id="icon-fonts-0" hash="3ec1f7b32ead" -->
## 图标字体

```python
# needs: fontawesome.ttf file exists
from nylib.imguiutils.icons import install_icon, IconSetMeta, IconFont
import pathlib

meta = IconSetMeta(
    name="fa",
    fonts=[IconFont(ttf=pathlib.Path("fontawesome.ttf"), glyphs="", size=16.0)]
)
install_icon(meta)  # call once before first frame
```

将 TTF 字形合并到 ImGui 字体图集中。`is_installed(name)` 检查是否已加载。

<!-- dt:section id="debug-view-memory-debugger-0" hash="e432f70e9161" -->
## 调试视图（内存调试器）

```python
# needs: a target process with a running pyimgui window
from nylib.imguiutils import DebugViewState, render_debug_view
from nylib.pyimgui import imgui
from nylib.pyimgui.imgui import ctx as imgui_ctx

state = DebugViewState(disasm_cursor=0x140001000, hex_cursor=0x140001000)
with imgui_ctx.Begin("Debugger", flags=imgui.ImGuiWindowFlags_MenuBar) as (show, _):
    if show:
        render_debug_view(state)

state.goto_disasm(0x400000)  # navigate disasm pane
state.goto_hex(0x400000)      # navigate hex pane
```

交互式内存查看器，具有反汇编（由 Capstone 驱动）、十六进制窗格、模块列表、断点管理器、模式扫描器和 Python 控制台。必须在具有 `ImGuiWindowFlags_MenuBar` 的窗口内调用 `render_debug_view(state)`。通过 `show_module_panel`、`show_bp_panel`、`show_address_resolver`、`show_pinned_panel`、`show_history_panel`、`show_pattern_scan`、`show_dump_module`、`show_python_console` 显示面板。将 `address_fmt` 设置为 `AddressFormat.HEX` 或 `AddressFormat.MODULE_OFFSET`。`mem_fmt` 是一个具有 `cell`（U8、U16、U32、U64）和 `radix`（"hex"或"dec"）的 `MemFormat`。调用 `state.close()` 停止后台工作线程。

<!-- dt:section id="notes-0" hash="14382385d17f" -->
## 注意

- 模态对话框自动注册到全局 `window_manager`；每帧调用 `window_manager.render()`。
- 文件过滤器使用 Windows 通配符：`*.py;*.pyx` 用于多个扩展名。
- 图标字体代码点为连续字符串；`install_icon` 构建高效的字形范围。
- 调试视图运行后台工作线程；调用 `state.close()` 停止它。
