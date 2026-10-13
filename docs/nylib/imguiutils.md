# nylib.imguiutils

Dear ImGui widgets and utilities for notifications, dialogs, file selection, and an interactive memory debugger (disassembler, hex viewer, breakpoint manager, pattern scanner).

Keywords: toast notifications, message box, file dialog, window manager, Dear ImGui widgets, memory debugger, hex viewer, disassembler, breakpoints, debug view

## Quick start

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

## Notifications (Alerts)

```python
# needs: running pyimgui window
from nylib.imguiutils import Alerts

alerts = Alerts(pop_at=Alerts.TOP_RIGHT, margin=5)
alerts.add("Message", level=Alerts.WARNING, timeout=5.0, dismissible=True)
alerts.render()
```

`Alerts` displays non-blocking toast notifications. Levels are `DEBUG`, `INFO`, `WARNING`, `ERROR`; positions are `TOP_LEFT`, `TOP_CENTER`, `TOP_RIGHT`. Call `render()` once per frame inside a window.

## Modal dialogs (MessageBox)

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

Creates a modal dialog with buttons. The callback fires once the user picks a button (value = payload) or closes the window (value = `None`). Auto-registers with the global window manager; you must call `window_manager.render()` each frame.

## File dialogs (FileDialog)

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

Interactive file browser. Filters are `(label, pattern)` tuples; patterns use `*` and `?`. Set `ask_save_file=True` for overwrite prompts, `select_dir=True` for directories. Auto-registers with window manager. Navigate with `go_path()`, `go_back()`, `go_forward()`, `go_up()`, `refresh()`.

## Window management (WindowManager)

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

Manages a stack of render functions. Each registered function returns `bool`: `True` keeps it in the manager, `False` removes it. Render functions are called in stack order (back to front), so later registrations appear on top. Use `bring_to_front`, `send_to_back`, `move(handle, delta)`, or `reorder(handle, position)` to reshuffle.

## Utilities

- `BeginFullScreenBackGround(name, open, flags)` - fullscreen non-dockable window filling the viewport.
- `PushDisabledButtonStyle(color)` - context manager to gray out and disable buttons.
- `Inspector` - base class for a filterable two-pane selector. Override `init_items()`, `item_name()`, `on_item_selected()`.

## Icon fonts

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

Merge TTF glyphs into the ImGui font atlas. `is_installed(name)` checks if already loaded.

## Debug view (memory debugger)

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

Interactive memory viewer with disassembly (Capstone-powered), hex pane, module list, breakpoint manager, pattern scanner, and Python console. Must call `render_debug_view(state)` inside a window with `ImGuiWindowFlags_MenuBar`. Panels shown via `show_module_panel`, `show_bp_panel`, `show_address_resolver`, `show_pinned_panel`, `show_history_panel`, `show_pattern_scan`, `show_dump_module`, `show_python_console`. Set `address_fmt` to `AddressFormat.HEX` or `AddressFormat.MODULE_OFFSET`. `mem_fmt` is a `MemFormat` with `cell` (U8, U16, U32, U64) and `radix` ("hex" or "dec"). Call `state.close()` to stop the background worker thread.

## Notes

- Modal dialogs auto-register with the global `window_manager`; call `window_manager.render()` each frame.
- File filters use Windows wildcards: `*.py;*.pyx` for multiple extensions.
- Icon font codepoints as a contiguous string; `install_icon` builds efficient glyph ranges.
- Debug view runs a background worker thread; call `state.close()` to stop it.
