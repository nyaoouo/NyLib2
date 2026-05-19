import os
import pathlib
import re
import subprocess
import sys
import time
import typing

from . import window_manager as _wm
from .alerts import Alerts
from .icons import fa
from .utils import PushDisabledButtonStyle
from ..pyimgui import imgui
from ..pyimgui.imgui import ctx as imgui_ctx
from ..utils.handles import Handles

PATH_SEP = "/"

color_disabled = imgui.ImVec4(0.5, 0.5, 0.5, 1)

handles = Handles()


def _window_file_name_matcher(pattern: str):
    pattern = re.escape(pattern.strip()).replace(r'\*', '.*').replace(r'\?', '.')
    return re.compile("^" + pattern + "$", re.IGNORECASE).match


def window_file_name_matcher(pattern: str):
    patterns = [_window_file_name_matcher(p) for p in pattern.split(';')]
    return lambda name: any(p(name) for p in patterns)


basic_filter = ("All Files(*)", "*", None)


def _extract_extensions(pattern: str) -> list[str]:
    """Pull simple extensions like ``.py`` / ``.h`` out of a filter pattern.

    Returns ``[]`` for patterns that don't constrain the extension (e.g. ``"*"``)
    or for wildcards we can't safely turn into a literal suffix (e.g. ``"*.tar.*"``).
    """
    if not pattern:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for token in pattern.split(';'):
        token = token.strip()
        if not token.startswith('*.'):
            continue
        rest = token[2:]
        if not rest or '*' in rest or '?' in rest:
            continue
        ext = '.' + rest
        if ext.lower() in seen:
            continue
        seen.add(ext.lower())
        out.append(ext)
    return out


def _format_size(n: int) -> str:
    if n <= 0:
        return ""
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    i = 0
    f = float(n)
    while f >= 1024 and i < len(units) - 1:
        f /= 1024
        i += 1
    return f"{int(f)} {units[i]}" if i == 0 else f"{f:.1f} {units[i]}"


def _format_mtime(t: float) -> str:
    if t <= 0:
        return ""
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(t))


def _list_drives() -> list[pathlib.Path]:
    if sys.platform != "win32":
        return []
    out: list[pathlib.Path] = []
    try:
        import string
        from ctypes import windll
        mask = windll.kernel32.GetLogicalDrives()
        for i, letter in enumerate(string.ascii_uppercase):
            if mask & (1 << i):
                out.append(pathlib.Path(f"{letter}:\\"))
    except Exception:
        pass
    return out


def _open_in_explorer(path: pathlib.Path) -> None:
    p = pathlib.Path(path)
    if sys.platform == "win32":
        if p.is_dir():
            os.startfile(str(p))
        else:
            subprocess.Popen(["explorer", f"/select,{p}"])
    elif sys.platform == "darwin":
        subprocess.Popen(["open", "-R", str(p)])
    else:
        target = p if p.is_dir() else p.parent
        subprocess.Popen(["xdg-open", str(target)])


def _open_in_terminal(path: pathlib.Path) -> None:
    p = pathlib.Path(path)
    target = p if p.is_dir() else p.parent
    if sys.platform == "win32":
        try:
            subprocess.Popen(["wt", "-d", str(target)])
            return
        except FileNotFoundError:
            pass
        subprocess.Popen("cmd", cwd=str(target), creationflags=subprocess.CREATE_NEW_CONSOLE)
        return
    if sys.platform == "darwin":
        subprocess.Popen(["open", "-a", "Terminal", str(target)])
        return
    for term in ("gnome-terminal", "konsole", "xfce4-terminal", "x-terminal-emulator"):
        try:
            subprocess.Popen([term], cwd=str(target))
            return
        except FileNotFoundError:
            continue
    raise FileNotFoundError("no terminal emulator found")


class FileDialog:
    def __init__(self, title=None, filters: list[tuple[str, str]] = None, on_ok=None, on_cancel=None,
                 initial_dir=None, initial_value=None,
                 ask_save_file=False, select_dir=False, allow_multi_select=False):
        self.handle = handles.get()
        self.title = (title or "") + f"###__file_dialog_{self.handle}"

        # Each entry: (display_label, raw_pattern, matcher_or_None)
        self.filters: list[tuple[str, str, typing.Optional[typing.Callable[[str], typing.Any]]]] = [
            (f"{fn}({pattern})", pattern, window_file_name_matcher(pattern))
            for fn, pattern in filters
        ] if filters else []
        self.filters.append(basic_filter)
        self._on_ok = on_ok
        self._on_cancel = on_cancel
        self.ask_save_file = ask_save_file
        self.select_dir = select_dir
        self.allow_multi_select = allow_multi_select
        self.input = initial_value or ''
        self.input_filter = ''
        self.selected_filter = 0
        self.dir = pathlib.Path(initial_dir or '.').resolve()

        self._loaded_dir = None

        self.history = [self.dir]
        self.history_ptr = 0

        self.dirs: list[pathlib.Path] = []
        self.files: list[pathlib.Path] = []
        self.stats: dict[pathlib.Path, tuple[int, float]] = {}
        self.filtered_files: list[pathlib.Path] = []
        self.filtered_dirs: list[pathlib.Path] = []

        # render state
        self.sort_key = 'name'
        self.sort_dir = 1
        self.path_edit_mode = False
        self.path_edit_buf = ''
        self.path_edit_focus = False
        self.selection: set[pathlib.Path] = set()
        self.last_click_idx: int | None = None
        self.new_item_kind: str | None = None
        self.new_item_name: str = ''
        self.new_item_focus = False
        self.request_open_new_item = False
        self.request_open_overwrite = False
        self.pending_save_path: pathlib.Path | None = None
        # save-as-with-extension prompt
        self.request_open_save_ext = False
        self.save_ext_options: list[str] = []
        self.save_ext_base: pathlib.Path | None = None

        self.alerts = Alerts()

        # Auto-register with the global window manager so the caller doesn't
        # have to track the instance or call render() themselves.
        self.wm_handle = _wm.window_manager.add(self._render)

    def __free_handle(self):
        if self.handle:
            handles.free(self.handle)
            self.handle = None

    def __del__(self):
        self.__free_handle()

    # ------------------------------------------------------------------
    # navigation / state
    # ------------------------------------------------------------------

    def go_path(self, path, push_history=True):
        path = pathlib.Path(path).resolve()
        if not path.exists():
            self.alerts.add(f"Path {path} does not exist", Alerts.ERROR)
            return
        if not path.is_dir():
            path = path.parent
        self.dir = path
        self.input = ''
        self.input_filter = ''
        self.selection.clear()
        self.last_click_idx = None
        if push_history:
            self.history = [self.dir] + self.history[self.history_ptr:]
            self.history_ptr = 0

    def go_back(self):
        if self.history_ptr + 1 < len(self.history):
            self.history_ptr += 1
            self.go_path(self.history[self.history_ptr], push_history=False)

    def go_forward(self):
        if self.history_ptr > 0:
            self.history_ptr -= 1
            self.go_path(self.history[self.history_ptr], push_history=False)

    def go_up(self):
        parent = self.dir.parent
        if parent != self.dir:
            self.go_path(parent)

    def refresh(self):
        self._loaded_dir = None
        self.update_path()

    def update_path(self):
        if self._loaded_dir == self.dir:
            return
        self._loaded_dir = self.dir
        self.dirs.clear()
        self.files.clear()
        self.stats.clear()
        try:
            entries = list(self.dir.iterdir())
        except Exception as e:
            self.alerts.add(f"Cannot read {self.dir}: {e}", Alerts.ERROR)
            self.update_filter()
            return
        for p in entries:
            try:
                st = p.stat()
                self.stats[p] = (st.st_size, st.st_mtime)
                if p.is_dir():
                    self.dirs.append(p)
                else:
                    self.files.append(p)
            except Exception:
                self.stats[p] = (0, 0.0)
                self.files.append(p)
        self.update_filter()

    def update_filter(self):
        if self.input_filter:
            needle = self.input_filter.lower()
            self.filtered_files = [f for f in self.files if needle in f.name.lower()]
            self.filtered_dirs = [d for d in self.dirs if needle in d.name.lower()]
        else:
            self.filtered_files = list(self.files)
            self.filtered_dirs = list(self.dirs)
        if self.filters and self.selected_filter < len(self.filters):
            matcher = self.filters[self.selected_filter][2]
            if matcher:
                self.filtered_files = [f for f in self.filtered_files if matcher(f.name)]
        self._apply_sort()

    def _apply_sort(self):
        rev = self.sort_dir < 0
        key = self.sort_key
        if key == 'size':
            kf = lambda p: self.stats.get(p, (0, 0.0))[0]
        elif key == 'mtime':
            kf = lambda p: self.stats.get(p, (0, 0.0))[1]
        else:
            kf = lambda p: p.name.lower()
        self.filtered_dirs.sort(key=kf, reverse=rev)
        self.filtered_files.sort(key=kf, reverse=rev)

    # ------------------------------------------------------------------
    # accept / cancel
    # ------------------------------------------------------------------

    def ok(self, fp: pathlib.Path, _bypass_ext_prompt: bool = False):
        if fp.is_dir() and not self.select_dir:
            self.go_path(fp)
            return
        if self.ask_save_file:
            if not _bypass_ext_prompt and not fp.suffix:
                exts = self._current_filter_extensions()
                if exts:
                    self.save_ext_options = list(exts)
                    self.save_ext_base = fp
                    self.request_open_save_ext = True
                    return
            if fp.exists():
                self.pending_save_path = fp
                self.request_open_overwrite = True
                return
        elif not fp.exists():
            self.alerts.add(f"{fp.name} does not exist", Alerts.ERROR)
            return
        self._finalize_ok([fp] if self.allow_multi_select else fp)

    def _current_filter_extensions(self) -> list[str]:
        if not self.filters or self.selected_filter >= len(self.filters):
            return []
        _, pattern, _ = self.filters[self.selected_filter]
        return _extract_extensions(pattern)

    def _finalize_ok(self, result):
        self.__free_handle()
        _wm.window_manager.close(self.wm_handle)
        if self._on_ok:
            self._on_ok(result)

    def cancel(self):
        self.__free_handle()
        _wm.window_manager.close(self.wm_handle)
        if self._on_cancel:
            self._on_cancel()

    # ------------------------------------------------------------------
    # render
    # ------------------------------------------------------------------

    def _render(self):
        if not self.handle:
            return False
        imgui.SetNextWindowSize(imgui.ImVec2(820, 520), imgui.ImGuiCond_FirstUseEver)
        flags = imgui.ImGuiWindowFlags_NoDocking
        with imgui_ctx.Begin(self.title, True, flags) as (show, window_open):
            if not window_open:
                self.cancel()
                return False
            if not show:
                return True
            imgui.BringWindowToFocusFront(imgui.GetCurrentWindow())

            self.update_path()

            self._render_toolbar()
            imgui.Separator()
            self._render_body()
            imgui.Separator()
            self._render_bottom_bar()

            self._render_new_item_popup()
            self._render_save_ext_popup()
            self._render_overwrite_popup()

            self.alerts.render()
        return self.handle is not None

    # ---- toolbar ----------------------------------------------------

    def _render_toolbar(self):
        can_back = self.history_ptr + 1 < len(self.history)
        can_fwd = self.history_ptr > 0
        can_up = self.dir.parent != self.dir

        self._nav_button(fa.fa_arrow_left, can_back, self.go_back, "Back")
        imgui.SameLine()
        self._nav_button(fa.fa_arrow_right, can_fwd, self.go_forward, "Forward")
        imgui.SameLine()
        self._nav_button(fa.fa_arrow_up, can_up, self.go_up, "Up")
        imgui.SameLine()
        self._nav_button(fa.fa_arrows_rotate, True, self.refresh, "Refresh")
        imgui.SameLine()

        avail_x = imgui.GetContentRegionAvail().x
        sp = imgui.GetStyle().ItemSpacing.x
        filter_w = 220.0
        path_w = max(80.0, avail_x - filter_w - sp)

        self._render_path_bar(path_w)
        imgui.SameLine()
        imgui.SetNextItemWidth(filter_w)
        changed, self.input_filter = imgui.InputText(
            f"##quickfilter_{self.handle}", self.input_filter,
        )
        if changed:
            self.update_filter()
        if not self.input_filter and not imgui.IsItemActive():
            self._draw_input_hint(f"{fa.fa_magnifying_glass}  filter")

    def _draw_input_hint(self, text: str):
        dl = imgui.GetWindowDrawList()
        mn = imgui.GetItemRectMin()
        pad = imgui.GetStyle().FramePadding
        col = imgui.GetColorU32(imgui.ImGuiCol_TextDisabled)
        dl.AddText(imgui.ImVec2(mn.x + pad.x, mn.y + pad.y), col, text)

    def _nav_button(self, icon: str, enabled: bool, on_click, tooltip: str):
        label = f"{icon}##nav_{tooltip}_{self.handle}"
        if enabled:
            if imgui.Button(label):
                on_click()
        else:
            with PushDisabledButtonStyle():
                with imgui_ctx.PushStyleColor(imgui.ImGuiCol_Text, color_disabled):
                    imgui.Button(label)
        if tooltip and imgui.IsItemHovered():
            with imgui_ctx.BeginTooltip() as show:
                if show:
                    imgui.Text(tooltip)

    def _render_path_bar(self, width: float):
        frame_h = imgui.GetFrameHeight()
        if self.path_edit_mode:
            imgui.SetNextItemWidth(width)
            if not self.path_edit_focus:
                imgui.SetKeyboardFocusHere()
                self.path_edit_focus = True
            flags = imgui.ImGuiInputTextFlags_EnterReturnsTrue | imgui.ImGuiInputTextFlags_AutoSelectAll
            committed, self.path_edit_buf = imgui.InputText(f"##pathedit_{self.handle}", self.path_edit_buf, flags)
            if imgui.IsKeyPressed(imgui.ImGuiKey_Escape):
                self.path_edit_mode = False
                self.path_edit_focus = False
            elif committed:
                self.path_edit_mode = False
                self.path_edit_focus = False
                self.go_path(self.path_edit_buf)
            return

        with imgui_ctx.BeginChild(
                f"##breadcrumb_{self.handle}",
                imgui.ImVec2(width, frame_h),
                child_flags=imgui.ImGuiChildFlags_FrameStyle,
        ):
            parts = self.dir.parts
            for i, part in enumerate(parts):
                if i > 0:
                    imgui.SameLine(0, 2)
                    imgui.TextDisabled(fa.fa_chevron_right)
                    imgui.SameLine(0, 2)
                label = part.rstrip("\\/") or part
                if imgui.SmallButton(f"{label}##bc_{self.handle}_{i}"):
                    self.go_path(pathlib.Path(*parts[:i + 1]))
            imgui.SameLine(0, 0)
            remaining = max(8.0, imgui.GetContentRegionAvail().x)
            if imgui.InvisibleButton(f"##pathedit_zone_{self.handle}", imgui.ImVec2(remaining, frame_h)):
                self.path_edit_mode = True
                self.path_edit_buf = str(self.dir)
                self.path_edit_focus = False

    # ---- body -------------------------------------------------------

    def _render_body(self):
        avail = imgui.GetContentRegionAvail()
        style = imgui.GetStyle()
        bottom_h = imgui.GetFrameHeight() + style.ItemSpacing.y * 2 + style.WindowPadding.y
        body_h = max(120.0, avail.y - bottom_h)

        drives = _list_drives()
        sidebar_w = 140.0

        with imgui_ctx.BeginChild(
                f"##sidebar_{self.handle}",
                imgui.ImVec2(sidebar_w, body_h),
                child_flags=imgui.ImGuiChildFlags_Border,
        ):
            self._render_sidebar(drives)
        imgui.SameLine()
        with imgui_ctx.BeginChild(
                f"##main_{self.handle}",
                imgui.ImVec2(0, body_h),
                child_flags=imgui.ImGuiChildFlags_Border,
        ):
            self._render_main_table()

    def _render_sidebar(self, drives: list[pathlib.Path]):
        home = pathlib.Path.home()
        if imgui.Selectable(f"{fa.fa_house}  Home##sb_home_{self.handle}", False):
            self.go_path(home)
        if drives:
            imgui.Separator()
            imgui.TextDisabled("Drives")
            for d in drives:
                label = d.drive or str(d).rstrip("\\/")
                if imgui.Selectable(f"{fa.fa_hard_drive}  {label}##sb_drv_{label}_{self.handle}", False):
                    self.go_path(d)

    def _render_main_table(self):
        flags = (
            imgui.ImGuiTableFlags_RowBg
            | imgui.ImGuiTableFlags_Sortable
            | imgui.ImGuiTableFlags_ScrollY
            | imgui.ImGuiTableFlags_Resizable
            | imgui.ImGuiTableFlags_BordersInnerV
        )
        with imgui_ctx.BeginTable(f"##files_{self.handle}", 3, flags):
            imgui.TableSetupScrollFreeze(0, 1)
            imgui.TableSetupColumn(
                "Name",
                imgui.ImGuiTableColumnFlags_WidthStretch | imgui.ImGuiTableColumnFlags_DefaultSort,
            )
            imgui.TableSetupColumn("Size", imgui.ImGuiTableColumnFlags_WidthFixed, 90.0)
            imgui.TableSetupColumn("Modified", imgui.ImGuiTableColumnFlags_WidthFixed, 140.0)
            imgui.TableHeadersRow()

            specs = imgui.TableGetSortSpecs()
            if specs and specs.SpecsDirty:
                if specs.SpecsCount > 0 and specs.Specs is not None:
                    s = specs.Specs
                    col = int(s.ColumnIndex)
                    self.sort_key = ('name', 'size', 'mtime')[col] if 0 <= col < 3 else 'name'
                    self.sort_dir = 1 if int(s.SortDirection) == int(imgui.ImGuiSortDirection_Ascending) else -1
                    self._apply_sort()
                specs.SpecsDirty = False

            ordered = self.filtered_dirs + self.filtered_files
            n_dirs = len(self.filtered_dirs)

            clipper = imgui.ImGuiListClipper()
            clipper.Begin(len(ordered))
            while clipper.Step():
                for i in range(clipper.DisplayStart, clipper.DisplayEnd):
                    p = ordered[i]
                    self._render_row(i, p, is_dir=(i < n_dirs))

            if imgui.BeginPopupContextWindow(
                    f"##fd_empty_menu_{self.handle}",
                    imgui.ImGuiPopupFlags_MouseButtonRight | imgui.ImGuiPopupFlags_NoOpenOverItems,
            ):
                self._render_context_menu_items(target=None)
                imgui.EndPopup()

    def _render_row(self, idx: int, p: pathlib.Path, is_dir: bool):
        size, mtime = self.stats.get(p, (0, 0.0))
        icon = fa.fa_folder if is_dir else fa.fa_file
        is_selected = p in self.selection

        imgui.TableNextRow()
        imgui.TableSetColumnIndex(0)
        sel_flags = (
            imgui.ImGuiSelectableFlags_SpanAllColumns
            | imgui.ImGuiSelectableFlags_AllowOverlap
            | imgui.ImGuiSelectableFlags_AllowDoubleClick
        )
        clicked = imgui.Selectable(f"{icon}  {p.name}##row_{self.handle}_{idx}", is_selected, sel_flags)
        if clicked:
            self._on_row_click(idx, p, is_dir)
        if imgui.IsItemHovered() and imgui.IsMouseDoubleClicked(0):
            self._do_open(p, is_dir)

        if imgui.BeginPopupContextItem(f"##row_menu_{self.handle}_{idx}"):
            if not is_selected:
                self.selection.clear()
                self.selection.add(p)
                self.last_click_idx = idx
            self._render_context_menu_items(target=p)
            imgui.EndPopup()

        imgui.TableSetColumnIndex(1)
        if not is_dir:
            imgui.Text(_format_size(size))
        imgui.TableSetColumnIndex(2)
        imgui.Text(_format_mtime(mtime))

    def _on_row_click(self, idx: int, p: pathlib.Path, is_dir: bool):
        io = imgui.GetIO()
        if self.allow_multi_select and io.KeyShift and self.last_click_idx is not None:
            ordered = self.filtered_dirs + self.filtered_files
            lo, hi = sorted((self.last_click_idx, idx))
            self.selection.clear()
            for j in range(lo, min(hi + 1, len(ordered))):
                self.selection.add(ordered[j])
        elif self.allow_multi_select and (io.KeyCtrl or io.KeySuper):
            if p in self.selection:
                self.selection.discard(p)
            else:
                self.selection.add(p)
            self.last_click_idx = idx
        else:
            self.selection.clear()
            self.selection.add(p)
            self.last_click_idx = idx

        if self.allow_multi_select and len(self.selection) > 1:
            names = sorted(x.name for x in self.selection)
            self.input = ' '.join(f'"{n}"' for n in names)
        elif (not is_dir) or self.select_dir:
            self.input = p.name

    def _do_open(self, p: pathlib.Path, is_dir: bool | None = None):
        if is_dir is None:
            is_dir = p.is_dir()
        if is_dir:
            self.go_path(p)
        else:
            self.ok(p)

    # ---- bottom bar -------------------------------------------------

    def _render_bottom_bar(self):
        avail_x = imgui.GetContentRegionAvail().x
        style = imgui.GetStyle()
        sp = style.ItemSpacing.x
        pad = style.FramePadding.x

        ok_label = "Save" if self.ask_save_file else ("Select" if self.select_dir else "Open")
        ok_w = max(80.0, imgui.CalcTextSize(ok_label).x + pad * 2 + 20)
        cancel_w = max(80.0, imgui.CalcTextSize("Cancel").x + pad * 2 + 20)
        filter_w = 180.0
        label_w = imgui.CalcTextSize("File:").x
        input_w = max(120.0, avail_x - ok_w - cancel_w - filter_w - label_w - sp * 5)

        imgui.Text("File:")
        imgui.SameLine()
        imgui.SetNextItemWidth(input_w)
        enter_pressed, self.input = imgui.InputText(
            f"##fname_{self.handle}",
            self.input,
            imgui.ImGuiInputTextFlags_EnterReturnsTrue,
        )
        imgui.SameLine()
        imgui.SetNextItemWidth(filter_w)
        names = [f[0] for f in self.filters]
        changed, self.selected_filter = imgui.Combo(f"##filter_{self.handle}", self.selected_filter, names)
        if changed:
            self.update_filter()

        imgui.SameLine()
        ok_enabled = bool(self.input.strip()) or self.select_dir
        if ok_enabled:
            if imgui.Button(f"{ok_label}##ok_btn_{self.handle}", imgui.ImVec2(ok_w, 0)) or enter_pressed:
                self._submit()
        else:
            with PushDisabledButtonStyle():
                with imgui_ctx.PushStyleColor(imgui.ImGuiCol_Text, color_disabled):
                    imgui.Button(f"{ok_label}##ok_btn_d_{self.handle}", imgui.ImVec2(ok_w, 0))
        imgui.SameLine()
        if imgui.Button(f"Cancel##cancel_btn_{self.handle}", imgui.ImVec2(cancel_w, 0)):
            self.cancel()

    def _submit(self):
        if self.allow_multi_select and len(self.selection) > 1:
            valid = sorted(self.selection)
            for fp in valid:
                if not fp.exists():
                    self.alerts.add(f"{fp.name} does not exist", Alerts.ERROR)
                    return
            self._finalize_ok(list(valid))
            return
        text = self.input.strip().strip('"')
        if not text:
            if self.select_dir:
                self.ok(self.dir)
            return
        candidate = pathlib.Path(text)
        target = candidate.resolve() if candidate.is_absolute() else (self.dir / text).resolve()
        self.ok(target)

    # ---- context menu items ----------------------------------------

    def _render_context_menu_items(self, target: pathlib.Path | None):
        if target is not None:
            if imgui.MenuItem(f"{fa.fa_folder_open}  Open"):
                self._do_open(target)
            if imgui.MenuItem(f"{fa.fa_up_right_from_square}  Open in Explorer"):
                try:
                    _open_in_explorer(target)
                except Exception as e:
                    self.alerts.add(f"open explorer failed: {e}", Alerts.ERROR)
            if imgui.MenuItem(f"{fa.fa_terminal}  Open in Terminal"):
                try:
                    _open_in_terminal(target)
                except Exception as e:
                    self.alerts.add(f"open terminal failed: {e}", Alerts.ERROR)
            imgui.Separator()
        if imgui.MenuItem(f"{fa.fa_file_circle_plus}  New File"):
            self._request_new_item('file')
        if imgui.MenuItem(f"{fa.fa_folder_plus}  New Folder"):
            self._request_new_item('dir')

    def _request_new_item(self, kind: str):
        self.new_item_kind = kind
        self.new_item_name = ''
        self.new_item_focus = False
        self.request_open_new_item = True

    # ---- popups -----------------------------------------------------

    def _render_new_item_popup(self):
        pid = f"##new_item_{self.handle}"
        if self.request_open_new_item:
            self.request_open_new_item = False
            imgui.OpenPopup(pid)
        center = imgui.GetMainViewport().GetCenter()
        imgui.SetNextWindowPos(center, imgui.ImGuiCond_Appearing, imgui.ImVec2(0.5, 0.5))
        opened, _ = imgui.BeginPopupModal(pid, None, imgui.ImGuiWindowFlags_AlwaysAutoResize)
        if not opened:
            return
        kind_label = "Folder" if self.new_item_kind == 'dir' else "File"
        imgui.Text(f"New {kind_label} in {self.dir.name or str(self.dir)}")
        imgui.Spacing()
        imgui.SetNextItemWidth(320.0)
        if not self.new_item_focus:
            imgui.SetKeyboardFocusHere()
            self.new_item_focus = True
        enter, self.new_item_name = imgui.InputText(
            f"##new_item_name_{self.handle}",
            self.new_item_name,
            imgui.ImGuiInputTextFlags_EnterReturnsTrue,
        )
        if imgui.Button(f"Create##ni_ok_{self.handle}") or enter:
            self._create_new_item(self.new_item_name, self.new_item_kind)
            imgui.CloseCurrentPopup()
        imgui.SameLine()
        if imgui.Button(f"Cancel##ni_cancel_{self.handle}") or imgui.IsKeyPressed(imgui.ImGuiKey_Escape):
            imgui.CloseCurrentPopup()
        imgui.EndPopup()

    def _create_new_item(self, name: str, kind: str | None):
        name = name.strip()
        if not name or kind is None:
            return
        target = self.dir / name
        try:
            if kind == 'dir':
                target.mkdir()
            else:
                target.touch(exist_ok=False)
        except Exception as e:
            self.alerts.add(f"create failed: {e}", Alerts.ERROR)
            return
        self.refresh()
        self.alerts.add(f"created {target.name}", Alerts.INFO)

    def _render_save_ext_popup(self):
        pid = f"##save_ext_{self.handle}"
        if self.request_open_save_ext:
            self.request_open_save_ext = False
            imgui.OpenPopup(pid)
        center = imgui.GetMainViewport().GetCenter()
        imgui.SetNextWindowPos(center, imgui.ImGuiCond_Appearing, imgui.ImVec2(0.5, 0.5))
        opened, _ = imgui.BeginPopupModal(pid, None, imgui.ImGuiWindowFlags_AlwaysAutoResize)
        if not opened:
            return

        base = self.save_ext_base
        chosen: pathlib.Path | None = None
        chosen_bypass = False

        if base is None:
            imgui.CloseCurrentPopup()
        else:
            filter_label = self.filters[self.selected_filter][0] if self.filters else ""
            imgui.Text(f"Save as which file type?")
            imgui.TextDisabled(f"(filter: {filter_label})")
            imgui.Spacing()
            for ext in self.save_ext_options:
                suggested = base.with_suffix(ext)
                if imgui.Button(f"{suggested.name}##save_ext_{ext}_{self.handle}"):
                    chosen = suggested
            imgui.Spacing()
            if imgui.Button(f"{base.name}  (no extension)##save_ext_asis_{self.handle}"):
                chosen = base
                chosen_bypass = True
            imgui.SameLine()
            if imgui.Button(f"Cancel##save_ext_cancel_{self.handle}") or imgui.IsKeyPressed(imgui.ImGuiKey_Escape):
                self.save_ext_base = None
                self.save_ext_options = []
                imgui.CloseCurrentPopup()

        if chosen is not None:
            self.save_ext_base = None
            self.save_ext_options = []
            imgui.CloseCurrentPopup()

        imgui.EndPopup()

        # Continue the save flow OUTSIDE the popup (may queue the overwrite popup).
        if chosen is not None:
            self.ok(chosen, _bypass_ext_prompt=chosen_bypass)

    def _render_overwrite_popup(self):
        pid = f"##overwrite_{self.handle}"
        if self.request_open_overwrite:
            self.request_open_overwrite = False
            imgui.OpenPopup(pid)
        center = imgui.GetMainViewport().GetCenter()
        imgui.SetNextWindowPos(center, imgui.ImGuiCond_Appearing, imgui.ImVec2(0.5, 0.5))
        opened, _ = imgui.BeginPopupModal(pid, None, imgui.ImGuiWindowFlags_AlwaysAutoResize)
        if not opened:
            return
        if self.pending_save_path is not None:
            imgui.Text(f"Overwrite {self.pending_save_path.name}?")
        imgui.Spacing()
        if imgui.Button(f"Overwrite##ow_ok_{self.handle}"):
            fp = self.pending_save_path
            self.pending_save_path = None
            imgui.CloseCurrentPopup()
            if fp is not None:
                self._finalize_ok([fp] if self.allow_multi_select else fp)
        imgui.SameLine()
        if imgui.Button(f"Cancel##ow_cancel_{self.handle}") or imgui.IsKeyPressed(imgui.ImGuiKey_Escape):
            self.pending_save_path = None
            imgui.CloseCurrentPopup()
        imgui.EndPopup()
