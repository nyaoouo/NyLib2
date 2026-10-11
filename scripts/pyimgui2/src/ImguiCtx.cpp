#include "./ImguiCtx.h"
#include "./pyimgui.h"

using namespace G_UTILS_NAMESPACE;

namespace
{
    const char *OptionalCString(const py::object &value, std::string &storage)
    {
        if (value.is_none())
            return nullptr;
        if (py::isinstance<py::int_>(value) && py::cast<int>(value) == 0)
            return nullptr;
        storage = py::cast<std::string>(value);
        return storage.c_str();
    }

    PyCtxWrapper Ctx(py::object result, std::function<void()> on_exit)
    {
        return PyCtxWrapper(std::move(result), std::move(on_exit));
    }

    PyCtxWrapper CtxIf(py::object result, bool should_exit, std::function<void()> on_exit)
    {
        return PyCtxWrapper(std::move(result), should_exit ? std::move(on_exit) : std::function<void()>());
    }

    PyCtxWrapper BoolCtx(bool result, std::function<void()> on_exit)
    {
        return CtxIf(py::cast(result), result, std::move(on_exit));
    }

    PyCtxWrapper NoneCtx(std::function<void()> on_exit)
    {
        return Ctx(py::none(), std::move(on_exit));
    }

    PyCtxWrapper TreeNodeCtx(bool opened, ImGuiTreeNodeFlags flags)
    {
        return CtxIf(py::cast(opened), opened && !(flags & ImGuiTreeNodeFlags_NoTreePushOnOpen), [] { ImGui::TreePop(); });
    }

    // Finishes the log on exit only if this call started it.
    PyCtxWrapper LogCtx(const std::function<void()> &start)
    {
        bool was_enabled = GImGui->LogEnabled;
        start();
        return CtxIf(py::none(), !was_enabled && GImGui->LogEnabled, [] { ImGui::LogFinish(); });
    }

    void CheckStyleVar(ImGuiStyleVar idx, ImU32 count)
    {
        if (idx < 0 || idx >= ImGuiStyleVar_COUNT)
            _throwV_("invalid ImGuiStyleVar {}", idx);
        if (ImGui::GetStyleVarInfo(idx)->Count != count)
            _throwV_("ImGuiStyleVar {} has {} component(s)", idx, ImGui::GetStyleVarInfo(idx)->Count);
    }

    void CheckStyleColor(ImGuiCol idx)
    {
        if (idx < 0 || idx >= ImGuiCol_COUNT)
            _throwV_("invalid ImGuiCol {}", idx);
    }

    void CheckColumns(const char *name)
    {
        ImGuiWindow *window = ImGui::GetCurrentWindowRead();
        if (!window || !window->DC.CurrentColumns)
            _throwV_("{} needs active legacy columns (BeginColumns)", name);
    }

    void CheckTableColumns(int columns)
    {
        if (columns < 1 || columns >= IMGUI_TABLE_MAX_COLUMNS)
            _throwV_("table columns must be in [1, {}), got {}", IMGUI_TABLE_MAX_COLUMNS, columns);
    }
}

START_IMGUI_CTX_NAMESPACE
{
    void pybind_setup_ImguiCtx(pybind11::module_ m)
    {
        m.def("Begin", [](const char *name, std::optional<bool> open, ImGuiWindowFlags flags)
              {
                  bool open_value = open.value_or(true);
                  bool visible = ImGui::Begin(name, open ? &open_value : nullptr, flags);
                  return Ctx(py::make_tuple(visible, open ? open_value : true), [] { ImGui::End(); });
              }, py::arg("name").none(false), py::arg("open") = py::none(), py::arg("flags") = 0);
        m.def("BeginChild", [](const char *str_id, const ImVec2 &size, ImGuiChildFlags child_flags, ImGuiWindowFlags window_flags)
              {
                  bool visible = ImGui::BeginChild(str_id, size, child_flags, window_flags);
                  return Ctx(py::cast(visible), [] { ImGui::EndChild(); });
              }, py::arg("str_id").none(false), py::arg("size") = ImVec2(0, 0), py::arg("child_flags") = 0, py::arg("window_flags") = 0);
        m.def("BeginChild", [](ImGuiID id, const ImVec2 &size, ImGuiChildFlags child_flags, ImGuiWindowFlags window_flags)
              {
                  bool visible = ImGui::BeginChild(id, size, child_flags, window_flags);
                  return Ctx(py::cast(visible), [] { ImGui::EndChild(); });
              }, py::arg("id"), py::arg("size") = ImVec2(0, 0), py::arg("child_flags") = 0, py::arg("window_flags") = 0, py::return_value_policy::move);
        m.def("BeginChildEx", [](const char *name, ImGuiID id, const ImVec2 &size_arg, ImGuiChildFlags child_flags, ImGuiWindowFlags window_flags)
              {
                  bool visible = ImGui::BeginChildEx(name, id, size_arg, child_flags, window_flags);
                  return Ctx(py::cast(visible), [] { ImGui::EndChild(); });
              }, py::arg("name").none(false), py::arg("id"), py::arg("size_arg"), py::arg("child_flags"), py::arg("window_flags"));
        m.def("BeginChildFrame", [](ImGuiID id, const ImVec2 &size, ImGuiWindowFlags window_flags)
              {
                  bool visible = ImGui::BeginChildFrame(id, size, window_flags);
                  return Ctx(py::cast(visible), [] { ImGui::EndChildFrame(); });
              }, py::arg("id"), py::arg("size"), py::arg("window_flags") = 0, py::return_value_policy::move);
        m.def("BeginColumns", [](const char *str_id, int count, ImGuiOldColumnFlags flags)
              {
                  ImGui::BeginColumns(str_id, count, flags);
                  return NoneCtx([] { ImGui::EndColumns(); });
              }, py::arg("str_id"), py::arg("count"), py::arg("flags") = 0, py::return_value_policy::move);
        m.def("BeginCombo", [](const char *label, const char *preview_value, ImGuiComboFlags flags)
              {
                  return BoolCtx(ImGui::BeginCombo(label, preview_value, flags), [] { ImGui::EndCombo(); });
              }, py::arg("label").none(false), py::arg("preview_value"), py::arg("flags") = 0);
        m.def("BeginComboPreview", []
              {
                  return BoolCtx(ImGui::BeginComboPreview(), [] { ImGui::EndComboPreview(); });
              }, py::return_value_policy::move);
        m.def("BeginDisabled", [](bool disabled)
              {
                  ImGui::BeginDisabled(disabled);
                  return NoneCtx([] { ImGui::EndDisabled(); });
              }, py::arg("disabled") = true, py::return_value_policy::move);
        m.def("BeginDisabledOverrideReenable", []
              {
                  if (!(GImGui->CurrentItemFlags & ImGuiItemFlags_Disabled))
                      _throw_("BeginDisabledOverrideReenable needs an enclosing BeginDisabled(True)");
                  ImGui::BeginDisabledOverrideReenable();
                  return NoneCtx([] { ImGui::EndDisabledOverrideReenable(); });
              });
        m.def("BeginDragDropSource", [](ImGuiDragDropFlags flags)
              {
                  return BoolCtx(ImGui::BeginDragDropSource(flags), [] { ImGui::EndDragDropSource(); });
              }, py::arg("flags") = 0, py::return_value_policy::move);
        m.def("BeginDragDropTarget", []
              {
                  return BoolCtx(ImGui::BeginDragDropTarget(), [] { ImGui::EndDragDropTarget(); });
              }, py::return_value_policy::move);
        m.def("BeginDragDropTargetCustom", [](const ImRect &bb, ImGuiID id)
              {
                  return BoolCtx(ImGui::BeginDragDropTargetCustom(bb, id), [] { ImGui::EndDragDropTarget(); });
              }, py::arg("bb"), py::arg("id"), py::return_value_policy::move);
        m.def("BeginErrorTooltip", []
              {
                  return BoolCtx(ImGui::BeginErrorTooltip(), [] { ImGui::EndErrorTooltip(); });
              }, py::return_value_policy::move);
        m.def("BeginGroup", []
              {
                  ImGui::BeginGroup();
                  return NoneCtx([] { ImGui::EndGroup(); });
              }, py::return_value_policy::move);
        m.def("BeginItemTooltip", []
              {
                  return BoolCtx(ImGui::BeginItemTooltip(), [] { ImGui::EndTooltip(); });
              }, py::return_value_policy::move);
        m.def("BeginListBox", [](const char *label, const ImVec2 &size)
              {
                  return BoolCtx(ImGui::BeginListBox(label, size), [] { ImGui::EndListBox(); });
              }, py::arg("label").none(false), py::arg("size") = ImVec2(0, 0));
        m.def("BeginMainMenuBar", []
              {
                  return BoolCtx(ImGui::BeginMainMenuBar(), [] { ImGui::EndMainMenuBar(); });
              }, py::return_value_policy::move);
        m.def("BeginMenu", [](const char *label, bool enabled)
              {
                  return BoolCtx(ImGui::BeginMenu(label, enabled), [] { ImGui::EndMenu(); });
              }, py::arg("label").none(false), py::arg("enabled") = true);
        m.def("BeginMenuBar", []
              {
                  return BoolCtx(ImGui::BeginMenuBar(), [] { ImGui::EndMenuBar(); });
              }, py::return_value_policy::move);
        m.def("BeginMenuEx", [](const char *label, const char *icon, bool enabled)
              {
                  return BoolCtx(ImGui::BeginMenuEx(label, icon, enabled), [] { ImGui::EndMenu(); });
              }, py::arg("label").none(false), py::arg("icon"), py::arg("enabled") = true);
        m.def("BeginMultiSelect", [](ImGuiMultiSelectFlags flags, int selection_size, int items_count)
              {
                  py::list ios;
                  ios.append(py::cast(ImGui::BeginMultiSelect(flags, selection_size, items_count), py::return_value_policy::reference));
                  ios.append(py::none());
                  return Ctx(ios, [ios] { ios[1] = py::cast(ImGui::EndMultiSelect(), py::return_value_policy::reference); });
              }, py::arg("flags"), py::arg("selection_size") = -1, py::arg("items_count") = -1);
        m.def("BeginPopup", [](const char *str_id, ImGuiWindowFlags flags)
              {
                  return BoolCtx(ImGui::BeginPopup(str_id, flags), [] { ImGui::EndPopup(); });
              }, py::arg("str_id").none(false), py::arg("flags") = 0);
        m.def("BeginPopupContextItem", [](py::object str_id, ImGuiPopupFlags popup_flags)
              {
                  std::string storage;
                  return BoolCtx(ImGui::BeginPopupContextItem(OptionalCString(str_id, storage), popup_flags), [] { ImGui::EndPopup(); });
              }, py::arg("str_id") = py::none(), py::arg("popup_flags") = 1, py::return_value_policy::move);
        m.def("BeginPopupContextVoid", [](py::object str_id, ImGuiPopupFlags popup_flags)
              {
                  std::string storage;
                  return BoolCtx(ImGui::BeginPopupContextVoid(OptionalCString(str_id, storage), popup_flags), [] { ImGui::EndPopup(); });
              }, py::arg("str_id") = py::none(), py::arg("popup_flags") = 1, py::return_value_policy::move);
        m.def("BeginPopupContextWindow", [](py::object str_id, ImGuiPopupFlags popup_flags)
              {
                  std::string storage;
                  return BoolCtx(ImGui::BeginPopupContextWindow(OptionalCString(str_id, storage), popup_flags), [] { ImGui::EndPopup(); });
              }, py::arg("str_id") = py::none(), py::arg("popup_flags") = 1, py::return_value_policy::move);
        m.def("BeginPopupEx", [](ImGuiID id, ImGuiWindowFlags extra_window_flags)
              {
                  return BoolCtx(ImGui::BeginPopupEx(id, extra_window_flags), [] { ImGui::EndPopup(); });
              }, py::arg("id"), py::arg("extra_window_flags"), py::return_value_policy::move);
        m.def("BeginPopupModal", [](const char *name, std::optional<bool> open, ImGuiWindowFlags flags)
              {
                  bool open_value = open.value_or(true);
                  bool opened = ImGui::BeginPopupModal(name, open ? &open_value : nullptr, flags);
                  return CtxIf(py::make_tuple(opened, open ? open_value : true), opened, [] { ImGui::EndPopup(); });
              }, py::arg("name").none(false), py::arg("p_open") = py::none(), py::arg("flags") = 0);
        m.def("BeginTabBar", [](const char *str_id, ImGuiTabBarFlags flags)
              {
                  return BoolCtx(ImGui::BeginTabBar(str_id, flags), [] { ImGui::EndTabBar(); });
              }, py::arg("str_id").none(false), py::arg("flags") = 0);
        m.def("BeginTabItem", [](const char *label, std::optional<bool> open, ImGuiTabItemFlags flags)
              {
                  bool open_value = open.value_or(true);
                  bool selected = ImGui::BeginTabItem(label, open ? &open_value : nullptr, flags);
                  return CtxIf(py::make_tuple(selected, open ? open_value : true), selected, [] { ImGui::EndTabItem(); });
              }, py::arg("label").none(false), py::arg("p_open") = py::none(), py::arg("flags") = 0);
        m.def("BeginTable", [](const char *str_id, int columns, ImGuiTableFlags flags, const ImVec2 &outer_size, float inner_width)
              {
                  CheckTableColumns(columns);
                  return BoolCtx(ImGui::BeginTable(str_id, columns, flags, outer_size, inner_width), [] { ImGui::EndTable(); });
              }, py::arg("str_id").none(false), py::arg("columns"), py::arg("flags") = 0, py::arg("outer_size") = ImVec2(0, 0), py::arg("inner_width") = 0.0f);
        m.def("BeginTableEx", [](const char *name, ImGuiID id, int columns_count, ImGuiTableFlags flags, const ImVec2 &outer_size, float inner_width)
              {
                  CheckTableColumns(columns_count);
                  return BoolCtx(ImGui::BeginTableEx(name, id, columns_count, flags, outer_size, inner_width), [] { ImGui::EndTable(); });
              }, py::arg("name").none(false), py::arg("id"), py::arg("columns_count"), py::arg("flags") = 0, py::arg("outer_size") = ImVec2(0, 0), py::arg("inner_width") = 0.0f);
        m.def("BeginTooltip", []
              {
                  return BoolCtx(ImGui::BeginTooltip(), [] { ImGui::EndTooltip(); });
              }, py::return_value_policy::move);
        m.def("BeginTooltipEx", [](ImGuiTooltipFlags tooltip_flags, ImGuiWindowFlags extra_window_flags)
              {
                  return BoolCtx(ImGui::BeginTooltipEx(tooltip_flags, extra_window_flags), [] { ImGui::EndTooltip(); });
              }, py::arg("tooltip_flags"), py::arg("extra_window_flags"), py::return_value_policy::move);
        m.def("BeginTooltipHidden", []
              {
                  return Ctx(py::cast(ImGui::BeginTooltipHidden()), [] { ImGui::EndTooltip(); });
              });
        m.def("BeginViewportSideBar", [](const char *name, ImGuiViewport *viewport, int dir, float size, ImGuiWindowFlags window_flags)
              {
                  bool visible = ImGui::BeginViewportSideBar(name, viewport, static_cast<ImGuiDir>(dir), size, window_flags);
                  return Ctx(py::cast(visible), [] { ImGui::End(); });
              }, py::arg("name").none(false), py::arg("viewport"), py::arg("dir"), py::arg("size"), py::arg("window_flags"));

        m.def("DrawListChannels", [](ImDrawList *draw_list, int count)
              {
                  if (count < 1)
                      _throwV_("DrawListChannels: count must be >= 1, got {}", count);
                  if (draw_list->_Splitter._Count > 1 || draw_list->_Splitter._Current != 0)
                      _throw_("DrawListChannels: nested channel splitting is not supported");
                  draw_list->ChannelsSplit(count);
                  return NoneCtx([draw_list] { draw_list->ChannelsMerge(); });
              }, py::arg("draw_list").none(false), py::arg("count"));
        m.def("DrawListClipRect", [](ImDrawList *draw_list, const ImVec2 &clip_rect_min, const ImVec2 &clip_rect_max, bool intersect_with_current_clip_rect)
              {
                  draw_list->PushClipRect(clip_rect_min, clip_rect_max, intersect_with_current_clip_rect);
                  return NoneCtx([draw_list] { draw_list->PopClipRect(); });
              }, py::arg("draw_list").none(false), py::arg("clip_rect_min"), py::arg("clip_rect_max"), py::arg("intersect_with_current_clip_rect") = false);
        m.def("DrawListClipRectFullScreen", [](ImDrawList *draw_list)
              {
                  draw_list->PushClipRectFullScreen();
                  return NoneCtx([draw_list] { draw_list->PopClipRect(); });
              }, py::arg("draw_list").none(false));
        m.def("DrawListTextureID", [](ImDrawList *draw_list, ImTextureID texture_id)
              {
                  draw_list->PushTextureID(texture_id);
                  return NoneCtx([draw_list] { draw_list->PopTextureID(); });
              }, py::arg("draw_list").none(false), py::arg("texture_id"));

        m.def("Indent", [](float indent_w)
              {
                  float width = indent_w != 0.0f ? indent_w : ImGui::GetStyle().IndentSpacing;
                  ImGui::Indent(width);
                  return NoneCtx([width] { ImGui::Unindent(width); });
              }, py::arg("indent_w") = 0.0f);

        m.def("LogToBuffer", [](int auto_open_depth)
              {
                  return LogCtx([=] { ImGui::LogToBuffer(auto_open_depth); });
              }, py::arg("auto_open_depth") = -1);
        m.def("LogToClipboard", [](int auto_open_depth)
              {
                  return LogCtx([=] { ImGui::LogToClipboard(auto_open_depth); });
              }, py::arg("auto_open_depth") = -1);
        m.def("LogToFile", [](int auto_open_depth, std::optional<std::string> filename)
              {
                  return LogCtx([&] { ImGui::LogToFile(auto_open_depth, filename ? filename->c_str() : nullptr); });
              }, py::arg("auto_open_depth") = -1, py::arg("filename") = py::none());
        m.def("LogToTTY", [](int auto_open_depth)
              {
                  return LogCtx([=] { ImGui::LogToTTY(auto_open_depth); });
              }, py::arg("auto_open_depth") = -1);

        m.def("PushAllowKeyboardFocus", [](bool tab_stop)
              {
                  ImGui::PushAllowKeyboardFocus(tab_stop);
                  return NoneCtx([] { ImGui::PopAllowKeyboardFocus(); });
              }, py::arg("tab_stop"), py::return_value_policy::move);
        m.def("PushButtonRepeat", [](bool repeat)
              {
                  ImGui::PushButtonRepeat(repeat);
                  return NoneCtx([] { ImGui::PopButtonRepeat(); });
              }, py::arg("repeat"), py::return_value_policy::move);
        m.def("PushClipRect", [](const ImVec2 &clip_rect_min, const ImVec2 &clip_rect_max, bool intersect_with_current_clip_rect)
              {
                  ImGui::PushClipRect(clip_rect_min, clip_rect_max, intersect_with_current_clip_rect);
                  return NoneCtx([] { ImGui::PopClipRect(); });
              }, py::arg("clip_rect_min"), py::arg("clip_rect_max"), py::arg("intersect_with_current_clip_rect"), py::return_value_policy::move);
        m.def("PushColumnClipRect", [](int column_index)
              {
                  CheckColumns("PushColumnClipRect");
                  ImGui::PushColumnClipRect(column_index);
                  return NoneCtx([] { ImGui::PopClipRect(); });
              }, py::arg("column_index"));
        m.def("PushColumnsBackground", []
              {
                  CheckColumns("PushColumnsBackground");
                  ImGui::PushColumnsBackground();
                  return NoneCtx([] { ImGui::PopColumnsBackground(); });
              });
        m.def("PushFocusScope", [](ImGuiID id)
              {
                  ImGui::PushFocusScope(id);
                  return NoneCtx([] { ImGui::PopFocusScope(); });
              }, py::arg("id"), py::return_value_policy::move);
        m.def("PushFont", [](ImFont *font)
              {
                  ImGui::PushFont(font);
                  return NoneCtx([] { ImGui::PopFont(); });
              }, py::arg("font"), py::return_value_policy::move);
        m.def("PushID", [](const char *str_id)
              {
                  ImGui::PushID(str_id);
                  return NoneCtx([] { ImGui::PopID(); });
              }, py::arg("str_id").none(false));
        m.def("PushID", [](int int_id)
              {
                  ImGui::PushID(int_id);
                  return NoneCtx([] { ImGui::PopID(); });
              }, py::arg("int_id"));
        // Last, so that small ints keep the int overload; takes 64-bit ints, Pointer and ctypes objects.
        m.def("PushID", [](py::object ptr_id)
              {
                  ImGui::PushID(reinterpret_cast<const void *>(PYIMGUI_CORE_NAMESPACE::pyimgui_address_from_object(ptr_id)));
                  return NoneCtx([] { ImGui::PopID(); });
              }, py::arg("ptr_id").none(false));
        m.def("PushItemFlag", [](ImGuiItemFlags option, bool enabled)
              {
                  ImGui::PushItemFlag(option, enabled);
                  return NoneCtx([] { ImGui::PopItemFlag(); });
              }, py::arg("option"), py::arg("enabled"), py::return_value_policy::move);
        m.def("PushItemWidth", [](float item_width)
              {
                  ImGui::PushItemWidth(item_width);
                  return NoneCtx([] { ImGui::PopItemWidth(); });
              }, py::arg("item_width"), py::return_value_policy::move);
        m.def("PushMultiItemsWidths", [](int components, float width_full)
              {
                  if (components <= 0)
                      _throwV_("PushMultiItemsWidths: components must be > 0, got {}", components);
                  ImGui::PushMultiItemsWidths(components, width_full);
                  auto remaining = std::make_shared<int>(components);
                  py::cpp_function pop_next([remaining]
                                            {
                                                if (*remaining > 0)
                                                {
                                                    ImGui::PopItemWidth();
                                                    --*remaining;
                                                }
                                            });
                  return Ctx(pop_next, [remaining]
                             {
                                 for (; *remaining > 0; --*remaining)
                                     ImGui::PopItemWidth();
                             });
              }, py::arg("components"), py::arg("width_full"));
        m.def("PushOverrideID", [](ImGuiID id)
              {
                  ImGui::PushOverrideID(id);
                  return NoneCtx([] { ImGui::PopID(); });
              }, py::arg("id"), py::return_value_policy::move);
        m.def("PushStyleColor", [](ImGuiCol idx, ImU32 col)
              {
                  CheckStyleColor(idx);
                  ImGui::PushStyleColor(idx, col);
                  return NoneCtx([] { ImGui::PopStyleColor(); });
              }, py::arg("idx"), py::arg("col"));
        m.def("PushStyleColor", [](ImGuiCol idx, const ImVec4 &col)
              {
                  CheckStyleColor(idx);
                  ImGui::PushStyleColor(idx, col);
                  return NoneCtx([] { ImGui::PopStyleColor(); });
              }, py::arg("idx"), py::arg("col"));
        m.def("PushStyleVar", [](ImGuiStyleVar idx, float val)
              {
                  CheckStyleVar(idx, 1);
                  ImGui::PushStyleVar(idx, val);
                  return NoneCtx([] { ImGui::PopStyleVar(); });
              }, py::arg("idx"), py::arg("val"));
        m.def("PushStyleVar", [](ImGuiStyleVar idx, const ImVec2 &val)
              {
                  CheckStyleVar(idx, 2);
                  ImGui::PushStyleVar(idx, val);
                  return NoneCtx([] { ImGui::PopStyleVar(); });
              }, py::arg("idx"), py::arg("val"));
        m.def("PushStyleVarX", [](ImGuiStyleVar idx, float val_x)
              {
                  CheckStyleVar(idx, 2);
                  ImGui::PushStyleVarX(idx, val_x);
                  return NoneCtx([] { ImGui::PopStyleVar(); });
              }, py::arg("idx"), py::arg("val_x"));
        m.def("PushStyleVarY", [](ImGuiStyleVar idx, float val_y)
              {
                  CheckStyleVar(idx, 2);
                  ImGui::PushStyleVarY(idx, val_y);
                  return NoneCtx([] { ImGui::PopStyleVar(); });
              }, py::arg("idx"), py::arg("val_y"));
        m.def("PushTabStop", [](bool tab_stop)
              {
                  ImGui::PushTabStop(tab_stop);
                  return NoneCtx([] { ImGui::PopTabStop(); });
              }, py::arg("tab_stop"), py::return_value_policy::move);
        m.def("PushTextWrapPos", [](float wrap_local_pos_x)
              {
                  ImGui::PushTextWrapPos(wrap_local_pos_x);
                  return NoneCtx([] { ImGui::PopTextWrapPos(); });
              }, py::arg("wrap_local_pos_x") = 0.0f, py::return_value_policy::move);

        m.def("TreeNode", [](const char *label)
              {
                  return TreeNodeCtx(ImGui::TreeNode(label), ImGuiTreeNodeFlags_None);
              }, py::arg("label").none(false));
        m.def("TreeNodeEx", [](const char *label, ImGuiTreeNodeFlags flags)
              {
                  return TreeNodeCtx(ImGui::TreeNodeEx(label, flags), flags);
              }, py::arg("label").none(false), py::arg("flags") = 0);
        m.def("TreePush", [](const char *str_id)
              {
                  ImGui::TreePush(str_id);
                  return NoneCtx([] { ImGui::TreePop(); });
              }, py::arg("str_id").none(false));
        m.def("TreePush", [](py::object ptr_id)
              {
                  ImGui::TreePush(reinterpret_cast<const void *>(PYIMGUI_CORE_NAMESPACE::pyimgui_address_from_object(ptr_id)));
                  return NoneCtx([] { ImGui::TreePop(); });
              }, py::arg("ptr_id").none(false));
    }
}
END_IMGUI_CTX_NAMESPACE