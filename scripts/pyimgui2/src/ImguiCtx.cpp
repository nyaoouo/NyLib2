#include "./ImguiCtx.h"

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
              }, py::arg("name") = "", py::arg("open") = py::none(), py::arg("flags") = 0, py::return_value_policy::move);
        m.def("BeginChild", [](const char *str_id, const ImVec2 &size, ImGuiChildFlags child_flags, ImGuiWindowFlags window_flags)
              {
                  bool visible = ImGui::BeginChild(str_id, size, child_flags, window_flags);
                  return Ctx(py::cast(visible), [] { ImGui::EndChild(); });
              }, py::arg("str_id"), py::arg("size") = ImVec2(0, 0), py::arg("child_flags") = 0, py::arg("window_flags") = 0, py::return_value_policy::move);
        m.def("BeginChild", [](ImGuiID id, const ImVec2 &size, ImGuiChildFlags child_flags, ImGuiWindowFlags window_flags)
              {
                  bool visible = ImGui::BeginChild(id, size, child_flags, window_flags);
                  return Ctx(py::cast(visible), [] { ImGui::EndChild(); });
              }, py::arg("id"), py::arg("size") = ImVec2(0, 0), py::arg("child_flags") = 0, py::arg("window_flags") = 0, py::return_value_policy::move);
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
              }, py::arg("label"), py::arg("preview_value"), py::arg("flags") = 0, py::return_value_policy::move);
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
                  ImGui::BeginDisabledOverrideReenable();
                  return NoneCtx([] { ImGui::EndDisabledOverrideReenable(); });
              }, py::return_value_policy::move);
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
              }, py::arg("label"), py::arg("size") = ImVec2(0, 0), py::return_value_policy::move);
        m.def("BeginMainMenuBar", []
              {
                  return BoolCtx(ImGui::BeginMainMenuBar(), [] { ImGui::EndMainMenuBar(); });
              }, py::return_value_policy::move);
        m.def("BeginMenu", [](const char *label, bool enabled)
              {
                  return BoolCtx(ImGui::BeginMenu(label, enabled), [] { ImGui::EndMenu(); });
              }, py::arg("label"), py::arg("enabled") = true, py::return_value_policy::move);
        m.def("BeginMenuBar", []
              {
                  return BoolCtx(ImGui::BeginMenuBar(), [] { ImGui::EndMenuBar(); });
              }, py::return_value_policy::move);
        m.def("BeginMenuEx", [](const char *label, const char *icon, bool enabled)
              {
                  return BoolCtx(ImGui::BeginMenuEx(label, icon, enabled), [] { ImGui::EndMenu(); });
              }, py::arg("label"), py::arg("icon"), py::arg("enabled") = true, py::return_value_policy::move);
        m.def("BeginMultiSelect", [](ImGuiMultiSelectFlags flags, int selection_size, int items_count)
              {
                  auto *io = ImGui::BeginMultiSelect(flags, selection_size, items_count);
                  return Ctx(py::cast(io, py::return_value_policy::reference), [] { ImGui::EndMultiSelect(); });
              }, py::arg("flags"), py::arg("selection_size") = -1, py::arg("items_count") = -1, py::return_value_policy::move);
        m.def("BeginPopup", [](const char *str_id, ImGuiWindowFlags flags)
              {
                  return BoolCtx(ImGui::BeginPopup(str_id, flags), [] { ImGui::EndPopup(); });
              }, py::arg("str_id"), py::arg("flags") = 0, py::return_value_policy::move);
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
              }, py::arg("name"), py::arg("p_open") = py::none(), py::arg("flags") = 0, py::return_value_policy::move);
        m.def("BeginTabBar", [](const char *str_id, ImGuiTabBarFlags flags)
              {
                  return BoolCtx(ImGui::BeginTabBar(str_id, flags), [] { ImGui::EndTabBar(); });
              }, py::arg("str_id"), py::arg("flags") = 0, py::return_value_policy::move);
        m.def("BeginTabItem", [](const char *label, std::optional<bool> open, ImGuiTabItemFlags flags)
              {
                  bool open_value = open.value_or(true);
                  bool selected = ImGui::BeginTabItem(label, open ? &open_value : nullptr, flags);
                  return CtxIf(py::make_tuple(selected, open ? open_value : true), selected, [] { ImGui::EndTabItem(); });
              }, py::arg("label"), py::arg("p_open") = py::none(), py::arg("flags") = 0, py::return_value_policy::move);
        m.def("BeginTable", [](const char *str_id, int columns, ImGuiTableFlags flags, const ImVec2 &outer_size, float inner_width)
              {
                  return BoolCtx(ImGui::BeginTable(str_id, columns, flags, outer_size, inner_width), [] { ImGui::EndTable(); });
              }, py::arg("str_id"), py::arg("columns"), py::arg("flags") = 0, py::arg("outer_size") = ImVec2(0, 0), py::arg("inner_width") = 0.0f, py::return_value_policy::move);
        m.def("BeginTableEx", [](const char *name, ImGuiID id, int columns_count, ImGuiTableFlags flags, const ImVec2 &outer_size, float inner_width)
              {
                  return BoolCtx(ImGui::BeginTableEx(name, id, columns_count, flags, outer_size, inner_width), [] { ImGui::EndTable(); });
              }, py::arg("name"), py::arg("id"), py::arg("columns_count"), py::arg("flags") = 0, py::arg("outer_size") = ImVec2(0, 0), py::arg("inner_width") = 0.0f, py::return_value_policy::move);
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
                  return BoolCtx(ImGui::BeginTooltipHidden(), [] { ImGui::EndTooltip(); });
              }, py::return_value_policy::move);

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
                  ImGui::PushColumnClipRect(column_index);
                  return NoneCtx([] { ImGui::PopClipRect(); });
              }, py::arg("column_index"), py::return_value_policy::move);
        m.def("PushColumnsBackground", []
              {
                  ImGui::PushColumnsBackground();
                  return NoneCtx([] { ImGui::PopColumnsBackground(); });
              }, py::return_value_policy::move);
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
              }, py::arg("str_id"), py::return_value_policy::move);
        m.def("PushID", [](const char *str_id_begin, const char *str_id_end)
              {
                  ImGui::PushID(str_id_begin, str_id_end);
                  return NoneCtx([] { ImGui::PopID(); });
              }, py::arg("str_id_begin"), py::arg("str_id_end"), py::return_value_policy::move);
        m.def("PushID", [](int int_id)
              {
                  ImGui::PushID(int_id);
                  return NoneCtx([] { ImGui::PopID(); });
              }, py::arg("int_id"), py::return_value_policy::move);
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
                  ImGui::PushMultiItemsWidths(components, width_full);
                  return NoneCtx([components]
                                 {
                                     for (int i = 0; i < components; i++)
                                         ImGui::PopItemWidth();
                                 });
              }, py::arg("components"), py::arg("width_full"), py::return_value_policy::move);
        m.def("PushOverrideID", [](ImGuiID id)
              {
                  ImGui::PushOverrideID(id);
                  return NoneCtx([] { ImGui::PopID(); });
              }, py::arg("id"), py::return_value_policy::move);
        m.def("PushStyleColor", [](ImGuiCol idx, ImU32 col)
              {
                  ImGui::PushStyleColor(idx, col);
                  return NoneCtx([] { ImGui::PopStyleColor(); });
              }, py::arg("idx"), py::arg("col"), py::return_value_policy::move);
        m.def("PushStyleColor", [](ImGuiCol idx, const ImVec4 &col)
              {
                  ImGui::PushStyleColor(idx, col);
                  return NoneCtx([] { ImGui::PopStyleColor(); });
              }, py::arg("idx"), py::arg("col"), py::return_value_policy::move);
        m.def("PushStyleVar", [](ImGuiStyleVar idx, float val)
              {
                  ImGui::PushStyleVar(idx, val);
                  return NoneCtx([] { ImGui::PopStyleVar(); });
              }, py::arg("idx"), py::arg("val"), py::return_value_policy::move);
        m.def("PushStyleVar", [](ImGuiStyleVar idx, const ImVec2 &val)
              {
                  ImGui::PushStyleVar(idx, val);
                  return NoneCtx([] { ImGui::PopStyleVar(); });
              }, py::arg("idx"), py::arg("val"), py::return_value_policy::move);
        m.def("PushStyleVarX", [](ImGuiStyleVar idx, float val_x)
              {
                  ImGui::PushStyleVarX(idx, val_x);
                  return NoneCtx([] { ImGui::PopStyleVar(); });
              }, py::arg("idx"), py::arg("val_x"), py::return_value_policy::move);
        m.def("PushStyleVarY", [](ImGuiStyleVar idx, float val_y)
              {
                  ImGui::PushStyleVarY(idx, val_y);
                  return NoneCtx([] { ImGui::PopStyleVar(); });
              }, py::arg("idx"), py::arg("val_y"), py::return_value_policy::move);
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
    }
}
END_IMGUI_CTX_NAMESPACE