#include <pybind11/pybind11.h>

/*START:__GLOBAL_EXTRA__*/
static int pyimgui_input_text_callback(ImGuiInputTextCallbackData* data)
{
    auto value = static_cast<std::string*>(data->UserData);
    if (data->EventFlag == ImGuiInputTextFlags_CallbackResize)
    {
        value->resize(data->BufTextLen);
        data->Buf = value->data();
    }
    return 0;
}

static bool pyimgui_show_optional_window(void (*func)(bool*), bool is_open)
{
    bool open = is_open;
    func(&open);
    return open;
}
/*END:__GLOBAL_EXTRA__*/

/*START:__STRUCTS_EXTRA__*/
struct GlyphRanges
{
    const ImWchar* ranges = nullptr;

    std::vector<ImWchar> ToList() const
    {
        std::vector<ImWchar> result;
        if (!this->ranges)
            return result;
        for (const ImWchar* cursor = this->ranges; *cursor; ++cursor)
            result.push_back(*cursor);
        return result;
    }
};
/*END:__STRUCTS_EXTRA__*/

void _(py::module_ m)
{
    /*START:__GLOBAL_DEF_EXTRA__*/
    /*END:__GLOBAL_DEF_EXTRA__*/

    /*START:__STRUCTS_DEF_EXTRA__*/
    py::class_<PyImVectorBase>(m, "ImVector", py::dynamic_attr())
        .def_static("__class_getitem__", [](py::object) { return py::type::of<PyImVectorBase>(); });

    py::class_<GlyphRanges>(m, "GlyphRanges", py::dynamic_attr())
        .def("ToList", &GlyphRanges::ToList);
    /*END:__STRUCTS_DEF_EXTRA__*/
}

/*START:_CLS_EXTRA_:ImVec2*/
    .def(py::init<>())
    .def(py::init<float, float>(), py::arg("x"), py::arg("y"))
    .def("__repr__", [](const ImVec2& self) { return std::format("ImVec2({}, {})", self.x, self.y); })
/*END:_CLS_EXTRA_:ImVec2*/

/*START:_CLS_EXTRA_:ImVec4*/
    .def(py::init<>())
    .def(py::init<float, float, float, float>(), py::arg("x"), py::arg("y"), py::arg("z"), py::arg("w"))
    .def("__repr__", [](const ImVec4& self) { return std::format("ImVec4({}, {}, {}, {})", self.x, self.y, self.z, self.w); })
/*END:_CLS_EXTRA_:ImVec4*/

/*START:_CLS_EXTRA_:ImGuiWindowClass*/
    .def(py::init<>())
/*END:_CLS_EXTRA_:ImGuiWindowClass*/

/*START:_CLS_EXTRA_:ImFontAtlas*/
    .def("GetGlyphRangesChineseFull", [](ImFontAtlas& self) { return GlyphRanges{self.GetGlyphRangesChineseFull()}; })
    .def("GetGlyphRangesChineseSimplifiedCommon", [](ImFontAtlas& self) { return GlyphRanges{self.GetGlyphRangesChineseSimplifiedCommon()}; })
    .def("GetGlyphRangesCyrillic", [](ImFontAtlas& self) { return GlyphRanges{self.GetGlyphRangesCyrillic()}; })
    .def("GetGlyphRangesDefault", [](ImFontAtlas& self) { return GlyphRanges{self.GetGlyphRangesDefault()}; })
    .def("GetGlyphRangesGreek", [](ImFontAtlas& self) { return GlyphRanges{self.GetGlyphRangesGreek()}; })
    .def("GetGlyphRangesJapanese", [](ImFontAtlas& self) { return GlyphRanges{self.GetGlyphRangesJapanese()}; })
    .def("GetGlyphRangesKorean", [](ImFontAtlas& self) { return GlyphRanges{self.GetGlyphRangesKorean()}; })
    .def("GetGlyphRangesThai", [](ImFontAtlas& self) { return GlyphRanges{self.GetGlyphRangesThai()}; })
    .def("GetGlyphRangesVietnamese", [](ImFontAtlas& self) { return GlyphRanges{self.GetGlyphRangesVietnamese()}; })
/*END:_CLS_EXTRA_:ImFontAtlas*/

/*START:_MFUNC_:ImFontAtlas::AddFontFromFileTTF*/
        .def("AddFontFromFileTTF", [](ImFontAtlas& self, const char* filename, float size_pixels, py::object font_cfg, py::object glyph_ranges) {
            const ImWchar* ranges = nullptr;
            if (!glyph_ranges.is_none())
            {
                if (py::isinstance<GlyphRanges>(glyph_ranges))
                    ranges = glyph_ranges.cast<GlyphRanges>().ranges;
                else
                    ranges = reinterpret_cast<const ImWchar*>(pyimgui_address_from_object(glyph_ranges));
            }
            // Honour the caller's ImFontConfig (MergeMode, PixelSnapH, etc.).
            // pyimgui_ptr_from_object returns nullptr when font_cfg is None.
            const ImFontConfig* cfg = pyimgui_ptr_from_object<ImFontConfig>(font_cfg);
            return self.AddFontFromFileTTF(filename, size_pixels, cfg, ranges);
        }, py::arg("filename"), py::arg("size_pixels"), py::arg("font_cfg") = py::none(), py::arg("glyph_ranges") = py::none(), py::return_value_policy::reference)
/*END:_MFUNC_:ImFontAtlas::AddFontFromFileTTF*/

/*START:_CLS_EXTRA_:ImDrawList*/
    .def("AddRect", [](ImDrawList& self, const ImVec2& p_min, const ImVec2& p_max, ImU32 col, float rounding, ImDrawFlags flags, float thickness) {
        self.AddRect(p_min, p_max, col, rounding, flags, thickness);
    }, py::arg("p_min"), py::arg("p_max"), py::arg("col"), py::arg("rounding") = 0.0f, py::arg("flags") = 0, py::arg("thickness") = 1.0f)
/*END:_CLS_EXTRA_:ImDrawList*/

/*START:_GFUNC_:Begin*/
    m.def("Begin", [](const char* name, bool open, ImGuiWindowFlags flags) {
        bool is_open = open;
        bool visible = ImGui::Begin(name, &is_open, flags);
        return py::make_tuple(visible, is_open);
    }, py::arg("name") = "", py::arg("open") = true, py::arg("flags") = 0);
/*END:_GFUNC_:Begin*/

/*START:_GFUNC_:Button*/
    m.def("Button", [](const char* label, const ImVec2& size) { return ImGui::Button(label, size); }, py::arg("label"), py::arg("size") = ImVec2(0, 0));
/*END:_GFUNC_:Button*/

/*START:_GFUNC_:CalcTextSize*/
    m.def("CalcTextSize", [](const char* text, const char* text_end, bool hide_text_after_double_hash, float wrap_width) {
        return ImGui::CalcTextSize(text, text_end, hide_text_after_double_hash, wrap_width);
    }, py::arg("text"), py::arg("text_end") = nullptr, py::arg("hide_text_after_double_hash") = false, py::arg("wrap_width") = -1.0f);
/*END:_GFUNC_:CalcTextSize*/

/*START:_GFUNC_:Checkbox*/
    m.def("Checkbox", [](const char* label, bool value) {
        bool changed = ImGui::Checkbox(label, &value);
        return py::make_tuple(changed, value);
    }, py::arg("label"), py::arg("v") = false);
/*END:_GFUNC_:Checkbox*/

/*START:_GFUNC_:CollapsingHeader*/
    m.def("CollapsingHeader", [](const char* label, ImGuiTreeNodeFlags flags) { return ImGui::CollapsingHeader(label, flags); }, py::arg("label"), py::arg("flags") = 0);
/*END:_GFUNC_:CollapsingHeader*/

/*START:_GFUNC_:ColorEdit4*/
    m.def("ColorEdit4", [](const char* label, ImVec4 color, ImGuiColorEditFlags flags) {
        bool changed = ImGui::ColorEdit4(label, &color.x, flags);
        return py::make_tuple(changed, color);
    }, py::arg("label"), py::arg("color"), py::arg("flags") = 0);
/*END:_GFUNC_:ColorEdit4*/

/*START:_GFUNC_:Image*/
    m.def("Image", [](uintptr_t texture_id, const ImVec2& image_size, const ImVec2& uv0, const ImVec2& uv1, const ImVec4& tint_col, const ImVec4& border_col) {
        ImGui::Image((ImTextureID)texture_id, image_size, uv0, uv1, tint_col, border_col);
    }, py::arg("user_texture_id"), py::arg("image_size"), py::arg("uv0") = ImVec2(0, 0), py::arg("uv1") = ImVec2(1, 1), py::arg("tint_col") = ImVec4(1, 1, 1, 1), py::arg("border_col") = ImVec4(0, 0, 0, 0));
/*END:_GFUNC_:Image*/

/*START:_GFUNC_:ImageButton*/
    m.def("ImageButton", [](const char* str_id, uintptr_t texture_id, const ImVec2& image_size, const ImVec2& uv0, const ImVec2& uv1, const ImVec4& bg_col, const ImVec4& tint_col) {
        return ImGui::ImageButton(str_id, (ImTextureID)texture_id, image_size, uv0, uv1, bg_col, tint_col);
    }, py::arg("str_id"), py::arg("user_texture_id"), py::arg("image_size"), py::arg("uv0") = ImVec2(0, 0), py::arg("uv1") = ImVec2(1, 1), py::arg("bg_col") = ImVec4(0, 0, 0, 0), py::arg("tint_col") = ImVec4(1, 1, 1, 1));
/*END:_GFUNC_:ImageButton*/

/*START:_GFUNC_:InputText*/
    m.def("InputText", [](const char* label, std::string value, ImGuiInputTextFlags flags) {
        flags |= ImGuiInputTextFlags_CallbackResize;
        value.reserve(std::max<size_t>(value.size() + 1024, 4096));
        bool changed = ImGui::InputText(label, value.data(), value.capacity() + 1, flags, pyimgui_input_text_callback, &value);
        return py::make_tuple(changed, value);
    }, py::arg("label"), py::arg("value") = "", py::arg("flags") = 0);
/*END:_GFUNC_:InputText*/

/*START:_GFUNC_:ProgressBar*/
    m.def("ProgressBar", [](float fraction, const ImVec2& size_arg, const char* overlay) { ImGui::ProgressBar(fraction, size_arg, overlay); }, py::arg("fraction"), py::arg("size_arg") = ImVec2(-FLT_MIN, 0), py::arg("overlay") = nullptr);
/*END:_GFUNC_:ProgressBar*/

/*START:_GFUNC_:SameLine*/
    m.def("SameLine", [](float offset_from_start_x, float spacing) { ImGui::SameLine(offset_from_start_x, spacing); }, py::arg("offset_from_start_x") = 0.0f, py::arg("spacing") = -1.0f);
/*END:_GFUNC_:SameLine*/

/*START:_GFUNC_:Selectable*/
    m.def("Selectable", [](const char* label, bool selected, ImGuiSelectableFlags flags, const ImVec2& size) { return ImGui::Selectable(label, selected, flags, size); }, py::arg("label"), py::arg("selected") = false, py::arg("flags") = 0, py::arg("size") = ImVec2(0, 0));
/*END:_GFUNC_:Selectable*/

/*START:_GFUNC_:SetNextWindowClass*/
    m.def("SetNextWindowClass", [](const ImGuiWindowClass& window_class) { ImGui::SetNextWindowClass(&window_class); }, py::arg("window_class"));
/*END:_GFUNC_:SetNextWindowClass*/

/*START:_GFUNC_:SetNextWindowPos*/
    m.def("SetNextWindowPos", [](const ImVec2& pos, ImGuiCond cond, const ImVec2& pivot) { ImGui::SetNextWindowPos(pos, cond, pivot); }, py::arg("pos"), py::arg("cond") = 0, py::arg("pivot") = ImVec2(0, 0));
/*END:_GFUNC_:SetNextWindowPos*/

/*START:_GFUNC_:SetNextWindowSize*/
    m.def("SetNextWindowSize", [](const ImVec2& size, ImGuiCond cond) { ImGui::SetNextWindowSize(size, cond); }, py::arg("size"), py::arg("cond") = 0);
/*END:_GFUNC_:SetNextWindowSize*/

/*START:_GFUNC_:ShowAboutWindow*/
    m.def("ShowAboutWindow", [](bool is_open) { return pyimgui_show_optional_window(ImGui::ShowAboutWindow, is_open); }, py::arg("is_open") = true);
/*END:_GFUNC_:ShowAboutWindow*/

/*START:_GFUNC_:ShowDebugLogWindow*/
    m.def("ShowDebugLogWindow", [](bool is_open) { return pyimgui_show_optional_window(ImGui::ShowDebugLogWindow, is_open); }, py::arg("is_open") = true);
/*END:_GFUNC_:ShowDebugLogWindow*/

/*START:_GFUNC_:ShowDemoWindow*/
    m.def("ShowDemoWindow", [](bool is_open) { return pyimgui_show_optional_window(ImGui::ShowDemoWindow, is_open); }, py::arg("is_open") = true);
/*END:_GFUNC_:ShowDemoWindow*/

/*START:_GFUNC_:ShowIDStackToolWindow*/
    m.def("ShowIDStackToolWindow", [](bool is_open) { return pyimgui_show_optional_window(ImGui::ShowIDStackToolWindow, is_open); }, py::arg("is_open") = true);
/*END:_GFUNC_:ShowIDStackToolWindow*/

/*START:_GFUNC_:ShowMetricsWindow*/
    m.def("ShowMetricsWindow", [](bool is_open) { return pyimgui_show_optional_window(ImGui::ShowMetricsWindow, is_open); }, py::arg("is_open") = true);
/*END:_GFUNC_:ShowMetricsWindow*/

/*START:_GFUNC_:TableNextColumn*/
    m.def("TableNextColumn", []() { return ImGui::TableNextColumn(); });
/*END:_GFUNC_:TableNextColumn*/

/*START:_GFUNC_:TableNextRow*/
    m.def("TableNextRow", [](ImGuiTableRowFlags row_flags, float min_row_height) { ImGui::TableNextRow(row_flags, min_row_height); }, py::arg("row_flags") = 0, py::arg("min_row_height") = 0.0f);
/*END:_GFUNC_:TableNextRow*/

/*START:_GFUNC_:Text*/
    m.def("Text", [](const char* text) { ImGui::TextUnformatted(text ? text : ""); }, py::arg("text") = "");
/*END:_GFUNC_:Text*/

/*START:_GFUNC_:TextColored*/
    m.def("TextColored", [](const ImVec4& color, const char* text) { ImGui::TextColored(color, "%s", text ? text : ""); }, py::arg("color"), py::arg("text") = "");
/*END:_GFUNC_:TextColored*/

/*START:_GFUNC_:TextDisabled*/
    m.def("TextDisabled", [](const char* text) { ImGui::TextDisabled("%s", text ? text : ""); }, py::arg("text") = "");
/*END:_GFUNC_:TextDisabled*/

/*START:_GFUNC_:TextWrapped*/
    m.def("TextWrapped", [](const char* text) { ImGui::TextWrapped("%s", text ? text : ""); }, py::arg("text") = "");
/*END:_GFUNC_:TextWrapped*/