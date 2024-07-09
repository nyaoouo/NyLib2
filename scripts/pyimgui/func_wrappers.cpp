#include <pybind11/pybind11.h>

/*START:__GLOBAL_EXTRA__*/
static int mImguiInputTextCallback(ImGuiInputTextCallbackData *data)
{
     auto userStr = (std::string *)data->UserData;
     if (data->EventFlag == ImGuiInputTextFlags_CallbackResize)
     {
          userStr->resize(data->BufTextLen);
          data->Buf = (char *)userStr->c_str();
     }
     return 0;
}
/*END:__GLOBAL_EXTRA__*/

/*START:__STRUCTS_EXTRA__*/
template <typename T>
struct PyArrayWrapper
{
    T *data;
    size_t size;

    PyArrayWrapper(T *data, size_t size)
    {
        this->data = data;
        this->size = size;
    }

    inline T &operator[](size_t i)
    {
        if (i >= this->size)
            _throwV_("Index out of range: {} >= {}", i, this->size);
        return this->data[i];
    }

    static inline void pybind_setup(py::module_ m, const char *name)
    {
        py::class_<PyArrayWrapper<T>>(m, name)
            .def("__getitem__", [](PyArrayWrapper<T> &self, size_t i) { return self[i]; })
            .def("__setitem__", [](PyArrayWrapper<T> &self, size_t i, T v) { self[i] = v; })
            .def("__len__", [](PyArrayWrapper<T> &self) { return self.size; })
            .def("__iter__", [](PyArrayWrapper<T> &self) { return py::make_iterator(self.data, self.data + self.size); });
    }
};
/*END:__STRUCTS_EXTRA__*/

void _(py::module &m)
{
     /*START:__GLOBAL_DEF_EXTRA__*/
     /*END:__GLOBAL_DEF_EXTRA__*/
     /*START:__STRUCTS_DEF_EXTRA__*/
     /*END:__STRUCTS_DEF_EXTRA__*/
     m
     /*START:_CLS_FIELD_:ImGuiViewportP::_ImGuiViewport*/
     .def_property_readonly("_ImGuiViewport", [](ImGuiViewportP &self) { return (ImGuiViewport *)&self; })
     /*END:_CLS_FIELD_:ImGuiViewportP::_ImGuiViewport*/

         /*START:_GFUNC_:igText*/
         .def("Text", [](const char *s)
              { return igText(s); }, py::arg("s") = "")
         /*END:_GFUNC_:igText*/

         /*START:_GFUNC_:igCheckbox*/
         .def("Checkbox", [](const char *label, bool v)
              {auto changed = igCheckbox(label, &v);return py::make_tuple(changed,v); }, py::arg("label") = "", py::arg("v") = false)
         /*END:_GFUNC_:igCheckbox*/

         /*START:_GFUNC_:igShowAboutWindow*/
         .def("ShowAboutWindow", [](bool is_open)
              {igShowAboutWindow(&is_open);return is_open; }, py::arg("is_open") = true)
         /*END:_GFUNC_:igShowAboutWindow*/

         /*START:_GFUNC_:igShowDebugLogWindow*/
         .def("ShowDebugLogWindow", [](bool is_open)
              {igShowDebugLogWindow(&is_open);return is_open; }, py::arg("is_open") = true)
         /*END:_GFUNC_:igShowDebugLogWindow*/

         /*START:_GFUNC_:igShowDemoWindow*/
         .def("ShowDemoWindow", [](bool is_open)
              {igShowDemoWindow(&is_open);return is_open; }, py::arg("is_open") = true)
         /*END:_GFUNC_:igShowDemoWindow*/

         /*START:_GFUNC_:igShowIDStackToolWindow*/
         .def("ShowIDStackToolWindow", [](bool is_open)
              {igShowIDStackToolWindow(&is_open);return is_open; }, py::arg("is_open") = true)
         /*END:_GFUNC_:igShowIDStackToolWindow*/

         /*START:_GFUNC_:igShowMetricsWindow*/
         .def("ShowMetricsWindow", [](bool is_open)
              {igShowMetricsWindow(&is_open);return is_open; }, py::arg("is_open") = true)
         /*END:_GFUNC_:igShowMetricsWindow*/

         /*START:_GFUNC_:igBegin*/
         .def("Begin", [](const char *name, bool open, ImGuiWindowFlags flags)
              {auto is_collapsed = igBegin(name, &open, flags);return py::make_tuple(is_collapsed,open); }, py::arg("name") = "", py::arg("open") = true, py::arg("flags") = 0)
         /*END:_GFUNC_:igBegin*/

         /*START:_GFUNC_:igCombo_Str*/
         .def("Combo", [](const char *label, int current_item, const char *items_separated_by_zeros, int popup_max_height_in_items)
              {auto changed = igCombo_Str(label, &current_item, items_separated_by_zeros, popup_max_height_in_items);return py::make_tuple(changed,current_item); }, py::arg("label") = "", py::arg("current_item") = 0, py::arg("items_separated_by_zeros") = nullptr, py::arg("popup_max_height_in_items") = 0)
         /*END:_GFUNC_:igCombo_Str*/

         /*START:_GFUNC_:igGetWindowPos*/
         .def("GetWindowPos", []()
              {ImVec2 pos = {};igGetWindowPos(&pos);return pos; }, py::return_value_policy::move)
         /*END:_GFUNC_:igGetWindowPos*/

         /*START:_GFUNC_:igGetWindowSize*/
         .def("GetWindowSize", []()
              {ImVec2 size = {};igGetWindowSize(&size);return size; }, py::return_value_policy::move)
         /*END:_GFUNC_:igGetWindowSize*/

         /*START:_GFUNC_:igColorEdit3*/
         .def("ColorEdit3", [](const char *label, ImVec4 &color, ImGuiColorEditFlags flags)
              {auto changed = igColorEdit3(label, (float*)&color, flags);return py::make_tuple(changed,color); }, py::arg("label"), py::arg("color"), py::arg("flags") = 0)
         .def("ColorEdit3", [](const char *label, ImColor color, ImGuiColorEditFlags flags)
              {auto changed = igColorEdit3(label, (float*)&color, flags);return py::make_tuple(changed,color); }, py::arg("label"), py::arg("color"), py::arg("flags") = 0)
         /*END:_GFUNC_:igColorEdit3*/

         /*START:_GFUNC_:igColorEdit4*/
         .def("ColorEdit4", [](const char *label, ImVec4 &color, ImGuiColorEditFlags flags)
              {auto changed = igColorEdit4(label, (float*)&color, flags);return py::make_tuple(changed,color); }, py::arg("label"), py::arg("color"), py::arg("flags") = 0)
         .def("ColorEdit4", [](const char *label, ImColor color, ImGuiColorEditFlags flags)
              {auto changed = igColorEdit4(label, (float*)&color, flags);return py::make_tuple(changed,color); }, py::arg("label"), py::arg("color"), py::arg("flags") = 0)
         /*END:_GFUNC_:igColorEdit4*/

         /*START:_GFUNC_:igColorPicker3*/
         .def("ColorPicker3", [](const char *label, ImVec4 &color, ImGuiColorEditFlags flags)
              {auto changed = igColorPicker3(label, (float*)&color, flags);return py::make_tuple(changed,color); }, py::arg("label"), py::arg("color"), py::arg("flags") = 0)
         .def("ColorPicker3", [](const char *label, ImColor color, ImGuiColorEditFlags flags)
              {auto changed = igColorPicker3(label, (float*)&color, flags);return py::make_tuple(changed,color); }, py::arg("label"), py::arg("color"), py::arg("flags") = 0)
         /*END:_GFUNC_:igColorPicker3*/

         /*START:_GFUNC_:igColorPicker4*/
         .def("ColorPicker4", [](const char *label, ImVec4 &color, ImGuiColorEditFlags flags, const float *ref_col)
              {auto changed = igColorPicker4(label, (float*)&color, flags, ref_col);return py::make_tuple(changed,color); }, py::arg("label"), py::arg("color"), py::arg("flags") = 0, py::arg("ref_col") = nullptr)
         .def("ColorPicker4", [](const char *label, ImColor color, ImGuiColorEditFlags flags, const float *ref_col)
              {auto changed = igColorPicker4(label, (float*)&color, flags, ref_col);return py::make_tuple(changed,color); }, py::arg("label"), py::arg("color"), py::arg("flags") = 0, py::arg("ref_col") = nullptr)
         /*END:_GFUNC_:igColorPicker4*/

         /*START:_GFUNC_:igColorButton*/
         .def("ColorButton", [](const char *desc_id, ImVec4 &col, ImGuiColorEditFlags flags, ImVec2 size)
              { return igColorButton(desc_id, col, flags, size); }, py::arg("desc_id"), py::arg("col"), py::arg("flags") = 0, py::arg("size") = ImVec2(0, 0))
         .def("ColorButton", [](const char *desc_id, ImColor col, ImGuiColorEditFlags flags, ImVec2 size)
              { return igColorButton(desc_id, col.Value, flags, size); }, py::arg("desc_id"), py::arg("col"), py::arg("flags") = 0, py::arg("size") = ImVec2(0, 0))
         /*END:_GFUNC_:igColorButton*/

         /*START:_GFUNC_:igSliderAngle*/
         .def("SliderAngle", [](const char *label, float v_rad, float v_degrees_min, float v_degrees_max, const char *format, ImGuiSliderFlags flags)
              {
            auto changed = igSliderAngle(label, &v_rad, v_degrees_min, v_degrees_max, format, flags);
            return py::make_tuple(changed,v_rad); }, py::arg("label"), py::arg("v_rad"), py::arg("v_degrees_min") = -360.0f, py::arg("v_degrees_max") = +360.0f, py::arg("format") = "%.0f deg", py::arg("flags") = 0)
         /*END:_GFUNC_:igSliderAngle*/

         /*START:_GFUNC_:igSliderFloat*/
         .def("SliderFloat", [](const char *label, float v, float v_min, float v_max, const char *format, ImGuiSliderFlags flags)
              {
                auto changed = igSliderFloat(label, &v, v_min, v_max, format, flags);
                return py::make_tuple(changed, v); }, py::arg("label"), py::arg("v"), py::arg("v_min"), py::arg("v_max"), py::arg("format") = "%.3f", py::arg("flags") = 0)
         /*END:_GFUNC_:igSliderFloat*/

         /*START:_GFUNC_:igSliderFloat2*/
         .def("SliderFloat2", [](const char *label, std::tuple<float, float> v, float v_min, float v_max, const char *format, ImGuiSliderFlags flags)
              {
                float _v[] = {std::get<0>(v),std::get<1>(v)};
                auto changed = igSliderFloat2(label, _v, v_min, v_max, format, flags);
                auto _res_v = std::make_tuple(_v[0],_v[1]);
                return py::make_tuple(changed, _res_v); }, py::arg("label"), py::arg("v"), py::arg("v_min"), py::arg("v_max"), py::arg("format") = "%.3f", py::arg("flags") = 0)
         /*END:_GFUNC_:igSliderFloat2*/

         /*START:_GFUNC_:igSliderFloat3*/
         .def("SliderFloat3", [](const char *label, std::tuple<float, float, float> v, float v_min, float v_max, const char *format, ImGuiSliderFlags flags)
              {
                float _v[] = {std::get<0>(v),std::get<1>(v),std::get<2>(v)};
                auto changed = igSliderFloat3(label, _v, v_min, v_max, format, flags);
                auto _res_v = std::make_tuple(_v[0],_v[1],_v[2]);
                return py::make_tuple(changed, _res_v); }, py::arg("label"), py::arg("v"), py::arg("v_min"), py::arg("v_max"), py::arg("format") = "%.3f", py::arg("flags") = 0)
         /*END:_GFUNC_:igSliderFloat3*/

         /*START:_GFUNC_:igSliderFloat4*/
         .def("SliderFloat4", [](const char *label, std::tuple<float, float, float, float> v, float v_min, float v_max, const char *format, ImGuiSliderFlags flags)
              {
                float _v[] = {std::get<0>(v),std::get<1>(v),std::get<2>(v),std::get<3>(v)};
                auto changed = igSliderFloat4(label, _v, v_min, v_max, format, flags);
                auto _res_v = std::make_tuple(_v[0],_v[1],_v[2],_v[3]);
                return py::make_tuple(changed, _res_v); }, py::arg("label"), py::arg("v"), py::arg("v_min"), py::arg("v_max"), py::arg("format") = "%.3f", py::arg("flags") = 0)
         /*END:_GFUNC_:igSliderFloat4*/

         /*START:_GFUNC_:igSliderInt*/
         .def("SliderInt", [](const char *label, int v, int v_min, int v_max, const char *format, ImGuiSliderFlags flags)
              {
                    auto changed = igSliderInt(label, &v, v_min, v_max, format, flags);
                    return py::make_tuple(changed, v); }, py::arg("label"), py::arg("v"), py::arg("v_min"), py::arg("v_max"), py::arg("format") = "%d", py::arg("flags") = 0)
         /*END:_GFUNC_:igSliderInt*/

         /*START:_GFUNC_:igSliderInt2*/
         .def("SliderInt2", [](const char *label, std::tuple<int, int> v, int v_min, int v_max, const char *format, ImGuiSliderFlags flags)
              {
                int _v[] = {std::get<0>(v),std::get<1>(v)};
                auto changed = igSliderInt2(label, _v, v_min, v_max, format, flags);
                auto _res_v = std::make_tuple(_v[0],_v[1]);
                return py::make_tuple(changed, _res_v); }, py::arg("label"), py::arg("v"), py::arg("v_min"), py::arg("v_max"), py::arg("format") = "%d", py::arg("flags") = 0)
         /*END:_GFUNC_:igSliderInt2*/

         /*START:_GFUNC_:igSliderInt3*/
         .def("SliderInt3", [](const char *label, std::tuple<int, int, int> v, int v_min, int v_max, const char *format, ImGuiSliderFlags flags)
              {
                int _v[] = {std::get<0>(v),std::get<1>(v),std::get<2>(v)};
                auto changed = igSliderInt3(label, _v, v_min, v_max, format, flags);
                auto _res_v = std::make_tuple(_v[0],_v[1],_v[2]);
                return py::make_tuple(changed, _res_v); }, py::arg("label"), py::arg("v"), py::arg("v_min"), py::arg("v_max"), py::arg("format") = "%d", py::arg("flags") = 0)
         /*END:_GFUNC_:igSliderInt3*/

         /*START:_GFUNC_:igSliderInt4*/
         .def("SliderInt4", [](const char *label, std::tuple<int, int, int, int> v, int v_min, int v_max, const char *format, ImGuiSliderFlags flags)
              {
                int _v[] = {std::get<0>(v),std::get<1>(v),std::get<2>(v),std::get<3>(v)};
                auto changed = igSliderInt4(label, _v, v_min, v_max, format, flags);
                auto _res_v = std::make_tuple(_v[0],_v[1],_v[2],_v[3]);
                return py::make_tuple(changed, _res_v); }, py::arg("label"), py::arg("v"), py::arg("v_min"), py::arg("v_max"), py::arg("format") = "%d", py::arg("flags") = 0)
         /*END:_GFUNC_:igSliderInt4*/

         /*START:_GFUNC_:igInputText*/
         .def("InputText", [](const char *label, std::string &text, ImGuiInputTextFlags flags)
              {
                flags |= ImGuiInputTextFlags_CallbackResize;
                auto changed = igInputText(label, (char*)text.c_str(), text.capacity() + 1, flags, mImguiInputTextCallback, &text);
                return py::make_tuple(changed, text); }, py::arg("label"), py::arg("text"), py::arg("flags") = 0)
         /*END:_GFUNC_:igInputText*/

         /*START:_GFUNC_:igInputTextMultiline*/
         .def("InputTextMultiline", [](const char *label, std::string &text, const ImVec2 &size, ImGuiInputTextFlags flags)
              {
                flags |= ImGuiInputTextFlags_CallbackResize;
                auto changed = igInputTextMultiline(label, (char*)text.c_str(), text.capacity() + 1, size, flags, mImguiInputTextCallback, &text);
                return py::make_tuple(changed, text); }, py::arg("label"), py::arg("text"), py::arg("size") = ImVec2(0, 0), py::arg("flags") = 0)
         /*END:_GFUNC_:igInputTextMultiline*/

         /*START:_GFUNC_:igInputTextWithHint*/
         .def("InputTextWithHint", [](const char *label, const char *hint, std::string &text, ImGuiInputTextFlags flags)
              {
                flags |= ImGuiInputTextFlags_CallbackResize;
                auto changed = igInputTextWithHint(label, hint, (char*)text.c_str(), text.capacity() + 1, flags, mImguiInputTextCallback, &text);
                return py::make_tuple(changed, text); }, py::arg("label"), py::arg("hint"), py::arg("text"), py::arg("flags") = 0)
         /*END:_GFUNC_:igInputTextWithHint*/

         /*START:_GFUNC_:igInputFloat*/
         .def("InputFloat", [](const char *label, float &v, float step, float step_fast, const char *format, ImGuiInputTextFlags flags)
              {
                auto changed = igInputFloat(label, &v, step, step_fast, format, flags);
                return py::make_tuple(changed, v); }, py::arg("label"), py::arg("v"), py::arg("step") = 0.0f, py::arg("step_fast") = 0.0f, py::arg("format") = "%.3f", py::arg("flags") = 0)
         /*END:_GFUNC_:igInputFloat*/

         /*START:_GFUNC_:igInputFloat2*/
         .def("InputFloat2", [](const char *label, std::tuple<float, float> v, const char *format, ImGuiInputTextFlags flags)
              {
                float _v[] = {std::get<0>(v),std::get<1>(v)};
                auto changed = igInputFloat2(label, _v, format, flags);
                auto _res_v = std::make_tuple(_v[0],_v[1]);
                return py::make_tuple(changed, _res_v); }, py::arg("label"), py::arg("v"), py::arg("format") = "%.3f", py::arg("flags") = 0)
         /*END:_GFUNC_:igInputFloat2*/

         /*START:_GFUNC_:igInputFloat3*/
         .def("InputFloat3", [](const char *label, std::tuple<float, float, float> v, const char *format, ImGuiInputTextFlags flags)
              {
                float _v[] = {std::get<0>(v),std::get<1>(v),std::get<2>(v)};
                auto changed = igInputFloat3(label, _v, format, flags);
                auto _res_v = std::make_tuple(_v[0],_v[1],_v[2]);
                return py::make_tuple(changed, _res_v); }, py::arg("label"), py::arg("v"), py::arg("format") = "%.3f", py::arg("flags") = 0)
         /*END:_GFUNC_:igInputFloat3*/

         /*START:_GFUNC_:igInputFloat4*/
         .def("InputFloat4", [](const char *label, std::tuple<float, float, float, float> v, const char *format, ImGuiInputTextFlags flags)
              {
                float _v[] = {std::get<0>(v),std::get<1>(v),std::get<2>(v),std::get<3>(v)};
                auto changed = igInputFloat4(label, _v, format, flags);
                auto _res_v = std::make_tuple(_v[0],_v[1],_v[2],_v[3]);
                return py::make_tuple(changed, _res_v); }, py::arg("label"), py::arg("v"), py::arg("format") = "%.3f", py::arg("flags") = 0)
         /*END:_GFUNC_:igInputFloat4*/

         /*START:_GFUNC_:igInputInt*/
         .def("InputInt", [](const char *label, int &v, int step, int step_fast, ImGuiInputTextFlags flags)
              {
                auto changed = igInputInt(label, &v, step, step_fast, flags);
                return py::make_tuple(changed, v); }, py::arg("label"), py::arg("v"), py::arg("step") = 1, py::arg("step_fast") = 100, py::arg("flags") = 0)
         /*END:_GFUNC_:igInputInt*/

         /*START:_GFUNC_:igInputInt2*/
         .def("InputInt2", [](const char *label, std::tuple<int, int> v, ImGuiInputTextFlags flags)
              {
                int _v[] = {std::get<0>(v),std::get<1>(v)};
                auto changed = igInputInt2(label, _v, flags);
                auto _res_v = std::make_tuple(_v[0],_v[1]);
                return py::make_tuple(changed, _res_v); }, py::arg("label"), py::arg("v"), py::arg("flags") = 0)
         /*END:_GFUNC_:igInputInt2*/

         /*START:_GFUNC_:igInputInt3*/
         .def("InputInt3", [](const char *label, std::tuple<int, int, int> v, ImGuiInputTextFlags flags)
              {
                int _v[] = {std::get<0>(v),std::get<1>(v),std::get<2>(v)};
                auto changed = igInputInt3(label, _v, flags);
                auto _res_v = std::make_tuple(_v[0],_v[1],_v[2]);
                return py::make_tuple(changed, _res_v); }, py::arg("label"), py::arg("v"), py::arg("flags") = 0)
         /*END:_GFUNC_:igInputInt3*/

         /*START:_GFUNC_:igInputInt4*/
         .def("InputInt4", [](const char *label, std::tuple<int, int, int, int> v, ImGuiInputTextFlags flags)
              {
                int _v[] = {std::get<0>(v),std::get<1>(v),std::get<2>(v),std::get<3>(v)};
                auto changed = igInputInt4(label, _v, flags);
                auto _res_v = std::make_tuple(_v[0],_v[1],_v[2],_v[3]);
                return py::make_tuple(changed, _res_v); }, py::arg("label"), py::arg("v"), py::arg("flags") = 0)
         /*END:_GFUNC_:igInputInt4*/

         /*START:_GFUNC_:igInputDouble*/
         .def("InputDouble", [](const char *label, double &v, double step, double step_fast, const char *format, ImGuiInputTextFlags flags)
              {
                auto changed = igInputDouble(label, &v, step, step_fast, format, flags);
                return py::make_tuple(changed, v); }, py::arg("label"), py::arg("v"), py::arg("step") = 0.0, py::arg("step_fast") = 0.0, py::arg("format") = "%.6f", py::arg("flags") = 0)
     /*END:_GFUNC_:igInputDouble*/
}
