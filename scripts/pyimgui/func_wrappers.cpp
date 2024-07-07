#include <pybind11/pybind11.h>

void _(py::module &m)
{
    m

        /*START:igText*/
        .def("Text", [](const char *s)
             { return igText(s); }, py::arg("s") = "")
        /*END:igText*/

        /*START:igCheckbox*/
        .def("Checkbox", [](const char *label, bool v)
             {auto changed = igCheckbox(label, &v);return py::make_tuple(changed,v); }, py::arg("label") = "", py::arg("v") = false)
        /*END:igCheckbox*/

        /*START:igShowAboutWindow*/
        .def("ShowAboutWindow", [](bool is_open)
             {igShowAboutWindow(&is_open);return is_open; }, py::arg("is_open") = true)
        /*END:igShowAboutWindow*/

        /*START:igShowDebugLogWindow*/
        .def("ShowDebugLogWindow", [](bool is_open)
             {igShowDebugLogWindow(&is_open);return is_open; }, py::arg("is_open") = true)
        /*END:igShowDebugLogWindow*/

        /*START:igShowDemoWindow*/
        .def("ShowDemoWindow", [](bool is_open)
             {igShowDemoWindow(&is_open);return is_open; }, py::arg("is_open") = true)
        /*END:igShowDemoWindow*/

        /*START:igShowIDStackToolWindow*/
        .def("ShowIDStackToolWindow", [](bool is_open)
             {igShowIDStackToolWindow(&is_open);return is_open; }, py::arg("is_open") = true)
        /*END:igShowIDStackToolWindow*/

        /*START:igShowMetricsWindow*/
        .def("ShowMetricsWindow", [](bool is_open)
             {igShowMetricsWindow(&is_open);return is_open; }, py::arg("is_open") = true)
        /*END:igShowMetricsWindow*/

        /*START:igBegin*/
        .def("Begin", [](const char *name, bool open, ImGuiWindowFlags flags)
             {auto is_collapsed = igBegin(name, &open, flags);return py::make_tuple(is_collapsed,open); }, py::arg("name") = "", py::arg("open") = true, py::arg("flags") = 0)
        /*END:igBegin*/

        /*START:igCombo_Str*/
        .def("Combo", [](const char *label, int current_item, const char *items_separated_by_zeros, int popup_max_height_in_items)
             {auto changed = igCombo_Str(label, &current_item, items_separated_by_zeros, popup_max_height_in_items);return py::make_tuple(changed,current_item); }, py::arg("label") = "", py::arg("current_item") = 0, py::arg("items_separated_by_zeros") = nullptr, py::arg("popup_max_height_in_items") = 0)
        /*END:igCombo_Str*/

        /*START:igGetWindowPos*/
        .def("GetWindowPos", []()
             {ImVec2 pos = {};igGetWindowPos(&pos);return pos; }, py::return_value_policy::move)
        /*END:igGetWindowPos*/

        /*START:igGetWindowSize*/
        .def("GetWindowSize", []()
             {ImVec2 size = {};igGetWindowSize(&size);return size; }, py::return_value_policy::move)
        /*END:igGetWindowSize*/

        /*START:igColorEdit3*/
        .def("ColorEdit3", [](const char *label, ImVec4 &color, ImGuiColorEditFlags flags)
             {auto changed = igColorEdit3(label, (float*)&color, flags);return py::make_tuple(changed,color); }, py::arg("label"), py::arg("color"), py::arg("flags") = 0, py::return_value_policy::move)
        .def("ColorEdit3", [](const char *label, ImColor color, ImGuiColorEditFlags flags)
             {auto changed = igColorEdit3(label, (float*)&color, flags);return py::make_tuple(changed,color); }, py::arg("label"), py::arg("color"), py::arg("flags") = 0, py::return_value_policy::move)
        /*END:igColorEdit3*/

        /*START:igColorEdit4*/
        .def("ColorEdit4", [](const char *label, ImVec4 &color, ImGuiColorEditFlags flags)
             {auto changed = igColorEdit4(label, (float*)&color, flags);return py::make_tuple(changed,color); }, py::arg("label"), py::arg("color"), py::arg("flags") = 0, py::return_value_policy::move)
        .def("ColorEdit4", [](const char *label, ImColor color, ImGuiColorEditFlags flags)
             {auto changed = igColorEdit4(label, (float*)&color, flags);return py::make_tuple(changed,color); }, py::arg("label"), py::arg("color"), py::arg("flags") = 0, py::return_value_policy::move)
        /*END:igColorEdit4*/

        /*START:igGetIO*/
        .def("GetIO", &igGetIO, py::return_value_policy::reference)
        /*END:igGetIO*/

        /*START:igSliderAngle*/
        .def("SliderAngle", [](const char* label,float v_rad,float v_degrees_min,float v_degrees_max,const char* format,ImGuiSliderFlags flags)
             {
            auto changed = igSliderAngle(label, &v_rad, v_degrees_min, v_degrees_max, format, flags);
            return py::make_tuple(changed,v_rad); }, py::arg("label"), py::arg("v_rad"), py::arg("v_degrees_min") = -360.0f, py::arg("v_degrees_max") = +360.0f, py::arg("format") = "%.0f deg", py::arg("flags") = 0)
        /*END:igSliderAngle*/

        /*START:igSliderFloat*/
        .def("SliderFloat", [](const char* label,float v,float v_min,float v_max,const char* format,ImGuiSliderFlags flags)
                {
                auto changed = igSliderFloat(label, &v, v_min, v_max, format, flags);
                return py::make_tuple(changed, v); }, py::arg("label"), py::arg("v"), py::arg("v_min"), py::arg("v_max"), py::arg("format") = "%.3f", py::arg("flags") = 0)
        /*END:igSliderFloat*/

        /*START:igSliderFloat2*/
        .def("SliderFloat2", [](const char *label, std::tuple<float, float> v, float v_min, float v_max, const char *format, ImGuiSliderFlags flags)
             {
                float _v[] = {std::get<0>(v),std::get<1>(v)};
                auto changed = igSliderFloat2(label, _v, v_min, v_max, format, flags);
                auto _res_v = std::make_tuple(_v[0],_v[1]);
                return py::make_tuple(changed, _res_v); }, py::arg("label"), py::arg("v"), py::arg("v_min"), py::arg("v_max"), py::arg("format") = "%.3f", py::arg("flags") = 0)
        /*END:igSliderFloat2*/
        ;
}
