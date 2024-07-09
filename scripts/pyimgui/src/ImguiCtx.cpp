#include "./ImguiCtx.h"

using namespace G_UTILS_NAMESPACE;

START_IMGUI_CTX_NAMESPACE
{
    void pybind_setup_ImguiCtx(pybind11::module_ m){
        m.def("Begin", [](const char *name, bool open, ImGuiWindowFlags flags)
               {
               auto is_collapsed = igBegin(name, &open, flags);
               PyCtxWrapper res = {py::make_tuple(is_collapsed,open), igEnd};
               return res; }, py::arg("name") = "", py::arg("open") = true, py::arg("flags") = 0, py::return_value_policy::move);
     m.def("BeginChild", [](const char *str_id, const ImVec2 &size, ImGuiWindowFlags child_flags, ImGuiWindowFlags window_flags)
               {
              auto is_collapsed = igBeginChild_Str(str_id, size, child_flags, window_flags);
              PyCtxWrapper res = {py::cast(is_collapsed), igEndChild};
              return res; }, py::arg("str_id"), py::arg("size") = ImVec2(0, 0), py::arg("child_flags") = 0, py::arg("window_flags") = 0, py::return_value_policy::move);
     m.def("BeginChild", [](ImGuiID id, const ImVec2 &size, ImGuiWindowFlags child_flags, ImGuiWindowFlags window_flags)
               {
               auto is_collapsed = igBeginChild_ID(id, size, child_flags, window_flags);
               PyCtxWrapper res = {py::cast(is_collapsed), igEndChild};
               return res; }, py::arg("id"), py::arg("size") = ImVec2(0, 0), py::arg("child_flags") = 0, py::arg("window_flags") = 0, py::return_value_policy::move);
     m.def("BeginChildEx", [](const char *name, ImGuiID id, const ImVec2 &size_arg, ImGuiWindowFlags child_flags, ImGuiWindowFlags window_flags)
               {
               auto is_collapsed = igBeginChildEx(name, id, size_arg, child_flags, window_flags);
               PyCtxWrapper res = {py::cast(is_collapsed), igEndChild};
               return res; }, py::arg("name"), py::arg("id"), py::arg("size_arg"), py::arg("child_flags"), py::arg("window_flags"), py::return_value_policy::move);
     m.def("BeginGroup", []()
               {
               igBeginGroup();
               PyCtxWrapper res = {py::none(), igEndGroup};
               return res; }, py::return_value_policy::move);
     m.def("BeginCombo", [](const char *label, const char *preview_value, ImGuiComboFlags flags)
               {
               auto is_open = igBeginCombo(label, preview_value, flags);
               PyCtxWrapper res = {py::cast(is_open), igEndCombo};
               return res; }, py::arg("label"), py::arg("preview_value"), py::arg("flags")=0, py::return_value_policy::move);
     m.def("BeginListBox", [](const char *label, const ImVec2 &size)
               {
               auto is_open = igBeginListBox(label, size);
               PyCtxWrapper res = {py::cast(is_open), igEndListBox};
               return res; }, py::arg("label"), py::arg("size")=ImVec2(0,0), py::return_value_policy::move);
     m.def("BeginMainMenuBar", []()
               {
               auto is_open = igBeginMainMenuBar();
               PyCtxWrapper res = {py::cast(is_open), igEndMainMenuBar};
               return res; }, py::return_value_policy::move);
     m.def("BeginMenuBar", []()
               {
               auto is_open = igBeginMenuBar();
               PyCtxWrapper res = {py::cast(is_open), igEndMenuBar};
               return res; }, py::return_value_policy::move);
     m.def("BeginMenu", [](const char *label, bool enabled)
               {
               auto is_open = igBeginMenu(label, enabled);
               PyCtxWrapper res = {py::cast(is_open), igEndMenu};
               return res; }, py::arg("label"), py::arg("enabled")=true, py::return_value_policy::move);
     m.def("BeginTooltip", []()
               {
               igBeginTooltip();
               PyCtxWrapper res = {py::none(), igEndTooltip};
               return res; }, py::return_value_policy::move);
     m.def("BeginItemTooltip", []()
               {
               igBeginItemTooltip();
               PyCtxWrapper res = {py::none(), igEndTooltip};
               return res; }, py::return_value_policy::move);
     m.def("BeginPopup", [](const char *str_id, ImGuiWindowFlags flags)
               {
               auto res_ = igBeginPopup(str_id, flags);
               PyCtxWrapper res = {py::cast(res_), igEndPopup};
               return res; }, py::arg("str_id"), py::arg("flags")=0, py::return_value_policy::move);
     m.def("BeginPopupModal", [](const char *name, bool *p_open, ImGuiWindowFlags flags)
               {
               auto res_ = igBeginPopupModal(name, p_open, flags);
               PyCtxWrapper res = {py::cast(res_), igEndPopup};
               return res; }, py::arg("name"), py::arg("p_open"), py::arg("flags")=0, py::return_value_policy::move);
     m.def("BeginTable", [](const char* str_id,int columns,ImGuiTableFlags flags,const ImVec2 outer_size,float inner_width)
               {
               auto res_ = igBeginTable(str_id,columns,flags,outer_size,inner_width);
               PyCtxWrapper res = {py::cast(res_), igEndTable};
               return res; }, py::arg("str_id"), py::arg("columns"), py::arg("flags")=0, py::arg("outer_size")=ImVec2(0,0), py::arg("inner_width")=0.0f, py::return_value_policy::move);
     m.def("BeginTabBar", [](const char* str_id,ImGuiTabBarFlags flags)
               {
               auto res_ = igBeginTabBar(str_id,flags);
               PyCtxWrapper res = {py::cast(res_), igEndTabBar};
               return res; }, py::arg("str_id"), py::arg("flags")=0, py::return_value_policy::move);
     m.def("BeginTabItem", [](const char* label,bool p_open,ImGuiTabItemFlags flags)
               {
               auto res_ = igBeginTabItem(label,&p_open,flags);
               PyCtxWrapper res = {py::make_tuple(res_,p_open), igEndTabItem};
               return res; }, py::arg("label"), py::arg("p_open"), py::arg("flags")=0, py::return_value_policy::move);
     m.def("BeginDragDropSource", [](ImGuiDragDropFlags flags)
               {
               auto res_ = igBeginDragDropSource(flags);
               PyCtxWrapper res = {py::cast(res_), igEndDragDropSource};
               return res; }, py::arg("flags")=0, py::return_value_policy::move);
     m.def("BeginDragDropTarget", []()
               {
               auto res_ = igBeginDragDropTarget();
               PyCtxWrapper res = {py::cast(res_), igEndDragDropTarget};
               return res; }, py::return_value_policy::move);
     m.def("BeginDisabled", [](bool disabled)
               {
               igBeginDisabled(disabled);
               PyCtxWrapper res = {py::none(), igEndDisabled};
               return res; }, py::arg("disabled")=true, py::return_value_policy::move);
     m.def("BeginColumns", [](const char* str_id,int count,ImGuiOldColumnFlags flags)
               {
               igBeginColumns(str_id,count,flags);
               PyCtxWrapper res = {py::none(), igEndColumns};
               return res; }, py::arg("str_id"), py::arg("count")=-1, py::arg("flags")=0, py::return_value_policy::move);
    }
}
END_IMGUI_CTX_NAMESPACE