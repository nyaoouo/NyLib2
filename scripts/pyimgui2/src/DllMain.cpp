#pragma once
#include "./gheader.h"
#include "./pyimgui.h"
#include "./ImguiCtx.h"
#include "./UnhandledException.h"
#include "./Win32Font.h"

namespace
{
    std::string pyimgui_module_name = "pyimgui";

    py::object pyimgui_lazy_frontend_attr(const std::string &name)
    {
        static const std::unordered_map<std::string, std::pair<const char *, const char *>> frontend_attrs = {
            {"_Dx9Render", {"dx9", "_Dx9Render"}},
            {"_RenderBase", {"dx11", "_RenderBase"}},
            {"Dx9Inbound", {"dx9", "Dx9Inbound"}},
            {"Dx9Window", {"dx9", "Dx9Window"}},
            {"_Dx10Render", {"dx10", "_Dx10Render"}},
            {"Dx10Inbound", {"dx10", "Dx10Inbound"}},
            {"Dx10Render", {"dx10", "_Dx10Render"}},
            {"Dx10Window", {"dx10", "Dx10Window"}},
            {"_Dx11Render", {"dx11", "_Dx11Render"}},
            {"Dx11Inbound", {"dx11", "Dx11Inbound"}},
            {"Dx11Texture", {"dx11", "Dx11Texture"}},
            {"Dx11Window", {"dx11", "Dx11Window"}},
            {"Dx12Inbound", {"dx12", "Dx12Inbound"}},
            {"Dx12Render", {"dx12", "Dx12Render"}},
            {"Dx12TextureHelper", {"dx12", "Dx12TextureHelper"}},
            {"Dx12Window", {"dx12", "Dx12Window"}},
            {"_Gl3Render", {"gl3", "_Gl3Render"}},
            {"Gl3Inbound", {"gl3", "Gl3Inbound"}},
            {"Gl3Render", {"gl3", "_Gl3Render"}},
            {"Gl3Window", {"gl3", "Gl3Window"}},
            {"_VkRender", {"vk", "_VkRender"}},
            {"VkInbound", {"vk", "VkInbound"}},
            {"VkRender", {"vk", "_VkRender"}},
            {"VkWindow", {"vk", "VkWindow"}},
        };
        auto it = frontend_attrs.find(name);
        if (it == frontend_attrs.end())
            throw py::attribute_error("module 'pyimgui' has no attribute '" + name + "'");
        auto module_name = pyimgui_module_name + "." + it->second.first;
        return py::module_::import(module_name.c_str()).attr(it->second.second);
    }

    void pyimgui_enable_submodule_path(py::module_ &m)
    {
        auto pathlib = py::module_::import("pathlib");
        auto package_dir = pathlib.attr("Path")(m.attr("__file__")).attr("with_name")("pyimgui");
        py::list package_path;
        package_path.append(py::str(package_dir));
        m.attr("__path__") = package_path;
    }
}


PYBIND11_MODULE(pyimgui, m) {
    pyimgui_module_name = py::str(m.attr("__name__"));
    pyimgui_enable_submodule_path(m);
    // Expose `setup_unhandle_exception_filter` and the `MINIDUMP_TYPE` enum at
    // the top level of `pyimgui`. The filter is NOT installed automatically;
    // the user must call `setup_unhandle_exception_filter(...)` explicitly.
    G_UTILS_NAMESPACE::pybind_setup_UnhandledException(m);
    G_UTILS_NAMESPACE::pybind_setup_gUtils(m.def_submodule("gUtils"));
    auto imgui_m = m.def_submodule("imgui");
    PYIMGUI_CORE_NAMESPACE::pybind_setup_pyimgui_core(imgui_m);
    IMGUI_CTX_NAMESPACE::pybind_setup_ImguiCtx(imgui_m.def_submodule("ctx"));
    WIN32FONT_NAMESPACE::pybind_setup_Win32Font(m.def_submodule("win32_font"));
    m.def("__getattr__", &pyimgui_lazy_frontend_attr, py::arg("name"));
}
