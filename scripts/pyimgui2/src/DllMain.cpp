#pragma once
#include "./gheader.h"
#include "./pyimgui.h"
#include "./ImguiCtx.h"
#include "./OverlayQueries.h"
#include "./OverlayTypes.h"
#include "./TextureDecode.h"
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

    // Resolves the inbound frontend name, importing `<pyimgui_module_name>.<frontend>`
    // and returning `<X>Inbound(renderCallback)`. With frontend=None, picks the
    // sole loaded D3D9/10/11/12 runtime, or raises RuntimeError (none, or more
    // than one, naming the loaded DLLs).
    py::object CreateInboundImpl(std::optional<py::function> renderCallback, std::optional<py::str> frontend)
    {
        static const struct
        {
            const wchar_t *dllW;
            const char *dllA;
            const char *frontend;
        } runtime_dlls[] = {
            {L"d3d12.dll", "d3d12.dll", "dx12"},
            {L"d3d11.dll", "d3d11.dll", "dx11"},
            {L"d3d10.dll", "d3d10.dll", "dx10"},
            {L"d3d9.dll", "d3d9.dll", "dx9"},
        };
        static const std::unordered_map<std::string, const char *> frontend_classes = {
            {"dx9", "Dx9Inbound"},
            {"dx10", "Dx10Inbound"},
            {"dx11", "Dx11Inbound"},
            {"dx12", "Dx12Inbound"},
            {"gl3", "Gl3Inbound"},
            {"vk", "VkInbound"},
        };

        std::string frontend_name;
        if (!frontend.has_value())
        {
            std::vector<decltype(&runtime_dlls[0])> loaded;
            for (auto &entry : runtime_dlls)
                if (GetModuleHandleW(entry.dllW) != nullptr)
                    loaded.push_back(&entry);
            if (loaded.empty())
                _throw_("CreateInbound: no D3D9/10/11/12 runtime is loaded in this process; pass frontend= explicitly.");
            if (loaded.size() > 1)
            {
                std::string names = loaded[0]->dllA;
                for (size_t i = 1; i < loaded.size(); ++i)
                    names += std::string(", ") + loaded[i]->dllA;
                _throwV_("CreateInbound: more than one graphics runtime is loaded ({}); pass frontend= explicitly. Importing pyimgui.dxNN, or touching pyimgui._RenderBase (which imports dx11), loads that runtime for good.", names);
            }
            frontend_name = loaded.front()->frontend;
        }
        else
        {
            frontend_name = py::cast<std::string>(*frontend);
        }

        auto it = frontend_classes.find(frontend_name);
        if (it == frontend_classes.end())
            throw py::value_error("CreateInbound: unknown frontend '" + frontend_name + "'");

        auto module_name = pyimgui_module_name + "." + frontend_name;
        auto cls = py::module_::import(module_name.c_str()).attr(it->second);
        return cls(renderCallback ? py::object(*renderCallback) : py::none());
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
    OVERLAY_TYPES_NAMESPACE::pybind_setup_OverlayTypes(m);
    TEXTURE_DECODE_NAMESPACE::pybind_setup_TextureDecode(m);
    OVERLAY_QUERIES_NAMESPACE::pybind_setup_OverlayQueries(m);
    G_UTILS_NAMESPACE::pybind_setup_gUtils(m.def_submodule("gUtils"));
    auto imgui_m = m.def_submodule("imgui");
    PYIMGUI_CORE_NAMESPACE::pybind_setup_pyimgui_core(imgui_m);
    IMGUI_CTX_NAMESPACE::pybind_setup_ImguiCtx(imgui_m.def_submodule("ctx"));
    WIN32FONT_NAMESPACE::pybind_setup_Win32Font(m.def_submodule("win32_font"));
    m.def("CreateInbound", &CreateInboundImpl, py::arg("renderCallback") = py::none(), py::arg("frontend") = py::none());
    m.def("__getattr__", &pyimgui_lazy_frontend_attr, py::arg("name"));
}
