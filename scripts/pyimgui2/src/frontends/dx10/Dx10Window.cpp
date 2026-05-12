#include "./Dx10Window.h"

START_M_IMGUI_IMPL_DX10_NAMESPACE
{
    Dx10Window::Dx10Window(std::optional<py::function> renderCallback) : Dx10Render(renderCallback)
    {
        if (_instance != nullptr)
            _throw_("Only one Dx10Window instance is allowed");
        _instance = this;
    }

    Dx10Window::~Dx10Window()
    {
        if (_instance == this)
            _instance = nullptr;
    }

    void Dx10Window::Serve()
    {
    }

    Dx10Inbound::Dx10Inbound(std::optional<py::function> renderCallback) : Dx10Render(renderCallback)
    {
        if (_instance != nullptr)
            _throw_("Only one Dx10Inbound instance is allowed");
        _instance = this;
    }

    Dx10Inbound::~Dx10Inbound()
    {
        if (_instance == this)
            _instance = nullptr;
    }

    void Dx10Inbound::Attach()
    {
    }

    void Dx10Inbound::Detach()
    {
    }

    void Dx10Inbound::Update()
    {
    }

    void pybind_setup_mImguiImpl_Dx10(pybind11::module_ m)
    {
        pybind_setup_mImguiImpl_RenderBase(m);
        py::class_<Dx10Render, RenderBase>(m, "_Dx10Render", py::dynamic_attr(), py::module_local())
            .def_static("InvalidateDeviceObjects", []() { ImGui_ImplDX10_InvalidateDeviceObjects(); })
            .def_static("CreateDeviceObjects", []() { return ImGui_ImplDX10_CreateDeviceObjects(); });
        py::class_<Dx10Window, Dx10Render>(m, "Dx10Window", py::dynamic_attr(), py::module_local())
            .def(py::init<std::optional<py::function>>(), py::arg("renderCallback") = py::none())
            .def_readwrite("ClearColor", &Dx10Window::ClearColor)
            .def("Serve", &Dx10Window::Serve, py::call_guard<py::gil_scoped_release>());
        py::class_<Dx10Inbound, Dx10Render>(m, "Dx10Inbound", py::dynamic_attr(), py::module_local())
            .def(py::init<std::optional<py::function>>(), py::arg("renderCallback") = py::none())
            .def("Attach", &Dx10Inbound::Attach)
            .def("Detach", &Dx10Inbound::Detach);
    }
}
END_M_IMGUI_IMPL_DX10_NAMESPACE