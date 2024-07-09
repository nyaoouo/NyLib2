#include "./Impl_Win32.h"
#pragma comment(lib, "d3d12.lib")
#pragma comment(lib, "dxgi.lib")

#define M_IMGUI_IMPL_Dx12_NAMESPACE M_IMGUI_IMPL_NAMESPACE::Impl_Dx12
#define START_M_IMGUI_IMPL_Dx12_NAMESPACE \
    START_M_IMGUI_IMPL_NAMESPACE          \
    {                                     \
        namespace Impl_Dx12

#define END_M_IMGUI_IMPL_Dx12_NAMESPACE \
    }                                   \
    END_M_IMGUI_IMPL_NAMESPACE

START_M_IMGUI_IMPL_Dx12_NAMESPACE
{
    class Dx12Render
    {
    public:
        py::function renderCallback;
        HWND hwnd = nullptr;

        Dx12Render(py::function renderCallback)
        {
            this->renderCallback = renderCallback;
        }

        inline void Close()
        {
            if (this->hwnd != nullptr)
                PostMessage(this->hwnd, WM_CLOSE, 0, 0);
        }
    };

    class Dx12Window : public Dx12Render
    {
    public:
        static inline Dx12Window *_instance = nullptr;
        ImVec4 ClearColor = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

        Dx12Window(py::function renderCallback) : Dx12Render(renderCallback)
        {
            if (_instance != nullptr)
                throw "Only one instance of Dx12Window is allowed";
            _instance = this;
        }

        void Serve();
    };

    class Dx12Inbound : public Dx12Render
    {
    public:
        static inline Dx12Inbound *_instance = nullptr;
        bool isImGuiInitialized = false;

        Dx12Inbound(py::function renderCallback) : Dx12Render(renderCallback)
        {
            if (_instance != nullptr)
                throw "Only one instance of Dx12Inbound is allowed";
            _instance = this;
        }

        void Attach();
        void Detach();
        void Update();
    };

    inline void pybind_setup_mImguiImpl_Dx12(pybind11::module_ m)
    {
        py::class_<Dx12Render>(m, "Dx12Render")
            .def(py::init<py::function>())
            .def("Close", &Dx12Render::Close);
        py::class_<Dx12Window, Dx12Render>(m, "Dx12Window")
            .def(py::init<py::function>())
            .def_readwrite("ClearColor", &Dx12Window::ClearColor)
            .def("Serve", &Dx12Window::Serve);
        py::class_<Dx12Inbound, Dx12Render>(m, "Dx12Inbound")
            .def(py::init<py::function>())
            .def("Attach", &Dx12Inbound::Attach)
            .def("Detach", &Dx12Inbound::Detach);
    };
}
END_M_IMGUI_IMPL_Dx12_NAMESPACE