#include "./Impl_Win32.h"
#pragma comment(lib, "d3d10.lib")
#pragma comment(lib, "dxgi.lib")

#define M_IMGUI_IMPL_Dx10_NAMESPACE M_IMGUI_IMPL_NAMESPACE::Impl_Dx10
#define START_M_IMGUI_IMPL_Dx10_NAMESPACE \
    START_M_IMGUI_IMPL_NAMESPACE          \
    {                                     \
        namespace Impl_Dx10
#define END_M_IMGUI_IMPL_Dx10_NAMESPACE \
    }                                   \
    END_M_IMGUI_IMPL_NAMESPACE

START_M_IMGUI_IMPL_Dx10_NAMESPACE
{

    class Dx10Render
    {
    public:
        py::function renderCallback;
        HWND hwnd = nullptr;

        Dx10Render(py::function renderCallback)
        {
            this->renderCallback = renderCallback;
        }

        inline void Close()
        {
            if (this->hwnd != nullptr)
                PostMessage(this->hwnd, WM_CLOSE, 0, 0);
        }
    };

    class Dx10Window : public Dx10Render
    {
    public:
        static inline Dx10Window *_instance = nullptr;
        ImVec4 ClearColor = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

        Dx10Window(py::function renderCallback) : Dx10Render(renderCallback)
        {
            if (_instance != nullptr)
                throw "Only one instance of Dx10Window is allowed";
            _instance = this;
        }

        void Serve();
    };

    class Dx10Inbound : public Dx10Render
    {
    public:
        static inline Dx10Inbound *_instance = nullptr;
        bool isImGuiInitialized = false;

        Dx10Inbound(py::function renderCallback) : Dx10Render(renderCallback)
        {
            if (_instance != nullptr)
                throw "Only one instance of Dx10Inbound is allowed";
            _instance = this;
        }

        void Attach();
        void Detach();
        void Update();
    };

    inline void pybind_setup_mImguiImpl_Dx10(pybind11::module_ m)
    {
        py::class_<Dx10Render>(m, "Dx10Render")
            .def(py::init<py::function>())
            .def("Close", &Dx10Render::Close);
        py::class_<Dx10Window, Dx10Render>(m, "Dx10Window")
            .def(py::init<py::function>())
            .def_readwrite("ClearColor", &Dx10Window::ClearColor)
            .def("Serve", &Dx10Window::Serve);
        py::class_<Dx10Inbound, Dx10Render>(m, "Dx10Inbound")
            .def(py::init<py::function>())
            .def("Attach", &Dx10Inbound::Attach)
            .def("Detach", &Dx10Inbound::Detach);
    };
}
END_M_IMGUI_IMPL_Dx10_NAMESPACE