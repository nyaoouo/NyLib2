#include "./Impl_Win32.h"
#pragma comment(lib, "d3d9.lib")

#define M_IMGUI_IMPL_Dx9_NAMESPACE M_IMGUI_IMPL_NAMESPACE::Impl_Dx9
#define START_M_IMGUI_IMPL_Dx9_NAMESPACE \
    START_M_IMGUI_IMPL_NAMESPACE         \
    {                                    \
        namespace Impl_Dx9
#define END_M_IMGUI_IMPL_Dx9_NAMESPACE \
    }                                  \
    END_M_IMGUI_IMPL_NAMESPACE

START_M_IMGUI_IMPL_Dx9_NAMESPACE
{
    class Dx9Render
    {
    public:
        py::function renderCallback;
        HWND hwnd = nullptr;

        Dx9Render(py::function renderCallback)
        {
            this->renderCallback = renderCallback;
        }

        inline void Close()
        {
            if (this->hwnd != nullptr)
                PostMessage(this->hwnd, WM_CLOSE, 0, 0);
        }
    };

    class Dx9Window : public Dx9Render
    {
    public:
        static inline Dx9Window *_instance = nullptr;
        ImVec4 ClearColor = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

        Dx9Window(py::function renderCallback) : Dx9Render(renderCallback)
        {
            if (_instance != nullptr)
                throw "Only one instance of Dx9Window is allowed";
            _instance = this;
        }

        void Serve();
    };

    class Dx9Inbound : public Dx9Render
    {
    public:
        static inline Dx9Inbound *_instance = nullptr;
        bool isImGuiInitialized = false;

        Dx9Inbound(py::function renderCallback) : Dx9Render(renderCallback)
        {
            if (_instance != nullptr)
                throw "Only one instance of Dx9Inbound is allowed";
            _instance = this;
        }

        void Attach();
        void Detach();
        void Update();
    };

    inline void pybind_setup_mImguiImpl_Dx9(pybind11::module_ m)
    {
        py::class_<Dx9Render>(m, "Dx9Render")
            .def(py::init<py::function>())
            .def("Close", &Dx9Render::Close);
        py::class_<Dx9Window, Dx9Render>(m, "Dx9Window")
            .def(py::init<py::function>())
            .def_readwrite("ClearColor", &Dx9Window::ClearColor)
            .def("Serve", &Dx9Window::Serve);
        py::class_<Dx9Inbound, Dx9Render>(m, "Dx9Inbound")
            .def(py::init<py::function>())
            .def("Attach", &Dx9Inbound::Attach)
            .def("Detach", &Dx9Inbound::Detach);
    };
}
END_M_IMGUI_IMPL_Dx9_NAMESPACE