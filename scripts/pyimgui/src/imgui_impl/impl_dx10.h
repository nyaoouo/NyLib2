#pragma comment(lib, "d3d10.lib")
#pragma comment(lib, "dxgi.lib")
#include "../gheader.h"
#include <d3d10_1.h>
#include <d3d10.h>
#include "../m_imgui_internal.h"

namespace py = pybind11;

IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace mImguiImpl{namespace impl_dx10{
    LRESULT WINAPI  Dx10ImguiWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

    class Dx10ImguiWindow
    {
        public:
        static inline Dx10ImguiWindow* _instance = nullptr;
        py::function renderCallback;
        HWND hwnd = nullptr;

        ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

        Dx10ImguiWindow(py::function renderCallback)
        {
            if (_instance != nullptr)
                throw "Only one instance of Dx10ImguiWindow is allowed";
            this->renderCallback = renderCallback;
            _instance = this;
        }
        int Serve();

        inline void Close()
        {
            PostMessage(hwnd, WM_CLOSE, 0, 0);
        }
        static void RegPyCls(py::module_&m){
            py::class_<Dx10ImguiWindow>(m, "Dx10ImguiWindow")
                .def(py::init<py::function>())
                .def("Serve", &Dx10ImguiWindow::Serve)
                .def("Close", &Dx10ImguiWindow::Close)
                .def_readwrite("clear_color", &Dx10ImguiWindow::clear_color)
                ;
        }
    };
    class Dx10ImguiInternalWindow
    {
        public:
        static inline Dx10ImguiInternalWindow* _instance = nullptr;
        py::function renderCallback;
        Dx10ImguiInternalWindow(py::function renderCallback)
        {
            if (_instance != nullptr)
                throw "Only one instance of Dx10ImguiInternalWindow is allowed";
            this->renderCallback = renderCallback;
            _instance = this;
        }

        int Init();

        static void RegPyCls(py::module_&m){
            py::class_<Dx10ImguiInternalWindow>(m, "Dx10ImguiInternalWindow")
                .def(py::init<py::function>())
                .def("Init", &Dx10ImguiInternalWindow::Init)
                ;
        }
    };
}}