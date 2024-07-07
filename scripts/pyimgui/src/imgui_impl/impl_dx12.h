#pragma comment(lib, "d3d12.lib")
#pragma comment(lib, "dxgi.lib")
#include "../gheader.h"
#include <d3d12.h>
#include <dxgi1_4.h>
#include "../m_imgui_internal.h"

namespace py = pybind11;

IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace mImguiImpl{namespace impl_dx12{
    LRESULT WINAPI  Dx12ImguiWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

    class Dx12ImguiWindow
    {
        public:
        static inline Dx12ImguiWindow* _instance = nullptr;
        py::function renderCallback;
        HWND hwnd = nullptr;

        ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

        Dx12ImguiWindow(py::function renderCallback)
        {
            if (_instance != nullptr)
                throw "Only one instance of Dx12ImguiWindow is allowed";
            this->renderCallback = renderCallback;
            _instance = this;
        }
        int Serve();

        inline void Close()
        {
            PostMessage(hwnd, WM_CLOSE, 0, 0);
        }
        static void RegPyCls(py::module_&m){
            py::class_<Dx12ImguiWindow>(m, "Dx12ImguiWindow")
                .def(py::init<py::function>())
                .def("Serve", &Dx12ImguiWindow::Serve)
                .def("Close", &Dx12ImguiWindow::Close)
                .def_readwrite("clear_color", &Dx12ImguiWindow::clear_color)
                ;
        }
    };
    class Dx12ImguiInternalWindow
    {
        public:
        static inline Dx12ImguiInternalWindow* _instance = nullptr;
        py::function renderCallback;
         Dx12ImguiInternalWindow(py::function renderCallback)
        {
            if (_instance != nullptr)
                throw "Only one instance of Dx12ImguiInternalWindow is allowed";
            this->renderCallback = renderCallback;
            _instance = this;
        }

        int Init();

        static void RegPyCls(py::module_&m){
            py::class_<Dx12ImguiInternalWindow>(m, "Dx12ImguiInternalWindow")
                .def(py::init<py::function>())
                .def("Init", &Dx12ImguiInternalWindow::Init)
                ;
        }
    };
}}