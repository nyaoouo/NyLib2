#pragma comment(lib, "d3d9.lib")
#include "../gheader.h"
#include <d3d9.h>
#include "../m_imgui_internal.h"

namespace py = pybind11;

IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace mImguiImpl{namespace impl_dx9{

    LRESULT WINAPI  Dx9ImguiWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

    class Dx9ImguiWindow
    {
        public:
        static inline Dx9ImguiWindow* _instance = nullptr;

        LPDIRECT3D9 pD3D = nullptr;
        LPDIRECT3DDEVICE9 pd3dDevice = nullptr;
        bool DeviceLost = false;
        UINT ResizeWidth = 0, ResizeHeight = 0;
        D3DPRESENT_PARAMETERS d3dpp = {};
        ImGuiContext* ctx = nullptr;
        py::function renderCallback;
        HWND hwnd = nullptr;

        ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

        Dx9ImguiWindow(py::function renderCallback)
        {
            if (_instance != nullptr)
                throw "Only one instance of Dx9ImguiWindow is allowed";
            this->renderCallback = renderCallback;
            _instance = this;
        }

        bool CreateDeviceD3D();
        void CleanupDeviceD3D();
        void ResetDevice();
        int Serve();

        inline void Close()
        {
            PostMessage(hwnd, WM_CLOSE, 0, 0);
        }

        static void RegPyCls(py::module_&m){
            py::class_<Dx9ImguiWindow>(m, "Dx9ImguiWindow")
                .def(py::init<py::function>())
                .def("Serve", &Dx9ImguiWindow::Serve)
                .def("Close", &Dx9ImguiWindow::Close)
                .def_readwrite("clear_color", &Dx9ImguiWindow::clear_color)
                ;
        }
    };
    class Dx9ImguiInternalWindow
    {
        public:
        static inline Dx9ImguiInternalWindow* _instance = nullptr;
        LPDIRECT3DDEVICE9 pDevice = nullptr;

        py::function renderCallback;
        
        Dx9ImguiInternalWindow(py::function renderCallback)
        {
            if (_instance != nullptr)
                throw "Only one instance of Dx9ImguiInternalWindow is allowed";
            this->renderCallback = renderCallback;
            _instance = this;
        }

        int Init();

        static void RegPyCls(py::module_&m){
            py::class_<Dx9ImguiInternalWindow>(m, "Dx9ImguiInternalWindow")
                .def(py::init<py::function>())
                .def("Init", &Dx9ImguiInternalWindow::Init)
                ;
        }
    };
}}
