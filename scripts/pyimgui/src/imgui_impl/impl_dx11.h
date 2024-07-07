#pragma comment(lib, "d3d11.lib")
#include "../gheader.h"
#include <d3d11.h>
#include "../m_imgui_internal.h"
#include "./impl_win32.h"
#include "../pydetours.h"

namespace py = pybind11;

IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace mImguiImpl
{
    namespace impl_dx11
    {
        LRESULT WINAPI Dx11ImguiWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

        class Dx11ImguiWindow
        {
        public:
            static inline Dx11ImguiWindow *_instance = nullptr;
            py::function renderCallback;
            HWND hwnd = nullptr;

            ID3D11Device *pd3dDevice = nullptr;
            ID3D11DeviceContext *pd3dDeviceContext = nullptr;
            IDXGISwapChain *pSwapChain = nullptr;
            bool SwapChainOccluded = false;
            UINT ResizeWidth = 0, ResizeHeight = 0;
            ID3D11RenderTargetView *mainRenderTargetView = nullptr;
            ImGuiContext *ctx = nullptr;

            ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

            Dx11ImguiWindow(py::function renderCallback)
            {
                if (_instance != nullptr)
                    throw "Only one instance of Dx11ImguiWindow is allowed";
                this->renderCallback = renderCallback;
                _instance = this;
            }

            bool CreateDeviceD3D();
            void CleanupDeviceD3D();
            void CreateRenderTarget();
            void CleanupRenderTarget();

            int Serve();

            inline void Close()
            {
                PostMessage(hwnd, WM_CLOSE, 0, 0);
            }
            static void RegPyCls(py::module_ &m)
            {
                py::class_<Dx11ImguiWindow>(m, "Dx11ImguiWindow")
                    .def(py::init<py::function>())
                    .def("Serve", &Dx11ImguiWindow::Serve)
                    .def("Close", &Dx11ImguiWindow::Close)
                    .def_readwrite("clear_color", &Dx11ImguiWindow::clear_color);
            }
        };
        class Dx11ImguiInternalWindow
        {
        public:
            static inline Dx11ImguiInternalWindow *_instance = nullptr;
            py::function renderCallback;
            HWND hwnd = nullptr;

            ID3D11Device *pd3dDevice = nullptr;
            ID3D11DeviceContext *pd3dDeviceContext = nullptr;
            IDXGISwapChain *pSwapChain = nullptr;
            ID3D11RenderTargetView *mainRenderTargetView = nullptr;
            ImGuiContext *ctx = nullptr;
            UINT ResizeWidth = 0, ResizeHeight = 0;
            
            bool isInit = false;
            bool isInLogic = false;

            Dx11ImguiInternalWindow(py::function renderCallback)
            {
                if (_instance != nullptr)
                    _throw_("Only one instance of Dx11ImguiInternalWindow is allowed");
                this->renderCallback = renderCallback;
                this->isInit = false;
                this->isInLogic = false;
                _instance = this;
            }

            int Init();
            int Uninit();
            void Update(IDXGISwapChain *pSwapChain);
            void CreateRenderTarget();
            void CleanupRenderTarget();

            static void RegPyCls(py::module_ &m)
            {
                py::class_<Dx11ImguiInternalWindow>(m, "Dx11ImguiInternalWindow")
                    .def(py::init<py::function>())
                    .def_property_readonly("isInLogic", [](Dx11ImguiInternalWindow &self) { return self.isInLogic; })
                    .def("Init", &Dx11ImguiInternalWindow::Init);
            }
        };
    }
}