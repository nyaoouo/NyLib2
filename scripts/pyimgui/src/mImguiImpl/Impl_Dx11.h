#include "./Impl_Win32.h"
#include "./Helper_Dx11.h"
#include <vector>
#include <d3d11.h>
#pragma comment(lib, "d3d11.lib")

#define M_IMGUI_IMPL_Dx11_NAMESPACE M_IMGUI_IMPL_NAMESPACE::Impl_Dx11
#define START_M_IMGUI_IMPL_Dx11_NAMESPACE \
    START_M_IMGUI_IMPL_NAMESPACE          \
    {                                     \
        namespace Impl_Dx11
#define END_M_IMGUI_IMPL_Dx11_NAMESPACE \
    }                                   \
    END_M_IMGUI_IMPL_NAMESPACE

START_M_IMGUI_IMPL_Dx11_NAMESPACE
{
    class Dx11Render : public RenderBase
    {
    public:
        ID3D11Device *pd3dDevice = nullptr;
        ID3D11DeviceContext *pd3dDeviceContext = nullptr;
        IDXGISwapChain *pSwapChain = nullptr;
        ID3D11RenderTargetView *mainRenderTargetView = nullptr;

        Dx11Render(py::function renderCallback) : RenderBase(renderCallback) {}

        void CreateRenderTarget();
        void CleanupRenderTarget();
    };

    class Dx11Window : public Dx11Render
    {
    public:
        static inline Dx11Window *_instance = nullptr;
        bool SwapChainOccluded = false;
        UINT ResizeWidth = 0, ResizeHeight = 0;
        ImVec4 ClearColor = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

        Dx11Window(py::function renderCallback) : Dx11Render(renderCallback)
        {
            if (_instance != nullptr)
                throw "Only one instance of Dx11Window is allowed";
            _instance = this;
        }

        void CreateDeviceD3D();
        void CleanupDeviceD3D();
        void Serve();
    };

    class Dx11Inbound : public Dx11Render
    {
    public:
        static inline Dx11Inbound *_instance = nullptr;
        bool isImGuiInitialized = false;
        bool isInLogic = false;

        Dx11Inbound(py::function renderCallback) : Dx11Render(renderCallback)
        {
            if (_instance != nullptr)
                throw "Only one instance of Dx11Inbound is allowed";
            _instance = this;
        }

        void Attach();
        void Detach();

        void InitImGui(IDXGISwapChain *pSwapChain);
        void Update();
        void _Update();
    };

    inline void pybind_setup_mImguiImpl_Dx11(pybind11::module_ m)
    {
        M_IMGUI_HELPER_Dx11_NAMESPACE::pybind_setup_helper_Dx11(m);
        py::class_<Dx11Render, RenderBase>(m, "_Dx11Render", py::dynamic_attr())
            .def_static("InvalidateDeviceObjects", &ImGui_ImplDX11_InvalidateDeviceObjects)
            .def_static("CreateDeviceObjects", &ImGui_ImplDX11_CreateDeviceObjects)
            .def("CreateTexture", [](Dx11Render &self, const char *filename)
                 { return new M_IMGUI_HELPER_Dx11_NAMESPACE::Dx11TextureHelper(self.pd3dDevice, filename); }, py::arg("filename"), py::return_value_policy::take_ownership)
            .def("CreateTexture", [](Dx11Render &self)
                 { return new M_IMGUI_HELPER_Dx11_NAMESPACE::Dx11TextureHelper(self.pd3dDevice); }, py::return_value_policy::take_ownership);

        py::class_<Dx11Window, Dx11Render>(m, "Dx11Window", py::dynamic_attr())
            .def(py::init<py::function>(), py::arg("renderCallback") = py::none())
            .def_readwrite("ClearColor", &Dx11Window::ClearColor)
            .def("Serve", &Dx11Window::Serve);
        py::class_<Dx11Inbound, Dx11Render>(m, "Dx11Inbound", py::dynamic_attr())
            .def(py::init<py::function>(), py::arg("renderCallback") = py::none())
            .def_property_readonly("isInLogic", [](Dx11Inbound &self)
                                   { return self.isInLogic; }) // thread check?
            .def("Attach", &Dx11Inbound::Attach)
            .def("Detach", &Dx11Inbound::Detach);
    };
}
END_M_IMGUI_IMPL_Dx11_NAMESPACE