#include "./Impl_Win32.h"
#include <vector>
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
    inline size_t PyFuncArgc(py::function func)
    {
        pybind11::module inspect_module = pybind11::module::import("inspect");
        pybind11::object result = inspect_module.attr("signature")(func).attr("parameters");
        return pybind11::len(result);
    }

    class Dx11Render
    {
    public:
        std::vector<py::function> callBeforeFrameOnce = {};
        std::optional<py::function> renderCallback;
        size_t renderCallback_argc = 0;
        HWND hwnd = nullptr;

        ID3D11Device *pd3dDevice = nullptr;
        ID3D11DeviceContext *pd3dDeviceContext = nullptr;
        IDXGISwapChain *pSwapChain = nullptr;
        ID3D11RenderTargetView *mainRenderTargetView = nullptr;
        ImGuiContext *ctx = nullptr;

        inline void CallRenderCallback()
        {
            if (!this->renderCallback)
                return;
            if (this->renderCallback_argc == 0)
                this->renderCallback.value()();
            else if (this->renderCallback_argc == 1)
                this->renderCallback.value()(this);
            else
                _throwV_("Invalid renderCallback_argc {}", this->renderCallback_argc);
        }

        inline void SetRenderCallback(std::optional<py::function> renderCallback)
        {
            this->renderCallback = renderCallback;
            this->renderCallback_argc = renderCallback ? PyFuncArgc(renderCallback.value()) : 0;
        }

        Dx11Render(py::function renderCallback)
        {
            this->SetRenderCallback(renderCallback);
        }

        void CreateRenderTarget();
        void CleanupRenderTarget();

        inline void Close()
        {
            if (this->hwnd != nullptr)
                PostMessage(this->hwnd, WM_CLOSE, 0, 0);
        }
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
        py::class_<Dx11Render>(m, "_Dx11Render", py::dynamic_attr())
            .def_property("renderCallback", [](Dx11Render &self)
                          { return self.renderCallback; }, &Dx11Render::SetRenderCallback)
            .def("CallBeforeFrameOnce", [](Dx11Render &self, py::function func)
                 { self.callBeforeFrameOnce.push_back(func); })
            .def_static("InvalidateDeviceObjects", &ImGui_ImplDX11_InvalidateDeviceObjects)
            .def_static("CreateDeviceObjects", &ImGui_ImplDX11_CreateDeviceObjects)
            .def("Close", &Dx11Render::Close);
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