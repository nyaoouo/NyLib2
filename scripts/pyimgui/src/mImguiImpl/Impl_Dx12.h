#include "./Impl_Win32.h"
#include <d3d12.h>
#include <dxgi1_4.h>
#pragma comment(lib, "d3d12.lib")
#pragma comment(lib, "dxgi.lib")

#ifdef _DEBUG
#define DX12_ENABLE_DEBUG_LAYER
#endif

#ifdef DX12_ENABLE_DEBUG_LAYER
#include <dxgidebug.h>
#pragma comment(lib, "dxguid.lib")
#endif

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

    class Dx12Render : public RenderBase
    {
    public:
    };

    class Dx12Window : public Dx12Render
    {
    public:
        struct FrameContext
        {
            ID3D12CommandAllocator *CommandAllocator;
            UINT64 FenceValue;
        };
        static int const NUM_FRAMES_IN_FLIGHT = 3;
        static int const NUM_BACK_BUFFERS = 3;
        static inline Dx12Window *_instance = nullptr;
        ImVec4 ClearColor = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

        FrameContext frameContext[NUM_FRAMES_IN_FLIGHT] = {};
        UINT frameIndex = 0;
        ID3D12Device *pd3dDevice = nullptr;
        ID3D12DescriptorHeap *pd3dRtvDescHeap = nullptr;
        ID3D12DescriptorHeap *pd3dSrvDescHeap = nullptr;
        ID3D12CommandQueue *pd3dCommandQueue = nullptr;
        ID3D12GraphicsCommandList *pd3dCommandList = nullptr;
        ID3D12Fence *fence = nullptr;
        HANDLE fenceEvent = nullptr;
        UINT64 fenceLastSignaledValue = 0;
        IDXGISwapChain3 *pSwapChain = nullptr;
        bool SwapChainOccluded = false;
        HANDLE hSwapChainWaitableObject = nullptr;
        ID3D12Resource *mainRenderTargetResource[NUM_BACK_BUFFERS] = {};
        D3D12_CPU_DESCRIPTOR_HANDLE mainRenderTargetDescriptor[NUM_BACK_BUFFERS] = {};

        void CreateDeviceD3D();
        void CleanupDeviceD3D();
        void CreateRenderTarget();
        void CleanupRenderTarget();
        void WaitForLastSubmittedFrame();
        FrameContext *WaitForNextFrameResources();

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
        bool isInLogic = false;

        struct FrameContext
        {
            ID3D12CommandAllocator *CommandAllocator = nullptr;
            ID3D12Resource *MainRenderTargetResource = nullptr;
            D3D12_CPU_DESCRIPTOR_HANDLE MainRenderTargetDescriptor;
        };

        ID3D12Device *pd3dDevice = nullptr;
        ID3D12DescriptorHeap *pd3dRtvDescHeap = nullptr;
        ID3D12DescriptorHeap *pd3dSrvDescHeap = nullptr;
        ID3D12CommandQueue *pd3dCommandQueue = nullptr;
        ID3D12GraphicsCommandList *pd3dCommandList = nullptr;
        ID3D12Fence *fence = nullptr;
        UINT64 fenceLastSignaledValue = 0;
        IDXGISwapChain3 *pSwapChain = nullptr;
        UINT buffer_count = -1;
        FrameContext *frameContext = nullptr;

        Dx12Inbound(py::function renderCallback) : Dx12Render(renderCallback)
        {
            if (_instance != nullptr)
                throw "Only one instance of Dx12Inbound is allowed";
            _instance = this;
        }

        void Attach();
        void Detach();
        void Update();

        void InitImGui(IDXGISwapChain3 *pSwapChain);
        void _Update();
    };

    inline void pybind_setup_mImguiImpl_Dx12(pybind11::module_ m)
    {
        py::class_<Dx12Render, RenderBase>(m, "Dx12Render")
            .def_static("InvalidateDeviceObjects", &ImGui_ImplDX12_InvalidateDeviceObjects)
            .def_static("CreateDeviceObjects", &ImGui_ImplDX12_CreateDeviceObjects);
        py::class_<Dx12Window, Dx12Render>(m, "Dx12Window")
            .def(py::init<py::function>())
            .def_readwrite("ClearColor", &Dx12Window::ClearColor)
            .def("Serve", &Dx12Window::Serve);
        py::class_<Dx12Inbound, Dx12Render>(m, "Dx12Inbound")
            .def(py::init<py::function>())
            .def_property_readonly("isInLogic", [](Dx12Inbound &self)
                                   { return self.isInLogic; }) // thread check?
            .def("Attach", &Dx12Inbound::Attach)
            .def("Detach", &Dx12Inbound::Detach);
    };
}
END_M_IMGUI_IMPL_Dx12_NAMESPACE