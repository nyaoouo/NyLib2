#pragma once

#include "../common/RenderBase.h"
#include "../common/Win32Hook.h"

#include <d3d12.h>
#include <dxgi1_4.h>
#include "imgui_impl_win32.h"
#include "imgui_impl_dx12.h"

#define M_IMGUI_IMPL_DX12_NAMESPACE M_IMGUI_IMPL_NAMESPACE::Impl_Dx12
#define START_M_IMGUI_IMPL_DX12_NAMESPACE START_M_IMGUI_IMPL_NAMESPACE { namespace Impl_Dx12
#define END_M_IMGUI_IMPL_DX12_NAMESPACE } END_M_IMGUI_IMPL_NAMESPACE

START_M_IMGUI_IMPL_DX12_NAMESPACE
{
    class Dx12TextureHelper
    {
    public:
        ID3D12Device *d3dDevice = nullptr;
        D3D12_CPU_DESCRIPTOR_HANDLE srvCpuHandle = {};
        D3D12_GPU_DESCRIPTOR_HANDLE srvGpuHandle = {};
        ID3D12Resource *srv = nullptr;
        int width = 0;
        int height = 0;

        Dx12TextureHelper(ID3D12Device *d3dDevice, D3D12_CPU_DESCRIPTOR_HANDLE srvCpuHandle, D3D12_GPU_DESCRIPTOR_HANDLE srvGpuHandle, const char *filename = nullptr);
        ~Dx12TextureHelper();

        void FreeTexture();
        void LoadTextureFromFile(const char *filename);
        uintptr_t GetHandle() const;
        ImVec2 GetSize() const;
    };

    class Dx12Render : public RenderBase
    {
    public:
        ID3D12Device *pd3dDevice = nullptr;
        IDXGISwapChain3 *pSwapChain = nullptr;
        ID3D12DescriptorHeap *pd3dRtvDescHeap = nullptr;
        ID3D12DescriptorHeap *pd3dSrvDescHeap = nullptr;
        ID3D12CommandQueue *pd3dCommandQueue = nullptr;
        ID3D12GraphicsCommandList *pd3dCommandList = nullptr;

        Dx12Render(std::optional<py::function> renderCallback = std::nullopt) : RenderBase(renderCallback) {}

        Dx12TextureHelper *CreateTexture(const char *filename = nullptr);
    };

    class Dx12Window : public Dx12Render
    {
    public:
        struct FrameContext
        {
            ID3D12CommandAllocator *CommandAllocator = nullptr;
            UINT64 FenceValue = 0;
        };

        static int const NUM_FRAMES_IN_FLIGHT = 3;
        static int const NUM_BACK_BUFFERS = 3;
        static inline Dx12Window *_instance = nullptr;

        ImVec4 ClearColor = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);
        FrameContext frameContext[NUM_FRAMES_IN_FLIGHT] = {};
        UINT frameIndex = 0;
        ID3D12Fence *fence = nullptr;
        HANDLE fenceEvent = nullptr;
        UINT64 fenceLastSignaledValue = 0;
        bool swapChainOccluded = false;
        HANDLE hSwapChainWaitableObject = nullptr;
        ID3D12Resource *mainRenderTargetResource[NUM_BACK_BUFFERS] = {};
        D3D12_CPU_DESCRIPTOR_HANDLE mainRenderTargetDescriptor[NUM_BACK_BUFFERS] = {};

        Dx12Window(std::optional<py::function> renderCallback = std::nullopt);
        ~Dx12Window();

        void CreateDeviceD3D();
        void CleanupDeviceD3D();
        void CreateRenderTarget();
        void CleanupRenderTarget();
        void WaitForLastSubmittedFrame();
        FrameContext *WaitForNextFrameResources();
        void Serve();
    };

    class Dx12Inbound : public Dx12Render
    {
    public:
        struct FrameContext
        {
            ID3D12CommandAllocator *CommandAllocator = nullptr;
            ID3D12Resource *MainRenderTargetResource = nullptr;
            D3D12_CPU_DESCRIPTOR_HANDLE MainRenderTargetDescriptor = {};
        };

        static inline Dx12Inbound *_instance = nullptr;
        bool isImGuiInitialized = false;
        bool isInLogic = false;
        ID3D12Fence *fence = nullptr;
        UINT64 fenceLastSignaledValue = 0;
        UINT bufferCount = 0;
        FrameContext *frameContext = nullptr;

        Dx12Inbound(std::optional<py::function> renderCallback = std::nullopt);
        ~Dx12Inbound();

        void Attach();
        void Detach();
        void InitImGui(IDXGISwapChain3 *pSwapChain);
        void Update();
        void _Update();
    };

    void pybind_setup_mImguiImpl_Dx12(pybind11::module_ m);
}
END_M_IMGUI_IMPL_DX12_NAMESPACE