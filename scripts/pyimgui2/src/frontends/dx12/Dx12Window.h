#pragma once

#include "../common/RenderBase.h"
#include "../common/Win32Hook.h"
#include "../overlay/OverlayConfig.h"

#include <atomic>
#include <mutex>
#include <d3d12.h>
#include <dxgi1_4.h>
#include "imgui_impl_win32.h"
#include "imgui_impl_dx12.h"

#define M_IMGUI_IMPL_DX12_NAMESPACE M_IMGUI_IMPL_NAMESPACE::Impl_Dx12
#define START_M_IMGUI_IMPL_DX12_NAMESPACE START_M_IMGUI_IMPL_NAMESPACE { namespace Impl_Dx12
#define END_M_IMGUI_IMPL_DX12_NAMESPACE } END_M_IMGUI_IMPL_NAMESPACE

START_M_IMGUI_IMPL_DX12_NAMESPACE
{
    // Descriptor slots and deferred releases of one device session; shared by the renderer and its textures.
    class Dx12TextureStore
    {
    public:
        static UINT const HEAP_SIZE = 4096;
        static UINT const NULL_SLOT = 1;

        Dx12TextureStore(ID3D12Device *device, ID3D12DescriptorHeap *heap, DWORD renderThread); // AddRefs both and writes the null SRV into NULL_SLOT
        ~Dx12TextureStore();                                                 // after Close(true) releases device and heap; leaky or never closed: leaks them
        Dx12TextureStore(const Dx12TextureStore &) = delete;
        Dx12TextureStore &operator=(const Dx12TextureStore &) = delete;

        UINT Allocate();                                           // RuntimeError "no D3D12 device" when closed, "texture slots" when full
        void Unallocate(UINT slot) noexcept;                       // returns a slot whose descriptor was never drawn
        void Retire(ID3D12Resource *resource, UINT slot) noexcept; // any thread; nullptr / 0 allowed
        void Collect(UINT64 submitted, UINT64 completed) noexcept; // render thread, before the backend NewFrame
        void Close(bool gpuIdle) noexcept;                         // teardown, unwind guard or open site; idempotent
        bool IsOpen() const noexcept;                              // lock-free; read on every handle access
        bool OnRenderThread() const noexcept;                      // renderThread 0 (inbound): inside our hooked frame
        ID3D12Device *Device() const;
        D3D12_CPU_DESCRIPTOR_HANDLE CpuHandle(UINT slot) const;
        UINT64 GpuHandle(UINT slot) const;

    private:
        struct Entry
        {
            ID3D12Resource *resource;
            UINT slot;
            UINT64 value;
        };

        std::mutex mutex;
        std::atomic<bool> open{true};
        bool leaky = false;
        ID3D12Device *device;
        ID3D12DescriptorHeap *heap;
        DWORD renderThread;
        UINT increment;
        D3D12_CPU_DESCRIPTOR_HANDLE cpuStart;
        UINT64 gpuStart;
        std::vector<UINT> freeSlots;
        UINT nextSlot = NULL_SLOT + 1;
        std::vector<Entry> pending;
        std::vector<Entry> retired;
        std::vector<ID3D12Resource *> releases; // scratch of Collect and Close(true), which never run concurrently
    };

    class Dx12TextureHelper
    {
    public:
        std::shared_ptr<Dx12TextureStore> store;
        ID3D12Resource *srv = nullptr;
        UINT slot = 0;
        int width = 0;
        int height = 0;
        int mipLevels = 1;

        explicit Dx12TextureHelper(std::shared_ptr<Dx12TextureStore> store);
        ~Dx12TextureHelper();
        Dx12TextureHelper(const Dx12TextureHelper &) = delete;
        Dx12TextureHelper &operator=(const Dx12TextureHelper &) = delete;

        void FreeTexture();
        void LoadTextureFromFile(const std::string &filename); // GIL held on entry; released for decode and upload
        void Assign(ID3D12Resource *resource, UINT slot, int width, int height); // GIL held; retires the previous resource and slot
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
        std::shared_ptr<Dx12TextureStore> textures; // the open session's store; guarded by texturesMutex
        std::mutex texturesMutex;

        Dx12Render(std::optional<py::function> renderCallback = std::nullopt) : RenderBase(renderCallback) {}

        Dx12TextureHelper *CreateTexture(const char *filename = nullptr);
        Dx12TextureHelper *CreateTextureFromPixels(int width, int height, py::buffer pixels, long long rowPitch);
        std::shared_ptr<Dx12TextureStore> OpenTextures();           // the open store, else RuntimeError "no D3D12 device"; off the render thread RuntimeError "render thread"
        void InstallTextures(DWORD renderThread);                   // open site: closes a leftover store leaky, then opens one on pd3dDevice and pd3dSrvDescHeap; 0 for inbound
        void CollectTextures(UINT64 submitted, UINT64 completed) noexcept;
        void CloseTextures(bool gpuIdle) noexcept;
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
        Overlay::Config overlayConfig;

        Dx12Window(std::optional<py::function> renderCallback = std::nullopt);
        ~Dx12Window();

        void CreateDeviceD3D();
        void CleanupDeviceD3D();
        void CreateRenderTarget();
        void CleanupRenderTarget();
        void WaitForLastSubmittedFrame();
        FrameContext *WaitForNextFrameResources();
        void Serve();
        void ServeOverlay();
    };

    class Dx12Inbound : public Dx12Render
    {
    public:
        struct FrameContext
        {
            ID3D12CommandAllocator *CommandAllocator = nullptr;
            UINT64 FenceValue = 0;
        };

        struct BackBuffer
        {
            ID3D12Resource *MainRenderTargetResource = nullptr;
            D3D12_CPU_DESCRIPTOR_HANDLE MainRenderTargetDescriptor = {};
        };

        static int const NUM_FRAMES_IN_FLIGHT = 3;
        static inline Dx12Inbound *_instance = nullptr;
        bool isImGuiInitialized = false;
        bool isInLogic = false;
        ID3D12Fence *fence = nullptr;
        HANDLE fenceEvent = nullptr;
        HANDLE resizeFenceEvent = nullptr;
        UINT64 fenceLastSignaledValue = 0;
        FrameContext frameContext[NUM_FRAMES_IN_FLIGHT] = {};
        UINT frameIndex = 0;
        UINT bufferCount = 0;
        BackBuffer *backBuffers = nullptr;
        DXGI_FORMAT backBufferFormat = DXGI_FORMAT_UNKNOWN;
        std::atomic<bool> queueFallback{false};
        std::atomic<ID3D12CommandQueue *> fallbackQueueFromPresent{nullptr};
        std::atomic<ID3D12CommandQueue *> fallbackQueueAfterPresent{nullptr};
        std::atomic<bool> viewportsEnable{true};
        std::atomic<bool> viewportsDirty{false};

        Dx12Inbound(std::optional<py::function> renderCallback = std::nullopt);
        ~Dx12Inbound();

        void Attach();
        void Detach();
        void InitImGui(IDXGISwapChain3 *pSwapChain);
        bool CreateRenderTargets();
        void CleanupRenderTargets();
        bool WaitForFence(UINT64 value, HANDLE event, DWORD timeoutMs);
        void SetCommandQueue(ID3D12CommandQueue *queue);
        void OfferFallbackQueue(ID3D12CommandQueue *queue, bool fromPresent);
        void BeforeResize();
        void AfterResize(const UINT *pCreationNodeMask, IUnknown *const *ppPresentQueue);
        void Update();
        void _Update();
    };

    void pybind_setup_mImguiImpl_Dx12(pybind11::module_ m);
}
END_M_IMGUI_IMPL_DX12_NAMESPACE