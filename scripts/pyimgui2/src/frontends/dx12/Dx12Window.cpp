#include "./Dx12Window.h"
#include "../common/ImguiInbound.h"
#include "../common/PyDetours.h"
#include "../overlay/OverlayCanvas.h"

#include <mutex>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

START_M_IMGUI_IMPL_DX12_NAMESPACE
{
    // Depth of our own render logic, resize handling and submits on this thread; hooks reached from inside it pass through.
    static thread_local int logicDepth = 0;

    namespace
    {
        // Marks our own render logic, resize handling or submit on this thread.
        struct LogicScope
        {
            LogicScope() { logicDepth++; }
            ~LogicScope() { logicDepth--; }
        };
    }

    Dx12TextureHelper::Dx12TextureHelper(ID3D12Device *d3dDevice, D3D12_CPU_DESCRIPTOR_HANDLE srvCpuHandle, D3D12_GPU_DESCRIPTOR_HANDLE srvGpuHandle, const char *filename)
        : d3dDevice(d3dDevice), srvCpuHandle(srvCpuHandle), srvGpuHandle(srvGpuHandle)
    {
        if (filename != nullptr)
            this->LoadTextureFromFile(filename);
    }

    Dx12TextureHelper::~Dx12TextureHelper()
    {
        this->FreeTexture();
    }

    void Dx12TextureHelper::FreeTexture()
    {
        if (this->srv != nullptr)
        {
            this->srv->Release();
            this->srv = nullptr;
        }
        this->width = 0;
        this->height = 0;
    }

    uintptr_t Dx12TextureHelper::GetHandle() const
    {
        return (uintptr_t)this->srvGpuHandle.ptr;
    }

    ImVec2 Dx12TextureHelper::GetSize() const
    {
        return ImVec2((float)this->width, (float)this->height);
    }

    void Dx12TextureHelper::LoadTextureFromFile(const char *filename)
    {
        int imageWidth = 0;
        int imageHeight = 0;
        unsigned char *imageData = stbi_load(filename, &imageWidth, &imageHeight, nullptr, 4);
        if (imageData == nullptr)
            _throwV_("Failed to load image file {}", filename);

        D3D12_HEAP_PROPERTIES props = {};
        props.Type = D3D12_HEAP_TYPE_DEFAULT;

        D3D12_RESOURCE_DESC desc = {};
        desc.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
        desc.Width = imageWidth;
        desc.Height = imageHeight;
        desc.DepthOrArraySize = 1;
        desc.MipLevels = 1;
        desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.SampleDesc.Count = 1;
        desc.Layout = D3D12_TEXTURE_LAYOUT_UNKNOWN;

        ID3D12Resource *texture = nullptr;
        HRESULT hr = this->d3dDevice->CreateCommittedResource(&props, D3D12_HEAP_FLAG_NONE, &desc, D3D12_RESOURCE_STATE_COPY_DEST, nullptr, IID_PPV_ARGS(&texture));
        if (hr != S_OK)
            _throwV_("Failed to create texture resource with error code {}", hr);

        UINT uploadPitch = (imageWidth * 4 + D3D12_TEXTURE_DATA_PITCH_ALIGNMENT - 1u) & ~(D3D12_TEXTURE_DATA_PITCH_ALIGNMENT - 1u);
        UINT uploadSize = imageHeight * uploadPitch;
        D3D12_RESOURCE_DESC uploadDesc = {};
        uploadDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
        uploadDesc.Width = uploadSize;
        uploadDesc.Height = 1;
        uploadDesc.DepthOrArraySize = 1;
        uploadDesc.MipLevels = 1;
        uploadDesc.Format = DXGI_FORMAT_UNKNOWN;
        uploadDesc.SampleDesc.Count = 1;
        uploadDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;

        D3D12_HEAP_PROPERTIES uploadProps = {};
        uploadProps.Type = D3D12_HEAP_TYPE_UPLOAD;

        ID3D12Resource *uploadBuffer = nullptr;
        hr = this->d3dDevice->CreateCommittedResource(&uploadProps, D3D12_HEAP_FLAG_NONE, &uploadDesc, D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, IID_PPV_ARGS(&uploadBuffer));
        if (hr != S_OK)
            _throwV_("Failed to create upload buffer with error code {}", hr);

        void *mapped = nullptr;
        D3D12_RANGE range = {0, uploadSize};
        hr = uploadBuffer->Map(0, &range, &mapped);
        if (hr != S_OK)
            _throwV_("Failed to map upload buffer with error code {}", hr);
        for (int y = 0; y < imageHeight; y++)
            memcpy((void *)((uintptr_t)mapped + y * uploadPitch), imageData + y * imageWidth * 4, imageWidth * 4);
        uploadBuffer->Unmap(0, &range);

        D3D12_TEXTURE_COPY_LOCATION srcLocation = {};
        srcLocation.pResource = uploadBuffer;
        srcLocation.Type = D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT;
        srcLocation.PlacedFootprint.Footprint.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        srcLocation.PlacedFootprint.Footprint.Width = imageWidth;
        srcLocation.PlacedFootprint.Footprint.Height = imageHeight;
        srcLocation.PlacedFootprint.Footprint.Depth = 1;
        srcLocation.PlacedFootprint.Footprint.RowPitch = uploadPitch;

        D3D12_TEXTURE_COPY_LOCATION dstLocation = {};
        dstLocation.pResource = texture;
        dstLocation.Type = D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX;

        D3D12_RESOURCE_BARRIER barrier = {};
        barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
        barrier.Transition.pResource = texture;
        barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
        barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_COPY_DEST;
        barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE;

        ID3D12Fence *fence = nullptr;
        hr = this->d3dDevice->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&fence));
        if (hr != S_OK)
            _throwV_("Failed to create fence with error code {}", hr);
        HANDLE event = CreateEvent(nullptr, FALSE, FALSE, nullptr);
        if (event == nullptr)
            _throw_("Failed to create event");

        D3D12_COMMAND_QUEUE_DESC queueDesc = {};
        queueDesc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
        ID3D12CommandQueue *cmdQueue = nullptr;
        hr = this->d3dDevice->CreateCommandQueue(&queueDesc, IID_PPV_ARGS(&cmdQueue));
        if (hr != S_OK)
            _throwV_("Failed to create command queue with error code {}", hr);

        ID3D12CommandAllocator *cmdAlloc = nullptr;
        hr = this->d3dDevice->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&cmdAlloc));
        if (hr != S_OK)
            _throwV_("Failed to create command allocator with error code {}", hr);

        ID3D12GraphicsCommandList *cmdList = nullptr;
        hr = this->d3dDevice->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, cmdAlloc, nullptr, IID_PPV_ARGS(&cmdList));
        if (hr != S_OK)
            _throwV_("Failed to create command list with error code {}", hr);

        cmdList->CopyTextureRegion(&dstLocation, 0, 0, 0, &srcLocation, nullptr);
        cmdList->ResourceBarrier(1, &barrier);
        hr = cmdList->Close();
        if (hr != S_OK)
            _throwV_("Failed to close command list with error code {}", hr);
        {
            LogicScope ownSubmit;
            cmdQueue->ExecuteCommandLists(1, (ID3D12CommandList *const *)&cmdList);
        }
        hr = cmdQueue->Signal(fence, 1);
        if (hr != S_OK)
            _throwV_("Failed to signal fence with error code {}", hr);
        fence->SetEventOnCompletion(1, event);
        WaitForSingleObject(event, INFINITE);

        cmdList->Release();
        cmdAlloc->Release();
        cmdQueue->Release();
        CloseHandle(event);
        fence->Release();
        uploadBuffer->Release();

        D3D12_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
        srvDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        srvDesc.ViewDimension = D3D12_SRV_DIMENSION_TEXTURE2D;
        srvDesc.Texture2D.MipLevels = 1;
        srvDesc.Shader4ComponentMapping = D3D12_DEFAULT_SHADER_4_COMPONENT_MAPPING;
        this->d3dDevice->CreateShaderResourceView(texture, &srvDesc, this->srvCpuHandle);

        this->FreeTexture();
        this->srv = texture;
        this->width = imageWidth;
        this->height = imageHeight;
        stbi_image_free(imageData);
    }

    Dx12TextureHelper *Dx12Render::CreateTexture(const char *filename)
    {
        UINT handleIncrement = this->pd3dDevice->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
        int descriptorIndex = 1;
        D3D12_CPU_DESCRIPTOR_HANDLE srvCpuHandle = this->pd3dSrvDescHeap->GetCPUDescriptorHandleForHeapStart();
        srvCpuHandle.ptr += handleIncrement * descriptorIndex;
        D3D12_GPU_DESCRIPTOR_HANDLE srvGpuHandle = this->pd3dSrvDescHeap->GetGPUDescriptorHandleForHeapStart();
        srvGpuHandle.ptr += handleIncrement * descriptorIndex;
        return new Dx12TextureHelper(this->pd3dDevice, srvCpuHandle, srvGpuHandle, filename);
    }

    Dx12Window::Dx12Window(std::optional<py::function> renderCallback) : Dx12Render(renderCallback)
    {
        if (_instance != nullptr)
            _throw_("Only one Dx12Window instance is allowed");
        _instance = this;
    }

    Dx12Window::~Dx12Window()
    {
        if (_instance == this)
            _instance = nullptr;
    }

    LRESULT WINAPI Dx12ImguiWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        LRESULT trayResult = 0;
        if (M_IMGUI_IMPL_NAMESPACE::RenderBase::ProcessTrayWindowProc(hWnd, msg, wParam, lParam, trayResult))
            return trayResult;
        if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
            return true;
        if (Dx12Window::_instance == nullptr)
            return DefWindowProc(hWnd, msg, wParam, lParam);

        switch (msg)
        {
        case WM_SIZE:
        {
            auto instance = Dx12Window::_instance;
            if (instance->pd3dDevice != nullptr && wParam != SIZE_MINIMIZED)
            {
                instance->WaitForLastSubmittedFrame();
                instance->CleanupRenderTarget();
                HRESULT result = instance->pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT);
                if (!SUCCEEDED(result))
                    _throwV_("Failed to resize swapchain: {}", result);
                instance->CreateRenderTarget();
            }
            return 0;
        }
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU)
                return 0;
            break;
        case WM_DESTROY:
            ::PostQuitMessage(0);
            return 0;
        }
        return ::DefWindowProc(hWnd, msg, wParam, lParam);
    }

    void Dx12Window::CreateDeviceD3D()
    {
        HRESULT hr;

        DXGI_SWAP_CHAIN_DESC1 sd = {};
        sd.BufferCount = NUM_BACK_BUFFERS;
        sd.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        sd.Flags = DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT;
        sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        sd.SampleDesc.Count = 1;
        sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
        sd.Scaling = DXGI_SCALING_STRETCH;

        D3D_FEATURE_LEVEL featureLevel = D3D_FEATURE_LEVEL_11_0;
        if ((hr = D3D12CreateDevice(nullptr, featureLevel, IID_PPV_ARGS(&this->pd3dDevice))) != S_OK)
            _throwV_("Failed to create D3D12 device: {}", hr);

        D3D12_DESCRIPTOR_HEAP_DESC rtvDesc = {};
        rtvDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
        rtvDesc.NumDescriptors = NUM_BACK_BUFFERS;
        rtvDesc.NodeMask = 1;
        if ((hr = this->pd3dDevice->CreateDescriptorHeap(&rtvDesc, IID_PPV_ARGS(&this->pd3dRtvDescHeap))) != S_OK)
            _throwV_("Failed to create RTV descriptor heap: {}", hr);

        SIZE_T rtvDescriptorSize = this->pd3dDevice->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);
        D3D12_CPU_DESCRIPTOR_HANDLE rtvHandle = this->pd3dRtvDescHeap->GetCPUDescriptorHandleForHeapStart();
        for (UINT i = 0; i < NUM_BACK_BUFFERS; i++)
        {
            this->mainRenderTargetDescriptor[i] = rtvHandle;
            rtvHandle.ptr += rtvDescriptorSize;
        }

        D3D12_DESCRIPTOR_HEAP_DESC srvDesc = {};
        srvDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
        srvDesc.NumDescriptors = 2;
        srvDesc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;
        if ((hr = this->pd3dDevice->CreateDescriptorHeap(&srvDesc, IID_PPV_ARGS(&this->pd3dSrvDescHeap))) != S_OK)
            _throwV_("Failed to create SRV descriptor heap: {}", hr);

        D3D12_COMMAND_QUEUE_DESC queueDesc = {};
        queueDesc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
        queueDesc.NodeMask = 1;
        if ((hr = this->pd3dDevice->CreateCommandQueue(&queueDesc, IID_PPV_ARGS(&this->pd3dCommandQueue))) != S_OK)
            _throwV_("Failed to create command queue: {}", hr);

        for (UINT i = 0; i < NUM_FRAMES_IN_FLIGHT; i++)
            if ((hr = this->pd3dDevice->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&this->frameContext[i].CommandAllocator))) != S_OK)
                _throwV_("Failed to create command allocator[{}]: {}", i, hr);

        if ((hr = this->pd3dDevice->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, this->frameContext[0].CommandAllocator, nullptr, IID_PPV_ARGS(&this->pd3dCommandList))) != S_OK)
            _throwV_("Failed to create command list: {}", hr);
        if ((hr = this->pd3dCommandList->Close()) != S_OK)
            _throwV_("Failed to close command list: {}", hr);
        if ((hr = this->pd3dDevice->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&this->fence))) != S_OK)
            _throwV_("Failed to create fence: {}", hr);

        this->fenceEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);
        if (this->fenceEvent == nullptr)
            _throw_("Failed to create fence event");

        IDXGIFactory4 *dxgiFactory = nullptr;
        IDXGISwapChain1 *swapChain1 = nullptr;
        if ((hr = CreateDXGIFactory1(IID_PPV_ARGS(&dxgiFactory))) != S_OK)
            _throwV_("Failed to create DXGI factory: {}", hr);
        if ((hr = dxgiFactory->CreateSwapChainForHwnd(this->pd3dCommandQueue, this->hwnd, &sd, nullptr, nullptr, &swapChain1)) != S_OK)
            _throwV_("Failed to create swap chain: {}", hr);
        if ((hr = swapChain1->QueryInterface(IID_PPV_ARGS(&this->pSwapChain))) != S_OK)
            _throwV_("Failed to query swap chain: {}", hr);
        swapChain1->Release();
        dxgiFactory->Release();
        this->pSwapChain->SetMaximumFrameLatency(NUM_BACK_BUFFERS);
        this->hSwapChainWaitableObject = this->pSwapChain->GetFrameLatencyWaitableObject();

        this->CreateRenderTarget();
    }

    void Dx12Window::CleanupDeviceD3D()
    {
        this->CleanupRenderTarget();
        if (this->pSwapChain)
        {
            this->pSwapChain->SetFullscreenState(false, nullptr);
            this->pSwapChain->Release();
            this->pSwapChain = nullptr;
        }
        if (this->hSwapChainWaitableObject != nullptr)
            CloseHandle(this->hSwapChainWaitableObject);
        for (UINT i = 0; i < NUM_FRAMES_IN_FLIGHT; i++)
            if (this->frameContext[i].CommandAllocator)
            {
                this->frameContext[i].CommandAllocator->Release();
                this->frameContext[i].CommandAllocator = nullptr;
            }
        if (this->pd3dCommandQueue)
            this->pd3dCommandQueue->Release();
        if (this->pd3dCommandList)
            this->pd3dCommandList->Release();
        if (this->pd3dRtvDescHeap)
            this->pd3dRtvDescHeap->Release();
        if (this->pd3dSrvDescHeap)
            this->pd3dSrvDescHeap->Release();
        if (this->fence)
            this->fence->Release();
        if (this->fenceEvent)
            CloseHandle(this->fenceEvent);
        if (this->pd3dDevice)
            this->pd3dDevice->Release();
        this->pd3dCommandQueue = nullptr;
        this->pd3dCommandList = nullptr;
        this->pd3dRtvDescHeap = nullptr;
        this->pd3dSrvDescHeap = nullptr;
        this->fence = nullptr;
        this->fenceEvent = nullptr;
        this->pd3dDevice = nullptr;
        // Reset synchronization state so a later Serve() does not wait on a stale fence value.
        this->hSwapChainWaitableObject = nullptr;
        for (UINT i = 0; i < NUM_FRAMES_IN_FLIGHT; i++)
            this->frameContext[i].FenceValue = 0;
        this->frameIndex = 0;
        this->fenceLastSignaledValue = 0;
        this->swapChainOccluded = false;
    }

    void Dx12Window::CreateRenderTarget()
    {
        for (UINT i = 0; i < NUM_BACK_BUFFERS; i++)
        {
            ID3D12Resource *backBuffer = nullptr;
            this->pSwapChain->GetBuffer(i, IID_PPV_ARGS(&backBuffer));
            this->pd3dDevice->CreateRenderTargetView(backBuffer, nullptr, this->mainRenderTargetDescriptor[i]);
            this->mainRenderTargetResource[i] = backBuffer;
        }
    }

    void Dx12Window::CleanupRenderTarget()
    {
        this->WaitForLastSubmittedFrame();
        for (UINT i = 0; i < NUM_BACK_BUFFERS; i++)
            if (this->mainRenderTargetResource[i])
            {
                this->mainRenderTargetResource[i]->Release();
                this->mainRenderTargetResource[i] = nullptr;
            }
    }

    void Dx12Window::WaitForLastSubmittedFrame()
    {
        FrameContext *frameCtx = &this->frameContext[this->frameIndex % NUM_FRAMES_IN_FLIGHT];
        UINT64 fenceValue = frameCtx->FenceValue;
        if (fenceValue == 0)
            return;
        frameCtx->FenceValue = 0;
        if (this->fence->GetCompletedValue() >= fenceValue)
            return;
        this->fence->SetEventOnCompletion(fenceValue, this->fenceEvent);
        WaitForSingleObject(this->fenceEvent, INFINITE);
    }

    Dx12Window::FrameContext *Dx12Window::WaitForNextFrameResources()
    {
        UINT nextFrameIndex = this->frameIndex + 1;
        this->frameIndex = nextFrameIndex;
        HANDLE waitableObjects[] = {this->hSwapChainWaitableObject, nullptr};
        DWORD numWaitableObjects = 1;
        FrameContext *frameCtx = &this->frameContext[nextFrameIndex % NUM_FRAMES_IN_FLIGHT];
        UINT64 fenceValue = frameCtx->FenceValue;
        if (fenceValue != 0)
        {
            frameCtx->FenceValue = 0;
            this->fence->SetEventOnCompletion(fenceValue, this->fenceEvent);
            waitableObjects[1] = this->fenceEvent;
            numWaitableObjects = 2;
        }
        WaitForMultipleObjects(numWaitableObjects, waitableObjects, TRUE, INFINITE);
        return frameCtx;
    }

    void Dx12Window::Serve()
    {
        if (this->overlayConfig.overlay)
            return this->ServeOverlay();
        WNDCLASSEX wc = {sizeof(wc), CS_CLASSDC, Dx12ImguiWndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, _T("mImguiWindowDx12"), nullptr};
        ::RegisterClassEx(&wc);
        HWND hwnd = ::CreateWindow(wc.lpszClassName, _T(""), WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800, nullptr, nullptr, wc.hInstance, nullptr);
        if (hwnd == nullptr)
            _throwV_("Failed to create window, error code: {}", GetLastError());
        this->SetHwnd(hwnd);

        try
        {
            this->CreateDeviceD3D();
        }
        catch (...)
        {
            this->CleanupDeviceD3D();
            ::DestroyWindow(hwnd);
            ::UnregisterClass(wc.lpszClassName, wc.hInstance);
            throw;
        }

        ::ShowWindow(this->hwnd, SW_SHOWDEFAULT);
        ::UpdateWindow(this->hwnd);
        ::SetWindowTextA(this->hwnd, this->title.c_str());

        this->ctx = ImGui::CreateContext();
        ImGuiIO &io = ImGui::GetIO();
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;
        io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
        io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;
        ImGui::StyleColorsLight();

        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            ImGuiStyle &style = ImGui::GetStyle();
            style.WindowRounding = 0.0f;
            style.Colors[ImGuiCol_WindowBg].w = 1.0f;
        }

        ImGui_ImplWin32_Init(hwnd);
        ImGui_ImplDX12_Init(this->pd3dDevice, NUM_FRAMES_IN_FLIGHT, DXGI_FORMAT_R8G8B8A8_UNORM, this->pd3dSrvDescHeap, this->pd3dSrvDescHeap->GetCPUDescriptorHandleForHeapStart(), this->pd3dSrvDescHeap->GetGPUDescriptorHandleForHeapStart());

        do
        {
            MSG msg;
            bool done = false;
            while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
            {
                ::TranslateMessage(&msg);
                ::DispatchMessage(&msg);
                if (msg.message == WM_QUIT)
                    done = true;
            }
            if (done)
                break;

            if (this->swapChainOccluded && this->pSwapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED)
            {
                ::Sleep(10);
                continue;
            }
            this->swapChainOccluded = false;

            {
                py::gil_scoped_acquire gil;
                py::object self = py::cast(this, py::return_value_policy::reference);
                this->ProcessCallBeforeFrameOnce(self);
            }

            ImGui_ImplDX12_NewFrame();
            ImGui_ImplWin32_NewFrame();
            this->GateGamepad(false);
            ImGui::NewFrame();

            {
                py::gil_scoped_acquire gil;
                py::object self = py::cast(this, py::return_value_policy::reference);
                this->ProcessRenderCallback(self);
            }

            ImGui::Render();

            FrameContext *frameCtx = this->WaitForNextFrameResources();
            UINT backBufferIdx = this->pSwapChain->GetCurrentBackBufferIndex();
            frameCtx->CommandAllocator->Reset();

            D3D12_RESOURCE_BARRIER barrier = {};
            barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
            barrier.Transition.pResource = this->mainRenderTargetResource[backBufferIdx];
            barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
            barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_PRESENT;
            barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_RENDER_TARGET;

            this->pd3dCommandList->Reset(frameCtx->CommandAllocator, nullptr);
            this->pd3dCommandList->ResourceBarrier(1, &barrier);
            auto clearColor = this->ClearColor;
            const float clearColorWithAlpha[4] = {clearColor.x * clearColor.w, clearColor.y * clearColor.w, clearColor.z * clearColor.w, clearColor.w};
            this->pd3dCommandList->ClearRenderTargetView(this->mainRenderTargetDescriptor[backBufferIdx], clearColorWithAlpha, 0, nullptr);
            this->pd3dCommandList->OMSetRenderTargets(1, &this->mainRenderTargetDescriptor[backBufferIdx], FALSE, nullptr);
            this->pd3dCommandList->SetDescriptorHeaps(1, &this->pd3dSrvDescHeap);
            ImGui_ImplDX12_RenderDrawData(ImGui::GetDrawData(), this->pd3dCommandList);
            barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_RENDER_TARGET;
            barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_PRESENT;
            this->pd3dCommandList->ResourceBarrier(1, &barrier);
            this->pd3dCommandList->Close();
            this->pd3dCommandQueue->ExecuteCommandLists(1, (ID3D12CommandList *const *)&this->pd3dCommandList);

            if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
            {
                ImGui::UpdatePlatformWindows();
                ImGui::RenderPlatformWindowsDefault(nullptr, (void *)this->pd3dCommandList);
            }

            HRESULT hr = this->pSwapChain->Present(1, 0);
            this->swapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);
            UINT64 fenceValue = this->fenceLastSignaledValue + 1;
            this->pd3dCommandQueue->Signal(this->fence, fenceValue);
            this->fenceLastSignaledValue = fenceValue;
            frameCtx->FenceValue = fenceValue;
        } while (true);

        this->WaitForLastSubmittedFrame();
        ImGui_ImplDX12_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext(this->ctx);
        this->ctx = nullptr;
        this->CleanupDeviceD3D();
        ::DestroyWindow(hwnd);
        ::UnregisterClass(wc.lpszClassName, wc.hInstance);
        this->hwnd = nullptr;
    }

    namespace
    {
        template <class T>
        void ReleaseCom(T *&p) noexcept
        {
            if (p != nullptr)
            {
                p->Release();
                p = nullptr;
            }
        }

        void CloseHandleOnce(HANDLE &handle) noexcept
        {
            if (handle != nullptr)
            {
                CloseHandle(handle);
                handle = nullptr;
            }
        }

        // The overlay canvas's D3D12 side; keeps device, queue, swap chain, heaps and list in the window's Dx12Render fields.
        class Dx12OverlayRenderer : public Overlay::Renderer
        {
        public:
            explicit Dx12OverlayRenderer(Dx12Window &window) : window(window) {}

            ~Dx12OverlayRenderer() override
            {
                this->Release();
            }

            IUnknown *CreateSwapChain(UINT width, UINT height) override
            {
                HRESULT hr = D3D12CreateDevice(nullptr, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&this->window.pd3dDevice));
                if (FAILED(hr))
                    _throwV_("Failed to create D3D12 device: {:#x}", (unsigned)hr);
                ID3D12Device *device = this->window.pd3dDevice;

                D3D12_COMMAND_QUEUE_DESC queueDesc = {};
                queueDesc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
                hr = device->CreateCommandQueue(&queueDesc, IID_PPV_ARGS(&this->window.pd3dCommandQueue));
                if (FAILED(hr))
                    _throwV_("Failed to create the overlay command queue: {:#x}", (unsigned)hr);
                hr = CreateDXGIFactory2(0, IID_PPV_ARGS(&this->factory));
                if (FAILED(hr))
                    _throwV_("Failed to create IDXGIFactory2: {:#x}", (unsigned)hr);

                DXGI_SWAP_CHAIN_DESC1 desc = {};
                desc.Width = width;
                desc.Height = height;
                desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
                desc.SampleDesc.Count = 1;
                desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
                desc.BufferCount = Dx12Window::NUM_BACK_BUFFERS;
                desc.SwapEffect = DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL;
                desc.AlphaMode = DXGI_ALPHA_MODE_PREMULTIPLIED;
                desc.Scaling = DXGI_SCALING_STRETCH;
                desc.Flags = DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT;
                IDXGISwapChain1 *swapChain1 = nullptr;
                hr = this->factory->CreateSwapChainForComposition(this->window.pd3dCommandQueue, &desc, nullptr, &swapChain1);
                if (FAILED(hr))
                    _throwV_("CreateSwapChainForComposition failed: {:#x}", (unsigned)hr);
                hr = swapChain1->QueryInterface(IID_PPV_ARGS(&this->window.pSwapChain));
                swapChain1->Release();
                if (FAILED(hr))
                    _throwV_("Failed to query IDXGISwapChain3: {:#x}", (unsigned)hr);
                hr = this->window.pSwapChain->SetMaximumFrameLatency(Dx12Window::NUM_BACK_BUFFERS);
                if (FAILED(hr))
                    _throwV_("SetMaximumFrameLatency failed: {:#x}", (unsigned)hr);
                this->latencyWaitable = this->window.pSwapChain->GetFrameLatencyWaitableObject();
                if (this->latencyWaitable == nullptr)
                    _throw_("The overlay swap chain has no frame latency waitable object");

                D3D12_DESCRIPTOR_HEAP_DESC rtvDesc = {};
                rtvDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
                rtvDesc.NumDescriptors = Dx12Window::NUM_BACK_BUFFERS;
                hr = device->CreateDescriptorHeap(&rtvDesc, IID_PPV_ARGS(&this->window.pd3dRtvDescHeap));
                if (FAILED(hr))
                    _throwV_("Failed to create the overlay RTV heap: {:#x}", (unsigned)hr);
                D3D12_DESCRIPTOR_HEAP_DESC srvDesc = {};
                srvDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
                srvDesc.NumDescriptors = 2;
                srvDesc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;
                hr = device->CreateDescriptorHeap(&srvDesc, IID_PPV_ARGS(&this->window.pd3dSrvDescHeap));
                if (FAILED(hr))
                    _throwV_("Failed to create the overlay SRV heap: {:#x}", (unsigned)hr);

                for (UINT i = 0; i < Dx12Window::NUM_FRAMES_IN_FLIGHT; i++)
                {
                    hr = device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&this->allocators[i]));
                    if (FAILED(hr))
                        _throwV_("Failed to create overlay command allocator {}: {:#x}", i, (unsigned)hr);
                }
                hr = device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, this->allocators[0], nullptr, IID_PPV_ARGS(&this->window.pd3dCommandList));
                if (FAILED(hr))
                    _throwV_("Failed to create the overlay command list: {:#x}", (unsigned)hr);
                hr = this->window.pd3dCommandList->Close();
                if (FAILED(hr))
                    _throwV_("Failed to close the overlay command list: {:#x}", (unsigned)hr);
                hr = device->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&this->fence));
                if (FAILED(hr))
                    _throwV_("Failed to create the overlay fence: {:#x}", (unsigned)hr);
                this->fenceEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
                if (this->fenceEvent == nullptr)
                    _throwV_("Failed to create the overlay fence event: {}", GetLastError());

                this->AcquireBackBuffers();
                return this->window.pSwapChain;
            }

            void InitBackend() override
            {
                ID3D12DescriptorHeap *srvHeap = this->window.pd3dSrvDescHeap;
                if (!ImGui_ImplDX12_Init(this->window.pd3dDevice, Dx12Window::NUM_FRAMES_IN_FLIGHT, DXGI_FORMAT_R8G8B8A8_UNORM, srvHeap,
                                         srvHeap->GetCPUDescriptorHandleForHeapStart(), srvHeap->GetGPUDescriptorHandleForHeapStart()))
                    _throw_("ImGui_ImplDX12_Init failed");
            }

            void ShutdownBackend() noexcept override
            {
                ImGui_ImplDX12_Shutdown();
            }

            // Waits for a fresh fence value, so a list executed just before a throw is covered too.
            void WaitIdle() noexcept override
            {
                if (this->window.pd3dCommandQueue == nullptr || this->fence == nullptr || this->fenceEvent == nullptr)
                    return;
                UINT64 value = this->lastSignaled + 1;
                if (FAILED(this->window.pd3dCommandQueue->Signal(this->fence, value)))
                    return;
                this->lastSignaled = value;
                if (FAILED(this->fence->SetEventOnCompletion(value, this->fenceEvent)))
                    return;
                WaitForSingleObject(this->fenceEvent, INFINITE);
            }

            void Resize(UINT width, UINT height) override
            {
                if (this->fence->GetCompletedValue() < this->lastSignaled)
                    _throw_("The GPU is still using the overlay back buffers");
                this->ReleaseBackBuffers();
                HRESULT hr = this->window.pSwapChain->ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT);
                if (FAILED(hr))
                    _throwV_("Failed to resize the overlay swap chain: {:#x}", (unsigned)hr);
                this->AcquireBackBuffers();
            }

            void NewFrame() override
            {
                ImGui_ImplDX12_NewFrame();
            }

            bool RenderAndPresent() override
            {
                IDXGISwapChain3 *swapChain = this->window.pSwapChain;
                if (this->occluded)
                {
                    if (swapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED)
                        return false;
                    this->occluded = false;
                }

                UINT slot = this->WaitForSlot();
                UINT backBuffer = swapChain->GetCurrentBackBufferIndex();
                ID3D12GraphicsCommandList *list = this->window.pd3dCommandList;
                HRESULT hr = this->allocators[slot]->Reset();
                if (FAILED(hr))
                    _throwV_("Failed to reset the overlay command allocator: {:#x}", (unsigned)hr);
                hr = list->Reset(this->allocators[slot], nullptr);
                if (FAILED(hr))
                    _throwV_("Failed to reset the overlay command list: {:#x}", (unsigned)hr);

                D3D12_RESOURCE_BARRIER barrier = {};
                barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
                barrier.Transition.pResource = this->backBuffers[backBuffer];
                barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
                barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_PRESENT;
                barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_RENDER_TARGET;
                list->ResourceBarrier(1, &barrier);
                const float clearColor[4] = {0.0f, 0.0f, 0.0f, 0.0f};
                list->ClearRenderTargetView(this->rtvHandles[backBuffer], clearColor, 0, nullptr);
                list->OMSetRenderTargets(1, &this->rtvHandles[backBuffer], FALSE, nullptr);
                list->SetDescriptorHeaps(1, &this->window.pd3dSrvDescHeap);
                ImGui_ImplDX12_RenderDrawData(ImGui::GetDrawData(), list);
                barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_RENDER_TARGET;
                barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_PRESENT;
                list->ResourceBarrier(1, &barrier);
                hr = list->Close();
                if (FAILED(hr))
                    _throwV_("Failed to close the overlay command list: {:#x}", (unsigned)hr);

                this->window.pd3dCommandQueue->ExecuteCommandLists(1, (ID3D12CommandList *const *)&list);
                hr = swapChain->Present(1, 0);
                this->SignalSlot(slot);
                if (hr == DXGI_STATUS_OCCLUDED)
                {
                    this->occluded = true;
                    return false;
                }
                if (FAILED(hr))
                    _throwV_("Failed to present the overlay swap chain: {:#x}", (unsigned)hr);
                return true;
            }

            void Release() noexcept override
            {
                this->ReleaseBackBuffers();
                ReleaseCom(this->window.pSwapChain);
                CloseHandleOnce(this->latencyWaitable);
                ReleaseCom(this->window.pd3dCommandList);
                for (ID3D12CommandAllocator *&allocator : this->allocators)
                    ReleaseCom(allocator);
                ReleaseCom(this->window.pd3dRtvDescHeap);
                ReleaseCom(this->window.pd3dSrvDescHeap);
                ReleaseCom(this->fence);
                CloseHandleOnce(this->fenceEvent);
                ReleaseCom(this->window.pd3dCommandQueue);
                ReleaseCom(this->factory);
                ReleaseCom(this->window.pd3dDevice);
                for (UINT64 &value : this->slotFenceValues)
                    value = 0;
                this->frameIndex = 0;
                this->lastSignaled = 0;
                this->occluded = false;
            }

        private:
            Dx12Window &window;
            IDXGIFactory2 *factory = nullptr;
            HANDLE latencyWaitable = nullptr;
            ID3D12CommandAllocator *allocators[Dx12Window::NUM_FRAMES_IN_FLIGHT] = {};
            UINT64 slotFenceValues[Dx12Window::NUM_FRAMES_IN_FLIGHT] = {};
            UINT frameIndex = 0;
            ID3D12Fence *fence = nullptr;
            HANDLE fenceEvent = nullptr;
            UINT64 lastSignaled = 0;
            bool occluded = false;
            ID3D12Resource *backBuffers[Dx12Window::NUM_BACK_BUFFERS] = {};
            D3D12_CPU_DESCRIPTOR_HANDLE rtvHandles[Dx12Window::NUM_BACK_BUFFERS] = {};

            void AcquireBackBuffers()
            {
                UINT increment = this->window.pd3dDevice->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);
                D3D12_CPU_DESCRIPTOR_HANDLE handle = this->window.pd3dRtvDescHeap->GetCPUDescriptorHandleForHeapStart();
                for (UINT i = 0; i < Dx12Window::NUM_BACK_BUFFERS; i++)
                {
                    HRESULT hr = this->window.pSwapChain->GetBuffer(i, IID_PPV_ARGS(&this->backBuffers[i]));
                    if (FAILED(hr))
                        _throwV_("Failed to get overlay back buffer {}: {:#x}", i, (unsigned)hr);
                    this->rtvHandles[i] = handle;
                    this->window.pd3dDevice->CreateRenderTargetView(this->backBuffers[i], nullptr, handle);
                    handle.ptr += increment;
                }
            }

            void ReleaseBackBuffers() noexcept
            {
                for (ID3D12Resource *&buffer : this->backBuffers)
                    ReleaseCom(buffer);
            }

            // Advances to the next slot and waits for the latency waitable and the slot's last frame; returns the slot.
            UINT WaitForSlot()
            {
                this->frameIndex++;
                UINT slot = this->frameIndex % Dx12Window::NUM_FRAMES_IN_FLIGHT;
                HANDLE handles[2] = {this->latencyWaitable, nullptr};
                DWORD count = 1;
                if (this->slotFenceValues[slot] != 0)
                {
                    HRESULT hr = this->fence->SetEventOnCompletion(this->slotFenceValues[slot], this->fenceEvent);
                    if (FAILED(hr))
                        _throwV_("Failed to set the overlay fence event: {:#x}", (unsigned)hr);
                    this->slotFenceValues[slot] = 0;
                    handles[1] = this->fenceEvent;
                    count = 2;
                }
                DWORD result = WaitForMultipleObjects(count, handles, TRUE, INFINITE);
                if (result >= WAIT_OBJECT_0 + count)
                    _throwV_("Failed to wait for the overlay frame: {:#x} (error {})", (unsigned)result, GetLastError());
                return slot;
            }

            // Signals the next fence value for the slot's list; on failure the slot stays 0.
            void SignalSlot(UINT slot)
            {
                UINT64 value = this->lastSignaled + 1;
                HRESULT hr = this->window.pd3dCommandQueue->Signal(this->fence, value);
                if (FAILED(hr))
                    _throwV_("Failed to signal the overlay fence: {:#x}", (unsigned)hr);
                this->lastSignaled = value;
                this->slotFenceValues[slot] = value;
            }
        };
    }

    void Dx12Window::ServeOverlay()
    {
        Dx12OverlayRenderer renderer(*this);
        Overlay::Serve(*this, this->overlayConfig, renderer, L"PyImgui2Dx12Overlay");
    }

    typedef long(__fastcall *PresentD3D12)(IDXGISwapChain3 *pSwapChain, UINT SyncInterval, UINT Flags);
    typedef void(__fastcall *ExecuteCommandListsD3D12)(ID3D12CommandQueue *dCommandQueue, UINT NumCommandLists, ID3D12CommandList *const *ppCommandLists);
    typedef HRESULT(__fastcall *ResizeBuffersD3D12)(IDXGISwapChain3 *pSwapChain, UINT BufferCount, UINT Width, UINT Height, DXGI_FORMAT NewFormat, UINT SwapChainFlags);
    typedef HRESULT(__fastcall *ResizeBuffers1D3D12)(IDXGISwapChain3 *pSwapChain, UINT BufferCount, UINT Width, UINT Height, DXGI_FORMAT Format, UINT SwapChainFlags, const UINT *pCreationNodeMask, IUnknown *const *ppPresentQueue);

    static PresentD3D12 oPresentD3D12 = nullptr;
    static ExecuteCommandListsD3D12 oExecuteCommandListsD3D12 = nullptr;
    static ResizeBuffersD3D12 oResizeBuffersD3D12 = nullptr;
    static ResizeBuffers1D3D12 oResizeBuffers1D3D12 = nullptr;

    static thread_local bool inGamePresent = false;
    static std::atomic<bool> presentSeen{false};
    static std::atomic<bool> fenceTimeoutReported{false};
    static size_t const SWAP_CHAIN_SCAN_SIZE = 0x400;
    static DWORD const FENCE_TIMEOUT_MS = 1000;

    // Hooks stay installed for the process lifetime and reach the instance only through hookInstance.
    static std::atomic<Dx12Inbound *> hookInstance{nullptr};
    static std::atomic<bool> hooksEnabled{false};
    static std::atomic<int> hooksInFlight{0};
    static thread_local int hookBodyDepth = 0;
    static std::atomic<HWND> attachedHwnd{nullptr};
    static bool presentHooked = false;
    static bool executeCommandListsHooked = false;
    static bool resizeBuffersHooked = false;
    static bool resizeBuffers1Done = false;
    static bool atexitRegistered = false;
    // Serializes hooksEnabled, the Win32Hook subclass and the visible hwnd; never held while acquiring the GIL.
    static std::mutex transitionMutex;

    namespace
    {
        // Marks a hook body that may use hookInstance.
        struct HookBody
        {
            HookBody() { hookBodyDepth++; hooksInFlight++; }
            ~HookBody() { hooksInFlight--; hookBodyDepth--; }
        };
    }

    static bool IsFinalizing()
    {
#if PY_VERSION_HEX >= 0x030D0000
        return Py_IsFinalizing();
#else
        return _Py_IsFinalizing();
#endif
    }

    // Waits until no other thread is inside a hook body, releasing the GIL and serving sent messages meanwhile.
    static void WaitForHooks()
    {
        auto busy = []() { return hooksInFlight.load() != hookBodyDepth && !IsFinalizing(); };
        if (!busy())
            return;
        std::optional<py::gil_scoped_release> release;
        if (PyGILState_Check())
            release.emplace();
        MSG msg;
        while (busy())
        {
            ::MsgWaitForMultipleObjects(0, nullptr, FALSE, 1, QS_SENDMESSAGE);
            ::PeekMessage(&msg, nullptr, 0, 0, PM_NOREMOVE | PM_QS_SENDMESSAGE);
        }
    }

    // Stops drawing and input; the hooks stay installed.
    static void StopHooks()
    {
        std::lock_guard<std::mutex> lock(transitionMutex);
        hooksEnabled = false;
        try
        {
            if (HWND hwnd = attachedHwnd)
                M_IMGUI_IMPL_WIN32_NAMESPACE::Detach(hwnd);
        }
        catch (...)
        {
        }
    }

    // Stops drawing and input after a failure inside a hook and reports it on stderr.
    static void DisableFromHook(const char *reason)
    {
        StopHooks();
        fprintf(stderr, "[pyimgui] dx12 inbound disabled: %s\n", reason);
        std::fflush(stderr);
    }

    // Runs from atexit, before finalization; afterwards no hook reaches Python or the instance.
    static void StopHooksAtExit()
    {
        hookInstance = nullptr;
        StopHooks();
        WaitForHooks();
    }

    static int ReleasePendingReference(void *object)
    {
        Py_DECREF((PyObject *)object);
        return 0;
    }

    // Hands the last reference to Python's main thread and stops drawing and input at once; keeps the object alive if that cannot be scheduled.
    // The object is freed only when the main thread next runs bytecode.
    static void DeferLastReference(py::object &self)
    {
        if (Py_REFCNT(self.ptr()) != 1)
            return;
        PyObject *object = self.release().ptr();
        if (IsFinalizing() || Py_AddPendingCall(ReleasePendingReference, object) != 0)
        {
            fprintf(stderr, "[pyimgui] dx12 inbound: could not schedule the release of the last reference, keeping the object alive\n");
            std::fflush(stderr);
        }
        StopHooks();
    }

    static void ReleaseFallbackQueues(Dx12Inbound *instance)
    {
        for (std::atomic<ID3D12CommandQueue *> *slot : {&instance->fallbackQueueFromPresent, &instance->fallbackQueueAfterPresent})
            if (ID3D12CommandQueue *queue = slot->exchange(nullptr))
                queue->Release();
    }

    static bool IsReadable(const void *address, size_t size, uintptr_t *regionEnd = nullptr)
    {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (::VirtualQuery(address, &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
            return false;
        if ((mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) == 0)
            return false;
        uintptr_t end = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (regionEnd != nullptr)
            *regionEnd = end;
        return (uintptr_t)address + size <= end;
    }

    static bool ReadPointer(uintptr_t address, void **value)
    {
        __try
        {
            *value = *(void **)address;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    // Returns the swap chain's own DIRECT queue on pd3dDevice, AddRef'd, or nullptr unless exactly one candidate is found.
    static ID3D12CommandQueue *FindSwapChainQueue(IDXGISwapChain *pSwapChain, void **queueVtable, ID3D12Device *pd3dDevice)
    {
        uintptr_t begin = (uintptr_t)pSwapChain;
        uintptr_t end = 0;
        if (queueVtable == nullptr || !IsReadable(pSwapChain, sizeof(void *), &end))
            return nullptr;
        if (end > begin + SWAP_CHAIN_SCAN_SIZE)
            end = begin + SWAP_CHAIN_SCAN_SIZE;
        ID3D12CommandQueue *found = nullptr;
        for (uintptr_t slot = begin; slot + sizeof(void *) <= end; slot += sizeof(void *))
        {
            void *raw = nullptr;
            void *vptr = nullptr;
            if (!ReadPointer(slot, &raw))
                return nullptr;
            ID3D12CommandQueue *candidate = (ID3D12CommandQueue *)raw;
            if (candidate == nullptr || candidate == found || ((uintptr_t)candidate & (sizeof(void *) - 1)) != 0)
                continue;
            if (!IsReadable(candidate, sizeof(void *)) || !ReadPointer((uintptr_t)candidate, &vptr) || vptr != (void *)queueVtable)
                continue;
            if (candidate->GetDesc().Type != D3D12_COMMAND_LIST_TYPE_DIRECT)
                continue;
            ID3D12Device *device = nullptr;
            if (candidate->GetDevice(IID_PPV_ARGS(&device)) != S_OK)
                continue;
            device->Release();
            if (device != pd3dDevice)
                continue;
            if (found != nullptr)
                return nullptr;
            found = candidate;
        }
        if (found != nullptr)
            found->AddRef();
        return found;
    }

    long __fastcall hkPresentD3D12(IDXGISwapChain3 *pSwapChain, UINT SyncInterval, UINT Flags)
    {
        {
            HookBody body;
            Dx12Inbound *instance = hookInstance;
            if (instance != nullptr && hooksEnabled && logicDepth == 0 && (instance->pSwapChain == nullptr || instance->pSwapChain == pSwapChain))
            {
                try
                {
                    if (!instance->isImGuiInitialized)
                        instance->InitImGui(pSwapChain);
                    instance->Update();
                }
                catch (const std::exception &e)
                {
                    DisableFromHook(e.what());
                }
                catch (...)
                {
                    DisableFromHook("unknown exception");
                }
            }
        }
        inGamePresent = true;
        long result = oPresentD3D12(pSwapChain, SyncInterval, Flags);
        inGamePresent = false;
        presentSeen = true;
        return result;
    }

    void __fastcall hkExecuteCommandListsD3D12(ID3D12CommandQueue *dCommandQueue, UINT NumCommandLists, ID3D12CommandList *const *ppCommandLists)
    {
        {
            HookBody body;
            Dx12Inbound *instance = hookInstance;
            if (instance != nullptr && hooksEnabled && instance->queueFallback && logicDepth == 0)
                instance->OfferFallbackQueue(dCommandQueue, inGamePresent);
        }
        oExecuteCommandListsD3D12(dCommandQueue, NumCommandLists, ppCommandLists);
    }

    // While disabled, the resize hooks still release our back buffers but do not keep new ones.
    HRESULT __fastcall hkResizeBuffersD3D12(IDXGISwapChain3 *pSwapChain, UINT BufferCount, UINT Width, UINT Height, DXGI_FORMAT NewFormat, UINT SwapChainFlags)
    {
        HookBody body;
        Dx12Inbound *instance = hookInstance;
        if (logicDepth > 0 || instance == nullptr || !instance->isImGuiInitialized || instance->pSwapChain != pSwapChain)
            return oResizeBuffersD3D12(pSwapChain, BufferCount, Width, Height, NewFormat, SwapChainFlags);
        LogicScope logic;
        instance->BeforeResize();
        HRESULT hr = oResizeBuffersD3D12(pSwapChain, BufferCount, Width, Height, NewFormat, SwapChainFlags);
        instance->AfterResize(nullptr, nullptr);
        if (!hooksEnabled)
            instance->CleanupRenderTargets();
        return hr;
    }

    HRESULT __fastcall hkResizeBuffers1D3D12(IDXGISwapChain3 *pSwapChain, UINT BufferCount, UINT Width, UINT Height, DXGI_FORMAT Format, UINT SwapChainFlags, const UINT *pCreationNodeMask, IUnknown *const *ppPresentQueue)
    {
        HookBody body;
        Dx12Inbound *instance = hookInstance;
        if (logicDepth > 0 || instance == nullptr || !instance->isImGuiInitialized || instance->pSwapChain != pSwapChain)
            return oResizeBuffers1D3D12(pSwapChain, BufferCount, Width, Height, Format, SwapChainFlags, pCreationNodeMask, ppPresentQueue);
        LogicScope logic;
        instance->BeforeResize();
        HRESULT hr = oResizeBuffers1D3D12(pSwapChain, BufferCount, Width, Height, Format, SwapChainFlags, pCreationNodeMask, ppPresentQueue);
        instance->AfterResize(pCreationNodeMask, SUCCEEDED(hr) ? ppPresentQueue : nullptr);
        if (!hooksEnabled)
            instance->CleanupRenderTargets();
        return hr;
    }

    Dx12Inbound::Dx12Inbound(std::optional<py::function> renderCallback) : Dx12Render(renderCallback)
    {
        if (_instance != nullptr)
            _throw_("Only one Dx12Inbound instance is allowed");
        _instance = this;
        hookInstance = this;
    }

    Dx12Inbound::~Dx12Inbound()
    {
        hookInstance = nullptr;
        try
        {
            this->Detach();
        }
        catch (...)
        {
        }
        WaitForHooks();
        bool gpuIdle = this->fence == nullptr || this->fenceEvent == nullptr || this->WaitForFence(this->fenceLastSignaledValue, this->fenceEvent, FENCE_TIMEOUT_MS);
        this->CleanupRenderTargets();
        delete[] this->backBuffers;
        this->backBuffers = nullptr;
        this->bufferCount = 0;
        ReleaseFallbackQueues(this);
        this->SetCommandQueue(nullptr);
        // Leaks the objects the GPU may still use when the wait timed out; never releases the SRV heap.
        if (!gpuIdle)
        {
            fprintf(stderr, "[pyimgui] dx12 inbound: GPU fence wait timed out on destroy, leaking command objects\n");
            std::fflush(stderr);
        }
        else
        {
            for (FrameContext &frameCtx : this->frameContext)
                if (frameCtx.CommandAllocator != nullptr)
                    frameCtx.CommandAllocator->Release();
            for (IUnknown *object : std::initializer_list<IUnknown *>{this->pd3dCommandList, this->pd3dRtvDescHeap, this->fence, this->pd3dDevice})
                if (object != nullptr)
                    object->Release();
            for (HANDLE event : {this->fenceEvent, this->resizeFenceEvent})
                if (event != nullptr)
                    ::CloseHandle(event);
        }
        if (_instance == this)
            _instance = nullptr;
    }

    // Installs each hook at most once; a later Attach only re-enables drawing and input.
    void Dx12Inbound::Attach()
    {
        if (!atexitRegistered)
        {
            py::module_::import("atexit").attr("register")(py::cpp_function(StopHooksAtExit));
            atexitRegistered = true;
        }
        if (!presentHooked || !executeCommandListsHooked || !resizeBuffersHooked || !resizeBuffers1Done)
        {
            IMGUI_INBOUND_NAMESPACE::Init(IMGUI_INBOUND_NAMESPACE::D3D12);
            if (!presentHooked)
            {
                oPresentD3D12 = (PresentD3D12)IMGUI_INBOUND_NAMESPACE::GetMethod(140);
                PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oPresentD3D12, (PVOID)hkPresentD3D12);
                presentHooked = true;
            }
            if (!executeCommandListsHooked)
            {
                oExecuteCommandListsD3D12 = (ExecuteCommandListsD3D12)IMGUI_INBOUND_NAMESPACE::GetMethod(54);
                PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oExecuteCommandListsD3D12, (PVOID)hkExecuteCommandListsD3D12);
                executeCommandListsHooked = true;
            }
            if (!resizeBuffersHooked)
            {
                oResizeBuffersD3D12 = (ResizeBuffersD3D12)IMGUI_INBOUND_NAMESPACE::GetMethod(145);
                PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oResizeBuffersD3D12, (PVOID)hkResizeBuffersD3D12);
                resizeBuffersHooked = true;
            }
            PVOID *swapChain3Vtable = IMGUI_INBOUND_NAMESPACE::GetD3D12SwapChain3Vtable();
            if (!resizeBuffers1Done && swapChain3Vtable != nullptr)
            {
                oResizeBuffers1D3D12 = (ResizeBuffers1D3D12)swapChain3Vtable[39];
                PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oResizeBuffers1D3D12, (PVOID)hkResizeBuffers1D3D12);
            }
            resizeBuffers1Done = true;
        }
        std::lock_guard<std::mutex> lock(transitionMutex);
        HWND hwnd = attachedHwnd;
        if (this->isImGuiInitialized && hwnd != nullptr)
        {
            M_IMGUI_IMPL_WIN32_NAMESPACE::Attach(hwnd, &this->inputPolicy);
            this->SetHwnd(hwnd);
        }
        hooksEnabled = true;
    }

    // Disables drawing and input; the hooks and originals stay installed.
    void Dx12Inbound::Detach()
    {
        std::lock_guard<std::mutex> lock(transitionMutex);
        hooksEnabled = false;
        if (HWND hwnd = attachedHwnd)
            M_IMGUI_IMPL_WIN32_NAMESPACE::Detach(hwnd);
        this->SetHwnd(nullptr);
    }

    // Sets or clears ImGuiConfigFlags_ViewportsEnable on the current context.
    static void SetViewportsFlag(bool enable)
    {
        ImGuiIO &io = ImGui::GetIO();
        if (enable)
            io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;
        else
            io.ConfigFlags &= ~ImGuiConfigFlags_ViewportsEnable;
    }

    void Dx12Inbound::InitImGui(IDXGISwapChain3 *pSwapChain)
    {
        if (this->isImGuiInitialized)
            return;
        this->pSwapChain = pSwapChain;
        HRESULT hr = pSwapChain->GetDevice(__uuidof(ID3D12Device), (void **)&this->pd3dDevice);
        if (hr != S_OK)
            _throwV_("Failed to get D3D12 device: {}", hr);

        DXGI_SWAP_CHAIN_DESC sdesc = {};
        pSwapChain->GetDesc(&sdesc);
        HWND host = sdesc.OutputWindow;

        this->pd3dCommandQueue = FindSwapChainQueue(pSwapChain, (void **)IMGUI_INBOUND_NAMESPACE::GetD3D12QueueVtable(), this->pd3dDevice);
        this->queueFallback = this->pd3dCommandQueue == nullptr;
        if (!this->queueFallback)
        {
            fprintf(stderr, "[pyimgui] dx12 inbound: present queue from swap-chain scan\n");
            std::fflush(stderr);
        }

        if (!this->CreateRenderTargets())
            _throw_("Failed to create render targets");

        D3D12_DESCRIPTOR_HEAP_DESC srvDesc = {};
        srvDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
        srvDesc.NumDescriptors = this->bufferCount > 1 ? this->bufferCount : 2;
        srvDesc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;
        if ((hr = this->pd3dDevice->CreateDescriptorHeap(&srvDesc, IID_PPV_ARGS(&this->pd3dSrvDescHeap))) != S_OK)
            _throwV_("Failed to create SRV heap: {}", hr);

        for (UINT i = 0; i < NUM_FRAMES_IN_FLIGHT; i++)
            if ((hr = this->pd3dDevice->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&this->frameContext[i].CommandAllocator))) != S_OK)
                _throwV_("Failed to create command allocator[{}]: {}", i, hr);
        if ((hr = this->pd3dDevice->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, this->frameContext[0].CommandAllocator, nullptr, IID_PPV_ARGS(&this->pd3dCommandList))) != S_OK)
            _throwV_("Failed to create command list: {}", hr);
        if ((hr = this->pd3dCommandList->Close()) != S_OK)
            _throwV_("Failed to close command list: {}", hr);
        if ((hr = this->pd3dDevice->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&this->fence))) != S_OK)
            _throwV_("Failed to create fence: {}", hr);
        if ((this->fenceEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr)) == nullptr)
            _throwV_("Failed to create fence event: {}", GetLastError());
        if ((this->resizeFenceEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr)) == nullptr)
            _throwV_("Failed to create resize fence event: {}", GetLastError());

        this->ctx = ImGui::CreateContext();
        ImGuiIO &io = ImGui::GetIO();
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;
        io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
        io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;
        ImGui::StyleColorsLight();

        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            ImGuiStyle &style = ImGui::GetStyle();
            style.WindowRounding = 0.0f;
            style.Colors[ImGuiCol_WindowBg].w = 1.0f;
        }

        ImGui_ImplWin32_Init(host);
        ImGui_ImplDX12_Init(this->pd3dDevice, NUM_FRAMES_IN_FLIGHT, this->backBufferFormat, this->pd3dSrvDescHeap, this->pd3dSrvDescHeap->GetCPUDescriptorHandleForHeapStart(), this->pd3dSrvDescHeap->GetGPUDescriptorHandleForHeapStart());
        this->viewportsDirty = false;
        SetViewportsFlag(this->viewportsEnable);

        std::lock_guard<std::mutex> lock(transitionMutex);
        this->isImGuiInitialized = true;
        attachedHwnd = host;
        if (hooksEnabled && hookInstance == this)
        {
            M_IMGUI_IMPL_WIN32_NAMESPACE::Attach(host, &this->inputPolicy);
            this->SetHwnd(host);
        }
        dbgPrint("init dx12 inbound success, queue from %s\n", this->queueFallback ? "fallback" : "swap-chain scan");
    }

    // (Re)acquires the swap chain's back buffers and RTVs; rebuilds the RTV heap when BufferCount changed.
    bool Dx12Inbound::CreateRenderTargets()
    {
        DXGI_SWAP_CHAIN_DESC sdesc = {};
        if (this->pSwapChain->GetDesc(&sdesc) != S_OK || sdesc.BufferCount == 0)
            return false;
        this->backBufferFormat = sdesc.BufferDesc.Format;
        if (this->pd3dRtvDescHeap == nullptr || sdesc.BufferCount != this->bufferCount)
        {
            this->CleanupRenderTargets();
            if (this->pd3dRtvDescHeap != nullptr)
            {
                this->pd3dRtvDescHeap->Release();
                this->pd3dRtvDescHeap = nullptr;
            }
            delete[] this->backBuffers;
            this->backBuffers = nullptr;
            this->bufferCount = 0;

            D3D12_DESCRIPTOR_HEAP_DESC rtvDesc = {};
            rtvDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
            rtvDesc.NumDescriptors = sdesc.BufferCount;
            rtvDesc.NodeMask = 1;
            if (this->pd3dDevice->CreateDescriptorHeap(&rtvDesc, IID_PPV_ARGS(&this->pd3dRtvDescHeap)) != S_OK)
                return false;
            this->backBuffers = new BackBuffer[sdesc.BufferCount];
            this->bufferCount = sdesc.BufferCount;
            SIZE_T rtvDescriptorSize = this->pd3dDevice->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);
            D3D12_CPU_DESCRIPTOR_HANDLE rtvHandle = this->pd3dRtvDescHeap->GetCPUDescriptorHandleForHeapStart();
            for (UINT i = 0; i < this->bufferCount; i++)
            {
                this->backBuffers[i].MainRenderTargetDescriptor = rtvHandle;
                rtvHandle.ptr += rtvDescriptorSize;
            }
        }
        for (UINT i = 0; i < this->bufferCount; i++)
        {
            ID3D12Resource *backBuffer = nullptr;
            if (this->pSwapChain->GetBuffer(i, IID_PPV_ARGS(&backBuffer)) != S_OK)
            {
                this->CleanupRenderTargets();
                return false;
            }
            this->pd3dDevice->CreateRenderTargetView(backBuffer, nullptr, this->backBuffers[i].MainRenderTargetDescriptor);
            this->backBuffers[i].MainRenderTargetResource = backBuffer;
        }
        return true;
    }

    void Dx12Inbound::CleanupRenderTargets()
    {
        for (UINT i = 0; i < this->bufferCount; i++)
            if (this->backBuffers[i].MainRenderTargetResource != nullptr)
            {
                this->backBuffers[i].MainRenderTargetResource->Release();
                this->backBuffers[i].MainRenderTargetResource = nullptr;
            }
    }

    // Returns false when the GPU has not reached `value` within timeoutMs; each calling thread passes its own event.
    bool Dx12Inbound::WaitForFence(UINT64 value, HANDLE event, DWORD timeoutMs)
    {
        if (value == 0 || this->fence->GetCompletedValue() >= value)
            return true;
        if (this->fence->SetEventOnCompletion(value, event) != S_OK)
            return false;
        ULONGLONG deadline = GetTickCount64() + timeoutMs;
        while (this->fence->GetCompletedValue() < value)
        {
            ULONGLONG now = GetTickCount64();
            if (now >= deadline)
                return false;
            WaitForSingleObject(event, (DWORD)(deadline - now));
        }
        return true;
    }

    void Dx12Inbound::SetCommandQueue(ID3D12CommandQueue *queue)
    {
        if (queue == this->pd3dCommandQueue)
            return;
        if (queue != nullptr)
            queue->AddRef();
        if (this->pd3dCommandQueue != nullptr)
            this->pd3dCommandQueue->Release();
        this->pd3dCommandQueue = queue;
    }

    // Records a DIRECT queue of our device: one submitted inside the game's Present, or the first one after a Present.
    void Dx12Inbound::OfferFallbackQueue(ID3D12CommandQueue *queue, bool fromPresent)
    {
        std::atomic<ID3D12CommandQueue *> &slot = fromPresent ? this->fallbackQueueFromPresent : this->fallbackQueueAfterPresent;
        if (slot.load() != nullptr || (!fromPresent && !presentSeen))
            return;
        if (queue->GetDesc().Type != D3D12_COMMAND_LIST_TYPE_DIRECT)
            return;
        ID3D12Device *device = nullptr;
        if (queue->GetDevice(IID_PPV_ARGS(&device)) != S_OK)
            return;
        device->Release();
        if (device != this->pd3dDevice)
            return;
        ID3D12CommandQueue *expected = nullptr;
        queue->AddRef();
        if (!slot.compare_exchange_strong(expected, queue))
            queue->Release();
    }

    void Dx12Inbound::BeforeResize()
    {
        this->WaitForFence(this->fenceLastSignaledValue, this->resizeFenceEvent, FENCE_TIMEOUT_MS);
        this->CleanupRenderTargets();
    }

    // Adopts ResizeBuffers1's present queue when it is one queue on node 0; otherwise stops drawing.
    void Dx12Inbound::AfterResize(const UINT *pCreationNodeMask, IUnknown *const *ppPresentQueue)
    {
        if (ppPresentQueue != nullptr)
        {
            DXGI_SWAP_CHAIN_DESC sdesc = {};
            bool supported = this->pSwapChain->GetDesc(&sdesc) == S_OK && sdesc.BufferCount > 0 && ppPresentQueue[0] != nullptr;
            for (UINT i = 0; supported && i < sdesc.BufferCount; i++)
                supported = ppPresentQueue[i] == ppPresentQueue[0] && (pCreationNodeMask == nullptr || pCreationNodeMask[i] <= 1);
            ID3D12CommandQueue *queue = nullptr;
            if (supported && ppPresentQueue[0]->QueryInterface(IID_PPV_ARGS(&queue)) == S_OK)
            {
                this->SetCommandQueue(queue);
                queue->Release();
                fprintf(stderr, "[pyimgui] dx12 inbound: present queue from ResizeBuffers1\n");
            }
            else
            {
                this->SetCommandQueue(nullptr);
                fprintf(stderr, "[pyimgui] dx12 inbound: unsupported ResizeBuffers1 present queues or node masks, drawing disabled\n");
            }
            std::fflush(stderr);
            this->queueFallback = false;
            ReleaseFallbackQueues(this);
        }
        if (!this->CreateRenderTargets())
        {
            fprintf(stderr, "[pyimgui] dx12 inbound: failed to recreate render targets after resize, retrying each frame\n");
            std::fflush(stderr);
        }
    }

    void Dx12Inbound::_Update()
    {
        if (this->queueFallback)
        {
            ID3D12CommandQueue *fromPresent = this->fallbackQueueFromPresent.load();
            ID3D12CommandQueue *queue = fromPresent != nullptr ? fromPresent : this->fallbackQueueAfterPresent.load();
            if (queue != nullptr && queue != this->pd3dCommandQueue)
            {
                this->SetCommandQueue(queue);
                fprintf(stderr, "[pyimgui] dx12 inbound: present queue from ExecuteCommandLists fallback\n");
                std::fflush(stderr);
            }
            // Adopts a queue submitted inside Present for good and drops the slot references.
            if (fromPresent != nullptr)
            {
                this->queueFallback = false;
                ReleaseFallbackQueues(this);
            }
        }
        if (!this->pd3dCommandQueue)
            return;
        UINT backBufferIdx = this->pSwapChain->GetCurrentBackBufferIndex();
        if (backBufferIdx >= this->bufferCount || this->backBuffers[backBufferIdx].MainRenderTargetResource == nullptr)
        {
            // Re-acquires back buffers released while disabled or by a failed resize.
            this->CleanupRenderTargets();
            if (!this->CreateRenderTargets() || backBufferIdx >= this->bufferCount)
                return;
        }
        FrameContext &frameCtx = this->frameContext[this->frameIndex % NUM_FRAMES_IN_FLIGHT];
        if (!this->WaitForFence(frameCtx.FenceValue, this->fenceEvent, FENCE_TIMEOUT_MS))
        {
            if (!fenceTimeoutReported.exchange(true))
            {
                fprintf(stderr, "[pyimgui] dx12 inbound: GPU fence wait timed out, skipping frames\n");
                std::fflush(stderr);
            }
            return;
        }
        // Runs on the game's render thread inside Present, which does not hold the GIL.
        if (IsFinalizing())
            return;
        bool raised = false;
        {
            py::gil_scoped_acquire gil;
            if (hookInstance != this)
                return;
            py::object self = py::cast(this, py::return_value_policy::reference);
            try
            {
                this->ProcessCallBeforeFrameOnce(self);
            }
            catch (std::exception &e)
            {
                fprintf(stderr, "[pyimgui] dx12 inbound CallBeforeFrameOnce raised:\n%s\n", e.what());
                std::fflush(stderr);
                raised = true;
            }
            DeferLastReference(self);
        }
        if (raised)
        {
            DisableFromHook("CallBeforeFrameOnce raised");
            return;
        }

        // ImGui asserts when ViewportsEnable is first set on frame 1, so an assignment then waits one frame.
        if (ImGui::GetFrameCount() != 1 && this->viewportsDirty.exchange(false))
            SetViewportsFlag(this->viewportsEnable);
        ImGui_ImplDX12_NewFrame();
        ImGui_ImplWin32_NewFrame();
        this->GateGamepad(this->inputPolicy.load() == (int)OVERLAY_TYPES_NAMESPACE::InputPolicy::PassAll);
        ImGui::NewFrame();
        if (IsFinalizing())
            return;
        {
            py::gil_scoped_acquire gil;
            if (hookInstance != this)
                return;
            py::object self = py::cast(this, py::return_value_policy::reference);
            try
            {
                this->ProcessRenderCallback(self);
            }
            catch (std::exception &e)
            {
                fprintf(stderr, "[pyimgui] dx12 inbound render callback raised, detaching:\n%s\n", e.what());
                std::fflush(stderr);
                raised = true;
            }
            DeferLastReference(self);
        }
        if (raised)
        {
            DisableFromHook("render callback raised");
            return;
        }

        BackBuffer &backBuffer = this->backBuffers[backBufferIdx];
        frameCtx.CommandAllocator->Reset();
        D3D12_RESOURCE_BARRIER barrier = {};
        barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
        barrier.Transition.pResource = backBuffer.MainRenderTargetResource;
        barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
        barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_PRESENT;
        barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_RENDER_TARGET;

        this->pd3dCommandList->Reset(frameCtx.CommandAllocator, nullptr);
        this->pd3dCommandList->ResourceBarrier(1, &barrier);
        this->pd3dCommandList->OMSetRenderTargets(1, &backBuffer.MainRenderTargetDescriptor, FALSE, nullptr);
        this->pd3dCommandList->SetDescriptorHeaps(1, &this->pd3dSrvDescHeap);

        ImGui::EndFrame();
        ImGui::Render();
        ImGui_ImplDX12_RenderDrawData(ImGui::GetDrawData(), this->pd3dCommandList);

        barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_RENDER_TARGET;
        barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_PRESENT;
        this->pd3dCommandList->ResourceBarrier(1, &barrier);
        this->pd3dCommandList->Close();
        this->pd3dCommandQueue->ExecuteCommandLists(1, (ID3D12CommandList *const *)&this->pd3dCommandList);
        UINT64 fenceValue = this->fenceLastSignaledValue + 1;
        this->pd3dCommandQueue->Signal(this->fence, fenceValue);
        this->fenceLastSignaledValue = fenceValue;
        frameCtx.FenceValue = fenceValue;
        this->frameIndex++;

        // Runs every frame: ImGui's sanity check expects it even while viewports are off.
        ImGui::UpdatePlatformWindows();
        if (ImGui::GetCurrentContext()->ConfigFlagsCurrFrame & ImGuiConfigFlags_ViewportsEnable)
            ImGui::RenderPlatformWindowsDefault(nullptr, (void *)this->pd3dCommandList);
    }

    void Dx12Inbound::Update()
    {
        LogicScope logic;
        this->_Update();
    }

    void pybind_setup_mImguiImpl_Dx12(pybind11::module_ m)
    {
        pybind_setup_mImguiImpl_RenderBase(m);
        py::class_<Dx12TextureHelper>(m, "Dx12TextureHelper", py::dynamic_attr(), py::module_local())
            .def("LoadTextureFromFile", &Dx12TextureHelper::LoadTextureFromFile)
            .def("FreeTexture", &Dx12TextureHelper::FreeTexture)
            .def("__bool__", [](const Dx12TextureHelper &self) { return self.srv != nullptr; })
            .def_property_readonly("handle", &Dx12TextureHelper::GetHandle)
            .def_property_readonly("width", [](const Dx12TextureHelper &self) { return self.width; })
            .def_property_readonly("height", [](const Dx12TextureHelper &self) { return self.height; })
            .def_property_readonly("size", &Dx12TextureHelper::GetSize);

        py::class_<Dx12Render, RenderBase>(m, "Dx12Render", py::dynamic_attr(), py::module_local())
            .def_static("InvalidateDeviceObjects", []() { ImGui_ImplDX12_InvalidateDeviceObjects(); })
            .def_static("CreateDeviceObjects", []() { LogicScope ownSubmit; return ImGui_ImplDX12_CreateDeviceObjects(); })
            .def("CreateTexture", [](Dx12Render &self, const char *filename) { return self.CreateTexture(filename); }, py::arg("filename"), py::return_value_policy::take_ownership)
            .def("CreateTexture", [](Dx12Render &self) { return self.CreateTexture(); }, py::return_value_policy::take_ownership);

        py::class_<Dx12Window, Dx12Render> dx12Window(m, "Dx12Window", py::dynamic_attr(), py::module_local());
        dx12Window.def(py::init<std::optional<py::function>>(), py::arg("renderCallback") = py::none())
            .def_readwrite("ClearColor", &Dx12Window::ClearColor);
        Overlay::BindMembers(dx12Window);

        py::class_<Dx12Inbound, Dx12Render>(m, "Dx12Inbound", py::dynamic_attr(), py::module_local())
            .def(py::init<std::optional<py::function>>(), py::arg("renderCallback") = py::none())
            .def_property_readonly("isInLogic", [](Dx12Inbound &) { return logicDepth > 0; })
            .def_property("viewportsEnable",
                          [](Dx12Inbound &self) { return self.viewportsEnable.load(); },
                          [](Dx12Inbound &self, bool enable)
                          {
                              self.viewportsEnable = enable;
                              self.viewportsDirty = true;
                          })
            .def("Attach", &Dx12Inbound::Attach)
            .def("Detach", &Dx12Inbound::Detach);
    }
}
END_M_IMGUI_IMPL_DX12_NAMESPACE