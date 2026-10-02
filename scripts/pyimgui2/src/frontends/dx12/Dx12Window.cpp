#include "./Dx12Window.h"
#include "../common/ImguiInbound.h"
#include "../common/PyDetours.h"

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

START_M_IMGUI_IMPL_DX12_NAMESPACE
{
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
        cmdQueue->ExecuteCommandLists(1, (ID3D12CommandList *const *)&cmdList);
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

    Dx12Inbound::Dx12Inbound(std::optional<py::function> renderCallback) : Dx12Render(renderCallback)
    {
        if (_instance != nullptr)
            _throw_("Only one Dx12Inbound instance is allowed");
        _instance = this;
    }

    Dx12Inbound::~Dx12Inbound()
    {
        this->Detach();
        if (_instance == this)
            _instance = nullptr;
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
    static thread_local int resizeDepth = 0;
    static std::atomic<bool> presentSeen{false};
    static std::atomic<bool> fenceTimeoutReported{false};
    static size_t const SWAP_CHAIN_SCAN_SIZE = 0x400;
    static DWORD const FENCE_TIMEOUT_MS = 1000;

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
        Dx12Inbound *instance = Dx12Inbound::_instance;
        if (instance == nullptr || (instance->pSwapChain != nullptr && instance->pSwapChain != pSwapChain))
            return oPresentD3D12(pSwapChain, SyncInterval, Flags);
        try
        {
            if (!instance->isImGuiInitialized)
                instance->InitImGui(pSwapChain);
            instance->Update();
        }
        catch (const std::exception &e)
        {
            (void)e;
            dbgPrint("Dx12Inbound::Update() exception: %s\n", e.what());
            instance->Detach();
        }
        inGamePresent = true;
        long result = oPresentD3D12(pSwapChain, SyncInterval, Flags);
        inGamePresent = false;
        presentSeen = true;
        return result;
    }

    void __fastcall hkExecuteCommandListsD3D12(ID3D12CommandQueue *dCommandQueue, UINT NumCommandLists, ID3D12CommandList *const *ppCommandLists)
    {
        Dx12Inbound *instance = Dx12Inbound::_instance;
        if (instance != nullptr && instance->queueFallback && !instance->isInLogic)
            instance->OfferFallbackQueue(dCommandQueue, inGamePresent);
        oExecuteCommandListsD3D12(dCommandQueue, NumCommandLists, ppCommandLists);
    }

    HRESULT __fastcall hkResizeBuffersD3D12(IDXGISwapChain3 *pSwapChain, UINT BufferCount, UINT Width, UINT Height, DXGI_FORMAT NewFormat, UINT SwapChainFlags)
    {
        Dx12Inbound *instance = Dx12Inbound::_instance;
        if (resizeDepth > 0 || instance == nullptr || !instance->isImGuiInitialized || instance->pSwapChain != pSwapChain)
            return oResizeBuffersD3D12(pSwapChain, BufferCount, Width, Height, NewFormat, SwapChainFlags);
        resizeDepth++;
        instance->BeforeResize();
        HRESULT hr = oResizeBuffersD3D12(pSwapChain, BufferCount, Width, Height, NewFormat, SwapChainFlags);
        instance->AfterResize(nullptr, nullptr);
        resizeDepth--;
        return hr;
    }

    HRESULT __fastcall hkResizeBuffers1D3D12(IDXGISwapChain3 *pSwapChain, UINT BufferCount, UINT Width, UINT Height, DXGI_FORMAT Format, UINT SwapChainFlags, const UINT *pCreationNodeMask, IUnknown *const *ppPresentQueue)
    {
        Dx12Inbound *instance = Dx12Inbound::_instance;
        if (resizeDepth > 0 || instance == nullptr || !instance->isImGuiInitialized || instance->pSwapChain != pSwapChain)
            return oResizeBuffers1D3D12(pSwapChain, BufferCount, Width, Height, Format, SwapChainFlags, pCreationNodeMask, ppPresentQueue);
        resizeDepth++;
        instance->BeforeResize();
        HRESULT hr = oResizeBuffers1D3D12(pSwapChain, BufferCount, Width, Height, Format, SwapChainFlags, pCreationNodeMask, ppPresentQueue);
        instance->AfterResize(pCreationNodeMask, SUCCEEDED(hr) ? ppPresentQueue : nullptr);
        resizeDepth--;
        return hr;
    }

    void Dx12Inbound::Attach()
    {
        IMGUI_INBOUND_NAMESPACE::Init(IMGUI_INBOUND_NAMESPACE::D3D12);
        oPresentD3D12 = (PresentD3D12)IMGUI_INBOUND_NAMESPACE::GetMethod(140);
        oExecuteCommandListsD3D12 = (ExecuteCommandListsD3D12)IMGUI_INBOUND_NAMESPACE::GetMethod(54);
        oResizeBuffersD3D12 = (ResizeBuffersD3D12)IMGUI_INBOUND_NAMESPACE::GetMethod(145);
        PVOID *swapChain3Vtable = IMGUI_INBOUND_NAMESPACE::GetD3D12SwapChain3Vtable();
        oResizeBuffers1D3D12 = swapChain3Vtable != nullptr ? (ResizeBuffers1D3D12)swapChain3Vtable[39] : nullptr;
        PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oPresentD3D12, (PVOID)hkPresentD3D12);
        PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oExecuteCommandListsD3D12, (PVOID)hkExecuteCommandListsD3D12);
        PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oResizeBuffersD3D12, (PVOID)hkResizeBuffersD3D12);
        if (oResizeBuffers1D3D12 != nullptr)
            PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oResizeBuffers1D3D12, (PVOID)hkResizeBuffers1D3D12);
    }

    void Dx12Inbound::Detach()
    {
        if (this->hwnd != nullptr)
        {
            M_IMGUI_IMPL_WIN32_NAMESPACE::Detach(this->hwnd);
            this->hwnd = nullptr;
        }
        if (oPresentD3D12 != nullptr)
            PYDETOURS_NAMESPACE::SimpleDetach((PVOID *)&oPresentD3D12, (PVOID)hkPresentD3D12);
        if (oExecuteCommandListsD3D12 != nullptr)
            PYDETOURS_NAMESPACE::SimpleDetach((PVOID *)&oExecuteCommandListsD3D12, (PVOID)hkExecuteCommandListsD3D12);
        if (oResizeBuffersD3D12 != nullptr)
            PYDETOURS_NAMESPACE::SimpleDetach((PVOID *)&oResizeBuffersD3D12, (PVOID)hkResizeBuffersD3D12);
        if (oResizeBuffers1D3D12 != nullptr)
            PYDETOURS_NAMESPACE::SimpleDetach((PVOID *)&oResizeBuffers1D3D12, (PVOID)hkResizeBuffers1D3D12);
        oPresentD3D12 = nullptr;
        oExecuteCommandListsD3D12 = nullptr;
        oResizeBuffersD3D12 = nullptr;
        oResizeBuffers1D3D12 = nullptr;
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
        this->SetHwnd(sdesc.OutputWindow);

        this->pd3dCommandQueue = FindSwapChainQueue(pSwapChain, (void **)IMGUI_INBOUND_NAMESPACE::GetD3D12QueueVtable(), this->pd3dDevice);
        this->queueFallback = this->pd3dCommandQueue == nullptr;
        if (!this->queueFallback)
        {
            fprintf(stderr, "[pyimgui] dx12 inbound: present queue from swap-chain scan\n");
            std::fflush(stderr);
        }

        M_IMGUI_IMPL_WIN32_NAMESPACE::Attach(this->hwnd);

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

        ImGui_ImplWin32_Init(this->hwnd);
        ImGui_ImplDX12_Init(this->pd3dDevice, NUM_FRAMES_IN_FLIGHT, DXGI_FORMAT_R8G8B8A8_UNORM, this->pd3dSrvDescHeap, this->pd3dSrvDescHeap->GetCPUDescriptorHandleForHeapStart(), this->pd3dSrvDescHeap->GetGPUDescriptorHandleForHeapStart());
        this->isImGuiInitialized = true;
        dbgPrint("init dx12 inbound success, queue from %s\n", this->queueFallback ? "fallback" : "swap-chain scan");
    }

    // (Re)acquires the swap chain's back buffers and RTVs; rebuilds the RTV heap when BufferCount changed.
    bool Dx12Inbound::CreateRenderTargets()
    {
        DXGI_SWAP_CHAIN_DESC sdesc = {};
        if (this->pSwapChain->GetDesc(&sdesc) != S_OK || sdesc.BufferCount == 0)
            return false;
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
        }
        if (!this->CreateRenderTargets())
        {
            fprintf(stderr, "[pyimgui] dx12 inbound: failed to recreate render targets after resize, drawing paused\n");
            std::fflush(stderr);
        }
    }

    void Dx12Inbound::_Update()
    {
        if (this->queueFallback)
        {
            ID3D12CommandQueue *queue = this->fallbackQueueFromPresent.load();
            if (queue == nullptr)
                queue = this->fallbackQueueAfterPresent.load();
            if (queue != nullptr && queue != this->pd3dCommandQueue)
            {
                this->SetCommandQueue(queue);
                fprintf(stderr, "[pyimgui] dx12 inbound: present queue from ExecuteCommandLists fallback\n");
                std::fflush(stderr);
            }
        }
        if (!this->pd3dCommandQueue)
            return;
        UINT backBufferIdx = this->pSwapChain->GetCurrentBackBufferIndex();
        if (backBufferIdx >= this->bufferCount || this->backBuffers[backBufferIdx].MainRenderTargetResource == nullptr)
            return;
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
        {
            py::gil_scoped_acquire gil;
            py::object self = py::cast(this, py::return_value_policy::reference);
            this->ProcessCallBeforeFrameOnce(self);
        }

        ImGui_ImplDX12_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        try
        {
            py::gil_scoped_acquire gil;
            py::object self = py::cast(this, py::return_value_policy::reference);
            this->ProcessRenderCallback(self);
        }
        catch (std::exception &e)
        {
            // `e` may be error_already_set: what() and its destructor need the GIL.
            py::gil_scoped_acquire gil;
            fprintf(stderr, "[pyimgui] dx12 inbound render callback raised, detaching:\n%s\n", e.what());
            std::fflush(stderr);
            this->Detach();
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

        if (ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault(nullptr, (void *)this->pd3dCommandList);
        }
    }

    void Dx12Inbound::Update()
    {
        this->isInLogic = true;
        this->_Update();
        this->isInLogic = false;
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
            .def_static("CreateDeviceObjects", []() { return ImGui_ImplDX12_CreateDeviceObjects(); })
            .def("CreateTexture", [](Dx12Render &self, const char *filename) { return self.CreateTexture(filename); }, py::arg("filename"), py::return_value_policy::take_ownership)
            .def("CreateTexture", [](Dx12Render &self) { return self.CreateTexture(); }, py::return_value_policy::take_ownership);

        py::class_<Dx12Window, Dx12Render>(m, "Dx12Window", py::dynamic_attr(), py::module_local())
            .def(py::init<std::optional<py::function>>(), py::arg("renderCallback") = py::none())
            .def_readwrite("ClearColor", &Dx12Window::ClearColor)
            .def("Serve", &Dx12Window::Serve, py::call_guard<py::gil_scoped_release>());

        py::class_<Dx12Inbound, Dx12Render>(m, "Dx12Inbound", py::dynamic_attr(), py::module_local())
            .def(py::init<std::optional<py::function>>(), py::arg("renderCallback") = py::none())
            .def_property_readonly("isInLogic", [](Dx12Inbound &self) { return self.isInLogic; })
            .def("Attach", &Dx12Inbound::Attach)
            .def("Detach", &Dx12Inbound::Detach);
    }
}
END_M_IMGUI_IMPL_DX12_NAMESPACE