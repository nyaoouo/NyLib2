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

            this->ProcessCallBeforeFrameOnce(py::cast(this));

            ImGui_ImplDX12_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();
            this->ProcessRenderCallback(py::cast(this));
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
    typedef void(__fastcall *DrawInstancedD3D12)(ID3D12GraphicsCommandList *dCommandList, UINT VertexCountPerInstance, UINT InstanceCount, UINT StartVertexLocation, UINT StartInstanceLocation);
    typedef void(__fastcall *DrawIndexedInstancedD3D12)(ID3D12GraphicsCommandList *dCommandList, UINT IndexCount, UINT InstanceCount, UINT StartIndex, INT BaseVertex);
    typedef HRESULT(__fastcall *ExecuteCommandListsD3D12)(ID3D12CommandQueue *dCommandQueue, UINT NumCommandLists, ID3D12CommandList *const *ppCommandLists);
    typedef HRESULT(__fastcall *SignalD3D12)(ID3D12CommandQueue *dCommandQueue, ID3D12Fence *dFence, UINT64 Value);

    static PresentD3D12 oPresentD3D12 = nullptr;
    static DrawInstancedD3D12 oDrawInstancedD3D12 = nullptr;
    static DrawIndexedInstancedD3D12 oDrawIndexedInstancedD3D12 = nullptr;
    static ExecuteCommandListsD3D12 oExecuteCommandListsD3D12 = nullptr;
    static SignalD3D12 oSignalD3D12 = nullptr;

    long __fastcall hkPresentD3D12(IDXGISwapChain3 *pSwapChain, UINT SyncInterval, UINT Flags)
    {
        if (Dx12Inbound::_instance != nullptr && (Dx12Inbound::_instance->pSwapChain == nullptr || Dx12Inbound::_instance->pSwapChain == pSwapChain))
        {
            try
            {
                if (!Dx12Inbound::_instance->isImGuiInitialized)
                    Dx12Inbound::_instance->InitImGui(pSwapChain);
                Dx12Inbound::_instance->Update();
            }
            catch (const std::exception &e)
            {
                (void)e;
                dbgPrint("Dx12Inbound::Update() exception: %s\n", e.what());
                Dx12Inbound::_instance->Detach();
            }
        }
        return oPresentD3D12(pSwapChain, SyncInterval, Flags);
    }

    void __fastcall hkDrawInstancedD3D12(ID3D12GraphicsCommandList *dCommandList, UINT VertexCountPerInstance, UINT InstanceCount, UINT StartVertexLocation, UINT StartInstanceLocation)
    {
        oDrawInstancedD3D12(dCommandList, VertexCountPerInstance, InstanceCount, StartVertexLocation, StartInstanceLocation);
    }

    void __fastcall hkDrawIndexedInstancedD3D12(ID3D12GraphicsCommandList *dCommandList, UINT IndexCount, UINT InstanceCount, UINT StartIndex, INT BaseVertex)
    {
        oDrawIndexedInstancedD3D12(dCommandList, IndexCount, InstanceCount, StartIndex, BaseVertex);
    }

    HRESULT __fastcall hkExecuteCommandListsD3D12(ID3D12CommandQueue *dCommandQueue, UINT NumCommandLists, ID3D12CommandList *const *ppCommandLists)
    {
        if (Dx12Inbound::_instance != nullptr && Dx12Inbound::_instance->pd3dCommandQueue == nullptr)
            Dx12Inbound::_instance->pd3dCommandQueue = dCommandQueue;
        return oExecuteCommandListsD3D12(dCommandQueue, NumCommandLists, ppCommandLists);
    }

    HRESULT __fastcall hkSignalD3D12(ID3D12CommandQueue *dCommandQueue, ID3D12Fence *dFence, UINT64 Value)
    {
        if (dCommandQueue != nullptr && Dx12Inbound::_instance != nullptr && Dx12Inbound::_instance->pd3dCommandQueue == dCommandQueue)
        {
            Dx12Inbound::_instance->fence = dFence;
            Dx12Inbound::_instance->fenceLastSignaledValue = Value;
        }
        return oSignalD3D12(dCommandQueue, dFence, Value);
    }

    void Dx12Inbound::Attach()
    {
        IMGUI_INBOUND_NAMESPACE::Init(IMGUI_INBOUND_NAMESPACE::D3D12);
        oPresentD3D12 = (PresentD3D12)IMGUI_INBOUND_NAMESPACE::GetMethod(140);
        oDrawInstancedD3D12 = (DrawInstancedD3D12)IMGUI_INBOUND_NAMESPACE::GetMethod(84);
        oDrawIndexedInstancedD3D12 = (DrawIndexedInstancedD3D12)IMGUI_INBOUND_NAMESPACE::GetMethod(85);
        oExecuteCommandListsD3D12 = (ExecuteCommandListsD3D12)IMGUI_INBOUND_NAMESPACE::GetMethod(54);
        oSignalD3D12 = (SignalD3D12)IMGUI_INBOUND_NAMESPACE::GetMethod(58);
        PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oPresentD3D12, (PVOID)hkPresentD3D12);
        PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oDrawInstancedD3D12, (PVOID)hkDrawInstancedD3D12);
        PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oDrawIndexedInstancedD3D12, (PVOID)hkDrawIndexedInstancedD3D12);
        PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oExecuteCommandListsD3D12, (PVOID)hkExecuteCommandListsD3D12);
        PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oSignalD3D12, (PVOID)hkSignalD3D12);
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
        if (oDrawInstancedD3D12 != nullptr)
            PYDETOURS_NAMESPACE::SimpleDetach((PVOID *)&oDrawInstancedD3D12, (PVOID)hkDrawInstancedD3D12);
        if (oDrawIndexedInstancedD3D12 != nullptr)
            PYDETOURS_NAMESPACE::SimpleDetach((PVOID *)&oDrawIndexedInstancedD3D12, (PVOID)hkDrawIndexedInstancedD3D12);
        if (oExecuteCommandListsD3D12 != nullptr)
            PYDETOURS_NAMESPACE::SimpleDetach((PVOID *)&oExecuteCommandListsD3D12, (PVOID)hkExecuteCommandListsD3D12);
        if (oSignalD3D12 != nullptr)
            PYDETOURS_NAMESPACE::SimpleDetach((PVOID *)&oSignalD3D12, (PVOID)hkSignalD3D12);
        oPresentD3D12 = nullptr;
        oDrawInstancedD3D12 = nullptr;
        oDrawIndexedInstancedD3D12 = nullptr;
        oExecuteCommandListsD3D12 = nullptr;
        oSignalD3D12 = nullptr;
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
        this->bufferCount = sdesc.BufferCount;
        this->frameContext = new FrameContext[this->bufferCount];

        M_IMGUI_IMPL_WIN32_NAMESPACE::Attach(this->hwnd);

        D3D12_DESCRIPTOR_HEAP_DESC rtvDesc = {};
        rtvDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
        rtvDesc.NumDescriptors = this->bufferCount;
        rtvDesc.NodeMask = 1;
        if ((hr = this->pd3dDevice->CreateDescriptorHeap(&rtvDesc, IID_PPV_ARGS(&this->pd3dRtvDescHeap))) != S_OK)
            _throwV_("Failed to create RTV heap: {}", hr);

        SIZE_T rtvDescriptorSize = this->pd3dDevice->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);
        D3D12_CPU_DESCRIPTOR_HANDLE rtvHandle = this->pd3dRtvDescHeap->GetCPUDescriptorHandleForHeapStart();
        for (UINT i = 0; i < this->bufferCount; i++)
        {
            ID3D12Resource *backBuffer = nullptr;
            this->frameContext[i].MainRenderTargetDescriptor = rtvHandle;
            pSwapChain->GetBuffer(i, IID_PPV_ARGS(&backBuffer));
            this->pd3dDevice->CreateRenderTargetView(backBuffer, nullptr, rtvHandle);
            this->frameContext[i].MainRenderTargetResource = backBuffer;
            rtvHandle.ptr += rtvDescriptorSize;
        }

        D3D12_DESCRIPTOR_HEAP_DESC srvDesc = {};
        srvDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
        srvDesc.NumDescriptors = this->bufferCount > 1 ? this->bufferCount : 2;
        srvDesc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;
        if ((hr = this->pd3dDevice->CreateDescriptorHeap(&srvDesc, IID_PPV_ARGS(&this->pd3dSrvDescHeap))) != S_OK)
            _throwV_("Failed to create SRV heap: {}", hr);

        for (UINT i = 0; i < this->bufferCount; i++)
            if ((hr = this->pd3dDevice->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&this->frameContext[i].CommandAllocator))) != S_OK)
                _throwV_("Failed to create command allocator[{}]: {}", i, hr);
        if ((hr = this->pd3dDevice->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, this->frameContext[0].CommandAllocator, nullptr, IID_PPV_ARGS(&this->pd3dCommandList))) != S_OK)
            _throwV_("Failed to create command list: {}", hr);

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
        ImGui_ImplDX12_Init(this->pd3dDevice, this->bufferCount, DXGI_FORMAT_R8G8B8A8_UNORM, this->pd3dSrvDescHeap, this->pd3dSrvDescHeap->GetCPUDescriptorHandleForHeapStart(), this->pd3dSrvDescHeap->GetGPUDescriptorHandleForHeapStart());
        this->isImGuiInitialized = true;
        dbgPrint("init dx12 inbound success\n");
    }

    void Dx12Inbound::_Update()
    {
        if (!this->pd3dCommandQueue)
            return;
        this->ProcessCallBeforeFrameOnce(py::cast(this));

        ImGui_ImplDX12_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        try
        {
            this->ProcessRenderCallback(py::cast(this));
        }
        catch (std::exception &e)
        {
            printf("Error in render callback, detach: \n%s\n", e.what());
            this->Detach();
            return;
        }

        FrameContext &currentFrameContext = this->frameContext[this->pSwapChain->GetCurrentBackBufferIndex()];
        currentFrameContext.CommandAllocator->Reset();
        D3D12_RESOURCE_BARRIER barrier = {};
        barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
        barrier.Transition.pResource = currentFrameContext.MainRenderTargetResource;
        barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
        barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_PRESENT;
        barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_RENDER_TARGET;

        this->pd3dCommandList->Reset(currentFrameContext.CommandAllocator, nullptr);
        this->pd3dCommandList->ResourceBarrier(1, &barrier);
        this->pd3dCommandList->OMSetRenderTargets(1, &currentFrameContext.MainRenderTargetDescriptor, FALSE, nullptr);
        this->pd3dCommandList->SetDescriptorHeaps(1, &this->pd3dSrvDescHeap);

        ImGui::EndFrame();
        ImGui::Render();
        ImGui_ImplDX12_RenderDrawData(ImGui::GetDrawData(), this->pd3dCommandList);

        barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_RENDER_TARGET;
        barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_PRESENT;
        this->pd3dCommandList->ResourceBarrier(1, &barrier);
        this->pd3dCommandList->Close();
        this->pd3dCommandQueue->ExecuteCommandLists(1, (ID3D12CommandList *const *)&this->pd3dCommandList);

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