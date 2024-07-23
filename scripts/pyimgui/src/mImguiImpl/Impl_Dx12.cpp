#include "./Impl_Dx12.h"

START_M_IMGUI_IMPL_Dx12_NAMESPACE
{
    LRESULT WINAPI Dx12ImguiWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
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
                assert(SUCCEEDED(result) && "Failed to resize swapchain.");
                instance->CreateRenderTarget();
            }
            return 0;
        }
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
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

        // Setup swap chain
        DXGI_SWAP_CHAIN_DESC1 sd;
        {
            ZeroMemory(&sd, sizeof(sd));
            sd.BufferCount = NUM_BACK_BUFFERS;
            sd.Width = 0;
            sd.Height = 0;
            sd.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
            sd.Flags = DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT;
            sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
            sd.SampleDesc.Count = 1;
            sd.SampleDesc.Quality = 0;
            sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
            sd.AlphaMode = DXGI_ALPHA_MODE_UNSPECIFIED;
            sd.Scaling = DXGI_SCALING_STRETCH;
            sd.Stereo = FALSE;
        }

        // [DEBUG] Enable debug interface
#ifdef DX12_ENABLE_DEBUG_LAYER
        ID3D12Debug *pdx12Debug = nullptr;
        if (SUCCEEDED(D3D12GetDebugInterface(IID_PPV_ARGS(&pdx12Debug))))
            pdx12Debug->EnableDebugLayer();
#endif

        // Create device
        D3D_FEATURE_LEVEL featureLevel = D3D_FEATURE_LEVEL_11_0;
        if (hr = D3D12CreateDevice(nullptr, featureLevel, IID_PPV_ARGS(&this->pd3dDevice)); hr != S_OK)
        {
            _throwV_("Failed to create device, error code: {}", hr);
        }

        // [DEBUG] Setup debug interface to break on any warnings/errors
#ifdef DX12_ENABLE_DEBUG_LAYER
        if (pdx12Debug != nullptr)
        {
            ID3D12InfoQueue *pInfoQueue = nullptr;
            this->pd3dDevice->QueryInterface(IID_PPV_ARGS(&pInfoQueue));
            pInfoQueue->SetBreakOnSeverity(D3D12_MESSAGE_SEVERITY_ERROR, true);
            pInfoQueue->SetBreakOnSeverity(D3D12_MESSAGE_SEVERITY_CORRUPTION, true);
            pInfoQueue->SetBreakOnSeverity(D3D12_MESSAGE_SEVERITY_WARNING, true);
            pInfoQueue->Release();
            pdx12Debug->Release();
        }
#endif

        {
            D3D12_DESCRIPTOR_HEAP_DESC desc = {};
            desc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
            desc.NumDescriptors = NUM_BACK_BUFFERS;
            desc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_NONE;
            desc.NodeMask = 1;
            if (hr = this->pd3dDevice->CreateDescriptorHeap(&desc, IID_PPV_ARGS(&this->pd3dRtvDescHeap)); hr != S_OK)
            {
                _throwV_("Failed to create descriptor heap, error code: {}", hr);
            }

            SIZE_T rtvDescriptorSize = this->pd3dDevice->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);
            D3D12_CPU_DESCRIPTOR_HANDLE rtvHandle = this->pd3dRtvDescHeap->GetCPUDescriptorHandleForHeapStart();
            for (UINT i = 0; i < NUM_BACK_BUFFERS; i++)
            {
                this->mainRenderTargetDescriptor[i] = rtvHandle;
                rtvHandle.ptr += rtvDescriptorSize;
            }
        }

        {
            D3D12_DESCRIPTOR_HEAP_DESC desc = {};
            desc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
            desc.NumDescriptors = 2;
            desc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;
            if (hr = this->pd3dDevice->CreateDescriptorHeap(&desc, IID_PPV_ARGS(&this->pd3dSrvDescHeap)); hr != S_OK)
            {
                _throwV_("Failed to create descriptor heap, error code: {}", hr);
            }
        }

        {
            D3D12_COMMAND_QUEUE_DESC desc = {};
            desc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
            desc.Flags = D3D12_COMMAND_QUEUE_FLAG_NONE;
            desc.NodeMask = 1;
            if (hr = this->pd3dDevice->CreateCommandQueue(&desc, IID_PPV_ARGS(&this->pd3dCommandQueue)); hr != S_OK)
            {
                _throwV_("Failed to create command queue, error code: {}", hr);
            }
        }

        for (UINT i = 0; i < NUM_FRAMES_IN_FLIGHT; i++)
            if (hr = this->pd3dDevice->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&this->frameContext[i].CommandAllocator)); hr != S_OK)
                _throwV_("Failed to create command allocator[{}], error code: {}", i, hr);

        if (hr = this->pd3dDevice->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, this->frameContext[0].CommandAllocator, nullptr, IID_PPV_ARGS(&this->pd3dCommandList)); hr != S_OK)
            _throwV_("Failed to create command list, error code: {}", hr);

        if (hr = this->pd3dCommandList->Close(); hr != S_OK)
            _throwV_("Failed to close command list, error code: {}", hr);

        if (hr = this->pd3dDevice->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&this->fence)); hr != S_OK)
            _throwV_("Failed to create fence, error code: {}", hr);

        this->fenceEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);
        if (this->fenceEvent == nullptr)
            _throw_("Failed to create fence event");

        {
            IDXGIFactory4 *dxgiFactory = nullptr;
            IDXGISwapChain1 *swapChain1 = nullptr;
            if (hr = CreateDXGIFactory1(IID_PPV_ARGS(&dxgiFactory)); hr != S_OK)
                _throwV_("Failed to create dxgi factory, error code: {}", hr);
            if (hr = dxgiFactory->CreateSwapChainForHwnd(this->pd3dCommandQueue, this->hwnd, &sd, nullptr, nullptr, &swapChain1); hr != S_OK)
                _throwV_("Failed to create swap chain, error code: {}", hr);
            if (hr = swapChain1->QueryInterface(IID_PPV_ARGS(&this->pSwapChain)); hr != S_OK)
                _throwV_("Failed to query swap chain, error code: {}", hr);
            swapChain1->Release();
            dxgiFactory->Release();
            this->pSwapChain->SetMaximumFrameLatency(NUM_BACK_BUFFERS);
            this->hSwapChainWaitableObject = this->pSwapChain->GetFrameLatencyWaitableObject();
        }

        CreateRenderTarget();
    }

    void Dx12Window::CleanupDeviceD3D()
    {
        CleanupRenderTarget();
        if (this->pSwapChain)
        {
            this->pSwapChain->SetFullscreenState(false, nullptr);
            this->pSwapChain->Release();
            this->pSwapChain = nullptr;
        }
        if (this->hSwapChainWaitableObject != nullptr)
        {
            CloseHandle(this->hSwapChainWaitableObject);
        }
        for (UINT i = 0; i < NUM_FRAMES_IN_FLIGHT; i++)
            if (this->frameContext[i].CommandAllocator)
            {
                this->frameContext[i].CommandAllocator->Release();
                this->frameContext[i].CommandAllocator = nullptr;
            }
        if (this->pd3dCommandQueue)
        {
            this->pd3dCommandQueue->Release();
            this->pd3dCommandQueue = nullptr;
        }
        if (this->pd3dCommandList)
        {
            this->pd3dCommandList->Release();
            this->pd3dCommandList = nullptr;
        }
        if (this->pd3dRtvDescHeap)
        {
            this->pd3dRtvDescHeap->Release();
            this->pd3dRtvDescHeap = nullptr;
        }
        if (this->pd3dSrvDescHeap)
        {
            this->pd3dSrvDescHeap->Release();
            this->pd3dSrvDescHeap = nullptr;
        }
        if (this->fence)
        {
            this->fence->Release();
            this->fence = nullptr;
        }
        if (this->fenceEvent)
        {
            CloseHandle(this->fenceEvent);
            this->fenceEvent = nullptr;
        }
        if (this->pd3dDevice)
        {
            this->pd3dDevice->Release();
            this->pd3dDevice = nullptr;
        }

#ifdef DX12_ENABLE_DEBUG_LAYER
        IDXGIDebug1 *pDebug = nullptr;
        if (SUCCEEDED(DXGIGetDebugInterface1(0, IID_PPV_ARGS(&pDebug))))
        {
            pDebug->ReportLiveObjects(DXGI_DEBUG_ALL, DXGI_DEBUG_RLO_SUMMARY);
            pDebug->Release();
        }
#endif
    }

    void Dx12Window::CreateRenderTarget()
    {
        for (UINT i = 0; i < NUM_BACK_BUFFERS; i++)
        {
            ID3D12Resource *pBackBuffer = nullptr;
            this->pSwapChain->GetBuffer(i, IID_PPV_ARGS(&pBackBuffer));
            this->pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, this->mainRenderTargetDescriptor[i]);
            this->mainRenderTargetResource[i] = pBackBuffer;
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
            return; // No fence was signaled

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
        if (fenceValue != 0) // means no fence was signaled
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
        this->hwnd = ::CreateWindow(wc.lpszClassName, _T(""), WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800, nullptr, nullptr, wc.hInstance, nullptr);
        if (this->hwnd == nullptr)
            _throwV_("Failed to create window, error code: {}", GetLastError());

        try
        {
            CreateDeviceD3D();
        }
        catch (...)
        {
            CleanupDeviceD3D();
            ::DestroyWindow(hwnd);
            ::UnregisterClass(wc.lpszClassName, wc.hInstance);
            throw;
        }
        // Show the window
        ::ShowWindow(this->hwnd, SW_SHOWDEFAULT);
        ::UpdateWindow(this->hwnd);
        ::SetWindowTextA(this->hwnd, this->title.c_str());

        // Setup Dear ImGui context
        igCreateContext(NULL);
        ImGuiIO &io = *igGetIO();
        (void)io;
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard; // Enable Keyboard Controls
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;  // Enable Gamepad Controls
        io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;     // Enable Docking
        io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;   // Enable Multi-Viewport / Platform Windows

        igStyleColorsLight(NULL);

        // When viewports are enabled we tweak WindowRounding/WindowBg so platform windows can look identical to regular ones.
        ImGuiStyle &style = *igGetStyle();
        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            style.WindowRounding = 0.0f;
            style.Colors[ImGuiCol_WindowBg].w = 1.0f;
        }

        // Setup Platform/Renderer backends
        ImGui_ImplWin32_Init(hwnd);
        ImGui_ImplDX12_Init(this->pd3dDevice, NUM_FRAMES_IN_FLIGHT,
                            DXGI_FORMAT_R8G8B8A8_UNORM, this->pd3dSrvDescHeap,
                            this->pd3dSrvDescHeap->GetCPUDescriptorHandleForHeapStart(),
                            this->pd3dSrvDescHeap->GetGPUDescriptorHandleForHeapStart());

        do
        {
            // Poll and handle messages (inputs, window resize, etc.)
            // See the WndProc() function below for our to dispatch events to the Win32 backend.
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

            // Handle window screen locked
            if (this->SwapChainOccluded && this->pSwapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED)
            {
                ::Sleep(10);
                continue;
            }
            this->SwapChainOccluded = false;

            this->ProcessCallBeforeFrameOnce();

            // Start the Dear ImGui frame
            ImGui_ImplDX12_NewFrame();
            ImGui_ImplWin32_NewFrame();
            igNewFrame();

            this->ProcessRenderCallback();

            // Rendering
            igRender();

            FrameContext *frameCtx = this->WaitForNextFrameResources();
            UINT backBufferIdx = this->pSwapChain->GetCurrentBackBufferIndex();
            frameCtx->CommandAllocator->Reset();

            D3D12_RESOURCE_BARRIER barrier = {};
            barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
            barrier.Flags = D3D12_RESOURCE_BARRIER_FLAG_NONE;
            barrier.Transition.pResource = this->mainRenderTargetResource[backBufferIdx];
            barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
            barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_PRESENT;
            barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_RENDER_TARGET;
            this->pd3dCommandList->Reset(frameCtx->CommandAllocator, nullptr);
            this->pd3dCommandList->ResourceBarrier(1, &barrier);

            // Render Dear ImGui graphics
            auto clear_color = this->ClearColor;
            const float clear_color_with_alpha[4] = {clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w};
            this->pd3dCommandList->ClearRenderTargetView(this->mainRenderTargetDescriptor[backBufferIdx], clear_color_with_alpha, 0, nullptr);
            this->pd3dCommandList->OMSetRenderTargets(1, &this->mainRenderTargetDescriptor[backBufferIdx], FALSE, nullptr);
            this->pd3dCommandList->SetDescriptorHeaps(1, &this->pd3dSrvDescHeap);
            ImGui_ImplDX12_RenderDrawData(igGetDrawData(), this->pd3dCommandList);
            barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_RENDER_TARGET;
            barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_PRESENT;
            this->pd3dCommandList->ResourceBarrier(1, &barrier);
            this->pd3dCommandList->Close();

            this->pd3dCommandQueue->ExecuteCommandLists(1, (ID3D12CommandList *const *)&this->pd3dCommandList);

            // Update and Render additional Platform Windows
            if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
            {
                igUpdatePlatformWindows();
                igRenderPlatformWindowsDefault(nullptr, (void *)this->pd3dCommandList);
            }

            // Present
            HRESULT hr = this->pSwapChain->Present(1, 0); // Present with vsync
            // HRESULT hr = this->pSwapChain->Present(0, 0); // Present without vsync
            this->SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);

            UINT64 fenceValue = this->fenceLastSignaledValue + 1;
            this->pd3dCommandQueue->Signal(this->fence, fenceValue);
            this->fenceLastSignaledValue = fenceValue;
            frameCtx->FenceValue = fenceValue;
        } while (1);

        this->WaitForLastSubmittedFrame();

        // Cleanup
        ImGui_ImplDX12_Shutdown();
        ImGui_ImplWin32_Shutdown();
        igDestroyContext(NULL);

        CleanupDeviceD3D();
        ::DestroyWindow(hwnd);
        ::UnregisterClass(wc.lpszClassName, wc.hInstance);
    }

    void Dx12Inbound::InitImGui(IDXGISwapChain3 * pSwapChain)
    {
        this->pSwapChain = pSwapChain;
        HRESULT hr;
        if (hr = pSwapChain->GetDevice(__uuidof(ID3D12Device), (void **)&this->pd3dDevice); hr != S_OK)
        {
            _throwV_("Failed to get device, error code: {}", hr);
        }
        CreateEvent(nullptr, FALSE, FALSE, nullptr);

        {
            DXGI_SWAP_CHAIN_DESC sdesc;
            pSwapChain->GetDesc(&sdesc);
            sdesc.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
            sdesc.Windowed = (GetWindowLongPtr(this->hwnd, GWL_STYLE) & WS_POPUP) == 0;

            this->hwnd = sdesc.OutputWindow;
            this->buffer_count = sdesc.BufferCount;
            this->frameContext = new FrameContext[this->buffer_count];
        }

        M_IMGUI_IMPL_WIN32_NAMESPACE::Attach(this->hwnd);

        {
            D3D12_DESCRIPTOR_HEAP_DESC desc = {};
            desc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
            desc.NumDescriptors = buffer_count;
            desc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_NONE;
            desc.NodeMask = 1;
            if (hr = this->pd3dDevice->CreateDescriptorHeap(&desc, IID_PPV_ARGS(&this->pd3dRtvDescHeap)); hr != S_OK)
            {
                _throwV_("Failed to create descriptor heap, error code: {}", hr);
            }

            SIZE_T rtvDescriptorSize = this->pd3dDevice->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);
            D3D12_CPU_DESCRIPTOR_HANDLE rtvHandle = this->pd3dRtvDescHeap->GetCPUDescriptorHandleForHeapStart();
            for (UINT i = 0; i < this->buffer_count; i++)
            {
                ID3D12Resource *pBackBuffer = nullptr;

                this->frameContext[i].MainRenderTargetDescriptor = rtvHandle;
                pSwapChain->GetBuffer(i, IID_PPV_ARGS(&pBackBuffer));
                this->pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, rtvHandle);
                this->frameContext[i].MainRenderTargetResource = pBackBuffer;
                rtvHandle.ptr += rtvDescriptorSize;
            }
        }

        {
            D3D12_DESCRIPTOR_HEAP_DESC desc = {};
            desc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
            desc.NumDescriptors = this->buffer_count > 1 ? this->buffer_count : 2;
            desc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;
            if (hr = this->pd3dDevice->CreateDescriptorHeap(&desc, IID_PPV_ARGS(&this->pd3dSrvDescHeap)); hr != S_OK)
            {
                _throwV_("Failed to create descriptor heap, error code: {}", hr);
            }
        }

        for (UINT i = 0; i < this->buffer_count; i++)
            if (hr = this->pd3dDevice->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&this->frameContext[i].CommandAllocator)); hr != S_OK)
                _throwV_("Failed to create command allocator[{}], error code: {}", i, hr);

        if (hr = this->pd3dDevice->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, this->frameContext[0].CommandAllocator, nullptr, IID_PPV_ARGS(&this->pd3dCommandList)); hr != S_OK)
            _throwV_("Failed to create command list, error code: {}", hr);

        this->ctx = igCreateContext(NULL);
        ImGuiIO &io = *igGetIO();
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard; // Enable Keyboard Controls
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;  // Enable Gamepad Controls
        io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;     // Enable Docking
        io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;   // Enable Multi-Viewport / Platform Windows

        // igStyleColorsDark(NULL);
        igStyleColorsLight(NULL);

        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            auto style = igGetStyle();
            style->WindowRounding = 0.0f;
            style->Colors[ImGuiCol_WindowBg].w = 1.0f;
        }
        ImGui_ImplWin32_Init(this->hwnd);
        ImGui_ImplDX12_Init(this->pd3dDevice, this->buffer_count,
                            DXGI_FORMAT_R8G8B8A8_UNORM, this->pd3dSrvDescHeap,
                            this->pd3dSrvDescHeap->GetCPUDescriptorHandleForHeapStart(),
                            this->pd3dSrvDescHeap->GetGPUDescriptorHandleForHeapStart());
        this->isImGuiInitialized = true;

        dbgPrint("init dx12 internal success\n");
    }

    typedef long(__fastcall * PresentD3D12)(IDXGISwapChain3 * pSwapChain, UINT SyncInterval, UINT Flags);
    typedef void(__fastcall * DrawInstancedD3D12)(ID3D12GraphicsCommandList * dCommandList, UINT VertexCountPerInstance, UINT InstanceCount, UINT StartVertexLocation, UINT StartInstanceLocation);
    typedef void(__fastcall * DrawIndexedInstancedD3D12)(ID3D12GraphicsCommandList * dCommandList, UINT IndexCount, UINT InstanceCount, UINT StartIndex, INT BaseVertex);
    typedef HRESULT(__fastcall * ExecuteCommandListsD3D12)(ID3D12CommandQueue * dCommandQueue, UINT NumCommandLists, ID3D12CommandList *const *ppCommandLists);
    typedef HRESULT(__fastcall * SignalD3D12)(ID3D12CommandQueue * dCommandQueue, ID3D12Fence * dFence, UINT64 Value);

    PresentD3D12 oPresentD3D12;
    DrawInstancedD3D12 oDrawInstancedD3D12;
    DrawIndexedInstancedD3D12 oDrawIndexedInstancedD3D12;
    ExecuteCommandListsD3D12 oExecuteCommandListsD3D12;
    SignalD3D12 oSignalD3D12;

    long __fastcall hkPresentD3D12(IDXGISwapChain3 * pSwapChain, UINT SyncInterval, UINT Flags)
    {
        if (Dx12Inbound::_instance != NULL && (Dx12Inbound::_instance->pSwapChain == NULL || Dx12Inbound::_instance->pSwapChain == pSwapChain))
        {
            try
            {
                if (!Dx12Inbound::_instance->isImGuiInitialized)
                    Dx12Inbound::_instance->InitImGui(pSwapChain);
                Dx12Inbound::_instance->Update();
            }
            catch (const std::exception &e)
            {
                dbgPrint("Dx12Inbound::Update() exception: %s\n", e.what());
                Dx12Inbound::_instance->Detach();
            }
        }
        return oPresentD3D12(pSwapChain, SyncInterval, Flags);
    }

    void __fastcall hkDrawInstancedD3D12(ID3D12GraphicsCommandList * dCommandList, UINT VertexCountPerInstance, UINT InstanceCount, UINT StartVertexLocation, UINT StartInstanceLocation)
    {
        oDrawInstancedD3D12(dCommandList, VertexCountPerInstance, InstanceCount, StartVertexLocation, StartInstanceLocation);
    }

    void __fastcall hkDrawIndexedInstancedD3D12(ID3D12GraphicsCommandList * dCommandList, UINT IndexCount, UINT InstanceCount, UINT StartIndex, INT BaseVertex)
    {
        oDrawIndexedInstancedD3D12(dCommandList, IndexCount, InstanceCount, StartIndex, BaseVertex);
    }

    HRESULT __fastcall hkExecuteCommandListsD3D12(ID3D12CommandQueue * dCommandQueue, UINT NumCommandLists, ID3D12CommandList *const *ppCommandLists)
    {
        if (Dx12Inbound::_instance != NULL && Dx12Inbound::_instance->pd3dCommandQueue == NULL)
        {
            Dx12Inbound::_instance->pd3dCommandQueue = dCommandQueue;
        }
        return oExecuteCommandListsD3D12(dCommandQueue, NumCommandLists, ppCommandLists);
    }

    HRESULT __fastcall hkSignalD3D12(ID3D12CommandQueue * dCommandQueue, ID3D12Fence * dFence, UINT64 Value)
    {
        if (dCommandQueue != NULL && Dx12Inbound::_instance != NULL && Dx12Inbound::_instance->pd3dCommandQueue == dCommandQueue)
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
        if (IMGUI_INBOUND_NAMESPACE::GetRenderType() != IMGUI_INBOUND_NAMESPACE::D3D12)
            return;
        if (this->hwnd != nullptr)
        {
            M_IMGUI_IMPL_WIN32_NAMESPACE::Detach(this->hwnd);
        }
        if (oPresentD3D12 != nullptr)
        {
            PYDETOURS_NAMESPACE::SimpleDetach((PVOID *)&oPresentD3D12, (PVOID)hkPresentD3D12);
        }
        if (oDrawInstancedD3D12 != nullptr)
        {
            PYDETOURS_NAMESPACE::SimpleDetach((PVOID *)&oDrawInstancedD3D12, (PVOID)hkDrawInstancedD3D12);
        }
        if (oDrawIndexedInstancedD3D12 != nullptr)
        {
            PYDETOURS_NAMESPACE::SimpleDetach((PVOID *)&oDrawIndexedInstancedD3D12, (PVOID)hkDrawIndexedInstancedD3D12);
        }
        if (oExecuteCommandListsD3D12 != nullptr)
        {
            PYDETOURS_NAMESPACE::SimpleDetach((PVOID *)&oExecuteCommandListsD3D12, (PVOID)hkExecuteCommandListsD3D12);
        }
        if (oSignalD3D12 != nullptr)
        {
            PYDETOURS_NAMESPACE::SimpleDetach((PVOID *)&oSignalD3D12, (PVOID)hkSignalD3D12);
        }
    }
    void Dx12Inbound::_Update()
    {
        if (!this->pd3dCommandQueue)
            return;
        this->ProcessCallBeforeFrameOnce();

        ImGui_ImplDX12_NewFrame();
        ImGui_ImplWin32_NewFrame();
        igNewFrame();

        try
        {
            this->ProcessRenderCallback();
        }
        catch (std::exception &e)
        {
            printf("Error in render callback,detach: \n");
            printf(e.what());
            this->Detach();
            return;
        }

        FrameContext &currentFrameContext = this->frameContext[this->pSwapChain->GetCurrentBackBufferIndex()];
        currentFrameContext.CommandAllocator->Reset();

        D3D12_RESOURCE_BARRIER barrier;
        barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
        barrier.Flags = D3D12_RESOURCE_BARRIER_FLAG_NONE;
        barrier.Transition.pResource = currentFrameContext.MainRenderTargetResource;
        barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
        barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_PRESENT;
        barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_RENDER_TARGET;

        this->pd3dCommandList->Reset(currentFrameContext.CommandAllocator, nullptr);
        this->pd3dCommandList->ResourceBarrier(1, &barrier);
        this->pd3dCommandList->OMSetRenderTargets(1, &currentFrameContext.MainRenderTargetDescriptor, FALSE, nullptr);
        this->pd3dCommandList->SetDescriptorHeaps(1, &this->pd3dSrvDescHeap);

        igEndFrame();
        igRender();
        ImGui_ImplDX12_RenderDrawData(igGetDrawData(), this->pd3dCommandList);

        barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_RENDER_TARGET;
        barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_PRESENT;
        this->pd3dCommandList->ResourceBarrier(1, &barrier);
        this->pd3dCommandList->Close();

        this->pd3dCommandQueue->ExecuteCommandLists(1, (ID3D12CommandList *const *)&this->pd3dCommandList);

        // Update and Render additional Platform Windows
        if (igGetIO()->ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            igUpdatePlatformWindows();
            igRenderPlatformWindowsDefault(nullptr, (void *)this->pd3dCommandList);
        }
    }
    void Dx12Inbound::Update()
    {
        this->isInLogic = true;
        this->_Update();
        this->isInLogic = false;
    }
}
END_M_IMGUI_IMPL_Dx12_NAMESPACE
