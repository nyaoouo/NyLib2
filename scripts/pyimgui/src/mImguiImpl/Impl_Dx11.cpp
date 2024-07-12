#include "./Impl_Dx11.h"

START_M_IMGUI_IMPL_Dx11_NAMESPACE
{

    void Dx11Render::CreateRenderTarget()
    {
        ID3D11Texture2D *pBackBuffer;
        HRESULT hr;
        if DX_HR_FAILED (hr, this->pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer)))
            _throwV_("Failed to get back buffer: {}", hr);
        if DX_HR_FAILED (hr, this->pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &this->mainRenderTargetView))
        {
            pBackBuffer->Release();
            _throwV_("Failed to create render target view: {}", hr);
        }
        pBackBuffer->Release();
    }

    void Dx11Render::CleanupRenderTarget()
    {
        if (this->mainRenderTargetView)
        {
            this->mainRenderTargetView->Release();
            this->mainRenderTargetView = NULL;
        }
    }

    void Dx11Window::CreateDeviceD3D()
    {
        DXGI_SWAP_CHAIN_DESC sd;
        ZeroMemory(&sd, sizeof(sd));
        sd.BufferCount = 2;
        sd.BufferDesc.Width = 0;
        sd.BufferDesc.Height = 0;
        sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        sd.BufferDesc.RefreshRate.Numerator = 60;
        sd.BufferDesc.RefreshRate.Denominator = 1;
        sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
        sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        sd.OutputWindow = this->hwnd;
        sd.SampleDesc.Count = 1;
        sd.SampleDesc.Quality = 0;
        sd.Windowed = TRUE;
        sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

        UINT createDeviceFlags = 0;
        D3D_FEATURE_LEVEL featureLevel;
        const D3D_FEATURE_LEVEL featureLevelArray[2] = {
            D3D_FEATURE_LEVEL_11_0,
            D3D_FEATURE_LEVEL_10_0,
        };
        HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &this->pSwapChain, &this->pd3dDevice, &featureLevel, &this->pd3dDeviceContext);
        if (hr == DXGI_ERROR_UNSUPPORTED) // Try high-performance WARP software driver if hardware is not available.
            hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &this->pSwapChain, &this->pd3dDevice, &featureLevel, &this->pd3dDeviceContext);
        if (hr != S_OK)
            _throwV_("Failed to create device and swap chain: {}", hr);

        this->CreateRenderTarget();
    }

    void Dx11Window::CleanupDeviceD3D()
    {
        this->CleanupRenderTarget();
        if (this->pSwapChain)
        {
            this->pSwapChain->Release();
            this->pSwapChain = nullptr;
        }
        if (this->pd3dDeviceContext)
        {
            this->pd3dDeviceContext->Release();
            this->pd3dDeviceContext = NULL;
        }
        if (this->pd3dDevice)
        {
            this->pd3dDevice->Release();
            this->pd3dDevice = NULL;
        }
    }

    LRESULT WINAPI Dx11ImguiWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
            return true;

        switch (msg)
        {
        case WM_SIZE:
        {
            if (wParam == SIZE_MINIMIZED)
                return 0;
            Dx11Window::_instance->ResizeWidth = (UINT)LOWORD(lParam); // Queue resize
            Dx11Window::_instance->ResizeHeight = (UINT)HIWORD(lParam);
            return 0;
        }
        case WM_SYSCOMMAND:
        {
            if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
                return 0;
            break;
        }
        case WM_DESTROY:
        {
            ::PostQuitMessage(0);
            return 0;
        }
        case WM_DPICHANGED:
        {
            if (igGetIO()->ConfigFlags & ImGuiConfigFlags_DpiEnableScaleViewports)
            {
                // const int dpi = HIWORD(wParam);
                // printf("WM_DPICHANGED to %d (%.0f%%)\n", dpi, (float)dpi / 96.0f * 100.0f);
                const RECT *suggested_rect = (RECT *)lParam;
                ::SetWindowPos(hWnd, nullptr, suggested_rect->left, suggested_rect->top, suggested_rect->right - suggested_rect->left, suggested_rect->bottom - suggested_rect->top, SWP_NOZORDER | SWP_NOACTIVATE);
            }
            break;
        }
        }
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }

    void Dx11Window::Serve()
    {
        WNDCLASSEX wc = {sizeof(wc), CS_CLASSDC, Dx11ImguiWndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, _T("mImguiWindow"), nullptr};
        ::RegisterClassEx(&wc);
        this->hwnd = ::CreateWindow(wc.lpszClassName, _T("mImguiWindow"), WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800, nullptr, nullptr, wc.hInstance, nullptr);

        try
        {
            this->CreateDeviceD3D();
        }
        catch (std::exception &e)
        {
            ::DestroyWindow(this->hwnd);
            ::UnregisterClass(wc.lpszClassName, wc.hInstance);
            throw e;
        }

        ::ShowWindow(this->hwnd, SW_SHOWDEFAULT);
        ::UpdateWindow(this->hwnd);

        this->ctx = igCreateContext(NULL);
        ImGuiIO *io = igGetIO();
        (void)io;
        io->ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard; // Enable Keyboard Controls
        io->ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;  // Enable Gamepad Controls
        io->ConfigFlags |= ImGuiConfigFlags_DockingEnable;     // Enable Docking
        io->ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;   // Enable Multi-Viewport / Platform Windows
        // io->ConfigViewportsNoAutoMerge = true;
        // io->ConfigViewportsNoTaskBarIcon = true;
        // io->ConfigViewportsNoDefaultParent = true;
        // io->ConfigDockingAlwaysTabBar = true;
        // io->ConfigDockingTransparentPayload = true;
        // io->ConfigFlags |= ImGuiConfigFlags_DpiEnableScaleFonts;     // FIXME-DPI: Experimental. THIS CURRENTLY DOESN'T WORK AS EXPECTED. DON'T USE IN USER APP!
        // io->ConfigFlags |= ImGuiConfigFlags_DpiEnableScaleViewports; // FIXME-DPI: Experimental.
        // ImFontAtlas_AddFontFromFileTTF(io->Fonts, "c:\\Windows\\Fonts\\msyh.ttc", 18.0f, nullptr, ImFontAtlas_GetGlyphRangesChineseFull(io->Fonts));
        // igStyleColorsDark(NULL);
        igStyleColorsLight(NULL);

        ImGuiStyle *style = igGetStyle();
        if (io->ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            style->WindowRounding = 0.0f;
            style->Colors[ImGuiCol_WindowBg].w = 1.0f;
        }
        ImGui_ImplWin32_Init(this->hwnd);
        ImGui_ImplDX11_Init(this->pd3dDevice, this->pd3dDeviceContext);
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

            // Handle window being minimized or screen locked
            if (this->SwapChainOccluded && this->pSwapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED)
            {
                ::Sleep(10);
                continue;
            }
            this->SwapChainOccluded = false;

            // Handle window resize (we don't resize directly in the WM_SIZE handler)
            if (this->ResizeWidth != 0 && this->ResizeHeight != 0)
            {
                CleanupRenderTarget();
                this->pSwapChain->ResizeBuffers(0, this->ResizeWidth, this->ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
                this->ResizeWidth = this->ResizeHeight = 0;
                CreateRenderTarget();
            }

            this->ProcessCallBeforeFrameOnce();

            // Start the Dear ImGui frame
            ImGui_ImplDX11_NewFrame();
            ImGui_ImplWin32_NewFrame();
            igNewFrame();

            this->ProcessRenderCallback();

            igEndFrame();
            igRender();

            auto clear_color = this->ClearColor;
            const float clear_color_with_alpha[4] = {clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w};
            this->pd3dDeviceContext->OMSetRenderTargets(1, &this->mainRenderTargetView, nullptr);
            this->pd3dDeviceContext->ClearRenderTargetView(this->mainRenderTargetView, clear_color_with_alpha);

            ImGui_ImplDX11_RenderDrawData(igGetDrawData());

            // Update and Render additional Platform Windows
            if (igGetIO()->ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
            {
                igUpdatePlatformWindows();
                igRenderPlatformWindowsDefault(NULL, NULL);
            }

            // Present
            HRESULT hr = this->pSwapChain->Present(1, 0); // Present with vsync
            // HRESULT hr = this->pSwapChain->Present(0, 0); // Present without vsync
            this->SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);

        } while (true);

        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        igDestroyContext(NULL);

        this->CleanupDeviceD3D();
        ::DestroyWindow(this->hwnd);
        ::UnregisterClass(wc.lpszClassName, wc.hInstance);
    }

    typedef long(__stdcall * Present)(IDXGISwapChain *, UINT, UINT);
    static Present oPresent = NULL;

    typedef HRESULT(__stdcall * ResizeBuffers)(IDXGISwapChain *, UINT, UINT, UINT, DXGI_FORMAT, UINT);
    static ResizeBuffers oResizeBuffers = NULL;

    HRESULT __stdcall hkResizeBuffers11(
        IDXGISwapChain * pSwapChain,
        UINT BufferCount,
        UINT Width,
        UINT Height,
        DXGI_FORMAT NewFormat,
        UINT SwapChainFlags)
    {
        if (Dx11Inbound::_instance != nullptr)
        {
            Dx11Inbound::_instance->CleanupRenderTarget();
        }
        auto res = oResizeBuffers(pSwapChain, BufferCount, Width, Height, NewFormat, SwapChainFlags);
        if (Dx11Inbound::_instance != nullptr)
        {
            Dx11Inbound::_instance->CreateRenderTarget();
        }
        return res;
    }

    HRESULT __stdcall hkPresent11(IDXGISwapChain * pSwapChain, UINT SyncInterval, UINT Flags)
    {
        if (Dx11Inbound::_instance != nullptr && !Dx11Inbound::_instance->isInLogic)
        {
            auto instance = Dx11Inbound::_instance;
            try
            {
                instance->InitImGui(pSwapChain);
                instance->Update();
            }
            catch (...)
            {
                instance->Detach();
            }
        }
        return oPresent(pSwapChain, SyncInterval, Flags);
    }

    void Dx11Inbound::Attach()
    {
        IMGUI_INBOUND_NAMESPACE::Init(IMGUI_INBOUND_NAMESPACE::D3D11);
        oPresent = (Present)IMGUI_INBOUND_NAMESPACE::GetMethod(8);
        oResizeBuffers = (ResizeBuffers)IMGUI_INBOUND_NAMESPACE::GetMethod(13);
        PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oPresent, (PVOID)hkPresent11);
        PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oResizeBuffers, (PVOID)hkResizeBuffers11);
    }
    void Dx11Inbound::Detach()
    {
        if (IMGUI_INBOUND_NAMESPACE::GetRenderType() != IMGUI_INBOUND_NAMESPACE::D3D11)
            return;
        if (this->hwnd != nullptr)
        {
            M_IMGUI_IMPL_WIN32_NAMESPACE::Detach(this->hwnd);
        }
        if (oPresent != nullptr && oPresent != IMGUI_INBOUND_NAMESPACE::GetMethod(8))
        {
            PYDETOURS_NAMESPACE::SimpleDetach((PVOID *)&oPresent, (PVOID)hkPresent11);
        }
        if (oResizeBuffers != nullptr && oResizeBuffers != IMGUI_INBOUND_NAMESPACE::GetMethod(13))
        {
            PYDETOURS_NAMESPACE::SimpleDetach((PVOID *)&oResizeBuffers, (PVOID)hkResizeBuffers11);
        }
    }
    void Dx11Inbound::InitImGui(IDXGISwapChain * pSwapChain)
    {
        if (this->isImGuiInitialized)
            return;
        this->pSwapChain = pSwapChain;
        DXGI_SWAP_CHAIN_DESC desc;
        this->pSwapChain->GetDesc(&desc);
        this->hwnd = desc.OutputWindow;
        this->pSwapChain->GetDevice(__uuidof(ID3D11Device), (void **)&this->pd3dDevice);
        this->pd3dDevice->GetImmediateContext(&this->pd3dDeviceContext);

        M_IMGUI_IMPL_WIN32_NAMESPACE::Attach(this->hwnd);

        this->CreateRenderTarget();
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
        ImGui_ImplDX11_Init(this->pd3dDevice, this->pd3dDeviceContext);
        this->isImGuiInitialized = true;

        dbgPrint("init dx11 internal success\n");
    }
    void Dx11Inbound::Update()
    {
        this->isInLogic = true;
        this->_Update();
        this->isInLogic = false;
    }
    void Dx11Inbound::_Update()
    {
        this->pd3dDeviceContext->OMSetRenderTargets(1, &this->mainRenderTargetView, nullptr);

        this->ProcessCallBeforeFrameOnce();

        ImGui_ImplDX11_NewFrame();
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

        igEndFrame();
        igRender();
        ImGui_ImplDX11_RenderDrawData(igGetDrawData());
        this->pd3dDeviceContext->OMSetRenderTargets(0, nullptr, nullptr);
        if ((*igGetIO()).ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            igUpdatePlatformWindows();
            igRenderPlatformWindowsDefault(NULL, NULL);
        }
    }
}

END_M_IMGUI_IMPL_Dx11_NAMESPACE