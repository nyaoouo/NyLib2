#include "./Impl_Dx9.h"

START_M_IMGUI_IMPL_Dx9_NAMESPACE
{
    void Dx9Window::CreateDeviceD3D()
    {
        if ((this->pD3D = Direct3DCreate9(D3D_SDK_VERSION)) == NULL)
            _throw_("Failed to create Direct3D9 object");

        ZeroMemory(&this->d3dpp, sizeof(this->d3dpp));
        this->d3dpp.Windowed = TRUE;
        this->d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
        this->d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
        this->d3dpp.EnableAutoDepthStencil = TRUE;
        this->d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
        this->d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;

        D3DDEVTYPE deviceType;

        if (this->pD3D->CheckDeviceType(
                D3DADAPTER_DEFAULT,
                D3DDEVTYPE_HAL,
                this->d3dpp.BackBufferFormat,
                this->d3dpp.BackBufferFormat,
                TRUE) == D3D_OK)
        {
            deviceType = D3DDEVTYPE_HAL;
        }
        else
        {
            deviceType = D3DDEVTYPE_REF;
        }

        if (HRESULT hr = this->pD3D->CreateDevice(
                D3DADAPTER_DEFAULT,
                deviceType,
                this->hwnd,
                D3DCREATE_SOFTWARE_VERTEXPROCESSING,
                &this->d3dpp,
                &this->pd3dDevice);
            hr != D3D_OK)
        {
            _throwV_("Failed to create device, error code: {}", hr);
        }
    }

    void Dx9Window::CleanupDeviceD3D()
    {
        if (this->pd3dDevice != NULL)
        {
            this->pd3dDevice->Release();
            this->pd3dDevice = NULL;
        }
        if (this->pD3D != NULL)
        {
            this->pD3D->Release();
            this->pD3D = NULL;
        }
    }

    void Dx9Window::ResetDevice()
    {
        ImGui_ImplDX9_InvalidateDeviceObjects();
        if (HRESULT hr = this->pd3dDevice->Reset(&this->d3dpp); hr == D3DERR_INVALIDCALL)
        {
            _throw_("Failed to reset device");
        }
        ImGui_ImplDX9_CreateDeviceObjects();
    }

    LRESULT WINAPI Dx9ImguiWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
            return true;
        if (Dx9Window::_instance == nullptr)
            return DefWindowProc(hWnd, msg, wParam, lParam);
        switch (msg)
        {
        case WM_SIZE:
        {
            if (wParam == SIZE_MINIMIZED)
                return 0;
            Dx9Window::_instance->ResizeWidth = (UINT)LOWORD(lParam); // Queue resize
            Dx9Window::_instance->ResizeHeight = (UINT)HIWORD(lParam);
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

    void Dx9Window::Serve()
    {
        WNDCLASSEX wc = {sizeof(wc), CS_CLASSDC, Dx9ImguiWndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, _T("mImguiWindowDx9"), nullptr};
        ::RegisterClassEx(&wc);
        this->hwnd = ::CreateWindow(wc.lpszClassName, _T(""), WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800, nullptr, nullptr, wc.hInstance, nullptr);
        if (this->hwnd == nullptr)
            _throwV_("Failed to create window, error code: {}", GetLastError());

        try
        {
            this->CreateDeviceD3D();
        }
        catch (...)
        {
            this->CleanupDeviceD3D();
            ::UnregisterClass(wc.lpszClassName, wc.hInstance);
            throw;
        }

        ::ShowWindow(this->hwnd, SW_SHOWDEFAULT);
        ::UpdateWindow(this->hwnd);
        ::SetWindowTextA(this->hwnd, this->title.c_str());

        this->ctx = igCreateContext(NULL);
        ImGuiIO *io = igGetIO();
        (void)io;
        io->ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard; // Enable Keyboard Controls
        io->ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;  // Enable Gamepad Controls
        io->ConfigFlags |= ImGuiConfigFlags_DockingEnable;     // Enable Docking
        io->ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;   // Enable Multi-Viewport / Platform Windows
        // igStyleColorsDark(NULL);
        igStyleColorsLight(NULL);

        ImGuiStyle *style = igGetStyle();
        if (io->ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            style->WindowRounding = 0.0f;
            style->Colors[ImGuiCol_WindowBg].w = 1.0f;
        }

        ImGui_ImplWin32_Init(this->hwnd);
        ImGui_ImplDX9_Init(this->pd3dDevice);

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

            if (this->DeviceLost)
            {
                HRESULT hr = this->pd3dDevice->TestCooperativeLevel();
                if (hr == D3DERR_DEVICELOST)
                {
                    ::Sleep(10);
                    continue;
                }
                if (hr == D3DERR_DEVICENOTRESET)
                    this->ResetDevice();
                this->DeviceLost = false;
            }

            // Handle window resize (we don't resize directly in the WM_SIZE handler)
            if (this->ResizeWidth != 0 && this->ResizeHeight != 0)
            {
                this->d3dpp.BackBufferWidth = this->ResizeWidth;
                this->d3dpp.BackBufferHeight = this->ResizeHeight;
                this->ResetDevice();
                this->ResizeWidth = this->ResizeHeight = 0;
            }

            this->ProcessCallBeforeFrameOnce();

            // Start the Dear ImGui frame
            ImGui_ImplDX9_NewFrame();
            ImGui_ImplWin32_NewFrame();
            igNewFrame();

            this->ProcessRenderCallback();

            igEndFrame();

            this->pd3dDevice->SetRenderState(D3DRS_ZENABLE, FALSE);
            this->pd3dDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, FALSE);
            this->pd3dDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, FALSE);

            auto clear_color = this->ClearColor;
            D3DCOLOR clear_col_dx = D3DCOLOR_RGBA((int)(clear_color.x * clear_color.w * 255.0f), (int)(clear_color.y * clear_color.w * 255.0f), (int)(clear_color.z * clear_color.w * 255.0f), (int)(clear_color.w * 255.0f));
            this->pd3dDevice->Clear(0, NULL, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, clear_col_dx, 1.0f, 0);
            if (this->pd3dDevice->BeginScene() >= 0)
            {
                igRender();
                ImGui_ImplDX9_RenderDrawData(igGetDrawData());
                this->pd3dDevice->EndScene();
            }

            // Update and Render additional Platform Windows
            if (igGetIO()->ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
            {
                igUpdatePlatformWindows();
                igRenderPlatformWindowsDefault(NULL, NULL);
            }

            HRESULT result = this->pd3dDevice->Present(NULL, NULL, NULL, NULL);
            if (result == D3DERR_DEVICELOST || result == D3DERR_DEVICEHUNG || result == D3DERR_DEVICEREMOVED)
                this->DeviceLost = true;
        } while (true);

        ImGui_ImplDX9_Shutdown();
        ImGui_ImplWin32_Shutdown();
        igDestroyContext(NULL);

        this->CleanupDeviceD3D();
        ::DestroyWindow(this->hwnd);
        ::UnregisterClass(wc.lpszClassName, wc.hInstance);
    }

    void Dx9Inbound::Attach()
    {
    }
    void Dx9Inbound::Detach()
    {
    }
    void Dx9Inbound::Update()
    {
    }
}
END_M_IMGUI_IMPL_Dx9_NAMESPACE