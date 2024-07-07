#include "./impl_dx9.h"

namespace mImguiImpl
{
    namespace impl_dx9
    {

        bool Dx9ImguiWindow::CreateDeviceD3D()
        {
            if ((this->pD3D = Direct3DCreate9(D3D_SDK_VERSION)) == nullptr)
                return false;

            // Create the D3DDevice
            ZeroMemory(&this->d3dpp, sizeof(this->d3dpp));
            this->d3dpp.Windowed = TRUE;
            this->d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
            this->d3dpp.BackBufferFormat = D3DFMT_UNKNOWN; // Need to use an explicit format with alpha if needing per-pixel alpha composition.
            this->d3dpp.EnableAutoDepthStencil = TRUE;
            this->d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
            this->d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE; // Present with vsync
            // this->d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;   // Present without vsync, maximum unthrottled framerate
            if (this->pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, this->hwnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &this->d3dpp, &this->pd3dDevice) < 0)
                return false;

            return true;
        }

        void Dx9ImguiWindow::CleanupDeviceD3D()
        {
            if (this->pd3dDevice)
            {
                this->pd3dDevice->Release();
                this->pd3dDevice = nullptr;
            }
            if (this->pD3D)
            {
                this->pD3D->Release();
                this->pD3D = nullptr;
            }
        }

        void Dx9ImguiWindow::ResetDevice()
        {
            ImGui_ImplDX9_InvalidateDeviceObjects();
            HRESULT hr = this->pd3dDevice->Reset(&this->d3dpp);
            if (hr == D3DERR_INVALIDCALL)
                throw "D3DERR_INVALIDCALL";
            ImGui_ImplDX9_CreateDeviceObjects();
        }

        LRESULT WINAPI Dx9ImguiWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
        {
            if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
                return true;
            switch (msg)
            {
            case WM_SIZE:
            {
                Dx9ImguiWindow::_instance->ResizeWidth = (UINT)LOWORD(lParam);
                Dx9ImguiWindow::_instance->ResizeHeight = (UINT)HIWORD(lParam);
            }
            break;
            case WM_SYSCOMMAND:
            {
                if ((wParam & 0xfff0) == SC_KEYMENU)
                    return 0;
            }
            break;
            case WM_DESTROY:
                ::PostQuitMessage(0);
                return 0;
            case WM_DPICHANGED:
                if (igGetIO()->ConfigFlags & ImGuiConfigFlags_DpiEnableScaleViewports)
                {
                    const RECT *suggested_rect = (RECT *)lParam;
                    ::SetWindowPos(hWnd, nullptr, suggested_rect->left, suggested_rect->top, suggested_rect->right - suggested_rect->left, suggested_rect->bottom - suggested_rect->top, SWP_NOZORDER | SWP_NOACTIVATE);
                }
                break;
            }
            return DefWindowProc(hWnd, msg, wParam, lParam);
        }

        int Dx9ImguiWindow::Serve()
        {
            WNDCLASSEX wc = {sizeof(wc), CS_CLASSDC, Dx9ImguiWndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, _T("mImguiWindow"), nullptr};
            ::RegisterClassEx(&wc);
            this->hwnd = ::CreateWindow(wc.lpszClassName, _T("mImguiWindow"), WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800, nullptr, nullptr, wc.hInstance, nullptr);

            if (!this->CreateDeviceD3D())
            {
                this->CleanupDeviceD3D();
                ::UnregisterClass(wc.lpszClassName, wc.hInstance);
                return 1;
            }

            // Show the window
            ::ShowWindow(this->hwnd, SW_SHOWDEFAULT);
            ::UpdateWindow(this->hwnd);
            this->ctx = igCreateContext(NULL);
            ImGuiIO &io = *igGetIO();
            (void)io;
            io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard; // Enable Keyboard Controls
            io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;  // Enable Gamepad Controls
            io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;     // Enable Docking
            io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;   // Enable Multi-Viewport / Platform Windows
            // io.ConfigViewportsNoAutoMerge = true;
            // io.ConfigViewportsNoTaskBarIcon = true;
            // igStyleColorsDark(NULL);
            igStyleColorsLight(NULL);

            ImGuiStyle &style = *igGetStyle();
            if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
            {
                style.WindowRounding = 0.0f;
                style.Colors[ImGuiCol_WindowBg].w = 1.0f;
            }
            ImGui_ImplWin32_Init(this->hwnd);
            ImGui_ImplDX9_Init(this->pd3dDevice);
            bool done = false;
            while (!done)
            {
                MSG msg;
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

                if (this->ResizeWidth != 0 && this->ResizeHeight != 0)
                {
                    this->d3dpp.BackBufferWidth = this->ResizeWidth;
                    this->d3dpp.BackBufferHeight = this->ResizeHeight;
                    this->ResizeWidth = this->ResizeHeight = 0;
                    this->ResetDevice();
                }

                ImGui_ImplDX9_NewFrame();
                ImGui_ImplWin32_NewFrame();
                igNewFrame();

                this->renderCallback(this);

                igEndFrame();
                this->pd3dDevice->SetRenderState(D3DRS_ZENABLE, FALSE);
                this->pd3dDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, FALSE);
                this->pd3dDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, FALSE);
                auto clear_color = this->clear_color;
                D3DCOLOR clear_col_dx = D3DCOLOR_RGBA((int)(clear_color.x * clear_color.w * 255.0f), (int)(clear_color.y * clear_color.w * 255.0f), (int)(clear_color.z * clear_color.w * 255.0f), (int)(clear_color.w * 255.0f));
                this->pd3dDevice->Clear(0, nullptr, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, clear_col_dx, 1.0f, 0);
                if (this->pd3dDevice->BeginScene() >= 0)
                {
                    igRender();
                    ImGui_ImplDX9_RenderDrawData(igGetDrawData());
                    this->pd3dDevice->EndScene();
                }
                if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
                {
                    igUpdatePlatformWindows();
                    igRenderPlatformWindowsDefault(NULL, NULL);
                }

                HRESULT result = this->pd3dDevice->Present(nullptr, nullptr, nullptr, nullptr);
                if (result == D3DERR_DEVICELOST)
                    this->DeviceLost = true;
            }

            ImGui_ImplDX9_Shutdown();
            ImGui_ImplWin32_Shutdown();
            igDestroyContext(this->ctx);

            CleanupDeviceD3D();
            ::DestroyWindow(this->hwnd);
            ::UnregisterClass(wc.lpszClassName, wc.hInstance);
            return 0;
        }

        int Dx9ImguiInternalWindow::Init()
        {
            if (mImguiInternal::init(mImguiInternal::RenderType::D3D9) != 0)
                return 1;
            /* todo... */
            return 0;
        }
    }
}
