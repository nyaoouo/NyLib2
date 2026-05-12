#include "./Dx9Window.h"
#include "../common/ImguiInbound.h"
#include "../common/PyDetours.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

START_M_IMGUI_IMPL_DX9_NAMESPACE
{
    Dx9Window::Dx9Window(std::optional<py::function> renderCallback) : Dx9Render(renderCallback)
    {
        if (_instance != nullptr)
            _throw_("Only one Dx9Window instance is allowed");
        _instance = this;
    }

    Dx9Window::~Dx9Window()
    {
        if (_instance == this)
            _instance = nullptr;
    }

    void Dx9Window::CreateDeviceD3D()
    {
        if ((this->pD3D = Direct3DCreate9(D3D_SDK_VERSION)) == nullptr)
            _throw_("Failed to create Direct3D9 object");

        ZeroMemory(&this->d3dpp, sizeof(this->d3dpp));
        this->d3dpp.Windowed = TRUE;
        this->d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
        this->d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
        this->d3dpp.EnableAutoDepthStencil = TRUE;
        this->d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
        this->d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;

        D3DDEVTYPE deviceType = D3DDEVTYPE_REF;
        if (this->pD3D->CheckDeviceType(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, this->d3dpp.BackBufferFormat, this->d3dpp.BackBufferFormat, TRUE) == D3D_OK)
            deviceType = D3DDEVTYPE_HAL;

        HRESULT hr = this->pD3D->CreateDevice(
            D3DADAPTER_DEFAULT,
            deviceType,
            this->hwnd,
            D3DCREATE_SOFTWARE_VERTEXPROCESSING,
            &this->d3dpp,
            &this->pd3dDevice);
        if (hr != D3D_OK)
            _throwV_("Failed to create D3D9 device: {}", hr);
    }

    void Dx9Window::CleanupDeviceD3D()
    {
        if (this->pd3dDevice != nullptr)
        {
            this->pd3dDevice->Release();
            this->pd3dDevice = nullptr;
        }
        if (this->pD3D != nullptr)
        {
            this->pD3D->Release();
            this->pD3D = nullptr;
        }
    }

    void Dx9Window::ResetDevice()
    {
        ImGui_ImplDX9_InvalidateDeviceObjects();
        HRESULT hr = this->pd3dDevice->Reset(&this->d3dpp);
        if (hr == D3DERR_INVALIDCALL)
            _throw_("Failed to reset D3D9 device");
        ImGui_ImplDX9_CreateDeviceObjects();
    }

    LRESULT WINAPI Dx9ImguiWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        LRESULT trayResult = 0;
        if (M_IMGUI_IMPL_NAMESPACE::RenderBase::ProcessTrayWindowProc(hWnd, msg, wParam, lParam, trayResult))
            return trayResult;
        if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
            return true;
        if (Dx9Window::_instance == nullptr)
            return DefWindowProc(hWnd, msg, wParam, lParam);
        switch (msg)
        {
        case WM_SIZE:
            if (wParam == SIZE_MINIMIZED)
                return 0;
            Dx9Window::_instance->resizeWidth = (UINT)LOWORD(lParam);
            Dx9Window::_instance->resizeHeight = (UINT)HIWORD(lParam);
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU)
                return 0;
            break;
        case WM_DESTROY:
            ::PostQuitMessage(0);
            return 0;
        case WM_DPICHANGED:
            if (ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_DpiEnableScaleViewports)
            {
                const RECT *suggested_rect = (RECT *)lParam;
                ::SetWindowPos(hWnd, nullptr, suggested_rect->left, suggested_rect->top, suggested_rect->right - suggested_rect->left, suggested_rect->bottom - suggested_rect->top, SWP_NOZORDER | SWP_NOACTIVATE);
            }
            break;
        }
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }

    void Dx9Window::Serve()
    {
        WNDCLASSEX wc = {sizeof(wc), CS_CLASSDC, Dx9ImguiWndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, _T("mImguiWindowDx9"), nullptr};
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
            ::DestroyWindow(this->hwnd);
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

        ImGui_ImplWin32_Init(this->hwnd);
        ImGui_ImplDX9_Init(this->pd3dDevice);

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

            if (this->deviceLost)
            {
                HRESULT hr = this->pd3dDevice->TestCooperativeLevel();
                if (hr == D3DERR_DEVICELOST)
                {
                    ::Sleep(10);
                    continue;
                }
                if (hr == D3DERR_DEVICENOTRESET)
                    this->ResetDevice();
                this->deviceLost = false;
            }

            if (this->resizeWidth != 0 && this->resizeHeight != 0)
            {
                this->d3dpp.BackBufferWidth = this->resizeWidth;
                this->d3dpp.BackBufferHeight = this->resizeHeight;
                this->ResetDevice();
                this->resizeWidth = this->resizeHeight = 0;
            }

            this->ProcessCallBeforeFrameOnce(py::cast(this));

            ImGui_ImplDX9_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();

            this->ProcessRenderCallback(py::cast(this));

            ImGui::EndFrame();

            this->pd3dDevice->SetRenderState(D3DRS_ZENABLE, FALSE);
            this->pd3dDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, FALSE);
            this->pd3dDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, FALSE);

            auto clear_color = this->ClearColor;
            D3DCOLOR clear_col_dx = D3DCOLOR_RGBA((int)(clear_color.x * clear_color.w * 255.0f), (int)(clear_color.y * clear_color.w * 255.0f), (int)(clear_color.z * clear_color.w * 255.0f), (int)(clear_color.w * 255.0f));
            this->pd3dDevice->Clear(0, nullptr, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, clear_col_dx, 1.0f, 0);
            if (this->pd3dDevice->BeginScene() >= 0)
            {
                ImGui::Render();
                ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
                this->pd3dDevice->EndScene();
            }

            if (ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
            {
                ImGui::UpdatePlatformWindows();
                ImGui::RenderPlatformWindowsDefault();
            }

            HRESULT result = this->pd3dDevice->Present(nullptr, nullptr, nullptr, nullptr);
            if (result == D3DERR_DEVICELOST || result == D3DERR_DEVICEHUNG || result == D3DERR_DEVICEREMOVED)
                this->deviceLost = true;
        } while (true);

        ImGui_ImplDX9_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext(this->ctx);
        this->ctx = nullptr;

        this->CleanupDeviceD3D();
        ::DestroyWindow(this->hwnd);
        ::UnregisterClass(wc.lpszClassName, wc.hInstance);
        this->hwnd = nullptr;
    }

    Dx9Inbound::Dx9Inbound(std::optional<py::function> renderCallback) : Dx9Render(renderCallback)
    {
        if (_instance != nullptr)
            _throw_("Only one Dx9Inbound instance is allowed");
        _instance = this;
    }

    Dx9Inbound::~Dx9Inbound()
    {
        this->Detach();
        if (_instance == this)
            _instance = nullptr;
    }

    typedef HRESULT(__stdcall *EndSceneD3D9)(LPDIRECT3DDEVICE9);
    typedef HRESULT(__stdcall *ResetD3D9)(LPDIRECT3DDEVICE9, D3DPRESENT_PARAMETERS *);

    static EndSceneD3D9 oEndSceneD3D9 = nullptr;
    static ResetD3D9 oResetD3D9 = nullptr;

    HRESULT __stdcall hkResetD3D9(LPDIRECT3DDEVICE9 pd3dDevice, D3DPRESENT_PARAMETERS *pPresentationParameters)
    {
        if (Dx9Inbound::_instance != nullptr && Dx9Inbound::_instance->isImGuiInitialized)
            ImGui_ImplDX9_InvalidateDeviceObjects();
        HRESULT result = oResetD3D9(pd3dDevice, pPresentationParameters);
        if (Dx9Inbound::_instance != nullptr && Dx9Inbound::_instance->isImGuiInitialized && result == D3D_OK)
            ImGui_ImplDX9_CreateDeviceObjects();
        return result;
    }

    HRESULT __stdcall hkEndSceneD3D9(LPDIRECT3DDEVICE9 pd3dDevice)
    {
        if (Dx9Inbound::_instance != nullptr && !Dx9Inbound::_instance->isInLogic)
        {
            auto instance = Dx9Inbound::_instance;
            try
            {
                instance->InitImGui(pd3dDevice);
                instance->Update();
            }
            catch (...)
            {
                instance->Detach();
            }
        }
        return oEndSceneD3D9(pd3dDevice);
    }

    void Dx9Inbound::Attach()
    {
        IMGUI_INBOUND_NAMESPACE::Init(IMGUI_INBOUND_NAMESPACE::D3D9);
        oResetD3D9 = (ResetD3D9)IMGUI_INBOUND_NAMESPACE::GetMethod(16);
        oEndSceneD3D9 = (EndSceneD3D9)IMGUI_INBOUND_NAMESPACE::GetMethod(42);
        PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oResetD3D9, (PVOID)hkResetD3D9);
        PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oEndSceneD3D9, (PVOID)hkEndSceneD3D9);
    }

    void Dx9Inbound::Detach()
    {
        if (this->hwnd != nullptr)
        {
            M_IMGUI_IMPL_WIN32_NAMESPACE::Detach(this->hwnd);
            this->hwnd = nullptr;
        }
        if (oResetD3D9 != nullptr)
        {
            auto originalReset = (ResetD3D9)IMGUI_INBOUND_NAMESPACE::GetMethod(16);
            if (oResetD3D9 != originalReset)
                PYDETOURS_NAMESPACE::SimpleDetach((PVOID *)&oResetD3D9, (PVOID)hkResetD3D9);
            oResetD3D9 = nullptr;
        }
        if (oEndSceneD3D9 != nullptr)
        {
            auto originalEndScene = (EndSceneD3D9)IMGUI_INBOUND_NAMESPACE::GetMethod(42);
            if (oEndSceneD3D9 != originalEndScene)
                PYDETOURS_NAMESPACE::SimpleDetach((PVOID *)&oEndSceneD3D9, (PVOID)hkEndSceneD3D9);
            oEndSceneD3D9 = nullptr;
        }
    }

    void Dx9Inbound::InitImGui(LPDIRECT3DDEVICE9 pd3dDevice)
    {
        if (this->isImGuiInitialized)
            return;
        this->pd3dDevice = pd3dDevice;
        D3DDEVICE_CREATION_PARAMETERS params = {};
        HRESULT hr = pd3dDevice->GetCreationParameters(&params);
        if (hr != D3D_OK)
            _throwV_("Failed to get D3D9 device creation parameters: {}", hr);
        this->SetHwnd(params.hFocusWindow);

        M_IMGUI_IMPL_WIN32_NAMESPACE::Attach(this->hwnd);
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
        ImGui_ImplDX9_Init(pd3dDevice);
        this->isImGuiInitialized = true;
        dbgPrint("init dx9 inbound success\n");
    }

    void Dx9Inbound::Update()
    {
        this->isInLogic = true;
        this->_Update();
        this->isInLogic = false;
    }

    void Dx9Inbound::_Update()
    {
        this->ProcessCallBeforeFrameOnce(py::cast(this));

        ImGui_ImplDX9_NewFrame();
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

        ImGui::EndFrame();
        ImGui::Render();
        ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());

        if (ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }
    }

    void pybind_setup_mImguiImpl_Dx9(pybind11::module_ m)
    {
        pybind_setup_mImguiImpl_RenderBase(m);
        py::class_<Dx9Render, RenderBase>(m, "_Dx9Render", py::dynamic_attr(), py::module_local())
            .def_static("InvalidateDeviceObjects", []() { ImGui_ImplDX9_InvalidateDeviceObjects(); })
            .def_static("CreateDeviceObjects", []() { return ImGui_ImplDX9_CreateDeviceObjects(); });
        py::class_<Dx9Window, Dx9Render>(m, "Dx9Window", py::dynamic_attr(), py::module_local())
            .def(py::init<std::optional<py::function>>(), py::arg("renderCallback") = py::none())
            .def_readwrite("ClearColor", &Dx9Window::ClearColor)
            .def("Serve", &Dx9Window::Serve, py::call_guard<py::gil_scoped_release>());
        py::class_<Dx9Inbound, Dx9Render>(m, "Dx9Inbound", py::dynamic_attr(), py::module_local())
            .def(py::init<std::optional<py::function>>(), py::arg("renderCallback") = py::none())
            .def_property_readonly("isInLogic", [](Dx9Inbound &self) { return self.isInLogic; })
            .def("Attach", &Dx9Inbound::Attach)
            .def("Detach", &Dx9Inbound::Detach);
    }
}
END_M_IMGUI_IMPL_DX9_NAMESPACE