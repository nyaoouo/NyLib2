#include "./Dx11Window.h"
#include "./frontends/common/ImguiInbound.h"
#include "./frontends/common/PyDetours.h"
#include "./frontends/common/Win32Hook.h"

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

START_M_IMGUI_IMPL_NAMESPACE
{
    Dx11Texture::Dx11Texture(ID3D11Device *device, const char *filename)
    {
        int channels = 0;
        unsigned char *image_data = stbi_load(filename, &this->width, &this->height, &channels, 4);
        if (!image_data)
            _throwV_("Failed to load image: {}", filename);

        D3D11_TEXTURE2D_DESC desc = {};
        desc.Width = this->width;
        desc.Height = this->height;
        desc.MipLevels = 1;
        desc.ArraySize = 1;
        desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.SampleDesc.Count = 1;
        desc.Usage = D3D11_USAGE_DEFAULT;
        desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

        D3D11_SUBRESOURCE_DATA subResource = {};
        subResource.pSysMem = image_data;
        subResource.SysMemPitch = desc.Width * 4;

        ID3D11Texture2D *texture = nullptr;
        HRESULT hr = device->CreateTexture2D(&desc, &subResource, &texture);
        stbi_image_free(image_data);
        if (hr != S_OK)
            _throwV_("Failed to create texture: {}", hr);

        D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
        srvDesc.Format = desc.Format;
        srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
        srvDesc.Texture2D.MipLevels = desc.MipLevels;
        hr = device->CreateShaderResourceView(texture, &srvDesc, &this->textureView);
        texture->Release();
        if (hr != S_OK)
            _throwV_("Failed to create texture view: {}", hr);
    }

    Dx11Texture::~Dx11Texture()
    {
        if (this->textureView)
            this->textureView->Release();
    }

    uintptr_t Dx11Texture::GetHandle() const
    {
        return reinterpret_cast<uintptr_t>(this->textureView);
    }

    Dx11Window::Dx11Window(std::optional<py::function> renderCallback) : Dx11Render(renderCallback)
    {
        if (_instance != nullptr)
            _throw_("Only one Dx11Window instance is allowed");
        _instance = this;
    }

    Dx11Window::~Dx11Window()
    {
        if (_instance == this)
            _instance = nullptr;
    }

    void Dx11Render::CreateRenderTarget()
    {
        ID3D11Texture2D *backBuffer = nullptr;
        HRESULT hr = this->pSwapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer));
        if (hr != S_OK)
            _throwV_("Failed to get back buffer: {}", hr);
        hr = this->pd3dDevice->CreateRenderTargetView(backBuffer, nullptr, &this->mainRenderTargetView);
        backBuffer->Release();
        if (hr != S_OK)
            _throwV_("Failed to create render target view: {}", hr);
    }

    void Dx11Render::CleanupRenderTarget()
    {
        if (this->mainRenderTargetView)
        {
            this->mainRenderTargetView->Release();
            this->mainRenderTargetView = nullptr;
        }
    }

    void Dx11Window::CreateDeviceD3D()
    {
        DXGI_SWAP_CHAIN_DESC sd = {};
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
        sd.Windowed = TRUE;
        sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

        const D3D_FEATURE_LEVEL featureLevelArray[2] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
        D3D_FEATURE_LEVEL featureLevel;
        HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &this->pSwapChain, &this->pd3dDevice, &featureLevel, &this->pd3dDeviceContext);
        if (hr == DXGI_ERROR_UNSUPPORTED)
            hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &this->pSwapChain, &this->pd3dDevice, &featureLevel, &this->pd3dDeviceContext);
        if (hr != S_OK)
            _throwV_("Failed to create D3D11 device: {}", hr);
        this->CreateRenderTarget();
    }

    void Dx11Window::CleanupDeviceD3D()
    {
        this->CleanupRenderTarget();
        if (this->pSwapChain) { this->pSwapChain->Release(); this->pSwapChain = nullptr; }
        if (this->pd3dDeviceContext) { this->pd3dDeviceContext->Release(); this->pd3dDeviceContext = nullptr; }
        if (this->pd3dDevice) { this->pd3dDevice->Release(); this->pd3dDevice = nullptr; }
    }

    static LRESULT WINAPI Dx11WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        LRESULT trayResult = 0;
        if (RenderBase::ProcessTrayWindowProc(hWnd, msg, wParam, lParam, trayResult))
            return trayResult;
        if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
            return true;
        switch (msg)
        {
        case WM_SIZE:
            if (wParam == SIZE_MINIMIZED || Dx11Window::_instance == nullptr)
                return 0;
            Dx11Window::_instance->resizeWidth = (UINT)LOWORD(lParam);
            Dx11Window::_instance->resizeHeight = (UINT)HIWORD(lParam);
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU)
                return 0;
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        }
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }

    void Dx11Window::Serve()
    {
        WNDCLASSEX wc = {sizeof(wc), CS_CLASSDC, Dx11WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, _T("PyImgui2Dx11Window"), nullptr};
        RegisterClassEx(&wc);
        HWND hwnd = CreateWindow(wc.lpszClassName, _T(""), WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800, nullptr, nullptr, wc.hInstance, nullptr);
        if (hwnd == nullptr)
            _throwV_("Failed to create window: {}", GetLastError());
        this->SetHwnd(hwnd);
        this->CreateDeviceD3D();

        ShowWindow(this->hwnd, SW_SHOWDEFAULT);
        UpdateWindow(this->hwnd);
        SetWindowTextA(this->hwnd, this->title.c_str());

        this->ctx = ImGui::CreateContext(nullptr);
        ImGuiIO &io = ImGui::GetIO();
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;
        io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
        io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;
        ImGui::StyleColorsLight();
        ImGuiStyle &style = ImGui::GetStyle();
        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            style.WindowRounding = 0.0f;
            style.Colors[ImGuiCol_WindowBg].w = 1.0f;
        }

        ImGui_ImplWin32_Init(this->hwnd);
        ImGui_ImplDX11_Init(this->pd3dDevice, this->pd3dDeviceContext);

        bool done = false;
        while (!done)
        {
            MSG msg;
            while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
            {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
                if (msg.message == WM_QUIT)
                    done = true;
            }
            if (done)
                break;

            if (this->swapChainOccluded && this->pSwapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED)
            {
                Sleep(10);
                continue;
            }
            this->swapChainOccluded = false;

            if (this->resizeWidth != 0 && this->resizeHeight != 0)
            {
                this->CleanupRenderTarget();
                this->pSwapChain->ResizeBuffers(0, this->resizeWidth, this->resizeHeight, DXGI_FORMAT_UNKNOWN, 0);
                this->resizeWidth = this->resizeHeight = 0;
                this->CreateRenderTarget();
            }

            {
                py::gil_scoped_acquire gil;
                py::object self = py::cast(this, py::return_value_policy::reference);
                this->ProcessCallBeforeFrameOnce(self);
            }
            ImGui_ImplDX11_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();

            {
                py::gil_scoped_acquire gil;
                py::object self = py::cast(this, py::return_value_policy::reference);
                this->ProcessRenderCallback(self);
            }

            ImGui::Render();
            ImVec4 clear_color = this->ClearColor;
            const float clear_color_with_alpha[4] = {clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w};
            this->pd3dDeviceContext->OMSetRenderTargets(1, &this->mainRenderTargetView, nullptr);
            this->pd3dDeviceContext->ClearRenderTargetView(this->mainRenderTargetView, clear_color_with_alpha);
            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

            if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
            {
                ImGui::UpdatePlatformWindows();
                ImGui::RenderPlatformWindowsDefault();
            }

            HRESULT hr = this->pSwapChain->Present(1, 0);
            this->swapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);
        }

        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext(this->ctx);
        this->ctx = nullptr;
        this->CleanupDeviceD3D();
        DestroyWindow(this->hwnd);
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        this->hwnd = nullptr;
    }

    Dx11Texture *Dx11Render::CreateTexture(const char *filename)
    {
        return new Dx11Texture(this->pd3dDevice, filename);
    }

    typedef HRESULT(__stdcall *Present)(IDXGISwapChain *, UINT, UINT);
    static Present oPresent = nullptr;

    typedef HRESULT(__stdcall *ResizeBuffers)(IDXGISwapChain *, UINT, UINT, UINT, DXGI_FORMAT, UINT);
    static ResizeBuffers oResizeBuffers = nullptr;

    HRESULT __stdcall hkResizeBuffers11(
        IDXGISwapChain *pSwapChain,
        UINT BufferCount,
        UINT Width,
        UINT Height,
        DXGI_FORMAT NewFormat,
        UINT SwapChainFlags)
    {
        if (Dx11Inbound::_instance != nullptr && Dx11Inbound::_instance->isImGuiInitialized)
            Dx11Inbound::_instance->CleanupRenderTarget();
        auto res = oResizeBuffers(pSwapChain, BufferCount, Width, Height, NewFormat, SwapChainFlags);
        if (Dx11Inbound::_instance != nullptr && Dx11Inbound::_instance->isImGuiInitialized)
            Dx11Inbound::_instance->CreateRenderTarget();
        return res;
    }

    HRESULT __stdcall hkPresent11(IDXGISwapChain *pSwapChain, UINT SyncInterval, UINT Flags)
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

    Dx11Inbound::Dx11Inbound(std::optional<py::function> renderCallback) : Dx11Render(renderCallback)
    {
        if (_instance != nullptr)
            _throw_("Only one instance of Dx11Inbound is allowed");
        _instance = this;
    }

    Dx11Inbound::~Dx11Inbound()
    {
        this->Detach();
        _instance = nullptr;
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
        if (this->hwnd != nullptr)
        {
            M_IMGUI_IMPL_WIN32_NAMESPACE::Detach(this->hwnd);
            this->hwnd = nullptr;
        }
        if (oPresent != nullptr)
        {
            auto originalPresent = (Present)IMGUI_INBOUND_NAMESPACE::GetMethod(8);
            if (oPresent != originalPresent)
                PYDETOURS_NAMESPACE::SimpleDetach((PVOID *)&oPresent, (PVOID)hkPresent11);
            oPresent = nullptr;
        }
        if (oResizeBuffers != nullptr)
        {
            auto originalResizeBuffers = (ResizeBuffers)IMGUI_INBOUND_NAMESPACE::GetMethod(13);
            if (oResizeBuffers != originalResizeBuffers)
                PYDETOURS_NAMESPACE::SimpleDetach((PVOID *)&oResizeBuffers, (PVOID)hkResizeBuffers11);
            oResizeBuffers = nullptr;
        }
    }

    void Dx11Inbound::InitImGui(IDXGISwapChain *pSwapChain)
    {
        if (this->isImGuiInitialized)
            return;
        this->pSwapChain = pSwapChain;
        DXGI_SWAP_CHAIN_DESC desc = {};
        HRESULT hr = this->pSwapChain->GetDesc(&desc);
        if (hr != S_OK)
            _throwV_("Failed to get swap chain desc: {}", hr);
        this->SetHwnd(desc.OutputWindow);
        hr = this->pSwapChain->GetDevice(__uuidof(ID3D11Device), (void **)&this->pd3dDevice);
        if (hr != S_OK)
            _throwV_("Failed to get D3D11 device from swap chain: {}", hr);
        this->pd3dDevice->GetImmediateContext(&this->pd3dDeviceContext);

        M_IMGUI_IMPL_WIN32_NAMESPACE::Attach(this->hwnd);
        this->CreateRenderTarget();
        this->ctx = ImGui::CreateContext();

        ImGuiIO &io = ImGui::GetIO();
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;
        io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
        io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;

        ImGui::StyleColorsLight();

        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            auto &style = ImGui::GetStyle();
            style.WindowRounding = 0.0f;
            style.Colors[ImGuiCol_WindowBg].w = 1.0f;
        }

        ImGui_ImplWin32_Init(this->hwnd);
        ImGui_ImplDX11_Init(this->pd3dDevice, this->pd3dDeviceContext);
        this->isImGuiInitialized = true;

        dbgPrint("init dx11 inbound success\n");
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

        this->ProcessCallBeforeFrameOnce(py::cast(this));

        ImGui_ImplDX11_NewFrame();
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
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        this->pd3dDeviceContext->OMSetRenderTargets(0, nullptr, nullptr);

        if (ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }
    }

    void pybind_setup_mImguiImpl(pybind11::module_ m)
    {
        py::class_<Dx11Texture>(m, "Dx11Texture", py::dynamic_attr(), py::module_local())
            .def_property_readonly("handle", &Dx11Texture::GetHandle)
            .def_readonly("width", &Dx11Texture::width)
            .def_readonly("height", &Dx11Texture::height);

        pybind_setup_mImguiImpl_RenderBase(m);

        py::class_<Dx11Render, RenderBase>(m, "_Dx11Render", py::dynamic_attr(), py::module_local())
            .def_static("InvalidateDeviceObjects", []() { ImGui_ImplDX11_InvalidateDeviceObjects(); })
            .def_static("CreateDeviceObjects", []() { return ImGui_ImplDX11_CreateDeviceObjects(); })
            .def("CreateTexture", &Dx11Render::CreateTexture, py::arg("filename"), py::return_value_policy::take_ownership);

        py::class_<Dx11Window, Dx11Render>(m, "Dx11Window", py::dynamic_attr(), py::module_local())
            .def(py::init<std::optional<py::function>>(), py::arg("renderCallback") = py::none())
            .def_readwrite("ClearColor", &Dx11Window::ClearColor)
            .def("InvalidateDeviceObjects", [](Dx11Window &) { ImGui_ImplDX11_InvalidateDeviceObjects(); })
            .def("CreateDeviceObjects", [](Dx11Window &) { return ImGui_ImplDX11_CreateDeviceObjects(); })
            .def("Serve", &Dx11Window::Serve, py::call_guard<py::gil_scoped_release>());

        py::class_<Dx11Inbound, Dx11Render>(m, "Dx11Inbound", py::dynamic_attr(), py::module_local())
            .def(py::init<std::optional<py::function>>(), py::arg("renderCallback") = py::none())
            .def_property_readonly("isInLogic", [](Dx11Inbound &self) { return self.isInLogic; })
            .def("Attach", &Dx11Inbound::Attach)
            .def("Detach", &Dx11Inbound::Detach);
    }
}
END_M_IMGUI_IMPL_NAMESPACE