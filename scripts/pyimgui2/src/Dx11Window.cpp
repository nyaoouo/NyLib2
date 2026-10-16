#include "./Dx11Window.h"
#include "./frontends/common/ImguiInbound.h"
#include "./frontends/common/PyDetours.h"
#include "./frontends/common/Win32Hook.h"
#include "./frontends/overlay/OverlayCanvas.h"

#include <dxgi1_2.h>
#include <atomic>
#include <mutex>

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
        if (this->overlayConfig.overlay)
            return this->ServeOverlay();
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
            if (this->invalidatePending.exchange(false))
                ImGui_ImplDX11_InvalidateDeviceObjects();
            ImGui_ImplDX11_NewFrame();
            ImGui_ImplWin32_NewFrame();
            this->GateGamepad(false);
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

    namespace
    {
        // The overlay canvas's D3D side; keeps device, context, swap chain and RTV in the window's Dx11Render fields.
        class Dx11OverlayRenderer : public Overlay::Renderer
        {
        public:
            explicit Dx11OverlayRenderer(Dx11Window &window) : window(window) {}

            ~Dx11OverlayRenderer() override
            {
                this->Release();
            }

            IUnknown *CreateSwapChain(UINT width, UINT height) override
            {
                const D3D_FEATURE_LEVEL featureLevelArray[2] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
                D3D_FEATURE_LEVEL featureLevel;
                HRESULT hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, featureLevelArray, 2, D3D11_SDK_VERSION, &this->window.pd3dDevice, &featureLevel, &this->window.pd3dDeviceContext);
                if (hr == DXGI_ERROR_UNSUPPORTED)
                    hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, featureLevelArray, 2, D3D11_SDK_VERSION, &this->window.pd3dDevice, &featureLevel, &this->window.pd3dDeviceContext);
                if (FAILED(hr))
                    _throwV_("Failed to create D3D11 device: {:#x}", (unsigned)hr);

                IDXGIDevice *dxgiDevice = nullptr;
                hr = this->window.pd3dDevice->QueryInterface(IID_PPV_ARGS(&dxgiDevice));
                if (FAILED(hr))
                    _throwV_("Failed to get IDXGIDevice: {:#x}", (unsigned)hr);
                IDXGIAdapter *adapter = nullptr;
                hr = dxgiDevice->GetAdapter(&adapter);
                dxgiDevice->Release();
                if (FAILED(hr))
                    _throwV_("Failed to get the DXGI adapter: {:#x}", (unsigned)hr);
                hr = adapter->GetParent(IID_PPV_ARGS(&this->factory));
                adapter->Release();
                if (FAILED(hr))
                    _throwV_("Failed to get IDXGIFactory2: {:#x}", (unsigned)hr);

                DXGI_SWAP_CHAIN_DESC1 desc = {};
                desc.Width = width;
                desc.Height = height;
                desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
                desc.SampleDesc.Count = 1;
                desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
                desc.BufferCount = 2;
                desc.SwapEffect = DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL;
                desc.AlphaMode = DXGI_ALPHA_MODE_PREMULTIPLIED;
                desc.Scaling = DXGI_SCALING_STRETCH;
                IDXGISwapChain1 *swapChain = nullptr;
                hr = this->factory->CreateSwapChainForComposition(this->window.pd3dDevice, &desc, nullptr, &swapChain);
                if (FAILED(hr))
                    _throwV_("CreateSwapChainForComposition failed: {:#x}", (unsigned)hr);
                this->window.pSwapChain = swapChain;
                this->window.CreateRenderTarget();
                return swapChain;
            }

            void InitBackend() override
            {
                if (!ImGui_ImplDX11_Init(this->window.pd3dDevice, this->window.pd3dDeviceContext))
                    _throw_("ImGui_ImplDX11_Init failed");
            }

            void ShutdownBackend() noexcept override
            {
                ImGui_ImplDX11_Shutdown();
            }

            void WaitIdle() noexcept override
            {
                if (this->window.pd3dDeviceContext != nullptr)
                    this->window.pd3dDeviceContext->Flush();
            }

            void Resize(UINT width, UINT height) override
            {
                this->window.pd3dDeviceContext->OMSetRenderTargets(0, nullptr, nullptr);
                this->window.CleanupRenderTarget();
                HRESULT hr = this->window.pSwapChain->ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, 0);
                if (FAILED(hr))
                    _throwV_("Failed to resize the overlay swap chain: {:#x}", (unsigned)hr);
                this->window.CreateRenderTarget();
            }

            void NewFrame() override
            {
                if (this->window.invalidatePending.exchange(false))
                    ImGui_ImplDX11_InvalidateDeviceObjects();
                ImGui_ImplDX11_NewFrame();
            }

            bool RenderAndPresent() override
            {
                const float clearColor[4] = {0.0f, 0.0f, 0.0f, 0.0f};
                this->window.pd3dDeviceContext->OMSetRenderTargets(1, &this->window.mainRenderTargetView, nullptr);
                this->window.pd3dDeviceContext->ClearRenderTargetView(this->window.mainRenderTargetView, clearColor);
                ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
                HRESULT hr = this->window.pSwapChain->Present(1, 0);
                if (hr == DXGI_STATUS_OCCLUDED)
                    return false;
                if (FAILED(hr))
                    _throwV_("Failed to present the overlay swap chain: {:#x}", (unsigned)hr);
                return true;
            }

            void Release() noexcept override
            {
                this->window.CleanupRenderTarget();
                if (this->window.pSwapChain) { this->window.pSwapChain->Release(); this->window.pSwapChain = nullptr; }
                if (this->factory) { this->factory->Release(); this->factory = nullptr; }
                if (this->window.pd3dDeviceContext)
                {
                    this->window.pd3dDeviceContext->ClearState();
                    this->window.pd3dDeviceContext->Flush();
                    this->window.pd3dDeviceContext->Release();
                    this->window.pd3dDeviceContext = nullptr;
                }
                if (this->window.pd3dDevice) { this->window.pd3dDevice->Release(); this->window.pd3dDevice = nullptr; }
            }

        private:
            Dx11Window &window;
            IDXGIFactory2 *factory = nullptr;
        };
    }

    void Dx11Window::ServeOverlay()
    {
        Dx11OverlayRenderer renderer(*this);
        Overlay::Serve(*this, this->overlayConfig, renderer, L"PyImgui2Dx11Overlay");
    }

    Dx11Texture *Dx11Render::CreateTexture(const char *filename)
    {
        if (this->pd3dDevice == nullptr)
            _throw_("CreateTexture: no D3D11 device; call it while Serve() runs (e.g. from CallBeforeFrameOnce) or after the inbound hook drew a frame");
        return new Dx11Texture(this->pd3dDevice, filename);
    }

    typedef HRESULT(__stdcall *Present)(IDXGISwapChain *, UINT, UINT);
    static Present oPresent = nullptr;

    typedef HRESULT(__stdcall *ResizeBuffers)(IDXGISwapChain *, UINT, UINT, UINT, DXGI_FORMAT, UINT);
    static ResizeBuffers oResizeBuffers = nullptr;

    // Hooks stay installed for the process lifetime and reach the instance only through hookInstance.
    static std::atomic<Dx11Inbound *> hookInstance{nullptr};
    static std::atomic<bool> hooksEnabled{false};
    static std::atomic<int> hooksInFlight{0};
    static thread_local int hookBodyDepth = 0;
    // Depth of our own render logic and submits on this thread; hooks reached from inside it pass through.
    static thread_local int logicDepth = 0;
    static std::atomic<HWND> attachedHwnd{nullptr};
    static bool presentHooked = false;
    static bool resizeHooked = false;
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

        // Marks our own render logic or submit on this thread.
        struct LogicScope
        {
            LogicScope() { logicDepth++; }
            ~LogicScope() { logicDepth--; }
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
        fprintf(stderr, "[pyimgui] dx11 inbound disabled: %s\n", reason);
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
            fprintf(stderr, "[pyimgui] dx11 inbound: could not schedule the release of the last reference, keeping the object alive\n");
            std::fflush(stderr);
        }
        StopHooks();
    }

    HRESULT __stdcall hkResizeBuffers11(
        IDXGISwapChain *pSwapChain,
        UINT BufferCount,
        UINT Width,
        UINT Height,
        DXGI_FORMAT NewFormat,
        UINT SwapChainFlags)
    {
        HookBody body;
        Dx11Inbound *instance = hookInstance;
        if (instance != nullptr && instance->isImGuiInitialized)
            instance->CleanupRenderTarget();
        auto res = oResizeBuffers(pSwapChain, BufferCount, Width, Height, NewFormat, SwapChainFlags);
        if (instance != nullptr && instance->isImGuiInitialized)
            instance->CreateRenderTarget();
        return res;
    }

    HRESULT __stdcall hkPresent11(IDXGISwapChain *pSwapChain, UINT SyncInterval, UINT Flags)
    {
        {
            HookBody body;
            Dx11Inbound *instance = hookInstance;
            if (instance != nullptr && hooksEnabled && logicDepth == 0)
            {
                try
                {
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
        return oPresent(pSwapChain, SyncInterval, Flags);
    }

    Dx11Inbound::Dx11Inbound(std::optional<py::function> renderCallback) : Dx11Render(renderCallback)
    {
        if (_instance != nullptr)
            _throw_("Only one instance of Dx11Inbound is allowed");
        _instance = this;
        hookInstance = this;
    }

    Dx11Inbound::~Dx11Inbound()
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
        this->CleanupRenderTarget();
        if (this->pd3dDeviceContext != nullptr)
        {
            this->pd3dDeviceContext->Release();
            this->pd3dDeviceContext = nullptr;
        }
        if (this->pd3dDevice != nullptr)
        {
            this->pd3dDevice->Release();
            this->pd3dDevice = nullptr;
        }
        _instance = nullptr;
    }

    // Installs each hook at most once; a later Attach only re-enables drawing and input.
    void Dx11Inbound::Attach()
    {
        if (!atexitRegistered)
        {
            py::module_::import("atexit").attr("register")(py::cpp_function(StopHooksAtExit));
            atexitRegistered = true;
        }
        if (!presentHooked || !resizeHooked)
        {
            IMGUI_INBOUND_NAMESPACE::Init(IMGUI_INBOUND_NAMESPACE::D3D11);
            if (!presentHooked)
            {
                oPresent = (Present)IMGUI_INBOUND_NAMESPACE::GetMethod(8);
                PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oPresent, (PVOID)hkPresent11);
                presentHooked = true;
            }
            if (!resizeHooked)
            {
                oResizeBuffers = (ResizeBuffers)IMGUI_INBOUND_NAMESPACE::GetMethod(13);
                PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oResizeBuffers, (PVOID)hkResizeBuffers11);
                resizeHooked = true;
            }
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
    void Dx11Inbound::Detach()
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

    void Dx11Inbound::InitImGui(IDXGISwapChain *pSwapChain)
    {
        if (this->isImGuiInitialized)
            return;
        this->pSwapChain = pSwapChain;
        DXGI_SWAP_CHAIN_DESC desc = {};
        HRESULT hr = this->pSwapChain->GetDesc(&desc);
        if (hr != S_OK)
            _throwV_("Failed to get swap chain desc: {}", hr);
        HWND host = desc.OutputWindow;
        hr = this->pSwapChain->GetDevice(__uuidof(ID3D11Device), (void **)&this->pd3dDevice);
        if (hr != S_OK)
            _throwV_("Failed to get D3D11 device from swap chain: {}", hr);
        this->pd3dDevice->GetImmediateContext(&this->pd3dDeviceContext);

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

        ImGui_ImplWin32_Init(host);
        ImGui_ImplDX11_Init(this->pd3dDevice, this->pd3dDeviceContext);
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
        dbgPrint("init dx11 inbound success\n");
    }

    void Dx11Inbound::Update()
    {
        LogicScope logic;
        this->_Update();
    }

    void Dx11Inbound::_Update()
    {
        this->pd3dDeviceContext->OMSetRenderTargets(1, &this->mainRenderTargetView, nullptr);

        // `_Update` runs from `hkPresent11`, which is invoked by D3D11's
        // Present implementation on a thread that does NOT hold the GIL.
        // `py::cast(this)` has to touch pybind11's registry (a CPython call),
        // so the GIL must be acquired BEFORE the cast - not just inside the
        // Process* methods. Doing the cast without the GIL races with any
        // Python work happening on other threads (e.g. the DebugView worker
        // doing imports) and corrupts CPython's runtime state; the symptom
        // is a delayed NULL function-pointer call on the OTHER thread.
        // See the standalone `Dx11Window::Update` path above for the same
        // pattern done correctly.
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
                fprintf(stderr, "[pyimgui] dx11 inbound CallBeforeFrameOnce raised:\n%s\n", e.what());
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
        if (this->invalidatePending.exchange(false))
            ImGui_ImplDX11_InvalidateDeviceObjects();
        ImGui_ImplDX11_NewFrame();
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
                fprintf(stderr, "[pyimgui] dx11 inbound render callback raised, detaching:\n%s\n", e.what());
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

        ImGui::EndFrame();
        ImGui::Render();
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        this->pd3dDeviceContext->OMSetRenderTargets(0, nullptr, nullptr);

        // Runs every frame: ImGui's sanity check expects it even while viewports are off.
        ImGui::UpdatePlatformWindows();
        if (ImGui::GetCurrentContext()->ConfigFlagsCurrFrame & ImGuiConfigFlags_ViewportsEnable)
            ImGui::RenderPlatformWindowsDefault();
    }

    void pybind_setup_mImguiImpl(pybind11::module_ m)
    {
        py::class_<Dx11Texture>(m, "Dx11Texture", py::dynamic_attr(), py::module_local())
            .def_property_readonly("handle", &Dx11Texture::GetHandle)
            .def_readonly("width", &Dx11Texture::width)
            .def_readonly("height", &Dx11Texture::height);

        pybind_setup_mImguiImpl_RenderBase(m);

        py::class_<Dx11Render, RenderBase>(m, "_Dx11Render", py::dynamic_attr(), py::module_local())
            .def_static("InvalidateDeviceObjects", []() { RenderBase::RequestInvalidateForCurrentContext(); })
            .def_static("CreateDeviceObjects", []() { RenderBase::RequestInvalidateForCurrentContext(); return true; })
            .def("CreateTexture", &Dx11Render::CreateTexture, py::arg("filename"), py::return_value_policy::take_ownership);

        py::class_<Dx11Window, Dx11Render> dx11Window(m, "Dx11Window", py::dynamic_attr(), py::module_local());
        dx11Window.def(py::init<std::optional<py::function>>(), py::arg("renderCallback") = py::none())
            .def_readwrite("ClearColor", &Dx11Window::ClearColor)
            .def("InvalidateDeviceObjects", [](Dx11Window &self) { self.invalidatePending = true; })
            .def("CreateDeviceObjects", [](Dx11Window &self) { self.invalidatePending = true; return true; });
        Overlay::BindMembers(dx11Window);

        py::class_<Dx11Inbound, Dx11Render>(m, "Dx11Inbound", py::dynamic_attr(), py::module_local())
            .def(py::init<std::optional<py::function>>(), py::arg("renderCallback") = py::none())
            .def_property_readonly("isInLogic", [](Dx11Inbound &) { return logicDepth > 0; })
            .def_property("viewportsEnable",
                          [](Dx11Inbound &self) { return self.viewportsEnable.load(); },
                          [](Dx11Inbound &self, bool enable)
                          {
                              self.viewportsEnable = enable;
                              self.viewportsDirty = true;
                          })
            .def("Attach", &Dx11Inbound::Attach)
            .def("Detach", &Dx11Inbound::Detach);
    }
}
END_M_IMGUI_IMPL_NAMESPACE