#include "./Dx9Window.h"
#include "../common/ImguiInbound.h"
#include "../common/PyDetours.h"

#include <atomic>
#include <mutex>

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

    typedef HRESULT(__stdcall *EndSceneD3D9)(LPDIRECT3DDEVICE9);
    typedef HRESULT(__stdcall *ResetD3D9)(LPDIRECT3DDEVICE9, D3DPRESENT_PARAMETERS *);

    static EndSceneD3D9 oEndSceneD3D9 = nullptr;
    static ResetD3D9 oResetD3D9 = nullptr;

    // Hooks stay installed for the process lifetime and reach the instance only through hookInstance.
    static std::atomic<Dx9Inbound *> hookInstance{nullptr};
    static std::atomic<bool> hooksEnabled{false};
    static std::atomic<int> hooksInFlight{0};
    static thread_local int hookBodyDepth = 0;
    // Depth of our own render logic and submits on this thread; hooks reached from inside it pass through.
    static thread_local int logicDepth = 0;
    static std::atomic<HWND> attachedHwnd{nullptr};
    static bool resetHooked = false;
    static bool endSceneHooked = false;
    static bool atexitRegistered = false;
    static std::atomic<bool> backendInitialized{false};
    static LPDIRECT3DDEVICE9 backendDevice = nullptr;
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
        fprintf(stderr, "[pyimgui] dx9 inbound disabled: %s\n", reason);
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
            fprintf(stderr, "[pyimgui] dx9 inbound: could not schedule the release of the last reference, keeping the object alive\n");
            std::fflush(stderr);
        }
        StopHooks();
    }

    HRESULT __stdcall hkResetD3D9(LPDIRECT3DDEVICE9 pd3dDevice, D3DPRESENT_PARAMETERS *pPresentationParameters)
    {
        if (backendInitialized)
            ImGui_ImplDX9_InvalidateDeviceObjects();
        HRESULT result = oResetD3D9(pd3dDevice, pPresentationParameters);
        if (backendInitialized && hookInstance != nullptr && result == D3D_OK)
            ImGui_ImplDX9_CreateDeviceObjects();
        return result;
    }

    HRESULT __stdcall hkEndSceneD3D9(LPDIRECT3DDEVICE9 pd3dDevice)
    {
        {
            HookBody body;
            Dx9Inbound *instance = hookInstance;
            if (instance != nullptr && hooksEnabled && logicDepth == 0)
            {
                try
                {
                    instance->InitImGui(pd3dDevice);
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
        return oEndSceneD3D9(pd3dDevice);
    }

    Dx9Inbound::Dx9Inbound(std::optional<py::function> renderCallback) : Dx9Render(renderCallback)
    {
        if (_instance != nullptr)
            _throw_("Only one Dx9Inbound instance is allowed");
        _instance = this;
        hookInstance = this;
    }

    Dx9Inbound::~Dx9Inbound()
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
        if (_instance == this)
            _instance = nullptr;
    }

    // Installs each hook at most once; a later Attach only re-enables drawing and input.
    void Dx9Inbound::Attach()
    {
        if (!atexitRegistered)
        {
            py::module_::import("atexit").attr("register")(py::cpp_function(StopHooksAtExit));
            atexitRegistered = true;
        }
        if (!resetHooked || !endSceneHooked)
        {
            IMGUI_INBOUND_NAMESPACE::Init(IMGUI_INBOUND_NAMESPACE::D3D9);
            if (!resetHooked)
            {
                oResetD3D9 = (ResetD3D9)IMGUI_INBOUND_NAMESPACE::GetMethod(16);
                PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oResetD3D9, (PVOID)hkResetD3D9);
                resetHooked = true;
            }
            if (!endSceneHooked)
            {
                oEndSceneD3D9 = (EndSceneD3D9)IMGUI_INBOUND_NAMESPACE::GetMethod(42);
                PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oEndSceneD3D9, (PVOID)hkEndSceneD3D9);
                endSceneHooked = true;
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
    void Dx9Inbound::Detach()
    {
        std::lock_guard<std::mutex> lock(transitionMutex);
        hooksEnabled = false;
        if (HWND hwnd = attachedHwnd)
            M_IMGUI_IMPL_WIN32_NAMESPACE::Detach(hwnd);
        this->SetHwnd(nullptr);
    }

    // Reuses the context and backends of an earlier instance on the same device.
    void Dx9Inbound::InitImGui(LPDIRECT3DDEVICE9 pd3dDevice)
    {
        if (this->isImGuiInitialized)
            return;
        this->pd3dDevice = pd3dDevice;
        D3DDEVICE_CREATION_PARAMETERS params = {};
        HRESULT hr = pd3dDevice->GetCreationParameters(&params);
        if (hr != D3D_OK)
            _throwV_("Failed to get D3D9 device creation parameters: {}", hr);
        HWND host = params.hFocusWindow;

        if (backendInitialized && backendDevice == pd3dDevice)
            this->ctx = ImGui::GetCurrentContext();
        else
        {
            if (backendInitialized)
                ImGui_ImplDX9_Shutdown();
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
            ImGui_ImplDX9_Init(pd3dDevice);
            backendDevice = pd3dDevice;
            backendInitialized = true;
        }

        std::lock_guard<std::mutex> lock(transitionMutex);
        this->isImGuiInitialized = true;
        attachedHwnd = host;
        if (hooksEnabled && hookInstance == this)
        {
            M_IMGUI_IMPL_WIN32_NAMESPACE::Attach(host, &this->inputPolicy);
            this->SetHwnd(host);
        }
        dbgPrint("init dx9 inbound success\n");
    }

    void Dx9Inbound::Update()
    {
        LogicScope logic;
        this->_Update();
    }

    void Dx9Inbound::_Update()
    {
        // Runs on the game's render thread, which does not hold the GIL.
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
                fprintf(stderr, "[pyimgui] dx9 inbound CallBeforeFrameOnce raised:\n%s\n", e.what());
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

        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
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
                fprintf(stderr, "[pyimgui] dx9 inbound render callback raised, detaching:\n%s\n", e.what());
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
            .def_property_readonly("isInLogic", [](Dx9Inbound &) { return logicDepth > 0; })
            .def("Attach", &Dx9Inbound::Attach)
            .def("Detach", &Dx9Inbound::Detach);
    }
}
END_M_IMGUI_IMPL_DX9_NAMESPACE