#include "./Gl3Window.h"
#include "../common/ImguiInbound.h"
#include "../common/PyDetours.h"

#include <atomic>
#include <mutex>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

START_M_IMGUI_IMPL_GL3_NAMESPACE
{
    // Shared per-viewport WGL state used by ImGui multi-viewport hooks.
    namespace
    {
        struct WGL_ViewportData
        {
            HDC hDC = nullptr;
            HWND hWnd = nullptr;
            bool ownsDC = false;
        };

        HGLRC g_sharedRC = nullptr;

        bool ChoosePixelFormatForDC(HDC hDc)
        {
            PIXELFORMATDESCRIPTOR pfd = {};
            pfd.nSize = sizeof(pfd);
            pfd.nVersion = 1;
            pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
            pfd.iPixelType = PFD_TYPE_RGBA;
            pfd.cColorBits = 32;
            int pf = ::ChoosePixelFormat(hDc, &pfd);
            if (pf == 0)
                return false;
            if (::SetPixelFormat(hDc, pf, &pfd) == FALSE)
                return false;
            return true;
        }

        void Hook_Renderer_CreateWindow(ImGuiViewport *viewport)
        {
            auto *data = IM_NEW(WGL_ViewportData)();
            data->hWnd = (HWND)viewport->PlatformHandle;
            HDC dc = ::GetDC(data->hWnd);
            if (dc != nullptr)
            {
                ChoosePixelFormatForDC(dc);
                data->hDC = dc;
                data->ownsDC = true;
            }
            viewport->RendererUserData = data;
        }

        void Hook_Renderer_DestroyWindow(ImGuiViewport *viewport)
        {
            if (auto *data = (WGL_ViewportData *)viewport->RendererUserData)
            {
                if (data->ownsDC && data->hDC && data->hWnd)
                    ::ReleaseDC(data->hWnd, data->hDC);
                IM_DELETE(data);
                viewport->RendererUserData = nullptr;
            }
        }

        void Hook_Platform_RenderWindow(ImGuiViewport *viewport, void *)
        {
            if (auto *data = (WGL_ViewportData *)viewport->RendererUserData)
                if (data->hDC && g_sharedRC)
                    ::wglMakeCurrent(data->hDC, g_sharedRC);
        }

        void Hook_Renderer_SwapBuffers(ImGuiViewport *viewport, void *)
        {
            if (auto *data = (WGL_ViewportData *)viewport->RendererUserData)
                if (data->hDC)
                    ::SwapBuffers(data->hDC);
        }

        void InstallViewportHooksIfNeeded()
        {
            if (!(ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_ViewportsEnable))
                return;
            ImGuiPlatformIO &io = ImGui::GetPlatformIO();
            io.Renderer_CreateWindow = Hook_Renderer_CreateWindow;
            io.Renderer_DestroyWindow = Hook_Renderer_DestroyWindow;
            io.Renderer_SwapBuffers = Hook_Renderer_SwapBuffers;
            io.Platform_RenderWindow = Hook_Platform_RenderWindow;
        }
    }

    Gl3Window::Gl3Window(std::optional<py::function> renderCallback) : Gl3Render(renderCallback)
    {
        if (_instance != nullptr)
            _throw_("Only one Gl3Window instance is allowed");
        _instance = this;
    }

    Gl3Window::~Gl3Window()
    {
        if (_instance == this)
            _instance = nullptr;
    }

    bool Gl3Window::CreateDeviceWGL(HWND hWnd)
    {
        HDC hDc = ::GetDC(hWnd);
        if (hDc == nullptr)
            return false;
        if (!ChoosePixelFormatForDC(hDc))
        {
            ::ReleaseDC(hWnd, hDc);
            return false;
        }
        ::ReleaseDC(hWnd, hDc);

        this->hDC = ::GetDC(hWnd);
        if (this->hDC == nullptr)
            return false;
        if (g_sharedRC == nullptr)
            g_sharedRC = ::wglCreateContext(this->hDC);
        this->hRC = g_sharedRC;
        return this->hRC != nullptr;
    }

    void Gl3Window::CleanupDeviceWGL()
    {
        ::wglMakeCurrent(nullptr, nullptr);
        if (this->hDC && this->hwnd)
        {
            ::ReleaseDC(this->hwnd, this->hDC);
            this->hDC = nullptr;
        }
        if (this->hRC && this->hRC == g_sharedRC)
        {
            ::wglDeleteContext(this->hRC);
            g_sharedRC = nullptr;
        }
        this->hRC = nullptr;
    }

    LRESULT WINAPI Gl3ImguiWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        LRESULT trayResult = 0;
        if (M_IMGUI_IMPL_NAMESPACE::RenderBase::ProcessTrayWindowProc(hWnd, msg, wParam, lParam, trayResult))
            return trayResult;
        if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
            return true;
        if (Gl3Window::_instance == nullptr)
            return ::DefWindowProc(hWnd, msg, wParam, lParam);
        switch (msg)
        {
        case WM_SIZE:
            if (wParam != SIZE_MINIMIZED)
            {
                Gl3Window::_instance->width = (int)LOWORD(lParam);
                Gl3Window::_instance->height = (int)HIWORD(lParam);
            }
            return 0;
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

    void Gl3Window::Serve()
    {
        WNDCLASSEX wc = {sizeof(wc), CS_OWNDC, Gl3ImguiWndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, _T("mImguiWindowGl3"), nullptr};
        ::RegisterClassEx(&wc);
        HWND hwnd = ::CreateWindow(wc.lpszClassName, _T(""), WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800, nullptr, nullptr, wc.hInstance, nullptr);
        if (hwnd == nullptr)
            _throwV_("Failed to create window, error code: {}", GetLastError());
        this->SetHwnd(hwnd);

        if (!this->CreateDeviceWGL(hwnd))
        {
            this->CleanupDeviceWGL();
            ::DestroyWindow(hwnd);
            ::UnregisterClass(wc.lpszClassName, wc.hInstance);
            _throw_("Failed to initialize WGL context");
        }
        ::wglMakeCurrent(this->hDC, this->hRC);

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

        ImGui_ImplWin32_InitForOpenGL(this->hwnd);
        ImGui_ImplOpenGL3_Init();
        InstallViewportHooksIfNeeded();

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
            if (::IsIconic(this->hwnd))
            {
                ::Sleep(10);
                continue;
            }

            this->ProcessCallBeforeFrameOnce(py::cast(this));

            if (this->invalidatePending.exchange(false))
                ImGui_ImplOpenGL3_DestroyDeviceObjects();
            ImGui_ImplOpenGL3_NewFrame();
            ImGui_ImplWin32_NewFrame();
            this->GateGamepad(false);
            ImGui::NewFrame();

            this->ProcessRenderCallback(py::cast(this));

            ImGui::Render();

            RECT clientRect;
            ::GetClientRect(this->hwnd, &clientRect);
            int viewportWidth = clientRect.right - clientRect.left;
            int viewportHeight = clientRect.bottom - clientRect.top;
            if (viewportWidth > 0 && viewportHeight > 0)
            {
                glViewport(0, 0, viewportWidth, viewportHeight);
                glClearColor(this->ClearColor.x * this->ClearColor.w,
                             this->ClearColor.y * this->ClearColor.w,
                             this->ClearColor.z * this->ClearColor.w,
                             this->ClearColor.w);
                glClear(GL_COLOR_BUFFER_BIT);
            }
            ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

            if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
            {
                ImGui::UpdatePlatformWindows();
                ImGui::RenderPlatformWindowsDefault();
                ::wglMakeCurrent(this->hDC, this->hRC);
            }

            ::SwapBuffers(this->hDC);
        } while (true);

        ImGui_ImplOpenGL3_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext(this->ctx);
        this->ctx = nullptr;
        this->CleanupDeviceWGL();
        ::DestroyWindow(this->hwnd);
        ::UnregisterClass(wc.lpszClassName, wc.hInstance);
        this->hwnd = nullptr;
    }

    typedef BOOL(WINAPI *WglSwapBuffersFn)(HDC);
    static WglSwapBuffersFn oWglSwapBuffers = nullptr;

    // Hooks stay installed for the process lifetime and reach the instance only through hookInstance.
    static std::atomic<Gl3Inbound *> hookInstance{nullptr};
    static std::atomic<bool> hooksEnabled{false};
    static std::atomic<int> hooksInFlight{0};
    static thread_local int hookBodyDepth = 0;
    // Depth of our own render logic and submits on this thread; hooks reached from inside it pass through.
    static thread_local int logicDepth = 0;
    static std::atomic<HWND> attachedHwnd{nullptr};
    static bool swapBuffersHooked = false;
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

    // Stops drawing and input; the hook stays installed.
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
        fprintf(stderr, "[pyimgui] gl3 inbound disabled: %s\n", reason);
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
            fprintf(stderr, "[pyimgui] gl3 inbound: could not schedule the release of the last reference, keeping the object alive\n");
            std::fflush(stderr);
        }
        StopHooks();
    }

    BOOL WINAPI hkWglSwapBuffers(HDC hDC)
    {
        {
            HookBody body;
            Gl3Inbound *instance = hookInstance;
            if (instance != nullptr && hooksEnabled && logicDepth == 0)
            {
                try
                {
                    instance->InitImGui(hDC);
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
        return oWglSwapBuffers(hDC);
    }

    Gl3Inbound::Gl3Inbound(std::optional<py::function> renderCallback) : Gl3Render(renderCallback)
    {
        if (_instance != nullptr)
            _throw_("Only one Gl3Inbound instance is allowed");
        _instance = this;
        hookInstance = this;
    }

    Gl3Inbound::~Gl3Inbound()
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

    // Installs the hook at most once; a later Attach only re-enables drawing and input.
    void Gl3Inbound::Attach()
    {
        if (!atexitRegistered)
        {
            py::module_::import("atexit").attr("register")(py::cpp_function(StopHooksAtExit));
            atexitRegistered = true;
        }
        if (!swapBuffersHooked)
        {
            HMODULE libGL = ::GetModuleHandleA("opengl32.dll");
            if (libGL == nullptr)
                libGL = ::LoadLibraryA("opengl32.dll");
            if (libGL == nullptr)
                _throwV_("Failed to load opengl32.dll, GetLastError: {}", ::GetLastError());
            oWglSwapBuffers = (WglSwapBuffersFn)::GetProcAddress(libGL, "wglSwapBuffers");
            if (oWglSwapBuffers == nullptr)
                _throwV_("Failed to resolve wglSwapBuffers, GetLastError: {}", ::GetLastError());
            PYDETOURS_NAMESPACE::SimpleAttach((PVOID *)&oWglSwapBuffers, (PVOID)hkWglSwapBuffers);
            swapBuffersHooked = true;
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

    // Disables drawing and input; the hook, the original and the ImGui context stay.
    void Gl3Inbound::Detach()
    {
        std::lock_guard<std::mutex> lock(transitionMutex);
        hooksEnabled = false;
        if (HWND hwnd = attachedHwnd)
            M_IMGUI_IMPL_WIN32_NAMESPACE::Detach(hwnd);
        this->SetHwnd(nullptr);
    }

    void Gl3Inbound::InitImGui(HDC hDC)
    {
        if (this->isImGuiInitialized)
            return;
        this->hostHDC = hDC;
        this->hostHGLRC = ::wglGetCurrentContext();
        HWND host = ::WindowFromDC(hDC);
        if (host == nullptr)
            _throw_("Failed to resolve HWND from current HDC");
        g_sharedRC = this->hostHGLRC;

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

        ImGui_ImplWin32_InitForOpenGL(host);
        ImGui_ImplOpenGL3_Init();
        InstallViewportHooksIfNeeded();

        std::lock_guard<std::mutex> lock(transitionMutex);
        this->isImGuiInitialized = true;
        attachedHwnd = host;
        if (hooksEnabled && hookInstance == this)
        {
            M_IMGUI_IMPL_WIN32_NAMESPACE::Attach(host, &this->inputPolicy);
            this->SetHwnd(host);
        }
        dbgPrint("init gl3 inbound success\n");
    }

    void Gl3Inbound::Update()
    {
        LogicScope logic;
        this->_Update();
    }

    void Gl3Inbound::_Update()
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
                fprintf(stderr, "[pyimgui] gl3 inbound CallBeforeFrameOnce raised:\n%s\n", e.what());
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

        if (this->invalidatePending.exchange(false))
            ImGui_ImplOpenGL3_DestroyDeviceObjects();
        ImGui_ImplOpenGL3_NewFrame();
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
                fprintf(stderr, "[pyimgui] gl3 inbound render callback raised, detaching:\n%s\n", e.what());
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
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        if (ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            HDC currentDC = ::wglGetCurrentDC();
            HGLRC currentRC = ::wglGetCurrentContext();
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
            if (currentDC && currentRC)
                ::wglMakeCurrent(currentDC, currentRC);
        }
    }

    void pybind_setup_mImguiImpl_Gl3(pybind11::module_ m)
    {
        pybind_setup_mImguiImpl_RenderBase(m);
        py::class_<Gl3Render, RenderBase>(m, "_Gl3Render", py::dynamic_attr(), py::module_local())
            .def_static("InvalidateDeviceObjects", []() { RenderBase::RequestInvalidateForCurrentContext(); })
            .def_static("CreateDeviceObjects", []() { RenderBase::RequestInvalidateForCurrentContext(); return true; })
            .def_static("DestroyDeviceObjects", []() { RenderBase::RequestInvalidateForCurrentContext(); })
            .def_static("CreateFontsTexture", []() { RenderBase::RequestInvalidateForCurrentContext(); return true; })
            .def_static("DestroyFontsTexture", []() { RenderBase::RequestInvalidateForCurrentContext(); });
        py::class_<Gl3Window, Gl3Render>(m, "Gl3Window", py::dynamic_attr(), py::module_local())
            .def(py::init<std::optional<py::function>>(), py::arg("renderCallback") = py::none())
            .def_readwrite("ClearColor", &Gl3Window::ClearColor)
            .def("Serve", &Gl3Window::Serve, py::call_guard<py::gil_scoped_release>());
        py::class_<Gl3Inbound, Gl3Render>(m, "Gl3Inbound", py::dynamic_attr(), py::module_local())
            .def(py::init<std::optional<py::function>>(), py::arg("renderCallback") = py::none())
            .def_property_readonly("isInLogic", [](Gl3Inbound &) { return logicDepth > 0; })
            .def("Attach", &Gl3Inbound::Attach)
            .def("Detach", &Gl3Inbound::Detach);
    }
}
END_M_IMGUI_IMPL_GL3_NAMESPACE
