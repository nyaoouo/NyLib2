#include "./OverlayCanvas.h"
#include "./OverlayTarget.h"
#include "../../OverlayQueries.h"

#include <dcomp.h>
#include <optional>
#include <unordered_set>

#include "imgui_impl_win32.h"

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

START_M_IMGUI_IMPL_NAMESPACE
{
    namespace Overlay
    {
        namespace
        {
            LRESULT CALLBACK CanvasWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) noexcept
            {
                if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wParam, lParam))
                    return true;
                switch (msg)
                {
                case WM_CLOSE:
                    PostQuitMessage(0);
                    return 0;
                case WM_DESTROY:
                    return 0;
                case WM_DPICHANGED:
                    return 0;
                case WM_SYSCOMMAND:
                    if ((wParam & 0xfff0) == SC_KEYMENU)
                        return 0;
                    break;
                }
                return DefWindowProcW(hwnd, msg, wParam, lParam);
            }

            constexpr int ZOrderWalkLimit = 1024;

            bool IsTopmost(HWND window) noexcept
            {
                return (GetWindowLongPtrW(window, GWL_EXSTYLE) & WS_EX_TOPMOST) != 0;
            }

            template <class T>
            void ReleaseCom(T *&p) noexcept
            {
                if (p != nullptr)
                {
                    p->Release();
                    p = nullptr;
                }
            }

            // One overlay Serve() call: setup, the loop steps and the teardown, which undoes only what was created.
            class Canvas
            {
            public:
                Canvas(RenderBase &self, Config &config, Renderer &renderer, const wchar_t *className)
                    : self(self), config(config), renderer(renderer), className(className), instance(GetModuleHandleW(nullptr)), tracker(self, config)
                {
                }

                Canvas(const Canvas &) = delete;
                Canvas &operator=(const Canvas &) = delete;

                void Setup()
                {
                    this->saved = ImGui::GetCurrentContext();
                    this->contextSaved = true;
                    ImGui::SetCurrentContext(nullptr);

                    this->RegisterCanvasClass();

                    RECT rect = this->PlacementRect(this->config.monitor.load());
                    this->canvas = CreateWindowExW(WS_EX_NOREDIRECTIONBITMAP | WS_EX_TOOLWINDOW | WS_EX_TOPMOST, this->className, L"", WS_POPUP,
                                                   rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top,
                                                   nullptr, nullptr, this->instance, nullptr);
                    if (this->canvas == nullptr)
                        _throwV_("Failed to create the overlay window: {}", GetLastError());
                    this->self.SetHwnd(this->canvas);
                    this->hwndSet = true;
                    SetWindowTextA(this->canvas, this->self.title.c_str());

                    RECT client{};
                    GetClientRect(this->canvas, &client);
                    this->bufferWidth = (UINT)(std::max)(1L, client.right - client.left);
                    this->bufferHeight = (UINT)(std::max)(1L, client.bottom - client.top);
                    IUnknown *swapChain = this->renderer.CreateSwapChain(this->bufferWidth, this->bufferHeight);
                    this->BindComposition(swapChain);

                    this->ctx = ImGui::CreateContext(nullptr);
                    this->self.ctx = this->ctx;
                    ImGui::SetCurrentContext(this->ctx);
                    ImGuiIO &io = ImGui::GetIO();
                    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
                    io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;
                    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
                    io.ConfigFlags &= ~ImGuiConfigFlags_ViewportsEnable;
                    ImGui::StyleColorsDark();

                    if (!ImGui_ImplWin32_Init(this->canvas))
                        _throw_("ImGui_ImplWin32_Init failed");
                    this->platformInitialized = true;
                    this->renderer.InitBackend();
                    this->rendererInitialized = true;
                }

                void Run()
                {
                    while (this->PumpMessages())
                    {
                        this->CheckSignals();
                        int monitor = this->config.monitor.load();
                        int zOrder = this->config.zOrder.load();
                        this->tracker.Step();
                        ImGui::SetCurrentContext(this->ctx);
                        this->UpdatePlacement(monitor, zOrder);
                        if (this->tracker.State() == TargetState::Hidden)
                        {
                            // The callback keeps running at most every 50 ms; nothing is resized or presented.
                            this->ProduceFrame();
                            ImGui::Render();
                            Sleep(50);
                            continue;
                        }
                        this->ResizeSwapChain();
                        this->ProduceFrame();
                        this->Present();
                    }
                }

                void Teardown() noexcept
                {
                    if (this->ctx != nullptr)
                        ImGui::SetCurrentContext(this->ctx);
                    this->renderer.WaitIdle();
                    if (this->rendererInitialized)
                    {
                        this->renderer.ShutdownBackend();
                        this->rendererInitialized = false;
                    }
                    if (this->platformInitialized)
                    {
                        ImGui_ImplWin32_Shutdown();
                        this->platformInitialized = false;
                    }
                    if (this->ctx != nullptr)
                    {
                        ImGui::DestroyContext(this->ctx);
                        this->ctx = nullptr;
                        this->self.ctx = nullptr;
                    }
                    ReleaseCom(this->dcompVisual);
                    ReleaseCom(this->dcompTarget);
                    ReleaseCom(this->dcompDevice);
                    this->renderer.Release();
                    if (this->canvas != nullptr)
                    {
                        DestroyWindow(this->canvas);
                        this->canvas = nullptr;
                    }
                    if (this->classRegistered)
                    {
                        UnregisterClassW(this->className, this->instance);
                        this->classRegistered = false;
                    }
                    if (this->hwndSet)
                    {
                        this->self.SetHwnd(nullptr);
                        this->hwndSet = false;
                    }
                    if (this->contextSaved)
                    {
                        ImGui::SetCurrentContext(this->saved);
                        this->contextSaved = false;
                    }
                    this->tracker.Reset();
                }

            private:
                RenderBase &self;
                Config &config;
                Renderer &renderer;
                const wchar_t *className;
                HINSTANCE instance;
                TargetTracker tracker;

                ImGuiContext *saved = nullptr;
                bool contextSaved = false;
                bool classRegistered = false;
                HWND canvas = nullptr;
                bool hwndSet = false;
                bool shown = false;
                bool everShown = false;
                IDCompositionDesktopDevice *dcompDevice = nullptr;
                IDCompositionTarget *dcompTarget = nullptr;
                IDCompositionVisual2 *dcompVisual = nullptr;
                ImGuiContext *ctx = nullptr;
                bool platformInitialized = false;
                bool rendererInitialized = false;
                UINT bufferWidth = 0;
                UINT bufferHeight = 0;
                std::unordered_set<int> warnedMonitors;

                static void ClearViewportsFlag()
                {
                    ImGui::GetIO().ConfigFlags &= ~ImGuiConfigFlags_ViewportsEnable;
                }

                void RegisterCanvasClass()
                {
                    WNDCLASSEXW existing{};
                    existing.cbSize = sizeof(existing);
                    if (GetClassInfoExW(this->instance, this->className, &existing))
                    {
                        if (existing.lpfnWndProc != CanvasWndProc)
                            _throw_("The overlay window class is already registered by someone else");
                        this->classRegistered = true;
                        return;
                    }
                    WNDCLASSEXW wc{};
                    wc.cbSize = sizeof(wc);
                    wc.lpfnWndProc = CanvasWndProc;
                    wc.hInstance = this->instance;
                    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
                    wc.lpszClassName = this->className;
                    if (RegisterClassExW(&wc) == 0)
                        _throwV_("Failed to register the overlay window class: {}", GetLastError());
                    this->classRegistered = true;
                }

                void BindComposition(IUnknown *swapChain)
                {
                    HRESULT hr = DCompositionCreateDevice2(nullptr, IID_PPV_ARGS(&this->dcompDevice));
                    if (FAILED(hr))
                        _throwV_("DCompositionCreateDevice2 failed: {:#x}", (unsigned)hr);
                    hr = this->dcompDevice->CreateTargetForHwnd(this->canvas, TRUE, &this->dcompTarget);
                    if (FAILED(hr))
                        _throwV_("DirectComposition CreateTargetForHwnd failed: {:#x}", (unsigned)hr);
                    hr = this->dcompDevice->CreateVisual(&this->dcompVisual);
                    if (FAILED(hr))
                        _throwV_("DirectComposition CreateVisual failed: {:#x}", (unsigned)hr);
                    hr = this->dcompVisual->SetContent(swapChain);
                    if (FAILED(hr))
                        _throwV_("DirectComposition SetContent failed: {:#x}", (unsigned)hr);
                    hr = this->dcompTarget->SetRoot(this->dcompVisual);
                    if (FAILED(hr))
                        _throwV_("DirectComposition SetRoot failed: {:#x}", (unsigned)hr);
                    hr = this->dcompDevice->Commit();
                    if (FAILED(hr))
                        _throwV_("DirectComposition Commit failed: {:#x}", (unsigned)hr);
                }

                void WarnMonitorOutOfRange(int index, size_t count)
                {
                    if (!this->warnedMonitors.insert(index).second)
                        return;
                    std::string line = std::format("[pyimgui] overlayMonitor {} is out of range ({} monitors); using the primary monitor\n", index, count);
                    py::gil_scoped_acquire gil;
                    PySys_WriteStderr("%s", line.c_str());
                }

                // The rect of monitor `index` in GetMonitors() order, in the thread's current DPI context; out of range falls back to the primary.
                RECT PlacementRect(int index)
                {
                    auto monitors = OVERLAY_QUERIES_NAMESPACE::EnumerateMonitors();
                    if (monitors.empty())
                        return RECT{0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)};
                    if (index < 0 || index >= (int)monitors.size())
                    {
                        this->WarnMonitorOutOfRange(index, monitors.size());
                        index = 0;
                    }
                    const auto &monitor = monitors[index];
                    POINT centre{(LONG)(monitor.pos.x + monitor.size.x / 2), (LONG)(monitor.pos.y + monitor.size.y / 2)};
                    HMONITOR hmon = nullptr;
                    {
                        OVERLAY_QUERIES_NAMESPACE::ThreadDpiScope physical(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
                        hmon = MonitorFromPoint(centre, MONITOR_DEFAULTTONEAREST);
                    }
                    MONITORINFO info{};
                    info.cbSize = sizeof(info);
                    if (!GetMonitorInfoW(hmon, &info))
                        _throwV_("GetMonitorInfoW failed: {}", GetLastError());
                    return info.rcMonitor;
                }

                bool PumpMessages()
                {
                    MSG msg;
                    while (PeekMessageW(&msg, nullptr, 0U, 0U, PM_REMOVE))
                    {
                        if (msg.message == WM_QUIT)
                            return false;
                        TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                    if (!IsWindow(this->canvas))
                        return false;
                    ImGui::SetCurrentContext(this->ctx);
                    return true;
                }

                // Raises KeyboardInterrupt on Ctrl+C; Python handles signals only on the main thread.
                void CheckSignals()
                {
                    {
                        py::gil_scoped_acquire gil;
                        if (PyErr_CheckSignals() != 0)
                            throw py::error_already_set();
                    }
                    ImGui::SetCurrentContext(this->ctx);
                }

                // The canvas half of the lifecycle step: placement, visibility, then z-order.
                void UpdatePlacement(int monitor, int zOrder)
                {
                    bool visible = this->tracker.State() != TargetState::Hidden;
                    if (visible)
                        this->Place(monitor);
                    this->SetVisible(visible);
                    if (visible)
                        this->UpdateZOrder(zOrder);
                }

                // Moves the canvas in the z-order only where overlayZOrder, the target's root and the foreground window say it is wrong.
                void UpdateZOrder(int zOrder) noexcept
                {
                    HWND foreground = GetForegroundWindow();
                    bool topmost = IsTopmost(this->canvas);
                    if (this->tracker.State() != TargetState::Tracking)
                    {
                        this->KeepTopmost(topmost, nullptr, foreground);
                        return;
                    }
                    HWND root = GetAncestor(this->tracker.Target(), GA_ROOT);
                    if (root == nullptr)
                        return;
                    if (zOrder == (int)OVERLAY_TYPES_NAMESPACE::OverlayZOrder::Topmost)
                    {
                        this->KeepTopmost(topmost, IsTopmost(root) ? root : nullptr, foreground);
                        return;
                    }
                    bool rootTopmost = IsTopmost(root);
                    if (!rootTopmost && (foreground == root || foreground == this->canvas))
                    {
                        if (!topmost)
                            this->InsertCanvas(HWND_TOPMOST);
                        return;
                    }
                    this->KeepAbove(root, rootTopmost, topmost);
                }

                // Topmost, and back in front of `above` (a topmost root) or a topmost foreground window that lies above the canvas.
                void KeepTopmost(bool topmost, HWND above, HWND foreground) noexcept
                {
                    // A window turning topmost enters at the bottom of the topmost band, so the walks below see where it landed.
                    if (!topmost)
                        this->InsertCanvas(HWND_TOPMOST);
                    if (above != nullptr && this->CanvasBelow(above))
                        this->InsertCanvas(HWND_TOPMOST);
                    else if (foreground != nullptr && foreground != this->canvas && IsTopmost(foreground) && this->CanvasBelow(foreground))
                        this->InsertCanvas(HWND_TOPMOST);
                }

                // Directly above the root, with the root's topmost bit.
                void KeepAbove(HWND root, bool rootTopmost, bool topmost) noexcept
                {
                    HWND above = GetWindow(root, GW_HWNDPREV);
                    if (above == this->canvas && topmost == rootTopmost)
                        return;
                    if (rootTopmost)
                    {
                        if (!topmost)
                            this->InsertCanvas(HWND_TOPMOST);
                        this->InsertCanvas(above == nullptr || above == this->canvas ? HWND_TOPMOST : above);
                    }
                    else if (above == nullptr || above == this->canvas || IsTopmost(above))
                    {
                        // HWND_NOTOPMOST puts a topmost canvas in front of every non-topmost window, so directly above this root.
                        if (!topmost)
                            this->InsertCanvas(HWND_TOPMOST);
                        this->InsertCanvas(HWND_NOTOPMOST);
                    }
                    else
                        this->InsertCanvas(above);
                }

                // True when a bounded walk up from `window` reaches the top of the z-order without meeting the canvas; false when a window on the way is destroyed.
                bool CanvasBelow(HWND window) const noexcept
                {
                    HWND current = window;
                    for (int i = 0; i < ZOrderWalkLimit; i++)
                    {
                        HWND previous = GetWindow(current, GW_HWNDPREV);
                        if (previous == nullptr)
                            return IsWindow(current) != FALSE;
                        if (previous == this->canvas)
                            return false;
                        current = previous;
                    }
                    return false;
                }

                // A failed call is left to the next iteration.
                void InsertCanvas(HWND insertAfter) noexcept
                {
                    SetWindowPos(this->canvas, insertAfter, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
                }

                // The target's client rect while tracking, else the monitor's; skipped when the target cannot be read.
                void Place(int monitor)
                {
                    RECT rect{};
                    if (this->tracker.State() == TargetState::Tracking)
                    {
                        if (!this->tracker.ClientRectOnScreen(rect))
                            return;
                    }
                    else
                        rect = this->PlacementRect(monitor);
                    RECT current{};
                    if (GetWindowRect(this->canvas, &current) && EqualRect(&current, &rect))
                        return;
                    SetWindowPos(this->canvas, nullptr, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, SWP_NOZORDER | SWP_NOACTIVATE);
                }

                // The first show inserts at the top of the topmost band; a later show keeps the z-order.
                void SetVisible(bool visible)
                {
                    if (visible == this->shown)
                        return;
                    if (visible && !this->everShown)
                        SetWindowPos(this->canvas, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
                    else if (visible)
                        SetWindowPos(this->canvas, nullptr, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW | SWP_NOZORDER);
                    else
                        SetWindowPos(this->canvas, nullptr, 0, 0, 0, 0, SWP_HIDEWINDOW | SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER);
                    this->shown = visible;
                    this->everShown = this->everShown || visible;
                }

                void ResizeSwapChain()
                {
                    RECT client{};
                    if (!GetClientRect(this->canvas, &client))
                        return;
                    UINT width = (UINT)(client.right - client.left);
                    UINT height = (UINT)(client.bottom - client.top);
                    if (width == 0 || height == 0 || (width == this->bufferWidth && height == this->bufferHeight))
                        return;
                    this->renderer.WaitIdle();
                    this->renderer.Resize(width, height);
                    this->bufferWidth = width;
                    this->bufferHeight = height;
                }

                void BeginFrame()
                {
                    {
                        py::gil_scoped_acquire gil;
                        py::object pySelf = py::cast(&this->self, py::return_value_policy::reference);
                        this->self.ProcessCallBeforeFrameOnce(pySelf);
                    }
                    ImGui::SetCurrentContext(this->ctx);
                    this->renderer.NewFrame();
                    ImGui_ImplWin32_NewFrame();
                }

                // BeginFrame through the render callback.
                void ProduceFrame()
                {
                    this->BeginFrame();
                    this->FeedMouse();
                    ClearViewportsFlag();
                    ImGui::NewFrame();
                    this->CallRender();
                }

                // Feeds the cursor even when the canvas is neither foreground nor under the cursor.
                void FeedMouse()
                {
                    POINT point;
                    if (GetCursorPos(&point) && ScreenToClient(this->canvas, &point))
                        ImGui::GetIO().AddMousePosEvent((float)point.x, (float)point.y);
                }

                void CallRender()
                {
                    {
                        py::gil_scoped_acquire gil;
                        py::object pySelf = py::cast(&this->self, py::return_value_policy::reference);
                        this->self.ProcessRenderCallback(pySelf);
                    }
                    ImGui::SetCurrentContext(this->ctx);
                    ClearViewportsFlag();
                }

                void Present()
                {
                    ImGui::Render();
                    if (!this->renderer.RenderAndPresent())
                        Sleep(10);
                }
            };
        }

        void Serve(RenderBase &self, Config &config, Renderer &renderer, const wchar_t *className)
        {
            std::optional<OVERLAY_QUERIES_NAMESPACE::ThreadDpiScope> dpiScope;
            if (config.dpiAware.load())
                dpiScope.emplace(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
            Canvas canvas(self, config, renderer, className);
            try
            {
                canvas.Setup();
                canvas.Run();
            }
            catch (...)
            {
                canvas.Teardown();
                throw;
            }
            canvas.Teardown();
        }
    }
}
END_M_IMGUI_IMPL_NAMESPACE
