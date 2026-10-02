#include "./Win32Hook.h"

#include <atomic>
#include <mutex>

START_M_IMGUI_IMPL_WIN32_NAMESPACE
{
    using OVERLAY_TYPES_NAMESPACE::InputPolicy;

    static std::atomic<WNDPROC> oWndProc{nullptr};
    static std::atomic<bool> inputEnabled{false};
    static std::atomic<int> handlersInFlight{0};
    // The attached inbound's inputPolicy; dereferenced only inside the in-flight section.
    static std::atomic<std::atomic<int> *> attachedPolicy{nullptr};
    static HWND chainedHwnd = nullptr;
    static std::mutex chainMutex;

    enum class MessageClass
    {
        Other,
        Mouse,
        Keyboard,
    };

    static MessageClass ClassifyMessage(UINT uMsg)
    {
        switch (uMsg)
        {
        case WM_LBUTTONDOWN:
        case WM_LBUTTONUP:
        case WM_LBUTTONDBLCLK:
        case WM_RBUTTONDOWN:
        case WM_RBUTTONUP:
        case WM_RBUTTONDBLCLK:
        case WM_MBUTTONDOWN:
        case WM_MBUTTONUP:
        case WM_MBUTTONDBLCLK:
        case WM_XBUTTONDOWN:
        case WM_XBUTTONUP:
        case WM_XBUTTONDBLCLK:
        case WM_MOUSEWHEEL:
        case WM_MOUSEHWHEEL:
            return MessageClass::Mouse;
        case WM_KEYDOWN:
        case WM_KEYUP:
        case WM_SYSKEYDOWN:
        case WM_SYSKEYUP:
        case WM_CHAR:
        case WM_SYSCHAR:
        case WM_DEADCHAR:
        case WM_SYSDEADCHAR:
        case WM_UNICHAR:
            return MessageClass::Keyboard;
        }
        return MessageClass::Other;
    }

    struct MessageRoute
    {
        bool handlerCalled = false;
        bool swallowed = false;
    };

    // Routes one message under `policy`: whether ImGui's handler saw it and whether the game is denied it.
    static MessageRoute HandleMessage(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam, InputPolicy policy)
    {
        MessageRoute route;
        if (ImGui::GetCurrentContext() == nullptr)
            return route;
        MessageClass messageClass = ClassifyMessage(uMsg);
        if (policy == InputPolicy::PassAll)
        {
            if (messageClass == MessageClass::Other && uMsg != WM_SETCURSOR)
            {
                ImGui_ImplWin32_WndProcHandler(hwnd, uMsg, wParam, lParam);
                route.handlerCalled = true;
            }
            return route;
        }

        route.handlerCalled = true;
        if (ImGui_ImplWin32_WndProcHandler(hwnd, uMsg, wParam, lParam) != 0)
            route.swallowed = true;
        else if (policy == InputPolicy::CaptureAll)
            route.swallowed = messageClass != MessageClass::Other;
        else if (messageClass == MessageClass::Mouse)
            route.swallowed = ImGui::GetIO().WantCaptureMouse;
        else if (messageClass == MessageClass::Keyboard)
            route.swallowed = ImGui::GetIO().WantCaptureKeyboard;
        return route;
    }

    static LRESULT CALLBACK hkWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
    {
        handlersInFlight++;
        MessageRoute route;
        if (inputEnabled)
        {
            std::atomic<int> *source = attachedPolicy;
            InputPolicy policy = source != nullptr ? (InputPolicy)source->load() : InputPolicy::Auto;
            route = HandleMessage(hwnd, uMsg, wParam, lParam, policy);
        }
        handlersInFlight--;
        if (route.swallowed)
            return (uMsg == WM_UNICHAR && wParam == UNICODE_NOCHAR) ? 0L : 1L;
        return ::CallWindowProc(oWndProc, hwnd, uMsg, wParam, lParam);
    }

    void Attach(HWND hwnd, std::atomic<int> *policySource)
    {
        std::lock_guard<std::mutex> lock(chainMutex);
        if (chainedHwnd != nullptr && !::IsWindow(chainedHwnd))
            chainedHwnd = nullptr;
        if (chainedHwnd == hwnd)
        {
            attachedPolicy = policySource;
            inputEnabled = true;
            return;
        }
        if (chainedHwnd != nullptr)
            _throwV_("window procedure is still chained on another window: {:#x}", (uintptr_t)chainedHwnd);
        oWndProc = (WNDPROC)::GetWindowLongPtr(hwnd, GWLP_WNDPROC);
        WNDPROC previous = (WNDPROC)::SetWindowLongPtr(hwnd, GWLP_WNDPROC, (LONG_PTR)hkWindowProc);
        if (previous == nullptr)
            _throwV_("SetWindowLongPtr failed: {}", ::GetLastError());
        oWndProc = previous;
        chainedHwnd = hwnd;
        attachedPolicy = policySource;
        inputEnabled = true;
    }

    // Waits for hook bodies on other threads; a no-op on the window's own thread.
    static void WaitForHandlers(HWND hwnd)
    {
        if (::GetWindowThreadProcessId(hwnd, nullptr) == ::GetCurrentThreadId())
            return;
        MSG msg;
        while (handlersInFlight != 0)
        {
            ::MsgWaitForMultipleObjects(0, nullptr, FALSE, 1, QS_SENDMESSAGE);
            ::PeekMessage(&msg, nullptr, 0, 0, PM_NOREMOVE | PM_QS_SENDMESSAGE);
        }
    }

    // Restores the window procedure only while ours is on top; otherwise stays chained as a pass-through.
    // On return, even by exception, no other thread still reads the policy source.
    void Detach(HWND hwnd)
    {
        std::lock_guard<std::mutex> lock(chainMutex);
        attachedPolicy = nullptr;
        inputEnabled = false;
        try
        {
            if (chainedHwnd == hwnd && (WNDPROC)::GetWindowLongPtr(hwnd, GWLP_WNDPROC) == hkWindowProc)
            {
                if (::SetWindowLongPtr(hwnd, GWLP_WNDPROC, (LONG_PTR)oWndProc.load()) == 0)
                    _throwV_("SetWindowLongPtr failed: {}", ::GetLastError());
                chainedHwnd = nullptr;
            }
        }
        catch (...)
        {
            WaitForHandlers(hwnd);
            throw;
        }
        WaitForHandlers(hwnd);
    }
}
END_M_IMGUI_IMPL_WIN32_NAMESPACE