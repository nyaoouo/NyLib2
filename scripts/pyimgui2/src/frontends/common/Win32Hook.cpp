#include "./Win32Hook.h"

#include <atomic>
#include <mutex>

START_M_IMGUI_IMPL_WIN32_NAMESPACE
{
    static std::atomic<WNDPROC> oWndProc{nullptr};
    static std::atomic<bool> inputEnabled{false};
    static std::atomic<int> handlersInFlight{0};
    static HWND chainedHwnd = nullptr;
    static std::mutex chainMutex;

    // Returns true when ImGui consumes the message.
    static bool HandleMessage(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
    {
        if (ImGui::GetCurrentContext() == nullptr)
            return false;
        if (ImGui_ImplWin32_WndProcHandler(hwnd, uMsg, wParam, lParam) > 0)
            return true;

        switch (uMsg)
        {
        case WM_LBUTTONDOWN:
        case WM_LBUTTONUP:
        case WM_RBUTTONDOWN:
        case WM_RBUTTONUP:
        case WM_MBUTTONDOWN:
        case WM_MBUTTONUP:
        case WM_XBUTTONDOWN:
        case WM_XBUTTONUP:
        case WM_MOUSEWHEEL:
        case WM_MOUSEHWHEEL:
            return ImGui::GetIO().WantCaptureMouse;
        case WM_KEYDOWN:
        case WM_KEYUP:
        case WM_SYSKEYDOWN:
        case WM_SYSKEYUP:
        case WM_CHAR:
            return ImGui::GetIO().WantCaptureKeyboard;
        }
        return false;
    }

    static LRESULT CALLBACK hkWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
    {
        handlersInFlight++;
        bool handled = inputEnabled && HandleMessage(hwnd, uMsg, wParam, lParam);
        handlersInFlight--;
        if (handled)
            return 1L;
        return ::CallWindowProc(oWndProc, hwnd, uMsg, wParam, lParam);
    }

    void Attach(HWND hwnd)
    {
        std::lock_guard<std::mutex> lock(chainMutex);
        if (chainedHwnd != nullptr && !::IsWindow(chainedHwnd))
            chainedHwnd = nullptr;
        if (chainedHwnd == hwnd)
        {
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
        inputEnabled = true;
    }

    // Restores the window procedure only while ours is on top; otherwise stays chained as a pass-through.
    void Detach(HWND hwnd)
    {
        std::lock_guard<std::mutex> lock(chainMutex);
        inputEnabled = false;
        if (chainedHwnd == hwnd && (WNDPROC)::GetWindowLongPtr(hwnd, GWLP_WNDPROC) == hkWindowProc)
        {
            if (::SetWindowLongPtr(hwnd, GWLP_WNDPROC, (LONG_PTR)oWndProc.load()) == 0)
                _throwV_("SetWindowLongPtr failed: {}", ::GetLastError());
            chainedHwnd = nullptr;
        }
        if (::GetWindowThreadProcessId(hwnd, nullptr) == ::GetCurrentThreadId())
            return;
        MSG msg;
        while (handlersInFlight != 0)
        {
            ::MsgWaitForMultipleObjects(0, nullptr, FALSE, 1, QS_SENDMESSAGE);
            ::PeekMessage(&msg, nullptr, 0, 0, PM_NOREMOVE | PM_QS_SENDMESSAGE);
        }
    }
}
END_M_IMGUI_IMPL_WIN32_NAMESPACE