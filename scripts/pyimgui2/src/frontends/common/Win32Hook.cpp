#include "./Win32Hook.h"

START_M_IMGUI_IMPL_WIN32_NAMESPACE
{
    static WNDPROC oWndProc = nullptr;

    static LRESULT CALLBACK hkWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
    {
        if (ImGui_ImplWin32_WndProcHandler(hwnd, uMsg, wParam, lParam) > 0)
            return 1L;

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
            if (ImGui::GetIO().WantCaptureMouse)
                return 1L;
            break;
        case WM_KEYDOWN:
        case WM_KEYUP:
        case WM_SYSKEYDOWN:
        case WM_SYSKEYUP:
        case WM_CHAR:
            if (ImGui::GetIO().WantCaptureKeyboard)
                return 1L;
            break;
        }

        return ::CallWindowProc(oWndProc, hwnd, uMsg, wParam, lParam);
    }

    void Attach(HWND hwnd)
    {
        if ((oWndProc = (WNDPROC)::SetWindowLongPtr(hwnd, GWLP_WNDPROC, (LONG_PTR)hkWindowProc)) == nullptr)
            _throwV_("SetWindowLongPtr failed: {}", ::GetLastError());
    }

    void Detach(HWND hwnd)
    {
        if (::SetWindowLongPtr(hwnd, GWLP_WNDPROC, (LONG_PTR)oWndProc) == NULL)
            _throwV_("SetWindowLongPtr failed: {}", ::GetLastError());
        oWndProc = nullptr;
    }
}
END_M_IMGUI_IMPL_WIN32_NAMESPACE