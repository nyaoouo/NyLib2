#include "win32_app.h"

#include <cstdlib>

namespace dxtest
{
    Window::Window(const wchar_t *class_name, const wchar_t *title, int width, int height)
        : hinstance(GetModuleHandleW(nullptr)), class_name_(class_name)
    {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.style = CS_CLASSDC;
        wc.lpfnWndProc = Window::WndProc;
        wc.hInstance = hinstance;
        wc.lpszClassName = class_name_;
        RegisterClassExW(&wc);

        RECT rect = {0, 0, width, height};
        AdjustWindowRect(&rect, WS_OVERLAPPEDWINDOW, FALSE);
        hwnd = CreateWindowW(
            class_name_, title, WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT,
            rect.right - rect.left, rect.bottom - rect.top,
            nullptr, nullptr, hinstance, this);
        ShowWindow(hwnd, SW_SHOWDEFAULT);
        UpdateWindow(hwnd);
    }

    Window::~Window()
    {
        if (hwnd != nullptr)
            DestroyWindow(hwnd);
        UnregisterClassW(class_name_, hinstance);
    }

    bool Window::PumpMessages()
    {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0U, 0U, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT)
                closed = true;
        }
        return !closed;
    }

    LRESULT CALLBACK Window::WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
    {
        if (msg == WM_NCCREATE)
        {
            auto create = reinterpret_cast<CREATESTRUCTW *>(lparam);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
        }
        auto self = reinterpret_cast<Window *>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (msg == WM_CLOSE || msg == WM_DESTROY)
        {
            if (self != nullptr)
                self->closed = true;
            PostQuitMessage(0);
            return 0;
        }
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    }

    int RunSecondsFromEnv(int default_seconds)
    {
        char *value = nullptr;
        size_t size = 0;
        if (_dupenv_s(&value, &size, "DXTEST_SECONDS") == 0 && value != nullptr)
        {
            int parsed = std::atoi(value);
            free(value);
            if (parsed > 0)
                return parsed;
        }
        return default_seconds;
    }
}