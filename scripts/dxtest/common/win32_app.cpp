#include "win32_app.h"

#include <cstdlib>
#include <cstdio>
#include <cwchar>

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

        RECT client_rect = {};
        GetClientRect(hwnd, &client_rect);
        this->width = client_rect.right - client_rect.left;
        this->height = client_rect.bottom - client_rect.top;
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
        if (msg == WM_SIZE)
        {
            if (self != nullptr && wparam != SIZE_MINIMIZED)
            {
                self->width = static_cast<int>(LOWORD(lparam));
                self->height = static_cast<int>(HIWORD(lparam));
                self->size_changed = true;
            }
        }
        else if (msg == WM_CLOSE || msg == WM_DESTROY)
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

    TitleStats::TitleStats(const wchar_t *base_title, double update_hz)
        : base_title_(base_title)
    {
        if (update_hz < 0.1)
            update_hz = 0.1;
        interval_s_ = 1.0 / update_hz;
    }

    void TitleStats::Update(HWND hwnd, unsigned long long tick)
    {
        if (hwnd == nullptr)
            return;
        auto now = std::chrono::steady_clock::now();
        if (!primed_)
        {
            primed_ = true;
            last_time_ = now;
            last_tick_ = tick;
            // Seed the title immediately so the user sees a counter on
            // the very first paint instead of waiting one interval.
            wchar_t buf[160];
            swprintf_s(buf, L"%s  tick=%llu  fps=--", base_title_, tick);
            SetWindowTextW(hwnd, buf);
            return;
        }
        double dt = std::chrono::duration<double>(now - last_time_).count();
        if (dt < interval_s_)
            return;
        // FPS = ticks-since-last-update / elapsed; the host bumps the
        // counter exactly once per frame so this matches frame rate.
        unsigned long long dtick = tick - last_tick_;
        fps_ = (dt > 0.0) ? (static_cast<double>(dtick) / dt) : 0.0;
        wchar_t buf[160];
        swprintf_s(buf, L"%s  tick=%llu  fps=%.1f",
                   base_title_, tick, fps_);
        SetWindowTextW(hwnd, buf);
        last_time_ = now;
        last_tick_ = tick;
    }
}