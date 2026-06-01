#pragma once

#include <windows.h>

#include <chrono>

namespace dxtest
{
    class Window
    {
    public:
        HWND hwnd = nullptr;
        HINSTANCE hinstance = nullptr;
        bool closed = false;

        int width = 0;
        int height = 0;
        bool size_changed = false;

        Window(const wchar_t *class_name, const wchar_t *title, int width, int height);
        ~Window();

        bool PumpMessages();

    private:
        const wchar_t *class_name_ = nullptr;
        static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);
    };

    int RunSecondsFromEnv(int default_seconds = 10);

    // Throttled "tick=N fps=F" title-bar overlay. The cheapest way to put
    // g_dxtest_tick on screen identically across D3D9/11/12 - no raw
    // text-rendering machinery, no swap-chain flag changes, no per-backend
    // GDI/D2D fork.
    //
    // Usage: construct once with the base title, then call Update(...) once
    // per frame with the current tick value. The class itself throttles
    // SetWindowTextW to ~5Hz so the WM_SETTEXT traffic stays cheap.
    class TitleStats
    {
    public:
        explicit TitleStats(const wchar_t *base_title,
                            double update_hz = 5.0);

        // Call once per frame after dxtest_tick(). When the throttle
        // interval has elapsed, formats "<base>  tick=N  fps=F.F" and
        // SetWindowTextW's the hwnd.
        void Update(HWND hwnd, unsigned long long tick);

        double last_fps() const { return fps_; }

    private:
        const wchar_t *base_title_ = nullptr;
        std::chrono::steady_clock::time_point last_time_ = {};
        unsigned long long last_tick_ = 0;
        double interval_s_ = 0.2;
        double fps_ = 0.0;
        bool primed_ = false;
    };
}