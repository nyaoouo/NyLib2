#pragma once

#include <windows.h>

namespace dxtest
{
    class Window
    {
    public:
        HWND hwnd = nullptr;
        HINSTANCE hinstance = nullptr;
        bool closed = false;

        Window(const wchar_t *class_name, const wchar_t *title, int width, int height);
        ~Window();

        bool PumpMessages();

    private:
        const wchar_t *class_name_ = nullptr;
        static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);
    };

    int RunSecondsFromEnv(int default_seconds = 10);
}