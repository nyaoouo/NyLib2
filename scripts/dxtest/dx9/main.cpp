#include "win32_app.h"

#include <d3d9.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

extern "C" __declspec(dllexport) volatile unsigned long long g_dxtest_tick = 0;

namespace
{
    std::string EnvOrEmpty(const char *name)
    {
        char *value = nullptr;
        size_t size = 0;
        std::string result;
        if (_dupenv_s(&value, &size, name) == 0 && value != nullptr)
        {
            result = value;
            free(value);
        }
        return result;
    }

    // Comma-separated seconds, e.g. "2,4" (DXTEST_RESIZE_AT; each resize runs IDirect3DDevice9::Reset).
    std::vector<double> ParseTimes(const std::string &text)
    {
        std::vector<double> result;
        size_t pos = 0;
        while (pos < text.size())
        {
            size_t next = text.find(',', pos);
            std::string token = text.substr(pos, next == std::string::npos ? std::string::npos : next - pos);
            if (!token.empty())
                result.push_back(std::atof(token.c_str()));
            if (next == std::string::npos)
                break;
            pos = next + 1;
        }
        return result;
    }
}

extern "C" __declspec(dllexport) void dxtest_tick(unsigned long long in,
                                                   unsigned long long* out) {
    g_dxtest_tick++;
    if (out) *out = in * 2 + g_dxtest_tick;
}

extern "C" __declspec(dllexport) unsigned long long dxtest_get_tick(void) {
    return g_dxtest_tick;
}

extern "C" __declspec(dllimport) void __stdcall dxtest_bootstrap_touch();

int main()
{
    dxtest_bootstrap_touch();

    dxtest::Window window(L"dxtest_dx9_window", L"dxtest dx9", 960, 540);
    dxtest::TitleStats title_stats(L"dxtest dx9");
    LPDIRECT3D9 d3d = Direct3DCreate9(D3D_SDK_VERSION);
    if (d3d == nullptr)
    {
        std::printf("Direct3DCreate9 failed\n");
        return 2;
    }

    D3DPRESENT_PARAMETERS pp = {};
    pp.Windowed = TRUE;
    pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    pp.BackBufferFormat = D3DFMT_UNKNOWN;
    pp.EnableAutoDepthStencil = TRUE;
    pp.AutoDepthStencilFormat = D3DFMT_D16;
    pp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;
    pp.hDeviceWindow = window.hwnd;

    LPDIRECT3DDEVICE9 device = nullptr;
    HRESULT hr = d3d->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, window.hwnd, D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &device);
    if (FAILED(hr))
        hr = d3d->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_REF, window.hwnd, D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &device);
    if (FAILED(hr))
    {
        std::printf("CreateDevice failed: 0x%08lx\n", hr);
        d3d->Release();
        return 3;
    }

    auto resize_at = ParseTimes(EnvOrEmpty("DXTEST_RESIZE_AT"));
    size_t resize_at_next = 0;

    auto start = std::chrono::steady_clock::now();
    auto seconds = std::chrono::seconds(dxtest::RunSecondsFromEnv());
    while (window.PumpMessages() && std::chrono::steady_clock::now() - start < seconds)
    {
        double elapsed_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        unsigned long long _dx_out = 0;
        dxtest_tick(g_dxtest_tick, &_dx_out);
        title_stats.Update(window.hwnd, g_dxtest_tick);

        if (resize_at_next < resize_at.size() && elapsed_s >= resize_at[resize_at_next])
        {
            ++resize_at_next;
            int new_w = (window.width > 800) ? 640 : 960;
            int new_h = (window.height > 480) ? 360 : 540;
            SetWindowPos(window.hwnd, nullptr, 0, 0, new_w, new_h, SWP_NOMOVE | SWP_NOZORDER);
        }

        if (window.size_changed && window.width > 0 && window.height > 0)
        {
            window.size_changed = false;
            pp.BackBufferWidth = (UINT)window.width;
            pp.BackBufferHeight = (UINT)window.height;
            HRESULT hrz = device->Reset(&pp);
            if (FAILED(hrz))
            {
                std::printf("dx9 Reset failed: 0x%08lx\n", hrz);
                std::fflush(stdout);
                return 10;
            }
            std::printf("dx9 Reset %dx%d ok\n", window.width, window.height);
            std::fflush(stdout);
        }

        device->Clear(0, nullptr, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, D3DCOLOR_XRGB(28, 42, 72), 1.0f, 0);
        if (SUCCEEDED(device->BeginScene()))
        {
            device->EndScene();
        }
        hr = device->Present(nullptr, nullptr, nullptr, nullptr);
        if (hr == D3DERR_DEVICELOST)
            Sleep(16);
    }

    device->Release();
    d3d->Release();
    return 0;
}