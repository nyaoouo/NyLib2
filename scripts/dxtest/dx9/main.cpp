#include "win32_app.h"

#include <d3d9.h>
#include <chrono>
#include <cstdio>

extern "C" __declspec(dllexport) volatile unsigned long long g_dxtest_tick = 0;

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

    auto start = std::chrono::steady_clock::now();
    auto seconds = std::chrono::seconds(dxtest::RunSecondsFromEnv());
    while (window.PumpMessages() && std::chrono::steady_clock::now() - start < seconds)
    {
        unsigned long long _dx_out = 0;
        dxtest_tick(g_dxtest_tick, &_dx_out);
        title_stats.Update(window.hwnd, g_dxtest_tick);

        if (window.size_changed && window.width > 0 && window.height > 0)
        {
            window.size_changed = false;
            pp.BackBufferWidth = (UINT)window.width;
            pp.BackBufferHeight = (UINT)window.height;
            HRESULT hrz = device->Reset(&pp);
            if (FAILED(hrz))
            {
                std::printf("dx9 Reset failed: 0x%08lx\n", hrz);
            }
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