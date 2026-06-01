#include "win32_app.h"

#include <d3d11.h>
#include <dxgi.h>
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

    dxtest::Window window(L"dxtest_dx11_window", L"dxtest dx11", 960, 540);
    dxtest::TitleStats title_stats(L"dxtest dx11");

    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = window.hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    IDXGISwapChain *swap_chain = nullptr;
    ID3D11Device *device = nullptr;
    ID3D11DeviceContext *context = nullptr;
    D3D_FEATURE_LEVEL feature_level = D3D_FEATURE_LEVEL_11_0;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
        nullptr, 0, D3D11_SDK_VERSION,
        &sd, &swap_chain, &device, &feature_level, &context);
    if (FAILED(hr))
    {
        std::printf("D3D11CreateDeviceAndSwapChain failed: 0x%08lx\n", hr);
        return 2;
    }

    ID3D11Texture2D *back_buffer = nullptr;
    ID3D11RenderTargetView *rtv = nullptr;
    swap_chain->GetBuffer(0, IID_PPV_ARGS(&back_buffer));
    device->CreateRenderTargetView(back_buffer, nullptr, &rtv);
    back_buffer->Release();

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
            if (rtv) { rtv->Release(); rtv = nullptr; }
            HRESULT hrz = swap_chain->ResizeBuffers(
                0, (UINT)window.width, (UINT)window.height,
                DXGI_FORMAT_UNKNOWN, 0);
            if (SUCCEEDED(hrz))
            {
                ID3D11Texture2D *new_bb = nullptr;
                swap_chain->GetBuffer(0, IID_PPV_ARGS(&new_bb));
                device->CreateRenderTargetView(new_bb, nullptr, &rtv);
                new_bb->Release();
            }
            else
            {
                std::printf("ResizeBuffers failed: 0x%08lx\n", hrz);
            }
        }

        float color[4] = {0.08f, 0.18f, 0.28f, 1.0f};
        context->OMSetRenderTargets(1, &rtv, nullptr);
        context->ClearRenderTargetView(rtv, color);
        swap_chain->Present(1, 0);
    }

    rtv->Release();
    swap_chain->Release();
    context->Release();
    device->Release();
    return 0;
}