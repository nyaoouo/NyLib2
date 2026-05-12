#include "win32_app.h"

#include <d3d11.h>
#include <dxgi.h>
#include <chrono>
#include <cstdio>

extern "C" __declspec(dllimport) void __stdcall dxtest_bootstrap_touch();

int main()
{
    dxtest_bootstrap_touch();

    dxtest::Window window(L"dxtest_dx11_window", L"dxtest dx11", 960, 540);

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