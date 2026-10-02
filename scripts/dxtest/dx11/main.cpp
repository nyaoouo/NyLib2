#include "win32_app.h"
#include "foreign_hook.h"

#include <d3d11.h>
#include <dxgi.h>
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

    // Comma-separated seconds, e.g. "2,4" (DXTEST_RESIZE_AT, T2, VF§8).
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

    auto resize_at = ParseTimes(EnvOrEmpty("DXTEST_RESIZE_AT"));
    size_t resize_at_next = 0;
    std::string foreign_mode = EnvOrEmpty("DXTEST_FOREIGN");
    unsigned long long foreign_calls_snapshot = 0;
    auto foreign_snapshot_time = std::chrono::steady_clock::now();

    auto start = std::chrono::steady_clock::now();
    auto seconds = std::chrono::seconds(dxtest::RunSecondsFromEnv());
    while (window.PumpMessages() && std::chrono::steady_clock::now() - start < seconds)
    {
        double elapsed_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        unsigned long long _dx_out = 0;
        dxtest_tick(g_dxtest_tick, &_dx_out);
        title_stats.Update(window.hwnd, g_dxtest_tick);

        if (!foreign_mode.empty())
        {
            dxtest::ForeignHookTick(swap_chain, elapsed_s);
            // Slide a ~1s-old snapshot forward so the end-of-run check below
            // can tell whether the counter is still advancing (T4, VF§8).
            if (std::chrono::duration<double>(std::chrono::steady_clock::now() - foreign_snapshot_time).count() >= 1.0)
            {
                foreign_calls_snapshot = g_foreign_present_calls;
                foreign_snapshot_time = std::chrono::steady_clock::now();
            }
        }

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

    if (!foreign_mode.empty() && g_foreign_present_calls <= foreign_calls_snapshot)
    {
        std::printf("dx11 foreign present counter stalled: now=%llu snapshot=%llu\n",
                     g_foreign_present_calls, foreign_calls_snapshot);
        return 13;
    }

    rtv->Release();
    swap_chain->Release();
    context->Release();
    device->Release();
    return 0;
}