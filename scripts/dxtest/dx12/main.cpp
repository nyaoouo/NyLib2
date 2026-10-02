#include "win32_app.h"
#include "foreign_hook.h"

#include <d3d12.h>
#include <d3d12sdklayers.h>
#include <dxgi1_4.h>
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

    // Maps rgba8|bgra8|rgb10a2 to a back-buffer format; empty gives `fallback`, anything else DXGI_FORMAT_UNKNOWN.
    DXGI_FORMAT ParseFormat(const std::string &text, DXGI_FORMAT fallback)
    {
        if (text.empty())
            return fallback;
        if (text == "rgba8")
            return DXGI_FORMAT_R8G8B8A8_UNORM;
        if (text == "bgra8")
            return DXGI_FORMAT_B8G8R8A8_UNORM;
        if (text == "rgb10a2")
            return DXGI_FORMAT_R10G10B10A2_UNORM;
        return DXGI_FORMAT_UNKNOWN;
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

namespace
{
    constexpr UINT FrameCount = 2;

    void wait_for_gpu(ID3D12CommandQueue *queue, ID3D12Fence *fence, HANDLE event_handle, UINT64 &fence_value)
    {
        const UINT64 value = ++fence_value;
        queue->Signal(fence, value);
        if (fence->GetCompletedValue() < value)
        {
            fence->SetEventOnCompletion(value, event_handle);
            WaitForSingleObject(event_handle, INFINITE);
        }
    }
}

int main()
{
    dxtest_bootstrap_touch();

    dxtest::Window window(L"dxtest_dx12_window", L"dxtest dx12", 960, 540);
    dxtest::TitleStats title_stats(L"dxtest dx12");

    // T8 (VF§8): enable the debug layer before device creation; errors are
    // polled via ID3D12InfoQueue near the end of the run.
    bool debug_layer_requested = EnvOrEmpty("DXTEST_D3D12_DEBUG") == "1";
    if (debug_layer_requested)
    {
        ID3D12Debug *debug = nullptr;
        if (SUCCEEDED(D3D12GetDebugInterface(IID_PPV_ARGS(&debug))))
        {
            debug->EnableDebugLayer();
            debug->Release();
        }
    }

    IDXGIFactory4 *factory = nullptr;
    HRESULT hr = CreateDXGIFactory1(IID_PPV_ARGS(&factory));
    if (FAILED(hr))
    {
        std::printf("CreateDXGIFactory1 failed: 0x%08lx\n", hr);
        return 2;
    }

    ID3D12Device *device = nullptr;
    hr = D3D12CreateDevice(nullptr, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&device));
    if (FAILED(hr))
    {
        std::printf("D3D12CreateDevice failed: 0x%08lx\n", hr);
        factory->Release();
        return 3;
    }

    ID3D12InfoQueue *debug_info_queue = nullptr;
    if (debug_layer_requested)
        device->QueryInterface(IID_PPV_ARGS(&debug_info_queue));

    // T3 (VF§8): queues created before the real present queue, so "take the
    // first queue seen" would pick the wrong one. DIRECT#1 is created but
    // never submitted to; a closed empty list runs on COMPUTE every frame,
    // ahead of the real present queue's submit.
    bool extra_queues_enabled = EnvOrEmpty("DXTEST_DX12_EXTRA_QUEUES") == "1";
    ID3D12CommandQueue *decoy_unused_direct_queue = nullptr;
    ID3D12CommandQueue *decoy_compute_queue = nullptr;
    ID3D12CommandAllocator *decoy_compute_allocator = nullptr;
    ID3D12GraphicsCommandList *decoy_compute_list = nullptr;
    if (extra_queues_enabled)
    {
        D3D12_COMMAND_QUEUE_DESC unused_desc = {};
        unused_desc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
        device->CreateCommandQueue(&unused_desc, IID_PPV_ARGS(&decoy_unused_direct_queue));

        D3D12_COMMAND_QUEUE_DESC compute_desc = {};
        compute_desc.Type = D3D12_COMMAND_LIST_TYPE_COMPUTE;
        device->CreateCommandQueue(&compute_desc, IID_PPV_ARGS(&decoy_compute_queue));

        device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_COMPUTE, IID_PPV_ARGS(&decoy_compute_allocator));
        device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_COMPUTE, decoy_compute_allocator, nullptr, IID_PPV_ARGS(&decoy_compute_list));
        decoy_compute_list->Close();
    }

    D3D12_COMMAND_QUEUE_DESC queue_desc = {};
    queue_desc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
    ID3D12CommandQueue *queue = nullptr;
    device->CreateCommandQueue(&queue_desc, IID_PPV_ARGS(&queue));

    // DXTEST_DX12_FORMAT sets the swap chain format; DXTEST_DX12_RESIZE_FORMAT the one passed from the first DXTEST_RESIZE_AT on.
    DXGI_FORMAT back_buffer_format = ParseFormat(EnvOrEmpty("DXTEST_DX12_FORMAT"), DXGI_FORMAT_R8G8B8A8_UNORM);
    DXGI_FORMAT resize_format = ParseFormat(EnvOrEmpty("DXTEST_DX12_RESIZE_FORMAT"), back_buffer_format);
    if (back_buffer_format == DXGI_FORMAT_UNKNOWN || resize_format == DXGI_FORMAT_UNKNOWN)
    {
        std::printf("dx12 unknown DXTEST_DX12_FORMAT / DXTEST_DX12_RESIZE_FORMAT value\n");
        return 14;
    }

    DXGI_SWAP_CHAIN_DESC1 swap_desc = {};
    swap_desc.BufferCount = FrameCount;
    swap_desc.Width = 0;
    swap_desc.Height = 0;
    swap_desc.Format = back_buffer_format;
    swap_desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    swap_desc.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
    swap_desc.SampleDesc.Count = 1;

    IDXGISwapChain1 *swap_chain1 = nullptr;
    factory->CreateSwapChainForHwnd(queue, window.hwnd, &swap_desc, nullptr, nullptr, &swap_chain1);
    IDXGISwapChain3 *swap_chain = nullptr;
    swap_chain1->QueryInterface(IID_PPV_ARGS(&swap_chain));
    swap_chain1->Release();

    D3D12_DESCRIPTOR_HEAP_DESC rtv_heap_desc = {};
    rtv_heap_desc.NumDescriptors = FrameCount;
    rtv_heap_desc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
    ID3D12DescriptorHeap *rtv_heap = nullptr;
    device->CreateDescriptorHeap(&rtv_heap_desc, IID_PPV_ARGS(&rtv_heap));
    UINT rtv_descriptor_size = device->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);

    ID3D12Resource *render_targets[FrameCount] = {};
    D3D12_CPU_DESCRIPTOR_HANDLE rtv_handle = rtv_heap->GetCPUDescriptorHandleForHeapStart();
    for (UINT i = 0; i < FrameCount; i++)
    {
        swap_chain->GetBuffer(i, IID_PPV_ARGS(&render_targets[i]));
        device->CreateRenderTargetView(render_targets[i], nullptr, rtv_handle);
        rtv_handle.ptr += rtv_descriptor_size;
    }

    ID3D12CommandAllocator *allocator = nullptr;
    device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&allocator));
    ID3D12GraphicsCommandList *command_list = nullptr;
    device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, allocator, nullptr, IID_PPV_ARGS(&command_list));
    command_list->Close();

    ID3D12Fence *fence = nullptr;
    device->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&fence));
    UINT64 fence_value = 0;
    HANDLE fence_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);

    auto resize_at = ParseTimes(EnvOrEmpty("DXTEST_RESIZE_AT"));
    size_t resize_at_next = 0;
    DXGI_FORMAT current_format = back_buffer_format;
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
            current_format = resize_format;
            int new_w = (window.width > 800) ? 640 : 960;
            int new_h = (window.height > 480) ? 360 : 540;
            SetWindowPos(window.hwnd, nullptr, 0, 0, new_w, new_h, SWP_NOMOVE | SWP_NOZORDER);
        }

        if (window.size_changed && window.width > 0 && window.height > 0)
        {
            window.size_changed = false;
            wait_for_gpu(queue, fence, fence_event, fence_value);

            for (UINT i = 0; i < FrameCount; ++i)
            {
                if (render_targets[i]) { render_targets[i]->Release(); render_targets[i] = nullptr; }
            }

            HRESULT hrz = swap_chain->ResizeBuffers(
                FrameCount, (UINT)window.width, (UINT)window.height,
                current_format, 0);
            if (FAILED(hrz))
            {
                std::printf("dx12 ResizeBuffers failed: 0x%08lx\n", hrz);
                return 10;
            }
            else
            {
                D3D12_CPU_DESCRIPTOR_HANDLE handle = rtv_heap->GetCPUDescriptorHandleForHeapStart();
                for (UINT i = 0; i < FrameCount; ++i)
                {
                    swap_chain->GetBuffer(i, IID_PPV_ARGS(&render_targets[i]));
                    device->CreateRenderTargetView(render_targets[i], nullptr, handle);
                    handle.ptr += rtv_descriptor_size;
                }
            }
        }

        UINT frame_index = swap_chain->GetCurrentBackBufferIndex();
        allocator->Reset();
        command_list->Reset(allocator, nullptr);

        D3D12_RESOURCE_BARRIER barrier = {};
        barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
        barrier.Transition.pResource = render_targets[frame_index];
        barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
        barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_PRESENT;
        barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_RENDER_TARGET;
        command_list->ResourceBarrier(1, &barrier);

        D3D12_CPU_DESCRIPTOR_HANDLE current_rtv = rtv_heap->GetCPUDescriptorHandleForHeapStart();
        current_rtv.ptr += frame_index * rtv_descriptor_size;
        float color[4] = {0.10f, 0.12f, 0.26f, 1.0f};
        command_list->OMSetRenderTargets(1, &current_rtv, FALSE, nullptr);
        command_list->ClearRenderTargetView(current_rtv, color, 0, nullptr);

        barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_RENDER_TARGET;
        barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_PRESENT;
        command_list->ResourceBarrier(1, &barrier);
        command_list->Close();

        if (extra_queues_enabled)
        {
            // Runs ahead of the real present queue's submit below, every
            // frame, so a "first queue seen" capture would pick this one.
            decoy_compute_allocator->Reset();
            decoy_compute_list->Reset(decoy_compute_allocator, nullptr);
            decoy_compute_list->Close();
            ID3D12CommandList *decoy_lists[] = {decoy_compute_list};
            decoy_compute_queue->ExecuteCommandLists(1, decoy_lists);
        }

        ID3D12CommandList *lists[] = {command_list};
        queue->ExecuteCommandLists(1, lists);
        swap_chain->Present(1, 0);
        wait_for_gpu(queue, fence, fence_event, fence_value);

        if (extra_queues_enabled && device->GetDeviceRemovedReason() != S_OK)
        {
            std::printf("dx12 device removed with extra queues: 0x%08lx\n", device->GetDeviceRemovedReason());
            return 11;
        }
    }

    int exit_code = 0;

    if (!foreign_mode.empty() && g_foreign_present_calls <= foreign_calls_snapshot)
    {
        std::printf("dx12 foreign present counter stalled: now=%llu snapshot=%llu\n",
                     g_foreign_present_calls, foreign_calls_snapshot);
        exit_code = 13;
    }

    if (debug_info_queue != nullptr)
    {
        UINT64 message_count = debug_info_queue->GetNumStoredMessages();
        for (UINT64 i = 0; i < message_count; ++i)
        {
            SIZE_T message_len = 0;
            debug_info_queue->GetMessage(i, nullptr, &message_len);
            std::vector<char> buffer(message_len);
            auto *message = reinterpret_cast<D3D12_MESSAGE *>(buffer.data());
            debug_info_queue->GetMessage(i, message, &message_len);
            if (message->Severity <= D3D12_MESSAGE_SEVERITY_ERROR)
            {
                std::printf("dx12 debug layer message (severity %d): %s\n",
                            (int)message->Severity, message->pDescription);
                exit_code = 12;
            }
        }
        debug_info_queue->Release();
    }

    wait_for_gpu(queue, fence, fence_event, fence_value);
    CloseHandle(fence_event);
    fence->Release();
    command_list->Release();
    allocator->Release();
    for (UINT i = 0; i < FrameCount; i++)
        render_targets[i]->Release();
    rtv_heap->Release();
    swap_chain->Release();
    queue->Release();
    if (decoy_compute_list) decoy_compute_list->Release();
    if (decoy_compute_allocator) decoy_compute_allocator->Release();
    if (decoy_compute_queue) decoy_compute_queue->Release();
    if (decoy_unused_direct_queue) decoy_unused_direct_queue->Release();
    device->Release();
    factory->Release();
    return exit_code;
}