#include "win32_app.h"

#include <d3d12.h>
#include <dxgi1_4.h>
#include <chrono>
#include <cstdio>

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

    D3D12_COMMAND_QUEUE_DESC queue_desc = {};
    queue_desc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
    ID3D12CommandQueue *queue = nullptr;
    device->CreateCommandQueue(&queue_desc, IID_PPV_ARGS(&queue));

    DXGI_SWAP_CHAIN_DESC1 swap_desc = {};
    swap_desc.BufferCount = FrameCount;
    swap_desc.Width = 0;
    swap_desc.Height = 0;
    swap_desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
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

    auto start = std::chrono::steady_clock::now();
    auto seconds = std::chrono::seconds(dxtest::RunSecondsFromEnv());
    while (window.PumpMessages() && std::chrono::steady_clock::now() - start < seconds)
    {
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

        ID3D12CommandList *lists[] = {command_list};
        queue->ExecuteCommandLists(1, lists);
        swap_chain->Present(1, 0);
        wait_for_gpu(queue, fence, fence_event, fence_value);
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
    device->Release();
    factory->Release();
    return 0;
}