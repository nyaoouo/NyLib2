#include "./Helper_Dx12.h"

START_M_IMGUI_HELPER_Dx12_NAMESPACE
{
    void Dx12TextureHelper::LoadTextureFromFile(const char *filename)
    {
        //  Load from disk into a raw RGBA buffer
        int image_width = 0;
        int image_height = 0;
        unsigned char *image_data = stbi_load(filename, &image_width, &image_height, NULL, 4);
        if (image_data == NULL)
            _throwV_("Failed to load image file {}", filename);

        // Create texture resource
        D3D12_HEAP_PROPERTIES props;
        ZeroMemory(&props, sizeof(D3D12_HEAP_PROPERTIES));
        props.Type = D3D12_HEAP_TYPE_DEFAULT;
        props.CPUPageProperty = D3D12_CPU_PAGE_PROPERTY_UNKNOWN;
        props.MemoryPoolPreference = D3D12_MEMORY_POOL_UNKNOWN;

        D3D12_RESOURCE_DESC desc;
        ZeroMemory(&desc, sizeof(desc));
        desc.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
        desc.Alignment = 0;
        desc.Width = image_width;
        desc.Height = image_height;
        desc.DepthOrArraySize = 1;
        desc.MipLevels = 1;
        desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.SampleDesc.Count = 1;
        desc.SampleDesc.Quality = 0;
        desc.Layout = D3D12_TEXTURE_LAYOUT_UNKNOWN;
        desc.Flags = D3D12_RESOURCE_FLAG_NONE;

        ID3D12Resource *pTexture = NULL;
        this->d3d_device->CreateCommittedResource(&props, D3D12_HEAP_FLAG_NONE, &desc,
                                                  D3D12_RESOURCE_STATE_COPY_DEST, NULL, IID_PPV_ARGS(&pTexture));

        // Create a temporary upload resource to move the data in
        UINT uploadPitch = (image_width * 4 + D3D12_TEXTURE_DATA_PITCH_ALIGNMENT - 1u) & ~(D3D12_TEXTURE_DATA_PITCH_ALIGNMENT - 1u);
        UINT uploadSize = image_height * uploadPitch;
        desc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
        desc.Alignment = 0;
        desc.Width = uploadSize;
        desc.Height = 1;
        desc.DepthOrArraySize = 1;
        desc.MipLevels = 1;
        desc.Format = DXGI_FORMAT_UNKNOWN;
        desc.SampleDesc.Count = 1;
        desc.SampleDesc.Quality = 0;
        desc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
        desc.Flags = D3D12_RESOURCE_FLAG_NONE;

        props.Type = D3D12_HEAP_TYPE_UPLOAD;
        props.CPUPageProperty = D3D12_CPU_PAGE_PROPERTY_UNKNOWN;
        props.MemoryPoolPreference = D3D12_MEMORY_POOL_UNKNOWN;

        ID3D12Resource *uploadBuffer = NULL;
        HRESULT hr = this->d3d_device->CreateCommittedResource(
            &props, D3D12_HEAP_FLAG_NONE, &desc,
            D3D12_RESOURCE_STATE_GENERIC_READ, NULL, IID_PPV_ARGS(&uploadBuffer));
        if(!SUCCEEDED(hr))
            _throwV_("Failed to create upload buffer with error code {}", hr);

        // Write pixels into the upload resource
        void *mapped = NULL;
        D3D12_RANGE range = {0, uploadSize};
        hr = uploadBuffer->Map(0, &range, &mapped);
        if(!SUCCEEDED(hr))
            _throwV_("Failed to map upload buffer with error code {}", hr);
        for (int y = 0; y < image_height; y++)
            memcpy((void *)((uintptr_t)mapped + y * uploadPitch), image_data + y * image_width * 4, image_width * 4);
        uploadBuffer->Unmap(0, &range);

        // Copy the upload resource content into the real resource
        D3D12_TEXTURE_COPY_LOCATION srcLocation = {};
        srcLocation.pResource = uploadBuffer;
        srcLocation.Type = D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT;
        srcLocation.PlacedFootprint.Footprint.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        srcLocation.PlacedFootprint.Footprint.Width = image_width;
        srcLocation.PlacedFootprint.Footprint.Height = image_height;
        srcLocation.PlacedFootprint.Footprint.Depth = 1;
        srcLocation.PlacedFootprint.Footprint.RowPitch = uploadPitch;

        D3D12_TEXTURE_COPY_LOCATION dstLocation = {};
        dstLocation.pResource = pTexture;
        dstLocation.Type = D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX;
        dstLocation.SubresourceIndex = 0;

        D3D12_RESOURCE_BARRIER barrier = {};
        barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
        barrier.Flags = D3D12_RESOURCE_BARRIER_FLAG_NONE;
        barrier.Transition.pResource = pTexture;
        barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
        barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_COPY_DEST;
        barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE;

        // Create a temporary command queue to do the copy with
        ID3D12Fence *fence = NULL;
        hr = this->d3d_device->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&fence));
        if(!SUCCEEDED(hr))
            _throwV_("Failed to create fence with error code {}", hr);

        HANDLE event = CreateEvent(0, 0, 0, 0);
        if(!SUCCEEDED(hr))
            _throwV_("Failed to create event with error code {}", hr);

        D3D12_COMMAND_QUEUE_DESC queueDesc = {};
        queueDesc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
        queueDesc.Flags = D3D12_COMMAND_QUEUE_FLAG_NONE;
        queueDesc.NodeMask = 1;

        ID3D12CommandQueue *cmdQueue = NULL;
        hr = this->d3d_device->CreateCommandQueue(&queueDesc, IID_PPV_ARGS(&cmdQueue));
        if(!SUCCEEDED(hr))
            _throwV_("Failed to create command queue with error code {}", hr);

        ID3D12CommandAllocator *cmdAlloc = NULL;
        hr = this->d3d_device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&cmdAlloc));
        if(!SUCCEEDED(hr))
            _throwV_("Failed to create command allocator with error code {}", hr);

        ID3D12GraphicsCommandList *cmdList = NULL;
        hr = this->d3d_device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, cmdAlloc, NULL, IID_PPV_ARGS(&cmdList));
        if(!SUCCEEDED(hr))
            _throwV_("Failed to create command list with error code {}", hr);

        cmdList->CopyTextureRegion(&dstLocation, 0, 0, 0, &srcLocation, NULL);
        cmdList->ResourceBarrier(1, &barrier);

        hr = cmdList->Close();
        if(!SUCCEEDED(hr))
            _throwV_("Failed to close command list with error code {}", hr);

        // Execute the copy
        cmdQueue->ExecuteCommandLists(1, (ID3D12CommandList *const *)&cmdList);
        hr = cmdQueue->Signal(fence, 1);
        if(!SUCCEEDED(hr))
            _throwV_("Failed to signal fence with error code {}", hr);

        // Wait for everything to complete
        fence->SetEventOnCompletion(1, event);
        WaitForSingleObject(event, INFINITE);

        // Tear down our temporary command queue and release the upload resource
        cmdList->Release();
        cmdAlloc->Release();
        cmdQueue->Release();
        CloseHandle(event);
        fence->Release();
        uploadBuffer->Release();

        // Create a shader resource view for the texture
        D3D12_SHADER_RESOURCE_VIEW_DESC srvDesc;
        ZeroMemory(&srvDesc, sizeof(srvDesc));
        srvDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        srvDesc.ViewDimension = D3D12_SRV_DIMENSION_TEXTURE2D;
        srvDesc.Texture2D.MipLevels = desc.MipLevels;
        srvDesc.Texture2D.MostDetailedMip = 0;
        srvDesc.Shader4ComponentMapping = D3D12_DEFAULT_SHADER_4_COMPONENT_MAPPING;
        this->d3d_device->CreateShaderResourceView(pTexture, &srvDesc, this->srv_cpu_handle);

        // Return results
        this->FreeTexture();
        this->srv = pTexture;
        this->width = image_width;
        this->height = image_height;
        stbi_image_free(image_data);
    }
}
END_M_IMGUI_HELPER_Dx12_NAMESPACE