// Per-draw DX12 samplers and blends: copies of ImGui_ImplDX12_CreateDeviceObjects' shaders and PSO with a sampler table, and of ImGui_ImplDX12_SetupRenderState's projection.
#include "./Dx12Window.h"
#include "../../TextureData.h"

#include <d3dcompiler.h>

START_M_IMGUI_IMPL_DX12_NAMESPACE
{
    // The root signature, straight and premultiplied PSOs and shader-visible sampler heap (18 variants plus the backend default) of a store's scopes.
    struct Dx12TextureStore::SamplerPipeline
    {
        ID3D12RootSignature *rootSignature = nullptr;
        ID3D12PipelineState *pipelineState[2] = {}; // 0 Straight, 1 Premultiplied
        ID3D12DescriptorHeap *samplerHeap = nullptr;
        UINT64 samplerStart = 0;
        UINT samplerIncrement = 0;
    };

    namespace
    {
        const char *const VERTEX_SHADER =
            "cbuffer vertexBuffer : register(b0) \
            {\
              float4x4 ProjectionMatrix; \
            };\
            struct VS_INPUT\
            {\
              float2 pos : POSITION;\
              float4 col : COLOR0;\
              float2 uv  : TEXCOORD0;\
            };\
            \
            struct PS_INPUT\
            {\
              float4 pos : SV_POSITION;\
              float4 col : COLOR0;\
              float2 uv  : TEXCOORD0;\
            };\
            \
            PS_INPUT main(VS_INPUT input)\
            {\
              PS_INPUT output;\
              output.pos = mul( ProjectionMatrix, float4(input.pos.xy, 0.f, 1.f));\
              output.col = input.col;\
              output.uv  = input.uv;\
              return output;\
            }";

        const char *const PIXEL_SHADER =
            "struct PS_INPUT\
            {\
              float4 pos : SV_POSITION;\
              float4 col : COLOR0;\
              float2 uv  : TEXCOORD0;\
            };\
            SamplerState sampler0 : register(s0);\
            Texture2D texture0 : register(t0);\
            \
            float4 main(PS_INPUT input) : SV_Target\
            {\
              float4 out_col = input.col * texture0.Sample(sampler0, input.uv); \
              return out_col; \
            }";

        // Releases the blob it holds on scope exit.
        struct Blob
        {
            ID3DBlob *blob = nullptr;

            ~Blob()
            {
                if (this->blob != nullptr)
                    this->blob->Release();
            }
        };

        void CompileShader(const char *source, const char *target, Blob &out)
        {
            Blob errors;
            HRESULT hr = D3DCompile(source, strlen(source), nullptr, nullptr, nullptr, "main", target, 0, 0, &out.blob, &errors.blob);
            if (FAILED(hr))
                _throwV_("Failed to compile the {} sampler shader: {:#x}", target, (unsigned)hr);
        }

        // The backend's orthographic projection of drawData's DisplayPos and DisplaySize.
        void Projection(const ImDrawData *drawData, float mvp[4][4])
        {
            float L = drawData->DisplayPos.x;
            float R = drawData->DisplayPos.x + drawData->DisplaySize.x;
            float T = drawData->DisplayPos.y;
            float B = drawData->DisplayPos.y + drawData->DisplaySize.y;
            float m[4][4] =
                {
                    {2.0f / (R - L), 0.0f, 0.0f, 0.0f},
                    {0.0f, 2.0f / (T - B), 0.0f, 0.0f},
                    {0.0f, 0.0f, 0.5f, 0.0f},
                    {(R + L) / (L - R), (T + B) / (B - T), 0.5f, 1.0f},
                };
            memcpy(mvp, m, sizeof(m));
        }
    }

    void Dx12TextureStore::ReleaseSamplerPipeline(SamplerPipeline *pipeline) noexcept
    {
        for (IUnknown *object : std::initializer_list<IUnknown *>{pipeline->samplerHeap, pipeline->pipelineState[1], pipeline->pipelineState[0], pipeline->rootSignature})
            if (object != nullptr)
                object->Release();
        delete pipeline;
    }

    Dx12TextureStore::SamplerPipeline *Dx12TextureStore::CreateSamplerPipeline(ID3D12Device *device, DXGI_FORMAT rtvFormat)
    {
        std::unique_ptr<SamplerPipeline, void (*)(SamplerPipeline *)> pipeline(new SamplerPipeline(), [](SamplerPipeline *p) { ReleaseSamplerPipeline(p); });

        D3D12_DESCRIPTOR_RANGE srvRange = {};
        srvRange.RangeType = D3D12_DESCRIPTOR_RANGE_TYPE_SRV;
        srvRange.NumDescriptors = 1;
        srvRange.BaseShaderRegister = 0;
        srvRange.RegisterSpace = 0;
        srvRange.OffsetInDescriptorsFromTableStart = 0;
        D3D12_DESCRIPTOR_RANGE samplerRange = srvRange;
        samplerRange.RangeType = D3D12_DESCRIPTOR_RANGE_TYPE_SAMPLER;

        D3D12_ROOT_PARAMETER param[3] = {};
        param[0].ParameterType = D3D12_ROOT_PARAMETER_TYPE_32BIT_CONSTANTS;
        param[0].Constants.ShaderRegister = 0;
        param[0].Constants.RegisterSpace = 0;
        param[0].Constants.Num32BitValues = 16;
        param[0].ShaderVisibility = D3D12_SHADER_VISIBILITY_VERTEX;
        param[1].ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
        param[1].DescriptorTable.NumDescriptorRanges = 1;
        param[1].DescriptorTable.pDescriptorRanges = &srvRange;
        param[1].ShaderVisibility = D3D12_SHADER_VISIBILITY_PIXEL;
        param[2].ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
        param[2].DescriptorTable.NumDescriptorRanges = 1;
        param[2].DescriptorTable.pDescriptorRanges = &samplerRange;
        param[2].ShaderVisibility = D3D12_SHADER_VISIBILITY_PIXEL;

        D3D12_ROOT_SIGNATURE_DESC rootDesc = {};
        rootDesc.NumParameters = _countof(param);
        rootDesc.pParameters = param;
        rootDesc.NumStaticSamplers = 0;
        rootDesc.Flags =
            D3D12_ROOT_SIGNATURE_FLAG_ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT |
            D3D12_ROOT_SIGNATURE_FLAG_DENY_HULL_SHADER_ROOT_ACCESS |
            D3D12_ROOT_SIGNATURE_FLAG_DENY_DOMAIN_SHADER_ROOT_ACCESS |
            D3D12_ROOT_SIGNATURE_FLAG_DENY_GEOMETRY_SHADER_ROOT_ACCESS;
        {
            Blob signature;
            HRESULT hr = D3D12SerializeRootSignature(&rootDesc, D3D_ROOT_SIGNATURE_VERSION_1, &signature.blob, nullptr);
            if (FAILED(hr))
                _throwV_("Failed to serialize the sampler root signature: {:#x}", (unsigned)hr);
            hr = device->CreateRootSignature(0, signature.blob->GetBufferPointer(), signature.blob->GetBufferSize(), IID_PPV_ARGS(&pipeline->rootSignature));
            if (FAILED(hr))
                _throwV_("Failed to create the sampler root signature: {:#x}", (unsigned)hr);
        }

        D3D12_GRAPHICS_PIPELINE_STATE_DESC psoDesc = {};
        psoDesc.NodeMask = 1;
        psoDesc.PrimitiveTopologyType = D3D12_PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE;
        psoDesc.pRootSignature = pipeline->rootSignature;
        psoDesc.SampleMask = UINT_MAX;
        psoDesc.NumRenderTargets = 1;
        psoDesc.RTVFormats[0] = rtvFormat;
        psoDesc.SampleDesc.Count = 1;
        psoDesc.Flags = D3D12_PIPELINE_STATE_FLAG_NONE;

        Blob vertexShader, pixelShader;
        CompileShader(VERTEX_SHADER, "vs_5_0", vertexShader);
        CompileShader(PIXEL_SHADER, "ps_5_0", pixelShader);
        psoDesc.VS = {vertexShader.blob->GetBufferPointer(), vertexShader.blob->GetBufferSize()};
        psoDesc.PS = {pixelShader.blob->GetBufferPointer(), pixelShader.blob->GetBufferSize()};
        static D3D12_INPUT_ELEMENT_DESC layout[] =
            {
                {"POSITION", 0, DXGI_FORMAT_R32G32_FLOAT, 0, (UINT)offsetof(ImDrawVert, pos), D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0},
                {"TEXCOORD", 0, DXGI_FORMAT_R32G32_FLOAT, 0, (UINT)offsetof(ImDrawVert, uv), D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0},
                {"COLOR", 0, DXGI_FORMAT_R8G8B8A8_UNORM, 0, (UINT)offsetof(ImDrawVert, col), D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0},
            };
        psoDesc.InputLayout = {layout, 3};

        D3D12_BLEND_DESC &blend = psoDesc.BlendState;
        blend.AlphaToCoverageEnable = false;
        blend.RenderTarget[0].BlendEnable = true;
        blend.RenderTarget[0].SrcBlend = D3D12_BLEND_SRC_ALPHA;
        blend.RenderTarget[0].DestBlend = D3D12_BLEND_INV_SRC_ALPHA;
        blend.RenderTarget[0].BlendOp = D3D12_BLEND_OP_ADD;
        blend.RenderTarget[0].SrcBlendAlpha = D3D12_BLEND_ONE;
        blend.RenderTarget[0].DestBlendAlpha = D3D12_BLEND_INV_SRC_ALPHA;
        blend.RenderTarget[0].BlendOpAlpha = D3D12_BLEND_OP_ADD;
        blend.RenderTarget[0].RenderTargetWriteMask = D3D12_COLOR_WRITE_ENABLE_ALL;

        D3D12_RASTERIZER_DESC &raster = psoDesc.RasterizerState;
        raster.FillMode = D3D12_FILL_MODE_SOLID;
        raster.CullMode = D3D12_CULL_MODE_NONE;
        raster.FrontCounterClockwise = FALSE;
        raster.DepthBias = D3D12_DEFAULT_DEPTH_BIAS;
        raster.DepthBiasClamp = D3D12_DEFAULT_DEPTH_BIAS_CLAMP;
        raster.SlopeScaledDepthBias = D3D12_DEFAULT_SLOPE_SCALED_DEPTH_BIAS;
        raster.DepthClipEnable = true;
        raster.MultisampleEnable = FALSE;
        raster.AntialiasedLineEnable = FALSE;
        raster.ForcedSampleCount = 0;
        raster.ConservativeRaster = D3D12_CONSERVATIVE_RASTERIZATION_MODE_OFF;

        D3D12_DEPTH_STENCIL_DESC &depth = psoDesc.DepthStencilState;
        depth.DepthEnable = false;
        depth.DepthWriteMask = D3D12_DEPTH_WRITE_MASK_ALL;
        depth.DepthFunc = D3D12_COMPARISON_FUNC_ALWAYS;
        depth.StencilEnable = false;
        depth.FrontFace.StencilFailOp = depth.FrontFace.StencilDepthFailOp = depth.FrontFace.StencilPassOp = D3D12_STENCIL_OP_KEEP;
        depth.FrontFace.StencilFunc = D3D12_COMPARISON_FUNC_ALWAYS;
        depth.BackFace = depth.FrontFace;

        HRESULT hr = device->CreateGraphicsPipelineState(&psoDesc, IID_PPV_ARGS(&pipeline->pipelineState[0]));
        if (FAILED(hr))
            _throwV_("Failed to create the sampler pipeline state: {:#x}", (unsigned)hr);
        blend.RenderTarget[0].SrcBlend = D3D12_BLEND_ONE;
        hr = device->CreateGraphicsPipelineState(&psoDesc, IID_PPV_ARGS(&pipeline->pipelineState[1]));
        if (FAILED(hr))
            _throwV_("Failed to create the premultiplied pipeline state: {:#x}", (unsigned)hr);

        D3D12_DESCRIPTOR_HEAP_DESC heapDesc = {};
        heapDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_SAMPLER;
        heapDesc.NumDescriptors = 19;
        heapDesc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;
        hr = device->CreateDescriptorHeap(&heapDesc, IID_PPV_ARGS(&pipeline->samplerHeap));
        if (FAILED(hr))
            _throwV_("Failed to create the sampler descriptor heap: {:#x}", (unsigned)hr);
        pipeline->samplerIncrement = device->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_SAMPLER);
        pipeline->samplerStart = pipeline->samplerHeap->GetGPUDescriptorHandleForHeapStart().ptr;
        D3D12_CPU_DESCRIPTOR_HANDLE cpuStart = pipeline->samplerHeap->GetCPUDescriptorHandleForHeapStart();
        for (UINT i = 0; i < 18; i++)
        {
            D3D12_SAMPLER_DESC desc = {};
            desc.Filter = i == 0 ? D3D12_FILTER_MIN_MAG_MIP_POINT : i == 1 ? D3D12_FILTER_MIN_MAG_MIP_LINEAR : D3D12_FILTER_ANISOTROPIC;
            desc.AddressU = D3D12_TEXTURE_ADDRESS_MODE_CLAMP;
            desc.AddressV = D3D12_TEXTURE_ADDRESS_MODE_CLAMP;
            desc.AddressW = D3D12_TEXTURE_ADDRESS_MODE_CLAMP;
            desc.MaxAnisotropy = i >= 2 ? i - 1 : 1;
            desc.ComparisonFunc = D3D12_COMPARISON_FUNC_ALWAYS;
            desc.MinLOD = 0.0f;
            desc.MaxLOD = D3D12_FLOAT32_MAX;
            device->CreateSampler(&desc, {cpuStart.ptr + (SIZE_T)i * pipeline->samplerIncrement});
        }
        // DEFAULT_SAMPLER: the backend's static sampler (ImGui_ImplDX12_CreateDeviceObjects).
        D3D12_SAMPLER_DESC backend = {};
        backend.Filter = D3D12_FILTER_MIN_MAG_MIP_LINEAR;
        backend.AddressU = D3D12_TEXTURE_ADDRESS_MODE_CLAMP;
        backend.AddressV = D3D12_TEXTURE_ADDRESS_MODE_CLAMP;
        backend.AddressW = D3D12_TEXTURE_ADDRESS_MODE_CLAMP;
        backend.MaxAnisotropy = 1;
        backend.ComparisonFunc = D3D12_COMPARISON_FUNC_ALWAYS;
        backend.MinLOD = 0.0f;
        backend.MaxLOD = 0.0f;
        device->CreateSampler(&backend, {cpuStart.ptr + (SIZE_T)DEFAULT_SAMPLER * pipeline->samplerIncrement});
        return pipeline.release();
    }

    void Dx12TextureStore::EnsureSamplerPipeline()
    {
        if (this->samplerPipeline.load() != nullptr)
            return;
        SamplerPipeline *created = CreateSamplerPipeline(this->device, this->rtvFormat);
        bool open;
        {
            std::lock_guard<std::mutex> lock(this->mutex);
            open = this->open;
            if (open && this->samplerPipeline.load() == nullptr)
                this->samplerPipeline = std::exchange(created, nullptr);
        }
        if (created != nullptr)
            ReleaseSamplerPipeline(created);
        if (!open)
            _throw_("no D3D12 device; the session of this renderer has closed");
    }

    std::pair<UINT, UINT> Dx12TextureStore::ScopeOf(ImDrawList *drawList) const
    {
        auto it = this->scopeState.find(drawList);
        return it != this->scopeState.end() ? it->second : std::pair<UINT, UINT>{DEFAULT_SAMPLER, 0};
    }

    void Dx12TextureStore::UpdateScope(ImDrawList *drawList, UINT sIdx, UINT bIdx)
    {
        if (sIdx == DEFAULT_SAMPLER && bIdx == 0)
        {
            this->scopeState.erase(drawList);
            drawList->AddCallback(ImDrawCallback_ResetRenderState, nullptr);
            return;
        }
        this->EnsureSamplerPipeline();
        this->scopeState[drawList] = {sIdx, bIdx};
        drawList->AddCallback(&Dx12TextureStore::SamplerCallback, &this->samplerRecords[sIdx][bIdx]);
    }

    void Dx12TextureStore::SamplerCallback(const ImDrawList *parentList, const ImDrawCmd *cmd) noexcept
    {
        auto *state = (ImGui_ImplDX12_RenderState *)ImGui::GetPlatformIO().Renderer_RenderState;
        auto *record = (const SamplerRecord *)cmd->UserCallbackData;
        if (state == nullptr || record == nullptr || !record->store->IsOpen())
            return;
        SamplerPipeline *pipeline = record->store->samplerPipeline.load();
        if (pipeline == nullptr)
            return;
        ImDrawData *drawData = nullptr;
        ImGuiPlatformIO &platformIO = ImGui::GetPlatformIO();
        for (int i = 0; i < platformIO.Viewports.Size && drawData == nullptr; i++)
        {
            ImDrawData *candidate = platformIO.Viewports[i]->DrawData;
            if (candidate != nullptr && candidate->CmdLists.contains((ImDrawList *)parentList))
                drawData = candidate;
        }
        if (drawData == nullptr)
            return;

        float mvp[4][4];
        Projection(drawData, mvp);
        ID3D12GraphicsCommandList *list = state->CommandList;
        ID3D12DescriptorHeap *heaps[2] = {record->store->heap, pipeline->samplerHeap};
        list->SetDescriptorHeaps(2, heaps);
        list->SetGraphicsRootSignature(pipeline->rootSignature);
        list->SetPipelineState(pipeline->pipelineState[record->blend]);
        list->SetGraphicsRoot32BitConstants(0, 16, mvp, 0);
        list->SetGraphicsRootDescriptorTable(2, {pipeline->samplerStart + (UINT64)record->sampler * pipeline->samplerIncrement});
    }

    std::shared_ptr<Dx12TextureStore> Dx12Render::SamplerScopeStore(ImDrawList *drawList)
    {
        ImGuiContext *context = ImGui::GetCurrentContext();
        if (context == nullptr || !context->WithinFrameScope)
            _throw_("no frame in progress; call it from the render callback, between NewFrame and Render");
        std::shared_ptr<Dx12TextureStore> store;
        {
            std::lock_guard<std::mutex> lock(this->texturesMutex);
            store = this->textures;
        }
        if (store == nullptr || !store->IsOpen())
            _throw_("no D3D12 device; the session of this renderer is not open");
        if (!store->OnRenderThread())
            _throw_("called off the render thread; call it from the render callback");
        if (drawList->_Data != ImGui::GetDrawListSharedData())
            throw py::value_error("drawList belongs to another ImGui context");
        return store;
    }

    void Dx12Render::SetTextureSampler(ImDrawList *drawList, OVERLAY_TYPES_NAMESPACE::TextureFilter filter, int anisotropy)
    {
        using OVERLAY_TYPES_NAMESPACE::TextureFilter;
        std::shared_ptr<Dx12TextureStore> store = this->SamplerScopeStore(drawList);
        switch (filter)
        {
        case TextureFilter::Point:
        case TextureFilter::Linear:
        case TextureFilter::Anisotropic:
            break;
        default:
            throw py::value_error(std::format("unknown TextureFilter value: {}", (int)filter));
        }
        if (anisotropy < 1 || anisotropy > 16)
            throw py::value_error(std::format("anisotropy must be in [1, 16], got {}", anisotropy));
        UINT sIdx = filter == TextureFilter::Point ? 0 : filter == TextureFilter::Linear ? 1 : 1 + (UINT)anisotropy;
        store->UpdateScope(drawList, sIdx, store->ScopeOf(drawList).second);
    }

    void Dx12Render::ResetTextureSampler(ImDrawList *drawList)
    {
        std::shared_ptr<Dx12TextureStore> store = this->SamplerScopeStore(drawList);
        store->UpdateScope(drawList, Dx12TextureStore::DEFAULT_SAMPLER, store->ScopeOf(drawList).second);
    }

    void Dx12Render::SetTextureBlend(ImDrawList *drawList, OVERLAY_TYPES_NAMESPACE::TextureBlend blend)
    {
        std::shared_ptr<Dx12TextureStore> store = this->SamplerScopeStore(drawList);
        TEXTURE_DATA_NAMESPACE::CheckTextureBlend(blend);
        UINT bIdx = blend == OVERLAY_TYPES_NAMESPACE::TextureBlend::Premultiplied ? 1 : 0;
        store->UpdateScope(drawList, store->ScopeOf(drawList).first, bIdx);
    }

    void Dx12Render::ResetTextureBlend(ImDrawList *drawList)
    {
        std::shared_ptr<Dx12TextureStore> store = this->SamplerScopeStore(drawList);
        store->UpdateScope(drawList, store->ScopeOf(drawList).first, 0);
    }
}
END_M_IMGUI_IMPL_DX12_NAMESPACE
