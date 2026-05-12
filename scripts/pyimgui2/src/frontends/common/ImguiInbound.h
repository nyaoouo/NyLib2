#pragma once

#include "../../gHeader.h"

#include <d3d9.h>
#include <d3d10_1.h>
#include <d3d10.h>
#include <d3d11.h>
#include <d3d12.h>
#include <dxgi.h>

#define IMGUI_INBOUND_NAMESPACE mNameSpace::ImguiInbound
#define START_IMGUI_INBOUND_NAMESPACE namespace mNameSpace { namespace ImguiInbound
#define END_IMGUI_INBOUND_NAMESPACE }

START_IMGUI_INBOUND_NAMESPACE
{
    enum RenderType
    {
        None,
        D3D9,
        D3D10,
        D3D11,
        D3D12,
        Auto,
        Unknown,
    };

    RenderType GuessRenderType();
    void Init(RenderType renderType);
    PVOID GetMethod(size_t index);
    RenderType GetRenderType();
    void pybind_setup_imgui_inbound(pybind11::module_ m);
}
END_IMGUI_INBOUND_NAMESPACE