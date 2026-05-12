#pragma once

#include "../common/RenderBase.h"

#include <d3d10_1.h>
#include <d3d10.h>
#include <dxgi.h>
#include "imgui_impl_win32.h"
#include "imgui_impl_dx10.h"

#define M_IMGUI_IMPL_DX10_NAMESPACE M_IMGUI_IMPL_NAMESPACE::Impl_Dx10
#define START_M_IMGUI_IMPL_DX10_NAMESPACE START_M_IMGUI_IMPL_NAMESPACE { namespace Impl_Dx10
#define END_M_IMGUI_IMPL_DX10_NAMESPACE } END_M_IMGUI_IMPL_NAMESPACE

START_M_IMGUI_IMPL_DX10_NAMESPACE
{
    class Dx10Render : public RenderBase
    {
    public:
        Dx10Render(std::optional<py::function> renderCallback = std::nullopt) : RenderBase(renderCallback) {}
    };

    class Dx10Window : public Dx10Render
    {
    public:
        static inline Dx10Window *_instance = nullptr;
        ImVec4 ClearColor = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

        Dx10Window(std::optional<py::function> renderCallback = std::nullopt);
        ~Dx10Window();

        void Serve();
    };

    class Dx10Inbound : public Dx10Render
    {
    public:
        static inline Dx10Inbound *_instance = nullptr;
        bool isImGuiInitialized = false;

        Dx10Inbound(std::optional<py::function> renderCallback = std::nullopt);
        ~Dx10Inbound();

        void Attach();
        void Detach();
        void Update();
    };

    void pybind_setup_mImguiImpl_Dx10(pybind11::module_ m);
}
END_M_IMGUI_IMPL_DX10_NAMESPACE