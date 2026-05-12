#pragma once

#include "../common/RenderBase.h"
#include "../common/Win32Hook.h"

#include <d3d9.h>
#include "imgui_impl_win32.h"
#include "imgui_impl_dx9.h"

#define M_IMGUI_IMPL_DX9_NAMESPACE M_IMGUI_IMPL_NAMESPACE::Impl_Dx9
#define START_M_IMGUI_IMPL_DX9_NAMESPACE START_M_IMGUI_IMPL_NAMESPACE { namespace Impl_Dx9
#define END_M_IMGUI_IMPL_DX9_NAMESPACE } END_M_IMGUI_IMPL_NAMESPACE

START_M_IMGUI_IMPL_DX9_NAMESPACE
{
    class Dx9Render : public RenderBase
    {
    public:
        Dx9Render(std::optional<py::function> renderCallback = std::nullopt) : RenderBase(renderCallback) {}
    };

    class Dx9Window : public Dx9Render
    {
    public:
        static inline Dx9Window *_instance = nullptr;
        ImVec4 ClearColor = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

        LPDIRECT3D9 pD3D = nullptr;
        LPDIRECT3DDEVICE9 pd3dDevice = nullptr;
        bool deviceLost = false;
        UINT resizeWidth = 0;
        UINT resizeHeight = 0;
        D3DPRESENT_PARAMETERS d3dpp = {};

        Dx9Window(std::optional<py::function> renderCallback = std::nullopt);
        ~Dx9Window();

        void CreateDeviceD3D();
        void CleanupDeviceD3D();
        void ResetDevice();
        void Serve();
    };

    class Dx9Inbound : public Dx9Render
    {
    public:
        static inline Dx9Inbound *_instance = nullptr;
        bool isImGuiInitialized = false;
        bool isInLogic = false;
        LPDIRECT3DDEVICE9 pd3dDevice = nullptr;

        Dx9Inbound(std::optional<py::function> renderCallback = std::nullopt);
        ~Dx9Inbound();

        void Attach();
        void Detach();
        void InitImGui(LPDIRECT3DDEVICE9 pd3dDevice);
        void Update();
        void _Update();
    };

    void pybind_setup_mImguiImpl_Dx9(pybind11::module_ m);
}
END_M_IMGUI_IMPL_DX9_NAMESPACE