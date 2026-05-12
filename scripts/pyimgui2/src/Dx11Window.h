#pragma once
#include "./frontends/common/RenderBase.h"

#include <d3d11.h>
#include <dxgi.h>
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

START_M_IMGUI_IMPL_NAMESPACE
{
    class Dx11Texture
    {
    public:
        ID3D11ShaderResourceView *textureView = nullptr;
        int width = 0;
        int height = 0;

        Dx11Texture(ID3D11Device *device, const char *filename);
        ~Dx11Texture();
        uintptr_t GetHandle() const;
    };

    class Dx11Render : public RenderBase
    {
    public:
        ID3D11Device *pd3dDevice = nullptr;
        ID3D11DeviceContext *pd3dDeviceContext = nullptr;
        IDXGISwapChain *pSwapChain = nullptr;
        ID3D11RenderTargetView *mainRenderTargetView = nullptr;

        Dx11Render(std::optional<py::function> renderCallback = std::nullopt) : RenderBase(renderCallback) {}

        void CreateRenderTarget();
        void CleanupRenderTarget();
        Dx11Texture *CreateTexture(const char *filename);
    };

    class Dx11Window : public Dx11Render
    {
    public:
        static inline Dx11Window *_instance = nullptr;
        bool swapChainOccluded = false;
        UINT resizeWidth = 0;
        UINT resizeHeight = 0;
        ImVec4 ClearColor = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

        Dx11Window(std::optional<py::function> renderCallback = std::nullopt);
        ~Dx11Window();

        void CreateDeviceD3D();
        void CleanupDeviceD3D();
        void Serve();
    };

    class Dx11Inbound : public Dx11Render
    {
    public:
        static inline Dx11Inbound *_instance = nullptr;
        bool isImGuiInitialized = false;
        bool isInLogic = false;

        Dx11Inbound(std::optional<py::function> renderCallback = std::nullopt);
        ~Dx11Inbound();

        void Attach();
        void Detach();
        void InitImGui(IDXGISwapChain *pSwapChain);
        void Update();
        void _Update();
    };

    void pybind_setup_mImguiImpl(pybind11::module_ m);
}
END_M_IMGUI_IMPL_NAMESPACE