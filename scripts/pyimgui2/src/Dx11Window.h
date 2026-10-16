#pragma once
#include "./frontends/common/RenderBase.h"
#include "./frontends/overlay/OverlayConfig.h"

#include <d3d11.h>
#include <dxgi.h>
#include <atomic>
#include <mutex>
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

START_M_IMGUI_IMPL_NAMESPACE
{
    // Deferred SRV releases of one D3D11 device session; shared by the renderer and its textures.
    class Dx11TextureStore
    {
    public:
        explicit Dx11TextureStore(ID3D11Device *device, DWORD renderThread); // AddRefs the device; reads D3D11_CREATE_DEVICE_SINGLETHREADED from GetCreationFlags()
        ~Dx11TextureStore();                                                  // runs after Close; a store never closed calls Close() first
        Dx11TextureStore(const Dx11TextureStore &) = delete;
        Dx11TextureStore &operator=(const Dx11TextureStore &) = delete;

        ID3D11Device *Device() const;
        bool SingleThreaded() const;
        bool OnRenderThread() const noexcept;                // renderThread 0 (inbound): inside our hooked frame
        void Retire(ID3D11ShaderResourceView *srv) noexcept; // any thread; open: deferred, closed: released now (single-threaded: leaked)
        void Collect() noexcept;                             // render thread, before the backend NewFrame
        void Close() noexcept;                               // teardown, unwind guard or open site; releases pending (single-threaded: leaks); idempotent
        bool IsOpen() const noexcept;                        // lock-free; read on every handle access

    private:
        std::mutex mutex;
        std::atomic<bool> open{true};
        ID3D11Device *device;
        DWORD renderThread;
        bool singleThreaded;
        std::vector<ID3D11ShaderResourceView *> pending;
        std::vector<ID3D11ShaderResourceView *> releases; // scratch of Collect and Close, which never run concurrently
    };

    class Dx11Texture
    {
    public:
        std::shared_ptr<Dx11TextureStore> store;
        ID3D11ShaderResourceView *textureView = nullptr;
        int width = 0;
        int height = 0;
        int mipLevels = 1;

        Dx11Texture(std::shared_ptr<Dx11TextureStore> store, int width, int height, const unsigned char *rgba, UINT rowPitch); // needs no GIL
        ~Dx11Texture();
        Dx11Texture(const Dx11Texture &) = delete;
        Dx11Texture &operator=(const Dx11Texture &) = delete;

        void FreeTexture();
        uintptr_t GetHandle() const;
        ImVec2 GetSize() const;
    };

    class Dx11Render : public RenderBase
    {
    public:
        ID3D11Device *pd3dDevice = nullptr;
        ID3D11DeviceContext *pd3dDeviceContext = nullptr;
        IDXGISwapChain *pSwapChain = nullptr;
        ID3D11RenderTargetView *mainRenderTargetView = nullptr;

        std::shared_ptr<Dx11TextureStore> textures; // the open session's store; guarded by texturesMutex
        std::mutex texturesMutex;

        Dx11Render(std::optional<py::function> renderCallback = std::nullopt) : RenderBase(renderCallback) {}

        void CreateRenderTarget();
        void CleanupRenderTarget();
        Dx11Texture *CreateTexture(const std::string &filename);
        Dx11Texture *CreateTextureFromPixels(int width, int height, py::buffer pixels, long long rowPitch);
        std::shared_ptr<Dx11TextureStore> OpenTextures(); // the open store, else RuntimeError "no D3D11 device"; off the render thread RuntimeError "render thread"
        void InstallTextures(DWORD renderThread);         // open site: closes a leftover store, then opens one on pd3dDevice; 0 for inbound
        void CollectTextures() noexcept;
        void CloseTextures() noexcept;
    };

    class Dx11Window : public Dx11Render
    {
    public:
        static inline Dx11Window *_instance = nullptr;
        bool swapChainOccluded = false;
        UINT resizeWidth = 0;
        UINT resizeHeight = 0;
        ImVec4 ClearColor = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);
        Overlay::Config overlayConfig;

        Dx11Window(std::optional<py::function> renderCallback = std::nullopt);
        ~Dx11Window();

        void CreateDeviceD3D();
        void CleanupDeviceD3D();
        void Serve();
        void ServeOverlay();
    };

    class Dx11Inbound : public Dx11Render
    {
    public:
        static inline Dx11Inbound *_instance = nullptr;
        bool isImGuiInitialized = false;
        bool isInLogic = false;
        std::atomic<bool> viewportsEnable{true};
        std::atomic<bool> viewportsDirty{false};

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