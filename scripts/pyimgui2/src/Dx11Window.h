#pragma once
#include "./frontends/common/RenderBase.h"
#include "./frontends/overlay/OverlayConfig.h"

#include <d3d11.h>
#include <dxgi.h>
#include <array>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <utility>
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

START_M_IMGUI_IMPL_NAMESPACE
{
    // Deferred SRV releases and the sampler cache of one D3D11 device session; shared by the renderer and its textures.
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
        void Close() noexcept;                               // teardown, unwind guard or open site; releases pending, samplers and blend states (single-threaded: leaks); idempotent
        bool IsOpen() const noexcept;                        // lock-free; read on every handle access
        ID3D11SamplerState *Sampler(OVERLAY_TYPES_NAMESPACE::TextureFilter filter, int anisotropy); // render thread; anisotropy in [1, 16]; cached until Close; RuntimeError on failure
        static int SamplerIndex(OVERLAY_TYPES_NAMESPACE::TextureFilter filter, int anisotropy);      // 0 Point, 1 Linear, 1 + anisotropy
        ID3D11BlendState *Blend(OVERLAY_TYPES_NAMESPACE::TextureBlend blend);                       // render thread; cached until Close; RuntimeError on failure
        bool BgraSupported();                                                                       // render thread; CheckFormatSupport, cached for the store's lifetime

        // Combined sampler+blend scope (render thread only, cleared in Collect): sIdx is a sampler
        // variant index (as Sampler()'s, 0..17) or DEFAULT_SAMPLER; bIdx is 0 Straight, 1 Premultiplied.
        static int const DEFAULT_SAMPLER = 18;
        std::pair<int, int> ScopeOf(ImDrawList *drawList) const;       // (DEFAULT_SAMPLER, 0) when absent
        void UpdateScope(ImDrawList *drawList, int sIdx, int bIdx);    // appends the combined callback, or ResetRenderState when fully default

        // Public so the free-function draw callback (ImDrawCmd::UserCallbackData) can read it.
        struct ScopeRecord
        {
            ID3D11SamplerState *sampler; // nullptr: use ImGui_ImplDX11_RenderState::SamplerDefault
            ID3D11BlendState *blend;
        };

    private:
        std::mutex mutex;
        std::atomic<bool> open{true};
        ID3D11Device *device;
        DWORD renderThread;
        bool singleThreaded;
        std::vector<ID3D11ShaderResourceView *> pending;
        std::vector<ID3D11ShaderResourceView *> releases; // scratch of Collect and Close, which never run concurrently
        ID3D11SamplerState *samplers[18] = {};            // Point, Linear, then Anisotropic 1..16
        ID3D11BlendState *blendStates[2] = {};            // 0 Straight, 1 Premultiplied
        bool bgraChecked = false;
        bool bgraSupported = false;

        ScopeRecord scopeRecords[19][2] = {};                       // [sIdx][bIdx]; stable addresses for AddCallback
        std::unordered_map<ImDrawList *, std::pair<int, int>> scopeState; // current (sIdx, bIdx) per drawList this frame
    };

    class Dx11Texture
    {
    public:
        std::shared_ptr<Dx11TextureStore> store;
        ID3D11ShaderResourceView *textureView = nullptr;
        int width = 0;
        int height = 0;
        int mipLevels = 1;
        bool mips = false; // creation value
        OVERLAY_TYPES_NAMESPACE::TextureFormat format = OVERLAY_TYPES_NAMESPACE::TextureFormat::RGBA8;
        bool premultiplied = false;

        Dx11Texture(std::shared_ptr<Dx11TextureStore> store, int width, int height, const unsigned char *rgba, UINT rowPitch, bool mips,
                    OVERLAY_TYPES_NAMESPACE::TextureFormat format = OVERLAY_TYPES_NAMESPACE::TextureFormat::RGBA8, bool premultiplied = false); // needs no GIL
        ~Dx11Texture();
        Dx11Texture(const Dx11Texture &) = delete;
        Dx11Texture &operator=(const Dx11Texture &) = delete;

        void FreeTexture();
        // render thread, GIL held on entry; rect=nullopt: same size, in place (handle kept), mips rebuilt;
        // rect=(x,y,w,h): in place (handle kept), only that rectangle, texture must have mips=False.
        void UpdatePixels(py::buffer pixels, long long rowPitch, std::optional<std::array<int, 4>> rect = std::nullopt);
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
        Dx11Texture *CreateTexture(const std::string &filename, std::optional<OVERLAY_TYPES_NAMESPACE::TextureTransform> transform = std::nullopt, bool mips = false);
        Dx11Texture *CreateTextureFromPixels(int width, int height, py::buffer pixels, long long rowPitch, bool mips,
                                             OVERLAY_TYPES_NAMESPACE::TextureFormat format = OVERLAY_TYPES_NAMESPACE::TextureFormat::RGBA8, bool premultiplied = false);
        void SetTextureSampler(ImDrawList *drawList, OVERLAY_TYPES_NAMESPACE::TextureFilter filter, int anisotropy); // the draws added after it to drawList, until Reset
        void ResetTextureSampler(ImDrawList *drawList);                                                             // back to the backend sampler, keeping the blend
        void SetTextureBlend(ImDrawList *drawList, OVERLAY_TYPES_NAMESPACE::TextureBlend blend); // the draws added after it to drawList, until Reset; composes with SetTextureSampler
        void ResetTextureBlend(ImDrawList *drawList);                                            // back to Straight, keeping the sampler
        std::shared_ptr<Dx11TextureStore> OpenTextures(); // the open store, else RuntimeError "no D3D11 device"; off the render thread RuntimeError "render thread"
        void InstallTextures(DWORD renderThread);         // open site: closes a leftover store, then opens one on pd3dDevice; 0 for inbound
        void CollectTextures() noexcept;
        void CloseTextures() noexcept;

    private:
        std::shared_ptr<Dx11TextureStore> SamplerScopeStore(ImDrawList *drawList); // frame, session, render-thread and context checks
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

        void Attach(OVERLAY_TYPES_NAMESPACE::HookMode mode = OVERLAY_TYPES_NAMESPACE::HookMode::Detours);
        void Detach();
        void InitImGui(IDXGISwapChain *pSwapChain);
        void Update();
        void _Update();
    };

    void pybind_setup_mImguiImpl(pybind11::module_ m);
}
END_M_IMGUI_IMPL_NAMESPACE
