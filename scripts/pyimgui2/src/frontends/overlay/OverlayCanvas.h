#pragma once

#include "../common/RenderBase.h"
#include "./OverlayConfig.h"

START_M_IMGUI_IMPL_NAMESPACE
{
    namespace Overlay
    {
        // The graphics side of the canvas; one implementation per frontend.
        class Renderer
        {
        public:
            virtual ~Renderer() = default;
            // Creates the device and a composition swap chain; returns the swap chain, still owned by the renderer.
            virtual IUnknown *CreateSwapChain(UINT width, UINT height) = 0;
            // Runs after ImGui_ImplWin32_Init, with the canvas context current; on throw it leaves no backend state.
            virtual void InitBackend() = 0;
            // Called only after InitBackend succeeded.
            virtual void ShutdownBackend() noexcept = 0;
            // Waits until the GPU is idle; a no-op without a device.
            virtual void WaitIdle() noexcept = 0;
            // Width and height are non-zero and differ from the current size.
            virtual void Resize(UINT width, UINT height) = 0;
            virtual void NewFrame() = 0;
            // Clears to (0,0,0,0), draws ImGui's draw data and presents with vsync; false when the present was occluded.
            virtual bool RenderAndPresent() = 0;
            // Idempotent, and safe after a partial CreateSwapChain.
            virtual void Release() noexcept = 0;
        };

        // Runs the overlay loop for `self` on a topmost canvas until it closes; tears down and rethrows on any error.
        void Serve(RenderBase &self, Config &config, Renderer &renderer, const wchar_t *className);
    }
}
END_M_IMGUI_IMPL_NAMESPACE
