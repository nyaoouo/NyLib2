#pragma once

#include "../common/RenderBase.h"
#include "./OverlayConfig.h"

#include <chrono>
#include <cstdint>

START_M_IMGUI_IMPL_NAMESPACE
{
    namespace Overlay
    {
        enum class TargetState
        {
            Monitor,
            Searching,
            Tracking,
            Hidden
        };

        // The Serve thread's side of overlayTarget for one Serve() call: resolution, loss, presentability and the found/lost callbacks.
        class TargetTracker
        {
        public:
            TargetTracker(RenderBase &self, Config &config);

            TargetTracker(const TargetTracker &) = delete;
            TargetTracker &operator=(const TargetTracker &) = delete;

            // Takes a new assignment, checks the target, resolves, then fires lost or found; may run Python and throw.
            void Step();
            // Publishes no target and drops the snapshot without firing a callback.
            void Reset() noexcept;
            TargetState State() const;
            // The target's client rect on the screen, in the calling thread's DPI context; false when it cannot be read.
            bool ClientRectOnScreen(RECT &rect) const;

        private:
            RenderBase &self;
            Config &config;

            PyObject *snapshot = nullptr;   // owned; touched only with the GIL held
            TargetKind kind = TargetKind::None;
            uintptr_t bits = 0;
            uint64_t seenGeneration = UINT64_MAX;
            TargetState state = TargetState::Monitor;
            bool armed = false;
            bool finderCalled = false;
            std::chrono::steady_clock::time_point lastFinderCall{};
            HWND hwnd = nullptr;
            DWORD pid = 0;

            bool TakeAssignment();
            bool Tracked() const;
            bool StillTracked() const;
            bool Presentable() const;
            void Lose();
            bool Resolve();
            uintptr_t CallFinder();
            void WriteRejected(uintptr_t candidate, const char *reason);
            void Publish(HWND target, DWORD targetPid);
            void FireCallback(std::optional<py::function> &slot, const size_t &argc, const char *name);   // argc by reference: read after the GIL is taken
        };
    }
}
END_M_IMGUI_IMPL_NAMESPACE
