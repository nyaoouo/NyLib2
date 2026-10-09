#include "./OverlayTarget.h"

#include <utility>

START_M_IMGUI_IMPL_NAMESPACE
{
    namespace Overlay
    {
        namespace
        {
            constexpr auto FinderPollInterval = std::chrono::milliseconds(250);
        }

        TargetTracker::TargetTracker(RenderBase &self, Config &config) : self(self), config(config)
        {
        }

        void TargetTracker::Step()
        {
            bool lost = false;
            if (this->config.targetGeneration.load() != this->seenGeneration)
                lost = this->TakeAssignment();
            if (!lost && this->state == TargetState::Tracking && !this->StillTracked())
                lost = true;
            if (lost)
                this->Lose();
            bool found = !lost && this->state == TargetState::Searching && this->Resolve();
            if (lost)
                this->FireCallback(this->config.targetLostCallback, this->config.targetLostArgc, "targetLostCallback");
            if (found)
                this->FireCallback(this->config.targetFoundCallback, this->config.targetFoundArgc, "targetFoundCallback");
        }

        void TargetTracker::Reset() noexcept
        {
            this->Publish(nullptr, 0);
            this->hwnd = nullptr;
            this->pid = 0;
            this->state = TargetState::Monitor;
            this->seenGeneration = UINT64_MAX;
            PyObject *dropped = std::exchange(this->snapshot, nullptr);
            if (dropped == nullptr)
                return;
            PyGILState_STATE gil = PyGILState_Ensure();
            Py_DECREF(dropped);
            PyGILState_Release(gil);
        }

        // Snapshots the slot; returns true when the tracked target is lost to a different value.
        bool TargetTracker::TakeAssignment()
        {
            py::gil_scoped_acquire gil;
            PyObject *previous = this->snapshot;
            TargetKind previousKind = this->kind;
            uintptr_t previousBits = this->bits;
            {
                std::lock_guard<std::mutex> lock(this->config.mutex);
                this->snapshot = this->config.target.ptr();
                Py_XINCREF(this->snapshot);
                this->kind = this->config.targetKind;
                this->bits = this->config.targetBits;
                this->seenGeneration = this->config.targetGeneration.load();
            }
            bool same = this->kind == previousKind && (this->kind == TargetKind::Fixed ? this->bits == previousBits : this->snapshot == previous);
            Py_XDECREF(previous);
            if (this->state == TargetState::Tracking)
            {
                if (same)
                    return false;
                this->armed = true;
                return true;
            }
            this->armed = true;
            this->state = this->kind == TargetKind::None ? TargetState::Monitor : TargetState::Searching;
            return false;
        }

        bool TargetTracker::StillTracked() const
        {
            DWORD owner = 0;
            return IsWindow(this->hwnd) && GetWindowThreadProcessId(this->hwnd, &owner) != 0 && owner == this->pid;
        }

        void TargetTracker::Lose()
        {
            this->hwnd = nullptr;
            this->pid = 0;
            this->Publish(nullptr, 0);
            this->state = this->kind == TargetKind::None ? TargetState::Monitor : TargetState::Searching;
        }

        // Tests a fixed value once per arm and calls a finder when armed or when its poll is due; true when a target was accepted.
        bool TargetTracker::Resolve()
        {
            bool pollDue = !this->finderCalled || std::chrono::steady_clock::now() - this->lastFinderCall >= FinderPollInterval;
            if (!this->armed && !(this->kind == TargetKind::Finder && pollDue))
                return false;
            this->armed = false;
            uintptr_t candidate = this->bits;
            if (this->kind == TargetKind::Finder)
                candidate = this->CallFinder();
            if (candidate == 0)
                return false;
            HWND window = (HWND)candidate;
            DWORD owner = 0;
            if (IsWindow(window))
                GetWindowThreadProcessId(window, &owner);
            if (owner == 0 || owner == GetCurrentProcessId())
            {
                if (this->kind == TargetKind::Fixed)
                    this->WriteRejected(candidate, owner == 0 ? "not a window" : "a window of this process");
                return false;
            }
            this->hwnd = window;
            this->pid = owner;
            this->Publish(window, owner);
            this->state = TargetState::Tracking;
            return true;
        }

        // The finder's candidate bits; None means 0, any other non-index return raises TypeError.
        uintptr_t TargetTracker::CallFinder()
        {
            py::gil_scoped_acquire gil;
            this->finderCalled = true;
            this->lastFinderCall = std::chrono::steady_clock::now();
            py::object result = py::reinterpret_steal<py::object>(PyObject_CallNoArgs(this->snapshot));
            if (!result)
                throw py::error_already_set();
            if (result.is_none())
                return 0;
            if (!PyIndex_Check(result.ptr()))
                throw py::type_error(std::format("an overlayTarget finder must return None or an int-like HWND, not {}", Py_TYPE(result.ptr())->tp_name));
            return TargetBits(result.ptr());
        }

        void TargetTracker::WriteRejected(uintptr_t candidate, const char *reason)
        {
            std::string line = std::format("[pyimgui] overlayTarget {:#x} was rejected ({}); assign it again to retry\n", candidate, reason);
            py::gil_scoped_acquire gil;
            PySys_WriteStderr("%s", line.c_str());
        }

        void TargetTracker::Publish(HWND target, DWORD targetPid)
        {
            std::lock_guard<std::mutex> lock(this->config.mutex);
            this->config.targetHwnd = target;
            this->config.targetPid = targetPid;
        }

        // Calls a found/lost callback with no argument or with the window; the copy is dropped before the GIL is released.
        void TargetTracker::FireCallback(std::optional<py::function> &slot, const size_t &argc, const char *name)
        {
            py::gil_scoped_acquire gil;
            if (!slot)
                return;
            py::function callback = *slot;
            size_t count = argc;
            if (count == 0)
                callback();
            else if (count == 1)
                callback(py::cast(&this->self, py::return_value_policy::reference));
            else
                _throwV_("Invalid {} argc: {}", name, count);
        }
    }
}
END_M_IMGUI_IMPL_NAMESPACE
