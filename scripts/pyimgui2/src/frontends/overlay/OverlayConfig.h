#pragma once

#include "../common/RenderBase.h"

#include <atomic>
#include <mutex>

START_M_IMGUI_IMPL_NAMESPACE
{
    namespace Overlay
    {
        struct Config
        {
            std::mutex mutex;   // orders `serving` against `overlay` assignments; never held while taking the GIL
            bool serving = false;
            std::atomic<bool> overlay{false};
            std::atomic<int> monitor{0};
            std::atomic<bool> dpiAware{true};
        };

        // Marks a Serve() call as running; raises RuntimeError if one already is.
        class ServeScope
        {
        public:
            explicit ServeScope(Config &config) : config(config)
            {
                std::lock_guard<std::mutex> lock(this->config.mutex);
                if (this->config.serving)
                    _throw_("Serve() is already running");
                this->config.serving = true;
            }

            ~ServeScope()
            {
                std::lock_guard<std::mutex> lock(this->config.mutex);
                this->config.serving = false;
            }

            ServeScope(const ServeScope &) = delete;
            ServeScope &operator=(const ServeScope &) = delete;

        private:
            Config &config;
        };

        // Adds the overlay members and the guarded Serve to a window class with an `overlayConfig` member.
        template <class W, class... Options>
        void BindMembers(py::class_<W, Options...> &cls)
        {
            cls.def_property("overlay",
                             [](W &self) { return self.overlayConfig.overlay.load(); },
                             [](W &self, bool value)
                             {
                                 std::lock_guard<std::mutex> lock(self.overlayConfig.mutex);
                                 if (self.overlayConfig.serving)
                                     _throw_("overlay cannot be changed while Serve() runs");
                                 self.overlayConfig.overlay = value;
                             })
                .def_property("overlayMonitor",
                              [](W &self) { return self.overlayConfig.monitor.load(); },
                              [](W &self, int value) { self.overlayConfig.monitor = value; })
                .def_property("overlayDpiAware",
                              [](W &self) { return self.overlayConfig.dpiAware.load(); },
                              [](W &self, bool value) { self.overlayConfig.dpiAware = value; })
                .def("Serve",
                     [](W &self)
                     {
                         ServeScope scope(self.overlayConfig);
                         self.Serve();
                     },
                     py::call_guard<py::gil_scoped_release>());
        }
    }
}
END_M_IMGUI_IMPL_NAMESPACE
