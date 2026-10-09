#pragma once

#include "../common/RenderBase.h"

#include <pybind11/typing.h>

#include <atomic>
#include <mutex>
#include <utility>

START_M_IMGUI_IMPL_NAMESPACE
{
    namespace Overlay
    {
        enum class TargetKind
        {
            None,
            Fixed,
            Finder
        };

        using TargetType = py::typing::Optional<py::typing::Union<py::int_, py::typing::Callable<py::int_()>>>;

        inline bool IsAnyObject(PyObject *)
        {
            return true;
        }

        // An overlayTarget argument: accepts any object, so binding it runs no type check (the setter validates).
        class TargetArg : public py::object
        {
            PYBIND11_OBJECT_DEFAULT(TargetArg, object, IsAnyObject)
            using object::object;
        };
    }
}
END_M_IMGUI_IMPL_NAMESPACE

namespace pybind11::detail
{
    template <>
    struct handle_type_name<M_IMGUI_IMPL_NAMESPACE::Overlay::TargetArg>
    {
        static constexpr auto name = handle_type_name<M_IMGUI_IMPL_NAMESPACE::Overlay::TargetType>::name;
    };
}

START_M_IMGUI_IMPL_NAMESPACE
{
    namespace Overlay
    {
        struct Config
        {
            std::mutex mutex;   // orders `serving` against `overlay` assignments, guards the target slot; never held while taking the GIL or running Python
            bool serving = false;
            std::atomic<bool> overlay{false};
            std::atomic<int> monitor{0};
            std::atomic<bool> dpiAware{true};
            py::object target;                                 // empty reads as None (GIL, then mutex)
            TargetKind targetKind = TargetKind::None;          // (mutex)
            uintptr_t targetBits = 0;                          // a Fixed value's pointer bits (mutex)
            std::atomic<uint64_t> targetGeneration{0};         // +1 with every target store, under the mutex
            std::optional<py::function> targetFoundCallback;   // (GIL)
            std::optional<py::function> targetLostCallback;    // (GIL)
            size_t targetFoundArgc = 0;                        // (GIL)
            size_t targetLostArgc = 0;                         // (GIL)
            HWND targetHwnd = nullptr;                         // published by the Serve thread (mutex)
            DWORD targetPid = 0;                               // (mutex)
        };

        // The pointer bits of an __index__ value in [-2**63, 2**64); `what` names the value in the OverflowError.
        // Runs Python: never call it under Config::mutex.
        inline uintptr_t TargetBits(PyObject *value, const char *what)
        {
            py::object index = py::reinterpret_steal<py::object>(PyNumber_Index(value));
            if (!index)
                throw py::error_already_set();
            int overflow = 0;
            long long bits = PyLong_AsLongLongAndOverflow(index.ptr(), &overflow);
            if (overflow == 0)
            {
                if (bits == -1 && PyErr_Occurred())
                    throw py::error_already_set();
                return (uintptr_t)bits;
            }
            if (overflow > 0)
            {
                unsigned long long unsignedBits = PyLong_AsUnsignedLongLong(index.ptr());
                if (unsignedBits != (unsigned long long)-1 || !PyErr_Occurred())
                    return (uintptr_t)unsignedBits;
                PyErr_Clear();
            }
            py::set_error(PyExc_OverflowError, std::format("{} must lie in [-2**63, 2**64)", what).c_str());
            throw py::error_already_set();
        }

        // Classifies an overlayTarget value. Runs Python: never call it under Config::mutex.
        inline TargetKind ClassifyTarget(PyObject *value, uintptr_t &bits)
        {
            bits = 0;
            if (value == Py_None)
                return TargetKind::None;
            if (PyBool_Check(value))
                throw py::type_error("overlayTarget cannot be a bool");
            if (PyIndex_Check(value))
            {
                bits = TargetBits(value, "overlayTarget");
                return TargetKind::Fixed;
            }
            if (PyCallable_Check(value))
                return TargetKind::Finder;
            throw py::type_error(std::format("overlayTarget must be None, an int-like HWND or a callable, not {}", Py_TYPE(value)->tp_name));
        }

        // Stores overlayTarget and bumps the generation; it never resolves the target.
        inline void StoreTarget(Config &config, py::object value)
        {
            uintptr_t bits = 0;
            TargetKind kind = ClassifyTarget(value.ptr(), bits);
            {
                std::lock_guard<std::mutex> lock(config.mutex);
                std::swap(config.target, value);
                config.targetKind = kind;
                config.targetBits = bits;
                config.targetGeneration.fetch_add(1);
            }
            // `value` now holds the previous target and is released here, unlocked and with the GIL held.
        }

        // Reads overlayTarget without a type check, so the read runs no Python.
        inline TargetType LoadTarget(Config &config)
        {
            py::object target;
            {
                std::lock_guard<std::mutex> lock(config.mutex);
                target = config.target;
            }
            if (!target)
                target = py::none();
            return py::reinterpret_steal<TargetType>(target.release());
        }

        // Stores a target callback with its argument count; the previous callback is released last, with the GIL held.
        inline void StoreTargetCallback(std::optional<py::function> &slot, size_t &argc, std::optional<py::function> value)
        {
            size_t count = value ? PyFuncArgc(*value) : 0;
            std::swap(slot, value);
            argc = count;
        }

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

        // Raises RuntimeError while an overlay Serve() runs.
        inline void RefuseWhileServingOverlay(Config &config, const char *method)
        {
            std::lock_guard<std::mutex> lock(config.mutex);
            if (config.serving && config.overlay)
                _throwV_("{}() cannot be called while the overlay Serve() runs", method);
        }

        // Adds the overlay members, the guarded Serve and the tray guards to a window class with an `overlayConfig` member.
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
                .def_property("overlayTarget",
                              [](W &self) { return LoadTarget(self.overlayConfig); },
                              [](W &self, TargetArg value) { StoreTarget(self.overlayConfig, std::move(value)); })
                .def_property("targetFoundCallback",
                              [](W &self) { return self.overlayConfig.targetFoundCallback; },
                              [](W &self, std::optional<py::function> value)
                              {
                                  StoreTargetCallback(self.overlayConfig.targetFoundCallback, self.overlayConfig.targetFoundArgc, std::move(value));
                              })
                .def_property("targetLostCallback",
                              [](W &self) { return self.overlayConfig.targetLostCallback; },
                              [](W &self, std::optional<py::function> value)
                              {
                                  StoreTargetCallback(self.overlayConfig.targetLostCallback, self.overlayConfig.targetLostArgc, std::move(value));
                              })
                .def_property_readonly("targetHwnd",
                                       [](W &self)
                                       {
                                           std::lock_guard<std::mutex> lock(self.overlayConfig.mutex);
                                           return (int64_t)(intptr_t)self.overlayConfig.targetHwnd;
                                       })
                .def_property_readonly("targetPid",
                                       [](W &self)
                                       {
                                           std::lock_guard<std::mutex> lock(self.overlayConfig.mutex);
                                           return (uint32_t)self.overlayConfig.targetPid;
                                       })
                .def("HideToTray",
                     [](W &self)
                     {
                         RefuseWhileServingOverlay(self.overlayConfig, "HideToTray");
                         self.HideToTray();
                     })
                .def("RestoreFromTray",
                     [](W &self)
                     {
                         RefuseWhileServingOverlay(self.overlayConfig, "RestoreFromTray");
                         self.RestoreFromTray();
                     })
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
