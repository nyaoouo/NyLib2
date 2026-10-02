#include "./OverlayQueries.h"

START_OVERLAY_QUERIES_NAMESPACE
{
    namespace
    {
        py::object GetMonitorsImpl()
        {
            try
            {
                return py::cast(EnumerateMonitors());
            }
            catch (const std::system_error &e)
            {
                PyErr_SetFromWindowsErr(e.code().value());
                throw py::error_already_set();
            }
        }

        // M4: AreDpiAwarenessContextsEqual must run first, since
        // GetAwarenessFromDpiAwarenessContext reports PER_MONITOR_AWARE for
        // both the v1 and v2 contexts.
        std::string GetDpiAwarenessImpl()
        {
            DPI_AWARENESS_CONTEXT ctx = GetThreadDpiAwarenessContext();
            if (AreDpiAwarenessContextsEqual(ctx, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2))
                return "per_monitor_v2";
            DPI_AWARENESS awareness = GetAwarenessFromDpiAwarenessContext(ctx);
            if (awareness == DPI_AWARENESS_PER_MONITOR_AWARE)
                return "per_monitor";
            if (awareness == DPI_AWARENESS_SYSTEM_AWARE)
                return "system";
            if (awareness == DPI_AWARENESS_UNAWARE)
                return "unaware";
            _throw_("GetDpiAwareness: invalid thread DPI awareness context");
        }
    }

    void pybind_setup_OverlayQueries(py::module_ m)
    {
        // Read-only snapshot: pos/size getters return copies so `m.pos.x = 1`
        // never mutates the snapshot.
        py::class_<MonitorInfo>(m, "MonitorInfo", py::dynamic_attr())
            .def_property_readonly("index", [](const MonitorInfo &self) { return self.index; })
            .def_property_readonly("name", [](const MonitorInfo &self) { return self.name; })
            .def_property_readonly("isPrimary", [](const MonitorInfo &self) { return self.isPrimary; })
            .def_property_readonly("pos", [](const MonitorInfo &self) { return self.pos; })
            .def_property_readonly("size", [](const MonitorInfo &self) { return self.size; });

        m.def("GetMonitors", &GetMonitorsImpl);
        m.def("GetDpiAwareness", &GetDpiAwarenessImpl);
    }
}
END_OVERLAY_QUERIES_NAMESPACE
