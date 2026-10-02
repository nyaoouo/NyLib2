#include "./OverlayQueries.h"

#include <cstdint>
#include <iterator>
#include <string_view>
#include <utility>

#include <dwmapi.h>
#pragma comment(lib, "dwmapi.lib")

START_OVERLAY_QUERIES_NAMESPACE
{
    namespace
    {
        std::wstring ToLowerCopy(std::wstring_view s)
        {
            std::wstring out(s);
            if (!out.empty())
                CharLowerBuffW(out.data(), (DWORD)out.size());
            return out;
        }

        bool EqualsCaseInsensitive(std::wstring_view a, std::wstring_view b)
        {
            return ToLowerCopy(a) == ToLowerCopy(b);
        }

        bool ContainsCaseInsensitive(std::wstring_view haystack, std::wstring_view needle)
        {
            return ToLowerCopy(haystack).find(ToLowerCopy(needle)) != std::wstring::npos;
        }

        // Read-only match criteria (None or non-empty string per criterion).
        // The candidate filter order mirrors `WindowQuery_EnumProc` below.
        class WindowQuery
        {
        public:
            WindowQuery(std::optional<std::wstring> exe, std::optional<std::wstring> windowClass, std::optional<std::wstring> title)
                : exe(std::move(exe)), windowClass(std::move(windowClass)), title(std::move(title))
            {
                if (!this->exe && !this->windowClass && !this->title)
                    throw py::value_error("WindowQuery: exe, windowClass and title cannot all be None");
                if ((this->exe && this->exe->empty()) || (this->windowClass && this->windowClass->empty()) || (this->title && this->title->empty()))
                    throw py::value_error("WindowQuery: exe, windowClass and title cannot be ''");
            }

            std::optional<std::wstring> exe;
            std::optional<std::wstring> windowClass;
            std::optional<std::wstring> title;
        };

        struct WindowQueryBest
        {
            HWND hwnd = nullptr;
            long long area = -1;
        };

        BOOL CALLBACK WindowQuery_EnumProc(HWND hwnd, LPARAM lParam)
        {
            auto &[self, best] = *reinterpret_cast<std::pair<const WindowQuery *, WindowQueryBest *> *>(lParam);

            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);
            if (pid == GetCurrentProcessId())
                return TRUE;

            if (!IsWindowVisible(hwnd))
                return TRUE;

            BOOL cloaked = FALSE;
            if (SUCCEEDED(DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, &cloaked, sizeof(cloaked))) && cloaked)
                return TRUE;

            if (self->windowClass)
            {
                wchar_t cls[256];
                int n = GetClassNameW(hwnd, cls, (int)std::size(cls));
                if (n <= 0 || !EqualsCaseInsensitive(std::wstring_view(cls, (size_t)n), *self->windowClass))
                    return TRUE;
            }

            if (self->title)
            {
                wchar_t text[512];
                int n = GetWindowTextW(hwnd, text, (int)std::size(text));
                if (n <= 0 || !ContainsCaseInsensitive(std::wstring_view(text, (size_t)n), *self->title))
                    return TRUE;
            }

            if (self->exe)
            {
                HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                if (!process)
                    return TRUE;
                wchar_t path[1024];
                DWORD size = (DWORD)std::size(path);
                BOOL ok = QueryFullProcessImageNameW(process, 0, path, &size);
                CloseHandle(process);
                if (!ok)
                    return TRUE;
                std::wstring_view full(path, size);
                auto pos = full.find_last_of(L"\\/");
                std::wstring_view base = pos == std::wstring_view::npos ? full : full.substr(pos + 1);
                if (!EqualsCaseInsensitive(base, *self->exe))
                    return TRUE;
            }

            RECT rect{};
            if (!GetClientRect(hwnd, &rect))
                return TRUE;
            long long area = (long long)(rect.right - rect.left) * (long long)(rect.bottom - rect.top);
            if (area > best->area)
            {
                best->area = area;
                best->hwnd = hwnd;
            }
            return TRUE;
        }

        // GIL released for the whole enumeration; no Python call happens in
        // `WindowQuery_EnumProc`. `EnumWindows` failure raises OSError only
        // after the GIL is reacquired.
        int64_t WindowQuery_CallImpl(const WindowQuery &self)
        {
            WindowQueryBest best;
            auto ctx = std::make_pair(&self, &best);
            BOOL ok;
            DWORD err = 0;
            {
                py::gil_scoped_release release;
                ok = EnumWindows(WindowQuery_EnumProc, reinterpret_cast<LPARAM>(&ctx));
                if (!ok)
                    err = GetLastError();
            }
            if (!ok)
            {
                PyErr_SetFromWindowsErr((int)err);
                throw py::error_already_set();
            }
            return (int64_t)reinterpret_cast<intptr_t>(best.hwnd);
        }

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

        // Checks per-monitor-v2 first; the awareness query reports v1 and v2 alike.
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

        py::class_<WindowQuery>(m, "WindowQuery", py::dynamic_attr())
            .def(py::init<std::optional<std::wstring>, std::optional<std::wstring>, std::optional<std::wstring>>(),
                 py::arg("exe") = py::none(), py::arg("windowClass") = py::none(), py::arg("title") = py::none())
            .def_property_readonly("exe", [](const WindowQuery &self) { return self.exe; })
            .def_property_readonly("windowClass", [](const WindowQuery &self) { return self.windowClass; })
            .def_property_readonly("title", [](const WindowQuery &self) { return self.title; })
            .def("__call__", &WindowQuery_CallImpl);
    }
}
END_OVERLAY_QUERIES_NAMESPACE
