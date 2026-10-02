#pragma once
#include "./gHeader.h"

#include <algorithm>
#include <string>
#include <system_error>
#include <vector>

#define OVERLAY_QUERIES_NAMESPACE mNameSpace::OverlayQueries
#define START_OVERLAY_QUERIES_NAMESPACE \
    namespace mNameSpace               \
    {                                  \
        namespace OverlayQueries
#define END_OVERLAY_QUERIES_NAMESPACE }

START_OVERLAY_QUERIES_NAMESPACE
{
    // RAII thread DPI awareness switch: sets `context` in the constructor and
    // restores the previous context on scope exit. Reused by stage 4's Serve
    // thread.
    class ThreadDpiScope
    {
    public:
        explicit ThreadDpiScope(DPI_AWARENESS_CONTEXT context)
        {
            this->prev = SetThreadDpiAwarenessContext(context);
            if (this->prev == nullptr)
                _throw_("SetThreadDpiAwarenessContext failed");
        }

        ~ThreadDpiScope()
        {
            SetThreadDpiAwarenessContext(this->prev);
        }

        ThreadDpiScope(const ThreadDpiScope &) = delete;
        ThreadDpiScope &operator=(const ThreadDpiScope &) = delete;

    private:
        DPI_AWARENESS_CONTEXT prev = nullptr;
    };

    struct MonitorInfo
    {
        int index = 0;
        std::wstring name;
        bool isPrimary = false;
        ImVec2 pos{};
        ImVec2 size{};
    };

    namespace detail
    {
        inline BOOL CALLBACK EnumerateMonitors_EnumProc(HMONITOR monitor, HDC, LPRECT, LPARAM lParam)
        {
            auto *out = reinterpret_cast<std::vector<MonitorInfo> *>(lParam);
            MONITORINFOEXW info{};
            info.cbSize = sizeof(info);
            if (!GetMonitorInfoW(monitor, &info))
                return TRUE;
            MonitorInfo entry;
            entry.name = info.szDevice;
            entry.isPrimary = (info.dwFlags & MONITORINFOF_PRIMARY) != 0;
            entry.pos = ImVec2((float)info.rcMonitor.left, (float)info.rcMonitor.top);
            entry.size = ImVec2((float)(info.rcMonitor.right - info.rcMonitor.left), (float)(info.rcMonitor.bottom - info.rcMonitor.top));
            out->push_back(std::move(entry));
            return TRUE;
        }
    }

    // Enumerates every display monitor in physical pixels (C14), ordered
    // primary first then ascending (left, top, name); `index` is the list
    // position. Throws std::system_error (GetLastError) if EnumDisplayMonitors
    // fails.
    inline std::vector<MonitorInfo> EnumerateMonitors()
    {
        ThreadDpiScope scope(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        std::vector<MonitorInfo> monitors;
        if (!EnumDisplayMonitors(nullptr, nullptr, detail::EnumerateMonitors_EnumProc, reinterpret_cast<LPARAM>(&monitors)))
            throw std::system_error((int)GetLastError(), std::system_category(), "EnumDisplayMonitors");
        std::stable_sort(monitors.begin(), monitors.end(), [](const MonitorInfo &a, const MonitorInfo &b)
        {
            if (a.isPrimary != b.isPrimary)
                return a.isPrimary;
            if (a.pos.x != b.pos.x)
                return a.pos.x < b.pos.x;
            if (a.pos.y != b.pos.y)
                return a.pos.y < b.pos.y;
            return a.name < b.name;
        });
        for (size_t i = 0; i < monitors.size(); ++i)
            monitors[i].index = (int)i;
        return monitors;
    }

    void pybind_setup_OverlayQueries(py::module_ m);
}
END_OVERLAY_QUERIES_NAMESPACE
