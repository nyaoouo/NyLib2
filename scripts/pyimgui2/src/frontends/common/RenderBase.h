#pragma once

#include "../../gHeader.h"
#include "../../OverlayTypes.h"   // InputPolicy type only; never call pybind_setup_OverlayTypes here

#include <atomic>

#define M_IMGUI_IMPL_NAMESPACE mNameSpace::MImguiImpl
#define START_M_IMGUI_IMPL_NAMESPACE namespace mNameSpace{ namespace MImguiImpl
#define END_M_IMGUI_IMPL_NAMESPACE }

START_M_IMGUI_IMPL_NAMESPACE
{
    size_t PyFuncArgc(py::function func);

    class RenderBase
    {
    public:
        std::vector<py::function> callBeforeFrameOnce = {};
        std::optional<py::function> renderCallback;
        size_t renderCallback_argc = 0;
        HWND hwnd = nullptr;
        std::string title = "";
        std::wstring trayTooltip = L"";
        std::wstring trayIconPath = L"";
        NOTIFYICONDATAW trayIconData = {};
        HICON trayIcon = nullptr;
        bool inTray = false;
        ImGuiContext *ctx = nullptr;
        std::atomic<int> inputPolicy{0};   // InputPolicy value; 0 = Auto
        std::atomic<int> gamepadPolicy{0}; // GamepadPolicy value; 0 = WhenForeground

        RenderBase(std::optional<py::function> renderCallback = std::nullopt);
        virtual ~RenderBase();

        void SetHwnd(HWND hwnd);
        std::string GetTitle();
        void SetTitle(std::string title);
        void SetRenderCallback(std::optional<py::function> renderCallback);
        void SetInputPolicy(OVERLAY_TYPES_NAMESPACE::InputPolicy policy);
        void SetGamepadPolicy(OVERLAY_TYPES_NAMESPACE::GamepadPolicy policy);
        void ProcessCallBeforeFrameOnce(py::object self);
        void ProcessRenderCallback(py::object self);
        void Close();
        void HideToTray();
        void RestoreFromTray();
        void UpdateTrayIconInfo(const std::wstring &tooltip, const std::wstring &iconPath = L"");

        static bool ProcessTrayWindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, LRESULT &result);

    private:
        bool AddTrayIcon();
        bool RemoveTrayIcon();
        LRESULT TrayWindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    };

    void pybind_setup_mImguiImpl_RenderBase(pybind11::module_ m);
}
END_M_IMGUI_IMPL_NAMESPACE