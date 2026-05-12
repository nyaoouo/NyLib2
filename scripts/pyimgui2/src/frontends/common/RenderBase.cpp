#include "./RenderBase.h"
#include <map>
#include <shellapi.h>

#define WM_TRAYICON (WM_APP + 0x100)

START_M_IMGUI_IMPL_NAMESPACE
{
    namespace
    {
        std::map<HWND, RenderBase *> trayWindowMap;
        UINT trayIconId = 1;
        UINT WM_TASKBARCREATED = RegisterWindowMessageW(L"TaskbarCreated");
        HICON defaultTrayIcon = LoadIconW(nullptr, IDI_APPLICATION);
    }

    size_t PyFuncArgc(py::function func)
    {
        py::module inspect_module = py::module::import("inspect");
        py::object result = inspect_module.attr("signature")(func).attr("parameters");
        return py::len(result);
    }

    RenderBase::RenderBase(std::optional<py::function> renderCallback)
    {
        this->trayIcon = defaultTrayIcon;
        this->SetRenderCallback(renderCallback);
    }

    RenderBase::~RenderBase()
    {
        this->RemoveTrayIcon();
        if (this->hwnd != nullptr)
            trayWindowMap.erase(this->hwnd);
        if (this->trayIcon != nullptr && this->trayIcon != defaultTrayIcon)
        {
            DestroyIcon(this->trayIcon);
            this->trayIcon = nullptr;
        }
    }

    void RenderBase::SetHwnd(HWND hwnd)
    {
        if (this->hwnd != nullptr)
            trayWindowMap.erase(this->hwnd);
        this->hwnd = hwnd;
        if (hwnd != nullptr)
            trayWindowMap[hwnd] = this;
    }

    std::string RenderBase::GetTitle()
    {
        if (this->hwnd == nullptr)
            return this->title;
        char buf[512] = {};
        GetWindowTextA(this->hwnd, buf, sizeof(buf));
        this->title = buf;
        return this->title;
    }

    void RenderBase::SetTitle(std::string title)
    {
        this->title = title;
        if (this->hwnd != nullptr)
            SetWindowTextA(this->hwnd, title.c_str());
    }

    void RenderBase::SetRenderCallback(std::optional<py::function> renderCallback)
    {
        this->renderCallback = renderCallback;
        this->renderCallback_argc = renderCallback ? PyFuncArgc(renderCallback.value()) : 0;
    }

    void RenderBase::ProcessCallBeforeFrameOnce(py::object self)
    {
        auto gstate = PyGILState_Ensure();
        try
        {
            while (!this->callBeforeFrameOnce.empty())
            {
                py::function func = this->callBeforeFrameOnce.back();
                this->callBeforeFrameOnce.pop_back();
                auto argc = PyFuncArgc(func);
                if (argc == 0)
                    func();
                else if (argc == 1)
                    func(self);
                else
                    _throwV_("Invalid CallBeforeFrameOnce argc: {}", argc);
            }
        }
        catch (...)
        {
            PyGILState_Release(gstate);
            throw;
        }
        PyGILState_Release(gstate);
    }

    void RenderBase::ProcessRenderCallback(py::object self)
    {
        auto gstate = PyGILState_Ensure();
        try
        {
            if (this->renderCallback)
            {
                if (this->renderCallback_argc == 0)
                    this->renderCallback.value()();
                else if (this->renderCallback_argc == 1)
                    this->renderCallback.value()(self);
                else
                    _throwV_("Invalid renderCallback argc: {}", this->renderCallback_argc);
            }
        }
        catch (...)
        {
            PyGILState_Release(gstate);
            throw;
        }
        PyGILState_Release(gstate);
    }

    void RenderBase::Close()
    {
        if (this->hwnd != nullptr)
            PostMessage(this->hwnd, WM_CLOSE, 0, 0);
    }

    bool RenderBase::ProcessTrayWindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, LRESULT &result)
    {
        auto it = trayWindowMap.find(hwnd);
        if (it == trayWindowMap.end())
            return false;
        result = it->second->TrayWindowProc(hwnd, msg, wParam, lParam);
        return result != 0;
    }

    LRESULT RenderBase::TrayWindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        if (msg == WM_TASKBARCREATED)
        {
            if (this->inTray && Shell_NotifyIconW(NIM_ADD, &this->trayIconData))
            {
                this->trayIconData.uVersion = NOTIFYICON_VERSION_4;
                Shell_NotifyIconW(NIM_SETVERSION, &this->trayIconData);
            }
            return 1;
        }

        if (msg == WM_TRAYICON)
        {
            switch (LOWORD(lParam))
            {
            case WM_LBUTTONDBLCLK:
            case WM_LBUTTONUP:
                this->RestoreFromTray();
                return 1;
            }
        }
        return 0;
    }

    void RenderBase::HideToTray()
    {
        if (this->inTray)
            return;
        if (!this->AddTrayIcon())
            return;
        ShowWindow(this->hwnd, SW_HIDE);
    }

    void RenderBase::RestoreFromTray()
    {
        if (!this->inTray)
            return;
        if (!this->RemoveTrayIcon())
            return;
        ShowWindow(this->hwnd, SW_SHOW);
        ShowWindow(this->hwnd, SW_RESTORE);
    }

    void RenderBase::UpdateTrayIconInfo(const std::wstring &tooltip, const std::wstring &iconPath)
    {
        if (this->trayIcon != nullptr && this->trayIcon != defaultTrayIcon)
        {
            DestroyIcon(this->trayIcon);
            this->trayIcon = nullptr;
        }

        this->trayTooltip = tooltip;
        this->trayIconPath = iconPath;
        if (!iconPath.empty())
            this->trayIcon = (HICON)LoadImageW(nullptr, iconPath.c_str(), IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE);
        if (this->trayIcon == nullptr)
            this->trayIcon = defaultTrayIcon;

        if (this->inTray)
        {
            this->RemoveTrayIcon();
            this->AddTrayIcon();
        }
    }

    bool RenderBase::AddTrayIcon()
    {
        if (this->inTray)
            return true;
        if (this->hwnd == nullptr)
            return false;

        ZeroMemory(&this->trayIconData, sizeof(NOTIFYICONDATAW));
        this->trayIconData.cbSize = sizeof(NOTIFYICONDATAW);
        this->trayIconData.hWnd = this->hwnd;
        this->trayIconData.uID = ++trayIconId;
        this->trayIconData.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        this->trayIconData.uCallbackMessage = WM_TRAYICON;
        this->trayIconData.hIcon = this->trayIcon ? this->trayIcon : defaultTrayIcon;
        wcsncpy_s(this->trayIconData.szTip, this->trayTooltip.c_str(), _TRUNCATE);

        if (Shell_NotifyIconW(NIM_ADD, &this->trayIconData))
        {
            this->trayIconData.uVersion = NOTIFYICON_VERSION_4;
            Shell_NotifyIconW(NIM_SETVERSION, &this->trayIconData);
            this->inTray = true;
            return true;
        }
        return false;
    }

    bool RenderBase::RemoveTrayIcon()
    {
        if (!this->inTray)
            return true;
        if (Shell_NotifyIconW(NIM_DELETE, &this->trayIconData))
        {
            this->inTray = false;
            return true;
        }
        return false;
    }

    void pybind_setup_mImguiImpl_RenderBase(pybind11::module_ m)
    {
        py::class_<RenderBase>(m, "_RenderBase", py::dynamic_attr(), py::module_local())
            .def_property("renderCallback", [](RenderBase &self) { return self.renderCallback; }, &RenderBase::SetRenderCallback)
            .def_property("title", &RenderBase::GetTitle, &RenderBase::SetTitle)
            .def("CallBeforeFrameOnce", [](RenderBase &self, py::function func) { self.callBeforeFrameOnce.push_back(func); })
            .def("Close", &RenderBase::Close)
            .def("UpdateTrayIconInfo", &RenderBase::UpdateTrayIconInfo, py::arg("tooltip"), py::arg("iconPath") = L"")
            .def("HideToTray", &RenderBase::HideToTray)
            .def("RestoreFromTray", &RenderBase::RestoreFromTray);
    }
}
END_M_IMGUI_IMPL_NAMESPACE