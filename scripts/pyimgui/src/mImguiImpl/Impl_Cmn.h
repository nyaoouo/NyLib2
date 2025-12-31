#pragma once
#include "../gHeader.h"
#include "../PyDetours.h"
#include "../ImguiInbound.h"
#include "./Helper_Cmn.h"

#define M_IMGUI_IMPL_NAMESPACE mNameSpace::MImguiImpl
#define START_M_IMGUI_IMPL_NAMESPACE \
    namespace mNameSpace             \
    {                                \
        namespace MImguiImpl
#define END_M_IMGUI_IMPL_NAMESPACE }

START_M_IMGUI_IMPL_NAMESPACE
{

    inline size_t PyFuncArgc(py::function func)
    {
        pybind11::module inspect_module = pybind11::module::import("inspect");
        pybind11::object result = inspect_module.attr("signature")(func).attr("parameters");
        return pybind11::len(result);
    }

    class RenderBase
    {
    public:
        std::vector<py::function> callBeforeFrameOnce = {};
        std::optional<py::function> renderCallback;
        size_t renderCallback_argc = 0;
        HWND hwnd = nullptr;
        std::string title = "";
        M_IMGUI_HELPER_NAMESPACE::Win32TrayIconHelper trayIconHelper = {};

        void SetHwnd(HWND hwnd)
        {
            this->hwnd = hwnd;
            this->trayIconHelper.SetHwnd(hwnd);
        }

        std::string GetTitle() {
            if (this->hwnd == nullptr) return this->title;
            char buf[256];
            GetWindowTextA(this->hwnd, buf, 256);
            this->title = buf;
            return this->title;
        }
        void SetTitle(std::string title)
        {
            this->title = title;
            if (this->hwnd != nullptr)
                SetWindowTextA(this->hwnd, title.c_str());
        }

        ImGuiContext *ctx = nullptr;

        template <typename T>
        inline void ProcessCallBeforeFrameOnce(T* self)
        {
            auto gstate = PyGILState_Ensure();
            try
            {
                while (!this->callBeforeFrameOnce.empty())
                {
                    auto &func = this->callBeforeFrameOnce.back();
                    auto argc = PyFuncArgc(func);

                    switch (argc)
                    {
                    case 0:
                        func();
                        break;
                    case 1:
                        func(self);
                        break;
                    default:
                        _throwV_("Invalid callBeforeFrameOnce argc {}", argc);
                    }
                    this->callBeforeFrameOnce.pop_back();
                }
            }
            catch (...)
            {
                PyGILState_Release(gstate);
                throw;
            }
            PyGILState_Release(gstate);
        }

        template <typename T>
        inline void ProcessRenderCallback(T* self)
        {
            auto gstate = PyGILState_Ensure();
            try
            {
                if (!this->renderCallback)
                    return;
                if (this->renderCallback_argc == 0)
                    this->renderCallback.value()();
                else if (this->renderCallback_argc == 1)
                    this->renderCallback.value()(self);
                else
                    _throwV_("Invalid renderCallback_argc {}", this->renderCallback_argc);
            }
            catch (...)
            {
                PyGILState_Release(gstate);
                throw;
            }
            PyGILState_Release(gstate);
        }

        inline void SetRenderCallback(std::optional<py::function> renderCallback)
        {
            this->renderCallback = renderCallback;
            this->renderCallback_argc = renderCallback ? PyFuncArgc(renderCallback.value()) : 0;
        }

        RenderBase(py::function renderCallback)
        {
            this->SetRenderCallback(renderCallback);
        }

        inline void Close()
        {
            if (this->hwnd != nullptr)
                PostMessage(this->hwnd, WM_CLOSE, 0, 0);
        }
    };

    inline void pybind_setup_mImguiImpl_Cmn(pybind11::module_ m)
    {
        py::class_<RenderBase>(m, "_RenderBase", py::dynamic_attr())
            .def_property("renderCallback", [](RenderBase &self)
                          { return self.renderCallback; }, &RenderBase::SetRenderCallback)
            .def_property("title", &RenderBase::GetTitle, &RenderBase::SetTitle)
            .def_property("window_size", [](RenderBase &self)
                          {
                              RECT rect;
                              GetClientRect(self.hwnd, &rect);
                              return py::make_tuple(rect.right - rect.left, rect.bottom - rect.top);
                          },
                          [](RenderBase &self, py::tuple size)
                          {
                              SetWindowPos(self.hwnd, nullptr, 0, 0, size[0].cast<int>(), size[1].cast<int>(), SWP_NOMOVE | SWP_NOZORDER);
                          })
            .def_property("window_pos", [](RenderBase &self)
                          {
                              RECT rect;
                              GetWindowRect(self.hwnd, &rect);
                              return py::make_tuple(rect.left, rect.top);
                          },
                          [](RenderBase &self, py::tuple pos)
                          {
                              SetWindowPos(self.hwnd, nullptr, pos[0].cast<int>(), pos[1].cast<int>(), 0, 0, SWP_NOSIZE | SWP_NOZORDER);
                          })
            .def("CallBeforeFrameOnce", [](RenderBase &self, py::function func)
                 {
                    if (PyFuncArgc(func) >1 ) _throwV_("Invalid CallBeforeFrameOnce argc");
                    self.callBeforeFrameOnce.push_back(func); })
            .def("Close", &RenderBase::Close)
            .def("UpdateTrayIconInfo", [](RenderBase &self, const std::wstring &tooltip, const std::wstring &iconPath)
                 {
                     self.trayIconHelper.UpdateInfo(tooltip, iconPath);
                 }, py::arg("tooltip"), py::arg("iconPath") = L"")
            .def("HideToTray", [](RenderBase &self)
                 {
                     self.trayIconHelper.HideToTray();
                 })
            .def("RestoreFromTray", [](RenderBase &self)
                 {
                     self.trayIconHelper.RestoreFromTray();
                 });
    };
}
END_M_IMGUI_IMPL_NAMESPACE
