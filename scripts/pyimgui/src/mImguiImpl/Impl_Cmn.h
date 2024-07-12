#pragma once
#include "../gHeader.h"
#include "../PyDetours.h"
#include "../ImguiInbound.h"

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

        ImGuiContext *ctx = nullptr;

        inline void ProcessCallBeforeFrameOnce()
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
                        func(this);
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

        inline void ProcessRenderCallback()
        {
            auto gstate = PyGILState_Ensure();
            try
            {
                if (!this->renderCallback)
                    return;
                if (this->renderCallback_argc == 0)
                    this->renderCallback.value()();
                else if (this->renderCallback_argc == 1)
                    this->renderCallback.value()(this);
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
            .def("CallBeforeFrameOnce", [](RenderBase &self, py::function func)
                 { 
                    if (PyFuncArgc(func) >1 ) _throwV_("Invalid CallBeforeFrameOnce argc");
                    self.callBeforeFrameOnce.push_back(func); })
            .def("Close", &RenderBase::Close);
    };
}
END_M_IMGUI_IMPL_NAMESPACE