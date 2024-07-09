#pragma once
#include "./gheader.h"
#include "./PyDetours.h"
#include "./pyimgui.h"
#include "./ImguiCtx.h"
#include "./mImguiImpl/index.h"


PYBIND11_MODULE(pyimgui, m) {
    G_UTILS_NAMESPACE::InstallUnhandledExceptionFilter();
    G_UTILS_NAMESPACE::pybind_setup_gUtils(m.def_submodule("gUtils"));
    PYDETOURS_NAMESPACE::pybind_setup_pydetours(m.def_submodule("detours"));
    auto imgui_m = m.def_submodule("imgui");
    PYIMGUI_CORE_NAMESPACE::pybind_setup_pyimgui_core(imgui_m);
    IMGUI_CTX_NAMESPACE::pybind_setup_ImguiCtx(imgui_m.def_submodule("ctx"));
    M_IMGUI_IMPL_NAMESPACE::pybind_setup_mImguiImpl(m);
}
