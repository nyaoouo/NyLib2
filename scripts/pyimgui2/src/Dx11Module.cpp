#include "./gHeader.h"
#include "./Dx11Window.h"
#include "./frontends/common/ImguiInbound.h"
#include "./frontends/common/PyDetours.h"
#include "./frontends/common/Win32Hook.h"

PYBIND11_MODULE(dx11, m) {
    pyimgui_import_parent_module(m);
    PYDETOURS_NAMESPACE::pybind_setup_pydetours(m.def_submodule("detours"));
    IMGUI_INBOUND_NAMESPACE::pybind_setup_imgui_inbound(m.def_submodule("inbound"));
    M_IMGUI_IMPL_WIN32_NAMESPACE::pybind_setup_mImguiImpl_Win32(m);
    M_IMGUI_IMPL_NAMESPACE::pybind_setup_mImguiImpl(m);
}