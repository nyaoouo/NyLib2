#include "./Dx10Window.h"
#include "../common/ImguiInbound.h"
#include "../common/PyDetours.h"

PYBIND11_MODULE(dx10, m) {
    pyimgui_import_parent_module(m);
    G_UTILS_NAMESPACE::InstallUnhandledExceptionFilter();
    PYDETOURS_NAMESPACE::pybind_setup_pydetours(m.def_submodule("detours"));
    IMGUI_INBOUND_NAMESPACE::pybind_setup_imgui_inbound(m.def_submodule("inbound"));
    M_IMGUI_IMPL_DX10_NAMESPACE::pybind_setup_mImguiImpl_Dx10(m);
}