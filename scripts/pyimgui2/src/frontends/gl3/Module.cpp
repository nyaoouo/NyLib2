#include "./Gl3Window.h"
#include "../common/ImguiInbound.h"
#include "../common/PyDetours.h"

PYBIND11_MODULE(gl3, m) {
    pyimgui_import_parent_module(m);
    PYDETOURS_NAMESPACE::pybind_setup_pydetours(m.def_submodule("detours"));
    IMGUI_INBOUND_NAMESPACE::pybind_setup_imgui_inbound(m.def_submodule("inbound"));
    M_IMGUI_IMPL_GL3_NAMESPACE::pybind_setup_mImguiImpl_Gl3(m);
}
