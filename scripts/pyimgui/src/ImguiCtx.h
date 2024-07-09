#include "gHeader.h"

#define IMGUI_CTX_NAMESPACE mNameSpace::ImguiCtx
#define START_IMGUI_CTX_NAMESPACE namespace mNameSpace{ namespace ImguiCtx
#define END_IMGUI_CTX_NAMESPACE }

START_IMGUI_CTX_NAMESPACE
{
    void pybind_setup_ImguiCtx(pybind11::module_ m);
}
END_IMGUI_CTX_NAMESPACE