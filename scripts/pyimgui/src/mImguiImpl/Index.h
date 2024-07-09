#pragma once
#include "./Impl_Win32.h"
#include "./Impl_Dx9.h"
#include "./Impl_Dx10.h"
#include "./Impl_Dx11.h"
#include "./Impl_Dx12.h"

START_M_IMGUI_IMPL_NAMESPACE
{
    inline void pybind_setup_mImguiImpl(pybind11::module_ m)
    {
        M_IMGUI_IMPL_WIN32_NAMESPACE::pybind_setup_mImguiImpl_Win32(m);
        M_IMGUI_IMPL_Dx9_NAMESPACE::pybind_setup_mImguiImpl_Dx9(m);
        M_IMGUI_IMPL_Dx10_NAMESPACE::pybind_setup_mImguiImpl_Dx10(m);
        M_IMGUI_IMPL_Dx11_NAMESPACE::pybind_setup_mImguiImpl_Dx11(m);
        M_IMGUI_IMPL_Dx12_NAMESPACE::pybind_setup_mImguiImpl_Dx12(m);
    }
}
END_M_IMGUI_IMPL_NAMESPACE