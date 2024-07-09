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

#define M_IMGUI_IMPL_WIN32_NAMESPACE M_IMGUI_IMPL_NAMESPACE::Impl_Win32
#define START_M_IMGUI_IMPL_WIN32_NAMESPACE \
    START_M_IMGUI_IMPL_NAMESPACE           \
    {                                      \
        namespace Impl_Win32

#define END_M_IMGUI_IMPL_WIN32_NAMESPACE \
    }                                    \
    END_M_IMGUI_IMPL_NAMESPACE

IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
START_M_IMGUI_IMPL_WIN32_NAMESPACE
{
    void Attach(HWND hwnd);
    void Detach(HWND hwnd);
    inline void pybind_setup_mImguiImpl_Win32(pybind11::module_ m) {};
}
END_M_IMGUI_IMPL_WIN32_NAMESPACE