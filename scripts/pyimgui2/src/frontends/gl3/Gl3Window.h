#pragma once

#include "../common/RenderBase.h"
#include "../common/Win32Hook.h"

#include <GL/GL.h>
#include "imgui_impl_win32.h"
#include "imgui_impl_opengl3.h"

#define M_IMGUI_IMPL_GL3_NAMESPACE M_IMGUI_IMPL_NAMESPACE::Impl_Gl3
#define START_M_IMGUI_IMPL_GL3_NAMESPACE START_M_IMGUI_IMPL_NAMESPACE { namespace Impl_Gl3
#define END_M_IMGUI_IMPL_GL3_NAMESPACE } END_M_IMGUI_IMPL_NAMESPACE

START_M_IMGUI_IMPL_GL3_NAMESPACE
{
    class Gl3Render : public RenderBase
    {
    public:
        Gl3Render(std::optional<py::function> renderCallback = std::nullopt) : RenderBase(renderCallback) {}
    };

    class Gl3Window : public Gl3Render
    {
    public:
        static inline Gl3Window *_instance = nullptr;
        ImVec4 ClearColor = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

        HDC hDC = nullptr;
        HGLRC hRC = nullptr;
        int width = 0;
        int height = 0;

        Gl3Window(std::optional<py::function> renderCallback = std::nullopt);
        ~Gl3Window();

        bool CreateDeviceWGL(HWND hWnd);
        void CleanupDeviceWGL();
        void Serve();
    };

    class Gl3Inbound : public Gl3Render
    {
    public:
        static inline Gl3Inbound *_instance = nullptr;
        bool isImGuiInitialized = false;
        bool isInLogic = false;
        HDC hostHDC = nullptr;
        HGLRC hostHGLRC = nullptr;

        Gl3Inbound(std::optional<py::function> renderCallback = std::nullopt);
        ~Gl3Inbound();

        void Attach();
        void Detach();
        void InitImGui(HDC hDC);
        void Update();
        void _Update();
    };

    void pybind_setup_mImguiImpl_Gl3(pybind11::module_ m);
}
END_M_IMGUI_IMPL_GL3_NAMESPACE
