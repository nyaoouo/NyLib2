#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <Windows.h>
#include <tchar.h>
#include <format>
#include <string>

#define PYBIND11_DETAILED_ERROR_MESSAGES
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/functional.h>
namespace py = pybind11;

#include <dxgiformat.h> // DXGI_FORMAT
#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#ifndef CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include "imgui.h"
#include "imgui_internal.h"
#endif
#include "cimgui.h"
#include "cimgui_impl.h"

#define _errV_(x, ...) (std::runtime_error(std::format(x "(at {}:{})", __VA_ARGS__, __FILE__, __LINE__)))
#define _err_(x) (std::runtime_error(std::format(x "(at {}:{})", __FILE__, __LINE__)))
#define _throwV_(x, ...)              \
    {                                 \
        throw _errV_(x, __VA_ARGS__); \
    }
#define _throw_(x)      \
    {                   \
        throw _err_(x); \
    }

#ifdef _DEBUG
#define dbgPrint(...)        \
    {                        \
        printf(__VA_ARGS__); \
    }
#else
#define dbgPrint(...) \
    {                 \
    }
#endif

#define DX_HR_FAILED(vname, ...) ((vname = (__VA_ARGS__)) != S_OK)

#define mNameSpace PyImgui

#define G_UTILS_NAMESPACE mNameSpace::GUtils
#define START_G_UTILS_NAMESPACE \
    namespace mNameSpace        \
    {                           \
        namespace GUtils
#define END_G_UTILS_NAMESPACE }

START_G_UTILS_NAMESPACE
{
    struct PyCtxWrapper
    {
        py::object res_onEnter;
        void (*onExit)();

        PyCtxWrapper(py::object res_onEnter, void (*onExit)())
        {
            this->res_onEnter = res_onEnter;
            this->onExit = onExit;
        }

        PyCtxWrapper(py::object res_onEnter) : PyCtxWrapper(res_onEnter, nullptr) {}
        PyCtxWrapper(void (*onExit)()) : PyCtxWrapper(py::none(), onExit) {}
        PyCtxWrapper() : PyCtxWrapper(py::none(), nullptr) {}
    };

    inline void pybind_setup_gUtils(py::module_ m)
    {
        py::class_<PyCtxWrapper>(m, "PyCtxWrapper")
            .def("__enter__", [](PyCtxWrapper &self)
                 { return self.res_onEnter; })
            .def("__exit__", [](PyCtxWrapper &self, py::args args)
                 { if(self.onExit)self.onExit(); });
    }

    void InstallUnhandledExceptionFilter();
}
END_G_UTILS_NAMESPACE
