#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <Windows.h>
#include <tchar.h>
#include <format>
#include <cstring>
#include <memory>
#include <string>
#include <optional>
#include <type_traits>
#include <unordered_map>
#include <vector>

#define PYBIND11_DETAILED_ERROR_MESSAGES
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/functional.h>
namespace py = pybind11;

#include <dxgiformat.h>
#include "imgui.h"
#include "imgui_internal.h"

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

// Window title helpers: std::string is UTF-8, the Win32 calls are the wide ones.
inline void SetWindowTextUtf8(HWND hwnd, const std::string &utf8)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), (int)utf8.size(), nullptr, 0);
    std::wstring w(n > 0 ? n : 0, L'\0');
    if (n > 0)
        MultiByteToWideChar(CP_UTF8, 0, utf8.data(), (int)utf8.size(), w.data(), n);
    SetWindowTextW(hwnd, w.c_str());
}

inline std::string GetWindowTextUtf8(HWND hwnd)
{
    int len = GetWindowTextLengthW(hwnd);
    if (len <= 0)
        return {};
    std::wstring w(len + 1, L'\0');
    w.resize(GetWindowTextW(hwnd, w.data(), len + 1));
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string utf8(n > 0 ? n : 0, '\0');
    if (n > 0)
        WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), utf8.data(), n, nullptr, nullptr);
    return utf8;
}

#define mNameSpace PyImgui

inline py::module_ pyimgui_import_parent_module(py::module_ m)
{
    std::string module_name = py::str(m.attr("__name__"));
    auto split_at = module_name.rfind('.');
    if (split_at == std::string::npos)
        return py::module_::import("pyimgui");
    return py::module_::import(module_name.substr(0, split_at).c_str());
}

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
        std::function<void()> onExit;
        bool entered = false;

        PyCtxWrapper(py::object res_onEnter, std::function<void()> onExit)
        {
            this->res_onEnter = res_onEnter;
            this->onExit = std::move(onExit);
        }

        PyCtxWrapper(py::object res_onEnter) : PyCtxWrapper(res_onEnter, std::function<void()>()) {}
        PyCtxWrapper(void (*onExit)()) : PyCtxWrapper(py::none(), std::function<void()>(onExit)) {}
        PyCtxWrapper() : PyCtxWrapper(py::none(), std::function<void()>()) {}
    };

    inline void pybind_setup_gUtils(py::module_ m)
    {
        py::class_<PyCtxWrapper>(m, "PyCtxWrapper")
            .def("__enter__", [](PyCtxWrapper &self)
                 {
                     if (self.entered)
                         _throw_("PyCtxWrapper is single-use; call the ctx function again for each with block");
                     self.entered = true;
                     return self.res_onEnter;
                 })
            .def("__exit__", [](PyCtxWrapper &self, py::args args)
                 {
                     auto onExit = std::move(self.onExit);
                     self.onExit = nullptr;
                     if (onExit)
                         onExit();
                 })
            .def("__bool__", [](PyCtxWrapper &) -> bool
                 { throw py::type_error("ctx objects are context managers: use 'with ctx.X(...) as v:' and test v"); });
    }
}
END_G_UTILS_NAMESPACE
