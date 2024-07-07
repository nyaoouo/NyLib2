#include "./win32.h"



void pybind_setup_win32(pybind11::module_ m){
    py::class_<WNDCLASSEXW>(m, "WNDCLASSEXW", py::dynamic_attr())
        .def(py::init<>())
        .def_readwrite("cbSize", &WNDCLASSEXW::cbSize)
        .def_readwrite("style", &WNDCLASSEXW::style)
        .def_readwrite("lpfnWndProc", &WNDCLASSEXW::lpfnWndProc)
        .def_readwrite("cbClsExtra", &WNDCLASSEXW::cbClsExtra)
        .def_readwrite("cbWndExtra", &WNDCLASSEXW::cbWndExtra)
        .def_readwrite("hInstance", &WNDCLASSEXW::hInstance)
        .def_readwrite("hIcon", &WNDCLASSEXW::hIcon)
        .def_readwrite("hCursor", &WNDCLASSEXW::hCursor)
        .def_readwrite("hbrBackground", &WNDCLASSEXW::hbrBackground)
        .def_readwrite("lpszMenuName", &WNDCLASSEXW::lpszMenuName)
        .def_readwrite("lpszClassName", &WNDCLASSEXW::lpszClassName)
        .def_readwrite("hIconSm", &WNDCLASSEXW::hIconSm);

    m.def("RegisterClassExW", [](const WNDCLASSEXW& lpwcx){ return RegisterClassExW(&lpwcx); }, py::arg("lpwcx"));

    m.def(
        "CreateWindowW", [](LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam){
            return CreateWindowW(lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
        },
        py::arg("lpClassName"),
        py::arg("lpWindowName"),
        py::arg("dwStyle"),
        py::arg("x"),
        py::arg("y"),
        py::arg("nWidth"),
        py::arg("nHeight"),
        py::arg("hWndParent"),
        py::arg("hMenu"),
        py::arg("hInstance"),
        py::arg("lpParam")
        );
}
