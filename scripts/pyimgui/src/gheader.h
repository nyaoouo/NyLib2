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
namespace py = pybind11;


#include <dxgiformat.h> // DXGI_FORMAT
#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include "cimgui.h"
#include "cimgui_impl.h"

#define _throwV_(x,...) {throw std::runtime_error(std::format(x"(at {}:{})",__VA_ARGS__,__FILE__,__LINE__));}
#define _throw_(x) {throw std::runtime_error(std::format(x"(at {}:{})",__FILE__,__LINE__));}

#ifdef _DEBUG
#define dbgPrint(...) {printf(__VA_ARGS__);}
#else
#define dbgPrint(...) {}
#endif