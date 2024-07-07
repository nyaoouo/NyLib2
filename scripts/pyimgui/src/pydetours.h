#pragma once
#include "./gheader.h"
#include <windows.h>
#include "detours/src/detours.h"
void pybind_setup_detours(pybind11::module_ m);

namespace mDetours
{
    LONG simpleAttach(PVOID *ppPointer, PVOID pDetour);

    LONG simpleDetach(PVOID *ppPointer, PVOID pDetour);
}
