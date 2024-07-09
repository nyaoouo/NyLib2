#pragma once
#include "gheader.h"
#include "detours/src/detours.h"

#define PYDETOURS_NAMESPACE mNameSpace::PyDetours
#define START_PYDETOURS_NAMESPACE namespace mNameSpace{ namespace PyDetours
#define END_PYDETOURS_NAMESPACE }

START_PYDETOURS_NAMESPACE
{
void pybind_setup_pydetours(pybind11::module_ m);

LONG SimpleAttach(PVOID *ppPointer, PVOID pDetour);

LONG SimpleDetach(PVOID *ppPointer, PVOID pDetour);
}
END_PYDETOURS_NAMESPACE