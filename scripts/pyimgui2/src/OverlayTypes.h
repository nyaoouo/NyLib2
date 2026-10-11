#pragma once
#include "./gHeader.h"

#define OVERLAY_TYPES_NAMESPACE mNameSpace::OverlayTypes
#define START_OVERLAY_TYPES_NAMESPACE \
    namespace mNameSpace               \
    {                                  \
        namespace OverlayTypes
#define END_OVERLAY_TYPES_NAMESPACE }

START_OVERLAY_TYPES_NAMESPACE
{
    enum class InputPolicy
    {
        Auto = 0,
        CaptureAll = 1,
        PassAll = 2,
    };

    enum class OverlayZOrder
    {
        AboveTarget = 0,
        Topmost = 1,
    };

    enum class GamepadPolicy
    {
        WhenForeground = 0,
        Always = 1,
        Never = 2,
    };

    // Register InputPolicy, OverlayZOrder and GamepadPolicy on `m` (the
    // top-level pyimgui module). Must be called exactly once (DllMain.cpp,
    // core only): all three are shared across py::module_local() frontend
    // classes.
    void pybind_setup_OverlayTypes(py::module_ m);
}
END_OVERLAY_TYPES_NAMESPACE
