#include "./OverlayTypes.h"

START_OVERLAY_TYPES_NAMESPACE
{
    void pybind_setup_OverlayTypes(py::module_ m)
    {
        // No py::arithmetic(): the frozen rule is int -> TypeError.
        py::enum_<InputPolicy>(m, "InputPolicy")
            .value("Auto", InputPolicy::Auto)
            .value("CaptureAll", InputPolicy::CaptureAll)
            .value("PassAll", InputPolicy::PassAll);

        py::enum_<OverlayZOrder>(m, "OverlayZOrder")
            .value("AboveTarget", OverlayZOrder::AboveTarget)
            .value("Topmost", OverlayZOrder::Topmost);

        py::enum_<GamepadPolicy>(m, "GamepadPolicy")
            .value("WhenForeground", GamepadPolicy::WhenForeground)
            .value("Always", GamepadPolicy::Always)
            .value("Never", GamepadPolicy::Never);
    }
}
END_OVERLAY_TYPES_NAMESPACE
